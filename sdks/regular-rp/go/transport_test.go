package regularrp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	rpctransport "github.com/catalystcommunity/csilgen/transports/go"
	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

const testAPIKey = "test-api-key"

// fakeRpReply is what the fake RP server sends back, plus the API key it
// saw in the request envelope.
type fakeRpReply struct {
	resp rpctransport.RpcResponse
	auth chan *string
}

// spawnFakeRp starts a pinned-TLS CSIL-RPC server on loopback that answers
// one request with reply.resp. It returns the address and the pin of its
// certificate. The handler encodes nothing, so it never calls t.Fatal off
// the test goroutine.
func spawnFakeRp(t *testing.T, reply fakeRpReply) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("certificate: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := tls.Server(conn, cfg)
		defer tlsConn.Close()
		carrier, err := rpctransport.NewStreamCarrierWithMaxFrame(tlsConn, maxFrameSize)
		if err != nil {
			return
		}
		frame, err := carrier.RecvFrame()
		if err != nil || frame == nil {
			return
		}
		req, err := rpctransport.DecodeRpcRequest(frame)
		if err != nil {
			return
		}
		reply.auth <- req.Auth
		encoded, err := reply.resp.Encode()
		if err != nil {
			return
		}
		_ = carrier.SendFrame(encoded)
	}()
	return ln.Addr().String(), Fingerprint([]byte(pub))
}

// verifyThroughGeneratedClient sends one Rp/verify-assertion call through
// PinnedRpcTransport and the generated client, answered with resp.
func verifyThroughGeneratedClient(t *testing.T, resp rpctransport.RpcResponse) (api.RpVerifyResponse, error) {
	t.Helper()
	reply := fakeRpReply{resp: resp, auth: make(chan *string, 1)}
	addr, pin := spawnFakeRp(t, reply)
	transport, err := NewPinnedRpcTransport(PinnedRpcTransportOptions{
		TCPAddress:     addr,
		Fingerprints:   []string{pin},
		APIKey:         testAPIKey,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	out, callErr := api.NewRpClient(transport).VerifyAssertion(context.Background(), api.RpVerifyRequest{
		SignedAssertion: "assertion",
		ExpectedDomain:  "home.example",
	})
	select {
	case auth := <-reply.auth:
		if auth == nil || *auth != testAPIKey {
			t.Errorf("request envelope did not carry the API key")
		}
	default:
		t.Errorf("fake RP received no request")
	}
	return out, callErr
}

func TestCallReplySuccessArm(t *testing.T) {
	payload := must[[]byte](t)(api.EncodeRpVerifyResponse(api.RpVerifyResponse{Verified: true}))
	out, err := verifyThroughGeneratedClient(t, rpctransport.NewRpcResponseOk("RpVerifyResponse", payload))
	if err != nil {
		t.Fatalf("verify-assertion: %v", err)
	}
	if !out.Verified {
		t.Errorf("success arm did not decode: %+v", out)
	}
}

func TestCallReplyRpErrorIsTyped(t *testing.T) {
	payload := must[[]byte](t)(api.EncodeRpError(api.RpError{Code: api.RpErrorCodeApplicationMismatch, Message: "wrong application"}))
	_, err := verifyThroughGeneratedClient(t, rpctransport.NewRpcResponseOk("RpError", payload))
	var refusal *api.RPCApplicationError[api.RpError]
	if !errors.As(err, &refusal) {
		t.Fatalf("want *api.RPCApplicationError[api.RpError], got %T: %v", err, err)
	}
	if refusal.Value.Code != api.RpErrorCodeApplicationMismatch || refusal.Value.Message != "wrong application" {
		t.Errorf("RpError did not round-trip: %+v", refusal.Value)
	}
}

func TestCallReplyUnknownVariantIsError(t *testing.T) {
	payload := must[[]byte](t)(api.EncodeRpVerifyResponse(api.RpVerifyResponse{Verified: true}))
	_, err := verifyThroughGeneratedClient(t, rpctransport.NewRpcResponseOk("NotAnArm", payload))
	var decodeErr *api.RPCDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("want *api.RPCDecodeError for an unknown variant, got %T: %v", err, err)
	}
}

func TestCallReplyMissingVariantIsError(t *testing.T) {
	payload := must[[]byte](t)(api.EncodeRpVerifyResponse(api.RpVerifyResponse{Verified: true}))
	_, err := verifyThroughGeneratedClient(t, rpctransport.RpcResponse{Status: rpctransport.StatusOk, Payload: payload})
	var decodeErr *api.RPCDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("want *api.RPCDecodeError for a missing variant, got %T: %v", err, err)
	}
}

func TestCallReplyTransportStatusIsServerError(t *testing.T) {
	_, err := verifyThroughGeneratedClient(t, rpctransport.NewRpcResponseTransportError(rpctransport.StatusInternal, "boom"))
	var serverErr *ServerError
	if !errors.As(err, &serverErr) || serverErr.Message != "boom" {
		t.Fatalf("want *ServerError, got %T: %v", err, err)
	}
}

// transportAnswering returns a PinnedRpcTransport whose fake RP answers one
// request with resp.
func transportAnswering(t *testing.T, resp rpctransport.RpcResponse) *PinnedRpcTransport {
	t.Helper()
	addr, pin := spawnFakeRp(t, fakeRpReply{resp: resp, auth: make(chan *string, 1)})
	transport, err := NewPinnedRpcTransport(PinnedRpcTransportOptions{
		TCPAddress:     addr,
		Fingerprints:   []string{pin},
		APIKey:         testAPIKey,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	return transport
}

// An operation without an error arm uses Transport.Call. A reply that does
// not decode must give the same *api.RPCDecodeError as the CallReply path.
func TestCallMalformedReplyIsDecodeError(t *testing.T) {
	transport := transportAnswering(t, rpctransport.NewRpcResponseOk("CheckResult", []byte{0xff}))
	_, err := api.NewOpsClient(transport).Healthcheck(context.Background(), api.EmptyRequest{})
	var decodeErr *api.RPCDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("want *api.RPCDecodeError on the Call path, got %T: %v", err, err)
	}
}

// The same applies to a malformed success arm on the CallReply path.
func TestCallReplyMalformedSuccessArmIsDecodeError(t *testing.T) {
	_, err := verifyThroughGeneratedClient(t, rpctransport.NewRpcResponseOk("RpVerifyResponse", []byte{0xff}))
	var decodeErr *api.RPCDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("want *api.RPCDecodeError for a malformed success arm, got %T: %v", err, err)
	}
}

// A request with no wire form gives *api.RPCEncodeError before any bytes
// go to the transport.
func TestUnencodableRequestIsEncodeError(t *testing.T) {
	_, err := api.NewAdminClient(nil).GetApplicationUsage(context.Background(), api.GetApplicationUsageRequest{
		UserId:   "u",
		FirstDay: "not-a-date",
		LastDay:  "2026-11-23",
	})
	var encodeErr *api.RPCEncodeError
	if !errors.As(err, &encodeErr) {
		t.Fatalf("want *api.RPCEncodeError, got %T: %v", err, err)
	}
}

// canceledTransport fails every call with context.Canceled.
type canceledTransport struct{}

func (canceledTransport) Call(context.Context, string, string, []byte) ([]byte, error) {
	return nil, context.Canceled
}

func (canceledTransport) CallReply(context.Context, string, string, []byte) (api.WireReply, error) {
	return api.WireReply{}, context.Canceled
}

// The generated client passes a transport error through unchanged, on both
// the Call and the CallReply path.
func TestGeneratedClientKeepsTransportError(t *testing.T) {
	_, err := api.NewOpsClient(canceledTransport{}).Healthcheck(context.Background(), api.EmptyRequest{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Call path: want context.Canceled, got %T: %v", err, err)
	}
	_, err = api.NewRpClient(canceledTransport{}).VerifyAssertion(context.Background(), api.RpVerifyRequest{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("CallReply path: want context.Canceled, got %T: %v", err, err)
	}
}
