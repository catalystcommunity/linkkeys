package localrp

import (
	"encoding/base64"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// URL parameter encoding helpers — mirrors crates/liblinkkeys/src/encoding.rs.
// All CBOR-in-URL values are base64url-encoded, unpadded (RFC 4648 §5,
// "URL and Filename Safe Alphabet", no `=` padding), matching
// `base64ct::Base64UrlUnpadded` exactly.

func encodeURLParam(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// encodedToURLParam takes the result of a generated `api.EncodeX` call and
// returns its URL-safe string form, or an *EncodeError when the encode failed.
func encodedToURLParam(what string, b []byte, err error) (string, error) {
	if err != nil {
		return "", encodeFailed(what, err)
	}
	return encodeURLParam(b), nil
}

func decodeURLParam(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, &DecodeError{Detail: "base64url decode failed: " + err.Error()}
	}
	return b, nil
}

// SignedLocalRpLoginRequestToURLParam encodes a SignedLocalRpLoginRequest
// for the begin route's `?signed_request=<...>` query parameter (Wire
// Precision: "URL and parameter conventions").
func SignedLocalRpLoginRequestToURLParam(signed api.SignedLocalRpLoginRequest) (string, error) {
	b, err := api.EncodeSignedLocalRpLoginRequest(signed)
	return encodedToURLParam("SignedLocalRpLoginRequest", b, err)
}

// SignedLocalRpLoginRequestFromURLParam decodes a SignedLocalRpLoginRequest
// from its URL-safe string form.
func SignedLocalRpLoginRequestFromURLParam(param string) (*api.SignedLocalRpLoginRequest, error) {
	b, err := decodeURLParam(param)
	if err != nil {
		return nil, err
	}
	v, err := api.DecodeSignedLocalRpLoginRequest(b)
	if err != nil {
		return nil, &DecodeError{Detail: "CBOR decode failed: " + err.Error()}
	}
	return &v, nil
}

// LocalRpEncryptedCallbackToURLParam encodes a LocalRpEncryptedCallback for
// the callback redirect's `&encrypted_token=<...>` query parameter (same
// name/mechanics as the existing DNS-pinned flow's `encrypted_token`
// parameter).
func LocalRpEncryptedCallbackToURLParam(cb api.LocalRpEncryptedCallback) (string, error) {
	b, err := api.EncodeLocalRpEncryptedCallback(cb)
	return encodedToURLParam("LocalRpEncryptedCallback", b, err)
}

// LocalRpEncryptedCallbackFromURLParam decodes a LocalRpEncryptedCallback
// from its URL-safe string form.
func LocalRpEncryptedCallbackFromURLParam(param string) (*api.LocalRpEncryptedCallback, error) {
	b, err := decodeURLParam(param)
	if err != nil {
		return nil, err
	}
	v, err := api.DecodeLocalRpEncryptedCallback(b)
	if err != nil {
		return nil, &DecodeError{Detail: "CBOR decode failed: " + err.Error()}
	}
	return &v, nil
}
