package regularrp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Unit tests for act-as grants: sign-then-verify round trips inside this
// package (the conformance vectors only prove Verify* agrees with Rust), and
// the RP calls against a fake api.Transport. No test opens a network
// connection.

const testHomeDomain = "home.example"

var actAsNow = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

type actAsWorld struct {
	audience        api.ApplicationRef
	audienceSigner  ApplicationSigner
	audienceKeys    []ApplicationKeyRef
	granteeApp      api.ApplicationRef
	appSigner       GranteeSigner
	granteeKeys     []ApplicationKeyRef
	localFP         string
	localSigner     GranteeSigner
	homeKey         api.DomainPublicKey
	homePriv        ed25519.PrivateKey
	requestDigest   []byte
	presentationAge int64
}

func newEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func appKey(t *testing.T, keyID string) (ApplicationSigner, ApplicationKeyRef) {
	t.Helper()
	pub, priv := newEd25519(t)
	return ApplicationSigner{KeyID: keyID, Algorithm: "ed25519", PrivateKeyBytes: priv.Seed()},
		ApplicationKeyRef{
			KeyID:       keyID,
			KeyUsage:    KeyUsageSign,
			Algorithm:   "ed25519",
			PublicKey:   pub,
			Fingerprint: Fingerprint(pub),
			CreatedAt:   FormatActAsTime(actAsNow.Add(-24 * time.Hour)),
			ExpiresAt:   FormatActAsTime(actAsNow.Add(365 * 24 * time.Hour)),
		}
}

func newDomainKey(t *testing.T, keyID string) (api.DomainPublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := newEd25519(t)
	return api.DomainPublicKey{
		KeyId:       keyID,
		PublicKey:   pub,
		Fingerprint: Fingerprint(pub),
		Algorithm:   "ed25519",
		KeyUsage:    "sign",
		CreatedAt:   FormatActAsTime(time.Now().Add(-24 * time.Hour)),
		ExpiresAt:   FormatActAsTime(time.Now().Add(10 * 365 * 24 * time.Hour)),
	}, priv
}

func newLocalRp(t *testing.T) (api.SignedLocalRpDescriptor, string, []byte) {
	t.Helper()
	pub, priv := newEd25519(t)
	encPub, _, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	descriptor := api.LocalRpDescriptor{
		AppName:             "local app",
		SigningPublicKey:    pub,
		EncryptionPublicKey: encPub[:],
		Fingerprint:         Fingerprint(pub),
		SupportedSuites:     []api.AeadSuite{"chacha20-poly1305"},
		CreatedAt:           FormatActAsTime(actAsNow.Add(-time.Hour)),
		ExpiresAt:           FormatActAsTime(actAsNow.Add(24 * time.Hour)),
	}
	descriptorBytes := api.EncodeLocalRpDescriptor(descriptor)
	return api.SignedLocalRpDescriptor{
		Descriptor: descriptorBytes,
		Signature:  ed25519.Sign(priv, envelopeSignatureInput(localRpDescriptorTag, descriptorBytes)),
	}, descriptor.Fingerprint, priv.Seed()
}

func newActAsWorld(t *testing.T) actAsWorld {
	t.Helper()
	audienceSigner, audienceKey := appKey(t, "audience-key")
	granteeSigner, granteeKey := appKey(t, "grantee-key")
	descriptor, fp, localSeed := newLocalRp(t)
	homeKey, homePriv := newDomainKey(t, "home-key")
	return actAsWorld{
		audience:        api.ApplicationRef{SubjectUserId: "owner-d", SubjectDomain: "d.example", ApplicationId: "app-d"},
		audienceSigner:  audienceSigner,
		audienceKeys:    []ApplicationKeyRef{audienceKey},
		granteeApp:      api.ApplicationRef{SubjectUserId: "owner-c", SubjectDomain: "c.example", ApplicationId: "app-c"},
		appSigner:       NewApplicationGranteeSigner("instance-c", granteeSigner),
		granteeKeys:     []ApplicationKeyRef{granteeKey},
		localFP:         fp,
		localSigner:     NewLocalRpGranteeSigner(descriptor, fp, localSeed),
		homeKey:         homeKey,
		homePriv:        homePriv,
		requestDigest:   []byte("request-digest"),
		presentationAge: 300,
	}
}

func (w actAsWorld) granteeRef(local bool) api.GranteeRef {
	if local {
		fp := w.localFP
		return api.GranteeRef{LocalRpDescriptorFingerprint: &fp}
	}
	app := w.granteeApp
	return api.GranteeRef{Application: &app}
}

// signGrant plays the home domain: it signs a grant for grantee.
func (w actAsWorld) signGrant(t *testing.T, grantee api.GranteeRef, mutate func(*api.ActAsGrant)) api.SignedActAsGrant {
	t.Helper()
	scopeSet, err := SignScopeSet(api.ActAsScopeSet{
		Audience:  w.audience,
		Grantee:   grantee,
		Entries:   []api.ActAsScopeEntry{{Scope: "read"}, {Scope: "write"}},
		IssuedAt:  FormatActAsTime(actAsNow.Add(-time.Hour)),
		ExpiresAt: FormatActAsTime(actAsNow.Add(-30 * time.Minute)), // expired: must not matter
	}, "instance-d", []ApplicationSigner{w.audienceSigner})
	if err != nil {
		t.Fatalf("sign scope set: %v", err)
	}
	grant := api.ActAsGrant{
		GrantId:        "grant-1",
		UserId:         "user-1",
		SubjectDomain:  testHomeDomain,
		Grantee:        grantee,
		Audience:       w.audience,
		ScopeSet:       scopeSet,
		ApprovedScope:  []string{"read"},
		IssuedAt:       FormatActAsTime(actAsNow.Add(-10 * time.Minute)),
		ExpiresAt:      FormatActAsTime(actAsNow.Add(50 * time.Minute)),
		SeriesIssuedAt: FormatActAsTime(actAsNow.Add(-10 * time.Minute)),
		RenewableUntil: FormatActAsTime(actAsNow.Add(2 * time.Hour)),
	}
	if mutate != nil {
		mutate(&grant)
	}
	grantBytes := api.EncodeActAsGrant(grant)
	return api.SignedActAsGrant{
		Grant: grantBytes,
		Signatures: []api.ClaimSignature{{
			Domain:        testHomeDomain,
			SignedByKeyId: w.homeKey.KeyId,
			Signature:     ed25519.Sign(w.homePriv, envelopeSignatureInput(GrantTag, grantBytes)),
		}},
	}
}

func (w actAsWorld) context() AudienceContext {
	return AudienceContext{
		OwnApplication:            w.audience,
		OwnScopeSetKeys:           w.audienceKeys,
		IssuerDomainKeys:          []api.DomainPublicKey{w.homeKey},
		GranteeInstanceKeys:       w.granteeKeys,
		ExpectedRequestDigest:     w.requestDigest,
		MaxPresentationAgeSeconds: w.presentationAge,
		Now:                       actAsNow,
		SkewSeconds:               60,
	}
}

func wantActAsKind(t *testing.T, name string, err error, kind ActAsErrorKind) {
	t.Helper()
	var e *ActAsError
	if !errors.As(err, &e) || e.Kind != kind {
		t.Errorf("%s: want %s, got %v", name, kind, err)
	}
}

func TestActAsCredentialRoundTrip(t *testing.T) {
	w := newActAsWorld(t)
	for _, local := range []bool{false, true} {
		name := fmt.Sprintf("local=%v", local)
		signer := w.appSigner
		if local {
			signer = w.localSigner
		}
		grant := w.signGrant(t, w.granteeRef(local), nil)
		credential, err := Present(grant, w.audience, w.requestDigest, actAsNow.Add(-time.Minute), []byte("nonce-1"), signer)
		if err != nil {
			t.Fatalf("%s: present: %v", name, err)
		}
		if id, ok := CredentialSignerInstance(credential); ok == local || (!local && id != "instance-c") {
			t.Errorf("%s: signer instance %q, %v", name, id, ok)
		}
		if id, err := CredentialScopeSetSigner(credential); err != nil || id != "instance-d" {
			t.Errorf("%s: scope set signer %q, %v", name, id, err)
		}

		got, err := VerifyCredential(credential, w.context())
		if err != nil {
			t.Fatalf("%s: verify: %v", name, err)
		}
		if got.UserID != "user-1@"+testHomeDomain || got.GrantID != "grant-1" ||
			!equalStrings(got.ApprovedScope, []string{"read"}) || !bytes.Equal(got.Nonce, []byte("nonce-1")) {
			t.Errorf("%s: unexpected result %+v", name, got)
		}

		// The audience never reads its own identity from the request.
		ctx := w.context()
		ctx.OwnApplication.ApplicationId = "other"
		_, err = VerifyCredential(credential, ctx)
		wantActAsKind(t, name+" another audience", err, ErrActAsMismatch)

		ctx = w.context()
		ctx.RevokedGrantIDs = []string{"grant-1"}
		_, err = VerifyCredential(credential, ctx)
		wantActAsKind(t, name+" revoked", err, ErrActAsGrantRevoked)

		ctx = w.context()
		ctx.Now = actAsNow.Add(time.Hour)
		_, err = VerifyCredential(credential, ctx)
		wantActAsKind(t, name+" expired", err, ErrActAsGrantExpired)
	}
}

func TestActAsGrantWithDeviceBindingIsRefused(t *testing.T) {
	w := newActAsWorld(t)
	grant := w.signGrant(t, w.granteeRef(false), func(g *api.ActAsGrant) {
		fp := "device"
		g.DeviceFingerprint = &fp
	})
	_, err := VerifyGrantSignature(grant, []api.DomainPublicKey{w.homeKey})
	wantActAsKind(t, "device binding", err, ErrActAsDeviceBindingUnsupported)
}

func TestActAsProofFormMustMatchGrantee(t *testing.T) {
	w := newActAsWorld(t)
	// A local-RP grant presented with an application key.
	grant := w.signGrant(t, w.granteeRef(true), nil)
	credential, err := Present(grant, w.audience, w.requestDigest, actAsNow, []byte("n"), w.appSigner)
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	_, err = VerifyCredential(credential, w.context())
	wantActAsKind(t, "form mismatch", err, ErrActAsProofDoesNotMatchGrantee)
}

func (w actAsWorld) scopeSet(t *testing.T, grantee api.GranteeRef) api.SignedActAsScopeSet {
	t.Helper()
	return w.signGrantDecoded(t, grantee).ScopeSet
}

func (w actAsWorld) signGrantDecoded(t *testing.T, grantee api.GranteeRef) api.ActAsGrant {
	t.Helper()
	grant, err := DecodeGrant(w.signGrant(t, grantee, nil))
	if err != nil {
		t.Fatalf("decode grant: %v", err)
	}
	return grant
}

func TestActAsGrantAndRefreshRequestRoundTrip(t *testing.T) {
	w := newActAsWorld(t)
	lifetime := int64(1800)
	for _, local := range []bool{false, true} {
		name := fmt.Sprintf("local=%v", local)
		signer := w.appSigner
		if local {
			signer = w.localSigner
		}
		grantee := w.granteeRef(local)
		signed, err := SignGrantRequest(api.ActAsGrantRequest{
			Grantee:                  grantee,
			ScopeSet:                 w.scopeSet(t, grantee),
			RequestedLifetimeSeconds: &lifetime,
			CallbackUrl:              "https://c.example/act-as/callback",
			Nonce:                    "nonce",
			RequestedAt:              FormatActAsTime(actAsNow),
			ExpiresAt:                FormatActAsTime(actAsNow.Add(5 * time.Minute)),
		}, signer)
		if err != nil {
			t.Fatalf("%s: sign grant request: %v", name, err)
		}
		if _, err := VerifyGrantRequest(signed, w.granteeKeys, actAsNow, 60); err != nil {
			t.Errorf("%s: verify grant request: %v", name, err)
		}

		refresh, err := SignRefreshRequest(api.ActAsRefreshRequest{
			GrantId:     "grant-1",
			Grantee:     grantee,
			RequestedAt: FormatActAsTime(actAsNow),
			ExpiresAt:   FormatActAsTime(actAsNow.Add(5 * time.Minute)),
			Nonce:       "refresh-nonce",
		}, signer)
		if err != nil {
			t.Fatalf("%s: sign refresh request: %v", name, err)
		}
		if _, err := VerifyRefreshRequest(refresh, grantee, w.granteeKeys, actAsNow, 60); err != nil {
			t.Errorf("%s: verify refresh request: %v", name, err)
		}
		_, err = VerifyRefreshRequest(refresh, w.granteeRef(!local), w.granteeKeys, actAsNow, 60)
		wantActAsKind(t, name+" another grantee", err, ErrActAsMismatch)
	}
}

func TestActAsSignRefusesMalformedGrantee(t *testing.T) {
	w := newActAsWorld(t)
	app := w.granteeApp
	fp := w.localFP
	for name, g := range map[string]api.GranteeRef{
		"none":           {},
		"both":           {Application: &app, LocalRpDescriptorFingerprint: &fp},
		"empty app id":   {Application: &api.ApplicationRef{SubjectUserId: "u", SubjectDomain: "d"}},
		"empty local fp": {LocalRpDescriptorFingerprint: new(string)},
	} {
		_, err := SignRefreshRequest(api.ActAsRefreshRequest{GrantId: "g", Grantee: g}, w.appSigner)
		wantActAsKind(t, name, err, ErrActAsMalformedGrantee)
	}
}

func TestActAsScopeSetShapeBounds(t *testing.T) {
	w := newActAsWorld(t)
	base := api.ActAsScopeSet{
		Audience:  w.audience,
		Grantee:   w.granteeRef(false),
		IssuedAt:  FormatActAsTime(actAsNow),
		ExpiresAt: FormatActAsTime(actAsNow.Add(time.Hour)),
	}
	tooMany := make([]api.ActAsScopeEntry, MaxScopeEntries+1)
	for i := range tooMany {
		tooMany[i].Scope = fmt.Sprintf("s%d", i)
	}
	long := strings.Repeat("x", MaxDescriptionBytes+1)
	for name, entries := range map[string][]api.ActAsScopeEntry{
		"empty":            nil,
		"too many":         tooMany,
		"repeat":           {{Scope: "a"}, {Scope: "a"}},
		"empty scope":      {{Scope: ""}},
		"long scope":       {{Scope: strings.Repeat("x", MaxScopeBytes+1)}},
		"long description": {{Scope: "a", Description: &long}},
	} {
		set := base
		set.Entries = entries
		_, err := SignScopeSet(set, "instance-d", []ApplicationSigner{w.audienceSigner})
		wantActAsKind(t, name, err, ErrActAsBadScopeSet)
	}
}

func TestActAsScopeSetKeyValidAtIssuedAt(t *testing.T) {
	w := newActAsWorld(t)
	signed := w.scopeSet(t, w.granteeRef(false))
	// A key revoked after the set was issued still verifies the set.
	keys := append([]ApplicationKeyRef{}, w.audienceKeys...)
	revokedLater := FormatActAsTime(actAsNow)
	keys[0].RevokedAt = &revokedLater
	if _, err := VerifyScopeSet(signed, w.audience, keys, AcceptBeforeRevocation); err != nil {
		t.Errorf("revoked after issue: %v", err)
	}
	// A key revoked before the set was issued does not.
	revokedBefore := FormatActAsTime(actAsNow.Add(-2 * time.Hour))
	keys[0].RevokedAt = &revokedBefore
	_, err := VerifyScopeSet(signed, w.audience, keys, AcceptBeforeRevocation)
	wantActAsKind(t, "revoked before issue", err, ErrActAsNoValidSignature)
}

func TestFormatActAsTime(t *testing.T) {
	zone := time.FixedZone("x", 2*3600)
	got := FormatActAsTime(time.Date(2026, 10, 6, 14, 0, 5, 999_000_000, zone))
	if got != "2026-10-06T12:00:05Z" {
		t.Errorf("got %s", got)
	}
}

func TestDecideRefreshHugeLifetime(t *testing.T) {
	grant := api.ActAsGrant{
		IssuedAt:       "2026-10-06T12:00:00Z",
		ExpiresAt:      "2026-10-06T13:00:00Z",
		RenewableUntil: "2026-10-07T12:00:00Z",
	}
	got, err := DecideRefresh(grant, 1<<62, mustTime(t, "2026-10-06T12:45:00Z"))
	if err != nil || !got.Renew || got.ExpiresAt != "2026-10-07T12:00:00Z" {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestGrantRequestURL(t *testing.T) {
	signed := api.SignedActAsGrantRequest{Request: []byte{1, 2, 3}}
	for base, want := range map[string]string{
		"https://home.example":       "https://home.example/auth/act-as?signed_request=",
		"https://home.example/idp/":  "https://home.example/idp/auth/act-as?signed_request=",
		"http://127.0.0.1:8080":      "http://127.0.0.1:8080/auth/act-as?signed_request=",
		"http://localhost:8080/base": "http://localhost:8080/base/auth/act-as?signed_request=",
	} {
		got, err := GrantRequestURL(base, signed)
		if err != nil || !strings.HasPrefix(got, want) || strings.ContainsAny(got[len(want):], "=+/") {
			t.Errorf("%s: got %q, %v", base, got, err)
		}
	}
	for _, base := range []string{
		"http://home.example",
		"ftp://home.example",
		"https://user:pw@home.example",
		"https://home.example?x=1",
		"/relative",
		"",
	} {
		if _, err := GrantRequestURL(base, signed); err == nil {
			t.Errorf("%q: want error", base)
		}
	}
}

// ---------------------------------------------------------------------------
// RP calls over a fake transport
// ---------------------------------------------------------------------------

type actAsCall struct {
	service, op string
	payload     []byte
}

// actAsFakeRP records every call and answers with handle.
type actAsFakeRP struct {
	calls  []actAsCall
	handle func(op string, payload []byte) ([]byte, error)
}

func (f *actAsFakeRP) Call(_ context.Context, service, op string, payload []byte) ([]byte, error) {
	f.calls = append(f.calls, actAsCall{service, op, payload})
	if service != "Rp" {
		return nil, fmt.Errorf("unexpected service %s", service)
	}
	return f.handle(op, payload)
}

func (w actAsWorld) signedRefresh(t *testing.T, grantID string) api.SignedActAsRefreshRequest {
	t.Helper()
	signed, err := SignRefreshRequest(api.ActAsRefreshRequest{
		GrantId:     grantID,
		Grantee:     w.granteeRef(false),
		RequestedAt: FormatActAsTime(actAsNow),
		ExpiresAt:   FormatActAsTime(actAsNow.Add(5 * time.Minute)),
		Nonce:       "refresh-nonce",
	}, w.appSigner)
	if err != nil {
		t.Fatalf("sign refresh: %v", err)
	}
	return signed
}

func TestRefreshGrantCallsRp(t *testing.T) {
	w := newActAsWorld(t)
	grant := w.signGrant(t, w.granteeRef(false), nil)
	request := w.signedRefresh(t, "grant-1")
	rp := &actAsFakeRP{handle: func(op string, payload []byte) ([]byte, error) {
		if op != "act-as-refresh-grant" {
			return nil, fmt.Errorf("unexpected op %s", op)
		}
		return api.EncodeRefreshActAsGrantResponse(api.RefreshActAsGrantResponse{Grant: grant, Signed: true}), nil
	}}

	got, err := RefreshGrant(context.Background(), rp, testHomeDomain, request)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !got.Signed || got.Decoded.GrantId != "grant-1" || !bytes.Equal(got.Grant.Grant, grant.Grant) {
		t.Errorf("unexpected result %+v", got)
	}
	if len(rp.calls) != 1 {
		t.Fatalf("want 1 call, got %d", len(rp.calls))
	}
	sent, err := api.DecodeRpActAsRefreshRequest(rp.calls[0].payload)
	if err != nil {
		t.Fatalf("decode sent payload: %v", err)
	}
	if sent.SubjectDomain != testHomeDomain || !bytes.Equal(api.EncodeSignedActAsRefreshRequest(sent.Request), api.EncodeSignedActAsRefreshRequest(request)) {
		t.Errorf("payload did not round-trip: %+v", sent)
	}

	// A grant for another grant id is refused.
	_, err = RefreshGrant(context.Background(), rp, testHomeDomain, w.signedRefresh(t, "grant-2"))
	wantActAsKind(t, "another grant id", err, ErrActAsMismatch)

	// A grant from another domain is refused.
	_, err = RefreshGrant(context.Background(), rp, "other.example", request)
	wantActAsKind(t, "another domain", err, ErrActAsMismatch)

	// Domain case folding is ASCII only: a Unicode look-alike is another
	// domain, and an ASCII case difference is the same domain.
	if _, err := RefreshGrant(context.Background(), rp, strings.ToUpper(testHomeDomain), request); err != nil {
		t.Errorf("ASCII case difference: %v", err)
	}
	if asciiEqualFold("\u212aey.example", "key.example") {
		t.Error("U+212A KELVIN SIGN must not fold to k")
	}

	// An RP error reaches the caller unchanged.
	rp.handle = func(string, []byte) ([]byte, error) {
		return nil, &ServerError{Status: 3, Message: "grant expired"}
	}
	_, err = RefreshGrant(context.Background(), rp, testHomeDomain, request)
	var serverErr *ServerError
	if !errors.As(err, &serverErr) || serverErr.Message != "grant expired" {
		t.Errorf("want ServerError, got %v", err)
	}

	if _, err := RefreshGrant(context.Background(), rp, " ", request); err == nil {
		t.Error("empty domain: want error")
	}
}

func (w actAsWorld) signRevocation(t *testing.T, grantID, domain string, priv ed25519.PrivateKey) api.SignedActAsGrantRevocation {
	t.Helper()
	revBytes := api.EncodeActAsGrantRevocation(api.ActAsGrantRevocation{
		GrantId:       grantID,
		UserId:        "user-1",
		SubjectDomain: domain,
		RevokedAt:     FormatActAsTime(actAsNow),
	})
	return api.SignedActAsGrantRevocation{
		Revocation: revBytes,
		Signatures: []api.ClaimSignature{{
			Domain:        testHomeDomain,
			SignedByKeyId: w.homeKey.KeyId,
			Signature:     ed25519.Sign(priv, envelopeSignatureInput(GrantRevocationTag, revBytes)),
		}},
	}
}

func TestResolveGrantRevocationsVerifies(t *testing.T) {
	w := newActAsWorld(t)
	_, forger := newEd25519(t)
	revocations := []api.SignedActAsGrantRevocation{
		w.signRevocation(t, "grant-1", testHomeDomain, w.homePriv),
		w.signRevocation(t, "grant-2", testHomeDomain, forger),             // bad signature
		w.signRevocation(t, "grant-3", "other.example", w.homePriv),        // another domain
		w.signRevocation(t, "grant-not-asked", testHomeDomain, w.homePriv), // not requested
		w.signRevocation(t, "grant-1", testHomeDomain, w.homePriv),         // duplicate
	}
	rp := &actAsFakeRP{handle: func(op string, payload []byte) ([]byte, error) {
		switch op {
		case "resolve-act-as-revocations":
			return api.EncodeGetActAsGrantRevocationsResponse(api.GetActAsGrantRevocationsResponse{Revocations: revocations}), nil
		case "resolve-domain-keys":
			return api.EncodeRpResolveDomainKeysResponse(api.RpResolveDomainKeysResponse{
				Domain:      testHomeDomain,
				Keys:        []api.DomainPublicKey{w.homeKey},
				CacheStatus: "fresh",
			}), nil
		}
		return nil, fmt.Errorf("unexpected op %s", op)
	}}

	ids := []string{"grant-1", "grant-2", "grant-3"}
	got, err := ResolveGrantRevocations(context.Background(), rp, testHomeDomain, ids)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(got) != 1 || got[0].GrantId != "grant-1" {
		t.Errorf("want only grant-1, got %+v", got)
	}
	if len(rp.calls) != 2 || rp.calls[0].op != "resolve-act-as-revocations" || rp.calls[1].op != "resolve-domain-keys" {
		t.Fatalf("unexpected calls %+v", rp.calls)
	}
	sent, err := api.DecodeRpResolveActAsRevocationsRequest(rp.calls[0].payload)
	if err != nil || sent.SubjectDomain != testHomeDomain || !equalStrings(sent.GrantIds, ids) {
		t.Errorf("revocation payload did not round-trip: %+v, %v", sent, err)
	}
	keysReq, err := api.DecodeRpResolveDomainKeysRequest(rp.calls[1].payload)
	if err != nil || keysReq.Domain != testHomeDomain {
		t.Errorf("domain-key payload: %+v, %v", keysReq, err)
	}
}

func TestResolveGrantRevocationsDomainKeyRevoked(t *testing.T) {
	w := newActAsWorld(t)
	revoked := w.homeKey
	at := FormatActAsTime(actAsNow)
	revoked.RevokedAt = &at
	rp := &actAsFakeRP{handle: func(op string, _ []byte) ([]byte, error) {
		if op == "resolve-act-as-revocations" {
			return api.EncodeGetActAsGrantRevocationsResponse(api.GetActAsGrantRevocationsResponse{
				Revocations: []api.SignedActAsGrantRevocation{w.signRevocation(t, "grant-1", testHomeDomain, w.homePriv)},
			}), nil
		}
		return api.EncodeRpResolveDomainKeysResponse(api.RpResolveDomainKeysResponse{Domain: testHomeDomain, Keys: []api.DomainPublicKey{revoked}}), nil
	}}
	got, err := ResolveGrantRevocations(context.Background(), rp, testHomeDomain, []string{"grant-1"})
	if err != nil || len(got) != 0 {
		t.Errorf("revoked domain key must not verify: %+v, %v", got, err)
	}
}

func TestResolveGrantRevocationsBoundsAndErrors(t *testing.T) {
	rp := &actAsFakeRP{handle: func(string, []byte) ([]byte, error) {
		return nil, errors.New("must not be called")
	}}
	tooMany := make([]string, MaxRevocationLookupIDs+1)
	for _, ids := range [][]string{nil, tooMany} {
		if _, err := ResolveGrantRevocations(context.Background(), rp, testHomeDomain, ids); err == nil {
			t.Errorf("%d ids: want error", len(ids))
		}
	}
	if _, err := ResolveGrantRevocations(context.Background(), rp, "", []string{"g"}); err == nil {
		t.Error("empty domain: want error")
	}
	if len(rp.calls) != 0 {
		t.Fatalf("bad input reached the RP: %+v", rp.calls)
	}

	// No revocations: no domain-key lookup.
	rp.handle = func(op string, _ []byte) ([]byte, error) {
		if op != "resolve-act-as-revocations" {
			return nil, fmt.Errorf("unexpected op %s", op)
		}
		return api.EncodeGetActAsGrantRevocationsResponse(api.GetActAsGrantRevocationsResponse{}), nil
	}
	got, err := ResolveGrantRevocations(context.Background(), rp, testHomeDomain, []string{"g"})
	if err != nil || len(got) != 0 || len(rp.calls) != 1 {
		t.Errorf("empty answer: %+v, %v, %d calls", got, err, len(rp.calls))
	}

	// An RP error reaches the caller unchanged.
	rp.handle = func(string, []byte) ([]byte, error) { return nil, &TransportError{Detail: "down"} }
	_, err = ResolveGrantRevocations(context.Background(), rp, testHomeDomain, []string{"g"})
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		t.Errorf("want TransportError, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Multi-signature scope sets and the revoked-key policy
// ---------------------------------------------------------------------------

// twoKeyScopeSet signs one scope set with two fresh audience keys and
// returns it with both key refs.
func twoKeyScopeSet(t *testing.T, w actAsWorld) (api.SignedActAsScopeSet, []ApplicationKeyRef) {
	t.Helper()
	signer1, key1 := appKey(t, "audience-key-1")
	signer2, key2 := appKey(t, "audience-key-2")
	signed, err := SignScopeSet(api.ActAsScopeSet{
		Audience:  w.audience,
		Grantee:   w.granteeRef(false),
		Entries:   []api.ActAsScopeEntry{{Scope: "read"}},
		IssuedAt:  FormatActAsTime(actAsNow.Add(-time.Hour)),
		ExpiresAt: FormatActAsTime(actAsNow.Add(time.Hour)),
	}, "instance-d", []ApplicationSigner{signer1, signer2})
	if err != nil {
		t.Fatalf("sign scope set: %v", err)
	}
	if len(signed.Signatures) != 2 {
		t.Fatalf("want 2 signatures, got %d", len(signed.Signatures))
	}
	return signed, []ApplicationKeyRef{key1, key2}
}

func TestActAsScopeSetOneValidSignatureIsEnough(t *testing.T) {
	w := newActAsWorld(t)
	signed, keys := twoKeyScopeSet(t, w)

	// key 1 expired before the set was issued; key 2 still verifies it.
	keys[0].ExpiresAt = FormatActAsTime(actAsNow.Add(-2 * time.Hour))
	if _, err := VerifyScopeSet(signed, w.audience, keys, AcceptBeforeRevocation); err != nil {
		t.Errorf("one key expired: %v", err)
	}
	// Only key 2 is known: still enough.
	if _, err := VerifyScopeSet(signed, w.audience, keys[1:], AcceptBeforeRevocation); err != nil {
		t.Errorf("one key unknown: %v", err)
	}
}

func TestActAsScopeSetRefusalNamesEveryKey(t *testing.T) {
	w := newActAsWorld(t)
	signed, keys := twoKeyScopeSet(t, w)
	revoked := FormatActAsTime(actAsNow.Add(-2 * time.Hour))
	keys[0].RevokedAt = &revoked
	_, err := VerifyScopeSet(signed, w.audience, keys[:1], AcceptBeforeRevocation)
	wantActAsKind(t, "all refused", err, ErrActAsNoValidSignature)
	want := "audience-key-1: revoked at " + revoked + ", before it signed; audience-key-2: not a key of the audience"
	if e := (*ActAsError)(nil); errors.As(err, &e) && e.Detail != want {
		t.Errorf("detail\n got  %s\n want %s", e.Detail, want)
	}

	// A bad signature and an expired key.
	signed2, keys2 := twoKeyScopeSet(t, w)
	signed2.Signatures[0].Signature = bytes.Repeat([]byte{1}, 64)
	keys2[1].ExpiresAt = FormatActAsTime(actAsNow.Add(-2 * time.Hour))
	_, err = VerifyScopeSet(signed2, w.audience, keys2, AcceptBeforeRevocation)
	want = "audience-key-1: signature did not verify; audience-key-2: not inside its validity window when it signed"
	if e := (*ActAsError)(nil); !errors.As(err, &e) || e.Detail != want {
		t.Errorf("detail\n got  %v\n want %s", err, want)
	}

	// No signatures at all.
	signed2.Signatures = nil
	_, err = VerifyScopeSet(signed2, w.audience, keys2, AcceptBeforeRevocation)
	wantActAsKind(t, "unsigned", err, ErrActAsNoValidSignature)
}

func TestActAsScopeSetRevokedKeyPolicy(t *testing.T) {
	w := newActAsWorld(t)
	signed, keys := twoKeyScopeSet(t, w)
	later := FormatActAsTime(actAsNow)
	keys[0].RevokedAt = &later
	keys = keys[:1]
	if _, err := VerifyScopeSet(signed, w.audience, keys, AcceptBeforeRevocation); err != nil {
		t.Errorf("accept before revocation: %v", err)
	}
	_, err := VerifyScopeSet(signed, w.audience, keys, RefuseRevoked)
	wantActAsKind(t, "refuse revoked", err, ErrActAsNoValidSignature)
	if e := (*ActAsError)(nil); errors.As(err, &e) && !strings.Contains(e.Detail, "this verifier refuses revoked keys") {
		t.Errorf("detail: %s", e.Detail)
	}

	// The credential checklist takes the policy from AudienceContext.
	grantee := w.granteeRef(false)
	credential, err := Present(w.signGrant(t, grantee, nil), w.audience, w.requestDigest, actAsNow, []byte("n"), w.appSigner)
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	ctx := w.context()
	ctx.OwnScopeSetKeys = append([]ApplicationKeyRef{}, w.audienceKeys...)
	ctx.OwnScopeSetKeys[0].RevokedAt = &later
	if _, err := VerifyCredential(credential, ctx); err != nil {
		t.Errorf("credential, default policy: %v", err)
	}
	ctx.RevokedKeyPolicy = RefuseRevoked
	_, err = VerifyCredential(credential, ctx)
	wantActAsKind(t, "credential, refuse revoked", err, ErrActAsNoValidSignature)
}

func TestActAsSignScopeSetSigners(t *testing.T) {
	w := newActAsWorld(t)
	set := api.ActAsScopeSet{
		Audience:  w.audience,
		Grantee:   w.granteeRef(false),
		Entries:   []api.ActAsScopeEntry{{Scope: "read"}},
		IssuedAt:  FormatActAsTime(actAsNow),
		ExpiresAt: FormatActAsTime(actAsNow.Add(time.Hour)),
	}
	_, err := SignScopeSet(set, "instance-d", nil)
	wantActAsKind(t, "no signers", err, ErrActAsNoValidSignature)
	_, err = SignScopeSet(set, "instance-d", []ApplicationSigner{w.audienceSigner, w.audienceSigner})
	wantActAsKind(t, "duplicate signer", err, ErrActAsNoValidSignature)
}

func TestAttestedKeyRefsKeepsExpiredAndRevokedKeys(t *testing.T) {
	att := func(id string) api.ApplicationKeyAttestation {
		return api.ApplicationKeyAttestation{KeyId: id, KeyUsage: KeyUsageSign, Algorithm: "ed25519"}
	}
	set := VerifiedApplicationKeySet{Keys: []VerifiedApplicationKey{
		{Attestation: att("usable"), Status: KeyStatus{Kind: KeyStatusUsable}},
		{Attestation: att("expired"), Status: KeyStatus{Kind: KeyStatusKeyExpired}},
		{Attestation: att("revoked"), Status: KeyStatus{Kind: KeyStatusRevoked, RevokedAt: "2026-10-01T00:00:00Z"}},
	}}
	all := set.AttestedKeyRefs()
	if len(all) != 3 {
		t.Fatalf("want 3 keys, got %d", len(all))
	}
	for _, k := range all {
		switch k.KeyID {
		case "revoked":
			if k.RevokedAt == nil || *k.RevokedAt != "2026-10-01T00:00:00Z" {
				t.Errorf("revoked key: RevokedAt %v", k.RevokedAt)
			}
		default:
			if k.RevokedAt != nil {
				t.Errorf("%s: unexpected RevokedAt", k.KeyID)
			}
		}
	}
	if usable := set.UsableKeyRefs(); len(usable) != 1 || usable[0].KeyID != "usable" {
		t.Errorf("UsableKeyRefs: %+v", usable)
	}
}

// ---------------------------------------------------------------------------
// Handle claims
// ---------------------------------------------------------------------------

// signHandleClaim signs a handle claim about party as domain.
func signHandleClaim(party api.ApplicationRef, handle, domain string, key api.DomainPublicKey, priv ed25519.PrivateKey, mutate func(*api.Claim)) api.Claim {
	claim := api.Claim{
		ClaimId:    "claim-1",
		UserId:     party.SubjectUserId,
		ClaimType:  HandleClaimType,
		ClaimValue: []byte(handle),
		AttestedAt: FormatActAsTime(time.Now().Add(-time.Hour)),
		CreatedAt:  FormatActAsTime(time.Now().Add(-time.Hour)),
	}
	if mutate != nil {
		mutate(&claim)
	}
	payload := claimSignPayload(claim.ClaimId, claim.ClaimType, claim.ClaimValue, claim.UserId, party.SubjectDomain, domain, claim.ExpiresAt, claim.AttestedAt)
	claim.Signatures = append(claim.Signatures, api.ClaimSignature{Domain: domain, SignedByKeyId: key.KeyId, Signature: ed25519.Sign(priv, payload)})
	return claim
}

func TestVerifyHandleClaim(t *testing.T) {
	w := newActAsWorld(t)
	party := w.audience
	domainKey, domainPriv := newDomainKey(t, "d-key")
	otherKey, otherPriv := newDomainKey(t, "other-key")
	keys := []api.DomainPublicKey{domainKey}

	good := signHandleClaim(party, "team-d", party.SubjectDomain, domainKey, domainPriv, nil)
	if handle, err := VerifyHandleClaim(good, party, keys); err != nil || handle != "team-d" {
		t.Errorf("good claim: %q, %v", handle, err)
	}

	// A third domain's extra signature is ignored.
	extra := good
	extra.Signatures = append(append([]api.ClaimSignature{}, good.Signatures...), api.ClaimSignature{Domain: "third.example", SignedByKeyId: "x", Signature: []byte("x")})
	if _, err := VerifyHandleClaim(extra, party, keys); err != nil {
		t.Errorf("extra third-domain signature: %v", err)
	}

	past := FormatActAsTime(time.Now().Add(-time.Minute))
	revokedKey := domainKey
	revokedKey.RevokedAt = &past
	for name, tc := range map[string]struct {
		claim api.Claim
		keys  []api.DomainPublicKey
	}{
		"third domain only":    {signHandleClaim(party, "team-d", "third.example", otherKey, otherPriv, nil), []api.DomainPublicKey{otherKey}},
		"not the domain's key": {signHandleClaim(party, "team-d", party.SubjectDomain, otherKey, otherPriv, nil), keys},
		"another account":      {signHandleClaim(party, "team-d", party.SubjectDomain, domainKey, domainPriv, func(c *api.Claim) { c.UserId = "someone-else" }), keys},
		"not a handle":         {signHandleClaim(party, "team-d", party.SubjectDomain, domainKey, domainPriv, func(c *api.Claim) { c.ClaimType = "email" }), keys},
		"expired claim":        {signHandleClaim(party, "team-d", party.SubjectDomain, domainKey, domainPriv, func(c *api.Claim) { c.ExpiresAt = &past }), keys},
		"revoked claim":        {signHandleClaim(party, "team-d", party.SubjectDomain, domainKey, domainPriv, func(c *api.Claim) { c.RevokedAt = &past }), keys},
		"key revoked before attestation": {good, []api.DomainPublicKey{func() api.DomainPublicKey {
			k := domainKey
			early := FormatActAsTime(time.Now().Add(-2 * time.Hour))
			k.RevokedAt = &early
			return k
		}()}},
		"not UTF-8": {signHandleClaim(party, "\xff", party.SubjectDomain, domainKey, domainPriv, nil), keys},
	} {
		_, err := VerifyHandleClaim(tc.claim, party, tc.keys)
		wantActAsKind(t, name, err, ErrActAsBadHandleClaim)
	}

	// A key revoked AFTER the claim was attested still verifies it (I-7).
	if _, err := VerifyHandleClaim(good, party, []api.DomainPublicKey{revokedKey}); err != nil {
		t.Errorf("key revoked after attestation: %v", err)
	}
}

func TestActAsHandleClaimShapeChecks(t *testing.T) {
	w := newActAsWorld(t)
	domainKey, domainPriv := newDomainKey(t, "d-key")

	// A scope set may carry a handle claim about the audience's own account
	// only.
	set := api.ActAsScopeSet{
		Audience:  w.audience,
		Grantee:   w.granteeRef(false),
		Entries:   []api.ActAsScopeEntry{{Scope: "read"}},
		IssuedAt:  FormatActAsTime(actAsNow),
		ExpiresAt: FormatActAsTime(actAsNow.Add(time.Hour)),
	}
	own := signHandleClaim(w.audience, "team-d", w.audience.SubjectDomain, domainKey, domainPriv, nil)
	set.AudienceHandleClaim = &own
	signed, err := SignScopeSet(set, "instance-d", []ApplicationSigner{w.audienceSigner})
	if err != nil {
		t.Fatalf("scope set with own handle claim: %v", err)
	}
	if got, err := VerifyScopeSet(signed, w.audience, w.audienceKeys, AcceptBeforeRevocation); err != nil || got.AudienceHandleClaim == nil {
		t.Errorf("verify scope set with handle claim: %v", err)
	}
	other := signHandleClaim(w.granteeApp, "team-c", w.granteeApp.SubjectDomain, domainKey, domainPriv, nil)
	set.AudienceHandleClaim = &other
	_, err = SignScopeSet(set, "instance-d", []ApplicationSigner{w.audienceSigner})
	wantActAsKind(t, "scope set claim about another account", err, ErrActAsBadHandleClaim)

	// A grant request may carry a handle claim about the grantee's account.
	request := func(local bool, claim *api.Claim) api.ActAsGrantRequest {
		grantee := w.granteeRef(local)
		return api.ActAsGrantRequest{
			Grantee:            grantee,
			ScopeSet:           w.scopeSet(t, grantee),
			GranteeHandleClaim: claim,
			CallbackUrl:        "https://c.example/act-as/callback",
			Nonce:              "nonce",
			RequestedAt:        FormatActAsTime(actAsNow),
			ExpiresAt:          FormatActAsTime(actAsNow.Add(5 * time.Minute)),
		}
	}
	granteeClaim := signHandleClaim(w.granteeApp, "team-c", w.granteeApp.SubjectDomain, domainKey, domainPriv, nil)
	signedRequest, err := SignGrantRequest(request(false, &granteeClaim), w.appSigner)
	if err != nil {
		t.Fatalf("sign request with handle claim: %v", err)
	}
	got, err := VerifyGrantRequest(signedRequest, w.granteeKeys, actAsNow, 60)
	if err != nil || got.GranteeHandleClaim == nil {
		t.Errorf("verify request with handle claim: %v", err)
	}
	_, err = SignGrantRequest(request(false, &own), w.appSigner)
	wantActAsKind(t, "request claim about another account", err, ErrActAsBadHandleClaim)
	_, err = SignGrantRequest(request(true, &granteeClaim), w.localSigner)
	wantActAsKind(t, "local-RP request with handle claim", err, ErrActAsBadHandleClaim)

	// The verifier refuses the same request when a grantee signs it anyway.
	localRequest := request(true, &granteeClaim)
	requestBytes := api.EncodeActAsGrantRequest(localRequest)
	proof, err := w.localSigner.Prove(envelopeSignatureInput(GrantRequestTag, requestBytes))
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	_, err = VerifyGrantRequest(api.SignedActAsGrantRequest{Request: requestBytes, Proof: proof}, nil, actAsNow, 60)
	wantActAsKind(t, "verify local-RP request with handle claim", err, ErrActAsBadHandleClaim)
}
