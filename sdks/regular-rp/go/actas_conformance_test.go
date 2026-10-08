package regularrp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/regular-rp/go/generated"
)

// Replays sdks/regular-rp/conformance/act_as_*.json against this package.
// Each test mirrors crates/liblinkkeys/tests/act_as_conformance.rs (consumer
// zero): it builds every input from the JSON alone, and every positive AND
// negative case must match expected_valid.

type appRefVec struct {
	SubjectUserID string `json:"subject_user_id"`
	SubjectDomain string `json:"subject_domain"`
	ApplicationID string `json:"application_id"`
}

func (v appRefVec) toRef() api.ApplicationRef {
	return api.ApplicationRef{SubjectUserId: v.SubjectUserID, SubjectDomain: v.SubjectDomain, ApplicationId: v.ApplicationID}
}

type granteeVec struct {
	Application                  *appRefVec `json:"application"`
	LocalRpDescriptorFingerprint *string    `json:"local_rp_descriptor_fingerprint"`
}

func (v granteeVec) toRef() api.GranteeRef {
	g := api.GranteeRef{LocalRpDescriptorFingerprint: v.LocalRpDescriptorFingerprint}
	if v.Application != nil {
		app := v.Application.toRef()
		g.Application = &app
	}
	return g
}

func appKeyRefs(t *testing.T, vs []appKeyRefVec) []ApplicationKeyRef {
	t.Helper()
	out := make([]ApplicationKeyRef, len(vs))
	for i, v := range vs {
		out[i] = v.toRef(t)
	}
	return out
}

func domainKeys(t *testing.T, vs []domainKeyVec) []api.DomainPublicKey {
	t.Helper()
	out := make([]api.DomainPublicKey, len(vs))
	for i, v := range vs {
		out[i] = v.toDomainKey(t)
	}
	return out
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("bad time %q: %v", s, err)
	}
	return v
}

// ---------------------------------------------------------------------------
// act_as_signatures.json
// ---------------------------------------------------------------------------

type actAsSignedCaseVec struct {
	Name             string         `json:"name"`
	ExpectedValid    bool           `json:"expected_valid"`
	SignedCborHex    string         `json:"signed_cbor_hex"`
	Now              *string        `json:"now"`
	ExpectedAudience *appRefVec     `json:"expected_audience"`
	ExpectedGrantID  *string        `json:"expected_grant_id"`
	AudienceKeys     []appKeyRefVec `json:"audience_keys"`
	RevokedKeyPolicy *string        `json:"revoked_key_policy"`
}

type actAsSignedSectionVec struct {
	Cases         []actAsSignedCaseVec `json:"cases"`
	NegativeCases []actAsSignedCaseVec `json:"negative_cases"`
	PolicyCases   []actAsSignedCaseVec `json:"policy_cases"`
}

type handleClaimCaseVec struct {
	Name           string  `json:"name"`
	ExpectedValid  bool    `json:"expected_valid"`
	ClaimCborHex   string  `json:"claim_cbor_hex"`
	ExpectedHandle *string `json:"expected_handle"`
}

// revokedKeyPolicy reads a vector's revoked_key_policy. An absent value is
// the default, accept_before_revocation.
func revokedKeyPolicy(t *testing.T, v *string) RevokedKeyPolicy {
	t.Helper()
	if v == nil {
		return AcceptBeforeRevocation
	}
	switch *v {
	case "accept_before_revocation":
		return AcceptBeforeRevocation
	case "refuse_revoked":
		return RefuseRevoked
	default:
		t.Fatalf("unknown revoked_key_policy %q", *v)
		return AcceptBeforeRevocation
	}
}

func (s actAsSignedSectionVec) all() []actAsSignedCaseVec {
	return append(append([]actAsSignedCaseVec{}, s.Cases...), s.NegativeCases...)
}

type actAsSignaturesFile struct {
	Now                 string            `json:"now"`
	SkewSeconds         int64             `json:"skew_seconds"`
	Audience            appRefVec         `json:"audience"`
	AudienceKeys        []appKeyRefVec    `json:"audience_keys"`
	GranteeInstanceKeys []appKeyRefVec    `json:"grantee_instance_keys"`
	HomeDomain          string            `json:"home_domain"`
	HomeDomainKeys      []domainKeyVec    `json:"home_domain_keys"`
	Tags                map[string]string `json:"tags"`
	ScopeSet            struct {
		actAsSignedSectionVec
		ScopeSetCborHex       string `json:"scope_set_cbor_hex"`
		SignatureInputCborHex string `json:"signature_input_cbor_hex"`
	} `json:"scope_set"`
	GrantRequest   actAsSignedSectionVec `json:"grant_request"`
	RefreshRequest struct {
		actAsSignedSectionVec
		Now          string     `json:"now"`
		GrantGrantee granteeVec `json:"grant_grantee"`
	} `json:"refresh_request"`
	Grant struct {
		SignedCborHex         string `json:"signed_cbor_hex"`
		GrantCborHex          string `json:"grant_cbor_hex"`
		GrantHashHex          string `json:"grant_hash_hex"`
		SignatureInputCborHex string `json:"signature_input_cbor_hex"`
	} `json:"grant"`
	Revocation   actAsSignedSectionVec `json:"revocation"`
	HandleClaims struct {
		Party           appRefVec            `json:"party"`
		PartyDomainKeys []domainKeyVec       `json:"party_domain_keys"`
		Cases           []handleClaimCaseVec `json:"cases"`
		NegativeCases   []handleClaimCaseVec `json:"negative_cases"`
	} `json:"handle_claims"`
}

func TestConformanceActAsSignatures(t *testing.T) {
	var v actAsSignaturesFile
	loadVectorFile(t, conformanceDir(t), "act_as_signatures.json", &v)

	wantTags := map[string]string{
		"scope_set":        ScopeSetTag,
		"grant":            GrantTag,
		"grant_request":    GrantRequestTag,
		"refresh_request":  RefreshRequestTag,
		"presentation":     PresentationTag,
		"grant_revocation": GrantRevocationTag,
	}
	for k, want := range wantTags {
		if v.Tags[k] != want {
			t.Errorf("tag %s: vector %q, package %q", k, v.Tags[k], want)
		}
	}

	now := mustTime(t, v.Now)
	audienceKeys := appKeyRefs(t, v.AudienceKeys)
	granteeKeys := appKeyRefs(t, v.GranteeInstanceKeys)
	homeKeys := domainKeys(t, v.HomeDomainKeys)

	if !bytes.Equal(envelopeSignatureInput(ScopeSetTag, mustHex(t, v.ScopeSet.ScopeSetCborHex)), mustHex(t, v.ScopeSet.SignatureInputCborHex)) {
		t.Errorf("scope_set: signature input differs from signature_input_cbor_hex")
	}
	if len(v.ScopeSet.PolicyCases) == 0 {
		t.Fatal("no scope_set policy_cases")
	}
	for _, c := range append(v.ScopeSet.all(), v.ScopeSet.PolicyCases...) {
		signed, err := api.DecodeSignedActAsScopeSet(mustHex(t, c.SignedCborHex))
		if err != nil {
			t.Fatalf("%s: decode: %v", c.Name, err)
		}
		audience := v.Audience.toRef()
		if c.ExpectedAudience != nil {
			audience = c.ExpectedAudience.toRef()
		}
		keys := audienceKeys
		if c.AudienceKeys != nil {
			keys = appKeyRefs(t, c.AudienceKeys)
		}
		_, err = VerifyScopeSet(signed, audience, keys, revokedKeyPolicy(t, c.RevokedKeyPolicy))
		checkExpected(t, "scope_set/"+c.Name, c.ExpectedValid, err)
		if err != nil {
			var actAsErr *ActAsError
			if errors.As(err, &actAsErr) && actAsErr.Kind == ErrActAsNoValidSignature && actAsErr.Detail == "" {
				t.Errorf("scope_set/%s: no_valid_signature without a refusal list", c.Name)
			}
		}
	}

	party := v.HandleClaims.Party.toRef()
	partyKeys := domainKeys(t, v.HandleClaims.PartyDomainKeys)
	handleCases := append(append([]handleClaimCaseVec{}, v.HandleClaims.Cases...), v.HandleClaims.NegativeCases...)
	if len(v.HandleClaims.Cases) == 0 || len(v.HandleClaims.NegativeCases) == 0 {
		t.Fatal("handle_claims needs positive and negative cases")
	}
	for _, c := range handleCases {
		claim, err := api.DecodeClaim(mustHex(t, c.ClaimCborHex))
		if err != nil {
			t.Fatalf("handle_claims/%s: decode: %v", c.Name, err)
		}
		handle, err := VerifyHandleClaim(claim, party, partyKeys)
		if err == nil && c.ExpectedHandle != nil && handle != *c.ExpectedHandle {
			t.Errorf("handle_claims/%s: handle %q, want %q", c.Name, handle, *c.ExpectedHandle)
		}
		checkExpected(t, "handle_claims/"+c.Name, c.ExpectedValid, err)
	}

	for _, c := range v.GrantRequest.all() {
		signed, err := api.DecodeSignedActAsGrantRequest(mustHex(t, c.SignedCborHex))
		if err != nil {
			t.Fatalf("%s: decode: %v", c.Name, err)
		}
		at := now
		if c.Now != nil {
			at = mustTime(t, *c.Now)
		}
		_, err = VerifyGrantRequest(signed, granteeKeys, at, v.SkewSeconds)
		checkExpected(t, "grant_request/"+c.Name, c.ExpectedValid, err)
	}

	refreshNow := mustTime(t, v.RefreshRequest.Now)
	grantGrantee := v.RefreshRequest.GrantGrantee.toRef()
	for _, c := range v.RefreshRequest.all() {
		signed, err := api.DecodeSignedActAsRefreshRequest(mustHex(t, c.SignedCborHex))
		if err != nil {
			t.Fatalf("%s: decode: %v", c.Name, err)
		}
		_, err = VerifyRefreshRequest(signed, grantGrantee, granteeKeys, refreshNow, v.SkewSeconds)
		checkExpected(t, "refresh_request/"+c.Name, c.ExpectedValid, err)
	}

	grant, err := api.DecodeSignedActAsGrant(mustHex(t, v.Grant.SignedCborHex))
	if err != nil {
		t.Fatalf("grant: decode: %v", err)
	}
	if !bytes.Equal(grant.Grant, mustHex(t, v.Grant.GrantCborHex)) {
		t.Errorf("grant: embedded bytes differ from grant_cbor_hex")
	}
	if !bytes.Equal(GrantHash(grant.Grant), mustHex(t, v.Grant.GrantHashHex)) {
		t.Errorf("grant: hash differs from grant_hash_hex")
	}
	if !bytes.Equal(envelopeSignatureInput(GrantTag, grant.Grant), mustHex(t, v.Grant.SignatureInputCborHex)) {
		t.Errorf("grant: signature input differs from signature_input_cbor_hex")
	}
	if _, err := VerifyGrantSignature(grant, homeKeys); err != nil {
		t.Errorf("grant: signature does not verify: %v", err)
	}

	for _, c := range v.Revocation.all() {
		signed, err := api.DecodeSignedActAsGrantRevocation(mustHex(t, c.SignedCborHex))
		if err != nil {
			t.Fatalf("%s: decode: %v", c.Name, err)
		}
		rev, err := VerifyGrantRevocation(signed, homeKeys, v.HomeDomain)
		if err == nil && c.ExpectedGrantID != nil && rev.GrantId != *c.ExpectedGrantID {
			t.Errorf("revocation/%s: grant id %q, want %q", c.Name, rev.GrantId, *c.ExpectedGrantID)
		}
		checkExpected(t, "revocation/"+c.Name, c.ExpectedValid, err)
	}
}

// ---------------------------------------------------------------------------
// act_as_credential.json
// ---------------------------------------------------------------------------

// credentialContextVec uses json.RawMessage so a case can override any
// subset of the shared context.
type credentialContextVec map[string]json.RawMessage

func TestConformanceActAsCredential(t *testing.T) {
	var v struct {
		Context       credentialContextVec   `json:"context"`
		Cases         []credentialContextVec `json:"cases"`
		NegativeCases []credentialContextVec `json:"negative_cases"`
	}
	loadVectorFile(t, conformanceDir(t), "act_as_credential.json", &v)

	cases := append(append([]credentialContextVec{}, v.Cases...), v.NegativeCases...)
	if len(cases) == 0 {
		t.Fatal("no credential cases")
	}
	for _, c := range cases {
		field := func(name string, out any) {
			t.Helper()
			raw, ok := c[name]
			if !ok {
				raw, ok = v.Context[name]
			}
			if !ok {
				t.Fatalf("missing field %s", name)
			}
			if err := json.Unmarshal(raw, out); err != nil {
				t.Fatalf("field %s: %v", name, err)
			}
		}
		var name, credentialHex, digestHex, now string
		var expectedValid bool
		var own appRefVec
		var ownKeys, granteeKeys []appKeyRefVec
		var issuer []domainKeyVec
		var revoked []string
		var maxAge, skew int64
		var policy *string
		field("name", &name)
		field("expected_valid", &expectedValid)
		field("credential_cbor_hex", &credentialHex)
		field("own_application", &own)
		field("own_scope_set_keys", &ownKeys)
		field("issuer_domain_keys", &issuer)
		field("grantee_instance_keys", &granteeKeys)
		field("expected_request_digest_hex", &digestHex)
		field("revoked_grant_ids", &revoked)
		field("max_presentation_age_seconds", &maxAge)
		field("now", &now)
		field("skew_seconds", &skew)
		field("revoked_key_policy", &policy)

		credential, err := api.DecodeActAsCredential(mustHex(t, credentialHex))
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		verified, err := VerifyCredential(credential, AudienceContext{
			OwnApplication:            own.toRef(),
			OwnScopeSetKeys:           appKeyRefs(t, ownKeys),
			IssuerDomainKeys:          domainKeys(t, issuer),
			GranteeInstanceKeys:       appKeyRefs(t, granteeKeys),
			ExpectedRequestDigest:     mustHex(t, digestHex),
			RevokedGrantIDs:           revoked,
			MaxPresentationAgeSeconds: maxAge,
			Now:                       mustTime(t, now),
			SkewSeconds:               skew,
			RevokedKeyPolicy:          revokedKeyPolicy(t, policy),
		})
		checkExpected(t, name, expectedValid, err)

		if raw, ok := c["expected"]; ok && err == nil {
			var want struct {
				GrantID          string   `json:"grant_id"`
				UserID           string   `json:"user_id"`
				ApprovedScope    []string `json:"approved_scope"`
				SignerInstanceID *string  `json:"signer_instance_id"`
				NonceHex         string   `json:"nonce_hex"`
			}
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatalf("%s: expected: %v", name, err)
			}
			wantInstance := ""
			if want.SignerInstanceID != nil {
				wantInstance = *want.SignerInstanceID
			}
			if verified.GrantID != want.GrantID || verified.UserID != want.UserID ||
				verified.Signer.InstanceID != wantInstance ||
				!bytes.Equal(verified.Nonce, mustHex(t, want.NonceHex)) ||
				!equalStrings(verified.ApprovedScope, want.ApprovedScope) {
				t.Errorf("%s: verified %+v, want %+v", name, verified, want)
			}
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// act_as_terms.json
// ---------------------------------------------------------------------------

func TestConformanceActAsTerms(t *testing.T) {
	var v struct {
		DomainBounds struct {
			DefaultLifetimeSeconds  int64 `json:"default_lifetime_seconds"`
			MaxLifetimeSeconds      int64 `json:"max_lifetime_seconds"`
			MaxRenewalWindowSeconds int64 `json:"max_renewal_window_seconds"`
		} `json:"domain_bounds"`
		OfferedTerms []struct {
			RequestedLifetimeSeconds      *int64 `json:"requested_lifetime_seconds"`
			RequestedRenewalWindowSeconds *int64 `json:"requested_renewal_window_seconds"`
			Expected                      struct {
				DefaultLifetimeSeconds      int64 `json:"default_lifetime_seconds"`
				MaxLifetimeSeconds          int64 `json:"max_lifetime_seconds"`
				DefaultRenewalWindowSeconds int64 `json:"default_renewal_window_seconds"`
				MaxRenewalWindowSeconds     int64 `json:"max_renewal_window_seconds"`
			} `json:"expected"`
		} `json:"offered_terms"`
		IssuedTerms struct {
			Offer struct {
				RequestedLifetimeSeconds      *int64 `json:"requested_lifetime_seconds"`
				RequestedRenewalWindowSeconds *int64 `json:"requested_renewal_window_seconds"`
			} `json:"offer"`
			Cases []struct {
				ChosenLifetimeSeconds      int64 `json:"chosen_lifetime_seconds"`
				ChosenRenewalWindowSeconds int64 `json:"chosen_renewal_window_seconds"`
				ExpectedValid              bool  `json:"expected_valid"`
			} `json:"cases"`
		} `json:"issued_terms"`
		Refresh []struct {
			Name  string `json:"name"`
			Grant struct {
				IssuedAt       string `json:"issued_at"`
				ExpiresAt      string `json:"expires_at"`
				RenewableUntil string `json:"renewable_until"`
			} `json:"grant"`
			LifetimeSeconds int64  `json:"lifetime_seconds"`
			Now             string `json:"now"`
			Expected        struct {
				Decision  string `json:"decision"`
				IssuedAt  string `json:"issued_at"`
				ExpiresAt string `json:"expires_at"`
			} `json:"expected"`
		} `json:"refresh"`
	}
	loadVectorFile(t, conformanceDir(t), "act_as_terms.json", &v)

	bounds := DomainTermBounds{
		DefaultLifetimeSeconds:  v.DomainBounds.DefaultLifetimeSeconds,
		MaxLifetimeSeconds:      v.DomainBounds.MaxLifetimeSeconds,
		MaxRenewalWindowSeconds: v.DomainBounds.MaxRenewalWindowSeconds,
	}
	for i, c := range v.OfferedTerms {
		got := OfferTerms(c.RequestedLifetimeSeconds, c.RequestedRenewalWindowSeconds, bounds)
		want := OfferedTerms(c.Expected)
		if got != want {
			t.Errorf("offered_terms[%d]: got %+v, want %+v", i, got, want)
		}
	}

	offered := OfferTerms(v.IssuedTerms.Offer.RequestedLifetimeSeconds, v.IssuedTerms.Offer.RequestedRenewalWindowSeconds, bounds)
	for i, c := range v.IssuedTerms.Cases {
		_, _, err := IssuedTerms(offered, c.ChosenLifetimeSeconds, c.ChosenRenewalWindowSeconds)
		checkExpected(t, fmt.Sprintf("issued_terms[%d]", i), c.ExpectedValid, err)
	}

	if len(v.Refresh) == 0 {
		t.Fatal("no refresh cases")
	}
	for _, c := range v.Refresh {
		grant := api.ActAsGrant{
			IssuedAt:       c.Grant.IssuedAt,
			ExpiresAt:      c.Grant.ExpiresAt,
			SeriesIssuedAt: c.Grant.IssuedAt,
			RenewableUntil: c.Grant.RenewableUntil,
		}
		got, err := DecideRefresh(grant, c.LifetimeSeconds, mustTime(t, c.Now))
		switch c.Expected.Decision {
		case "stored":
			if err != nil || got.Renew {
				t.Errorf("refresh/%s: want stored, got %+v, %v", c.Name, got, err)
			}
		case "renew":
			if err != nil || !got.Renew || got.IssuedAt != c.Expected.IssuedAt || got.ExpiresAt != c.Expected.ExpiresAt {
				t.Errorf("refresh/%s: want renew %s..%s, got %+v, %v", c.Name, c.Expected.IssuedAt, c.Expected.ExpiresAt, got, err)
			}
		case "expired":
			if err == nil {
				t.Errorf("refresh/%s: want expired, got %+v", c.Name, got)
			}
		default:
			t.Fatalf("refresh/%s: unknown decision %q", c.Name, c.Expected.Decision)
		}
	}
}

// ---------------------------------------------------------------------------
// act_as_grantee_signing.json
// ---------------------------------------------------------------------------

func TestConformanceActAsGranteeSigning(t *testing.T) {
	var v struct {
		ApplicationGrantee struct {
			InstanceID string `json:"instance_id"`
			Key        struct {
				KeyID         string `json:"key_id"`
				PrivateKeyHex string `json:"private_key_hex"`
			} `json:"key"`
		} `json:"application_grantee"`
		LocalRpGrantee struct {
			Fingerprint             string `json:"fingerprint"`
			SignedDescriptorCborHex string `json:"signed_descriptor_cbor_hex"`
			SigningPrivateKeyHex    string `json:"signing_private_key_hex"`
		} `json:"local_rp_grantee"`
		Cases []struct {
			Name         string     `json:"name"`
			Grantee      granteeVec `json:"grantee"`
			GrantRequest struct {
				Inputs struct {
					ScopeSetSignedCborHex         string `json:"scope_set_signed_cbor_hex"`
					RequestedLifetimeSeconds      *int64 `json:"requested_lifetime_seconds"`
					RequestedRenewalWindowSeconds *int64 `json:"requested_renewal_window_seconds"`
					CallbackURL                   string `json:"callback_url"`
					Nonce                         string `json:"nonce"`
					RequestedAt                   string `json:"requested_at"`
					ExpiresAt                     string `json:"expires_at"`
				} `json:"inputs"`
				RequestCborHex        string `json:"request_cbor_hex"`
				SignatureInputCborHex string `json:"signature_input_cbor_hex"`
				SignedCborHex         string `json:"signed_cbor_hex"`
				URLParam              string `json:"url_param"`
			} `json:"grant_request"`
			RefreshRequest struct {
				Inputs struct {
					GrantID     string `json:"grant_id"`
					RequestedAt string `json:"requested_at"`
					ExpiresAt   string `json:"expires_at"`
					Nonce       string `json:"nonce"`
				} `json:"inputs"`
				RequestCborHex string `json:"request_cbor_hex"`
				SignedCborHex  string `json:"signed_cbor_hex"`
			} `json:"refresh_request"`
			Presentation struct {
				Inputs struct {
					Audience           appRefVec `json:"audience"`
					GrantSignedCborHex string    `json:"grant_signed_cbor_hex"`
					NonceHex           string    `json:"nonce_hex"`
					PresentedAt        string    `json:"presented_at"`
					RequestDigestHex   string    `json:"request_digest_hex"`
				} `json:"inputs"`
				CredentialCborHex   string `json:"credential_cbor_hex"`
				GrantHashHex        string `json:"grant_hash_hex"`
				PresentationCborHex string `json:"presentation_cbor_hex"`
			} `json:"presentation"`
		} `json:"cases"`
	}
	loadVectorFile(t, conformanceDir(t), "act_as_grantee_signing.json", &v)

	appSigner := NewApplicationGranteeSigner(v.ApplicationGrantee.InstanceID, ApplicationSigner{
		KeyID:           v.ApplicationGrantee.Key.KeyID,
		Algorithm:       "ed25519",
		PrivateKeyBytes: mustHex(t, v.ApplicationGrantee.Key.PrivateKeyHex),
	})
	descriptor, err := api.DecodeSignedLocalRpDescriptor(mustHex(t, v.LocalRpGrantee.SignedDescriptorCborHex))
	if err != nil {
		t.Fatalf("decode local RP descriptor: %v", err)
	}
	localSigner := NewLocalRpGranteeSigner(descriptor, v.LocalRpGrantee.Fingerprint, mustHex(t, v.LocalRpGrantee.SigningPrivateKeyHex))

	if len(v.Cases) != 2 {
		t.Fatalf("want 2 grantee signing cases, got %d", len(v.Cases))
	}
	for _, c := range v.Cases {
		grantee := c.Grantee.toRef()
		signer := localSigner
		if grantee.Application != nil {
			signer = appSigner
		}

		in := c.GrantRequest.Inputs
		scopeSet, err := api.DecodeSignedActAsScopeSet(mustHex(t, in.ScopeSetSignedCborHex))
		if err != nil {
			t.Fatalf("%s: decode scope set: %v", c.Name, err)
		}
		signedRequest, err := SignGrantRequest(api.ActAsGrantRequest{
			Grantee:                       grantee,
			ScopeSet:                      scopeSet,
			RequestedLifetimeSeconds:      in.RequestedLifetimeSeconds,
			RequestedRenewalWindowSeconds: in.RequestedRenewalWindowSeconds,
			CallbackUrl:                   in.CallbackURL,
			Nonce:                         in.Nonce,
			RequestedAt:                   in.RequestedAt,
			ExpiresAt:                     in.ExpiresAt,
		}, signer)
		if err != nil {
			t.Fatalf("%s: sign grant request: %v", c.Name, err)
		}
		if !bytes.Equal(signedRequest.Request, mustHex(t, c.GrantRequest.RequestCborHex)) {
			t.Errorf("%s: grant request bytes differ", c.Name)
		}
		if !bytes.Equal(envelopeSignatureInput(GrantRequestTag, signedRequest.Request), mustHex(t, c.GrantRequest.SignatureInputCborHex)) {
			t.Errorf("%s: grant request signature input differs", c.Name)
		}
		if !bytes.Equal(api.EncodeSignedActAsGrantRequest(signedRequest), mustHex(t, c.GrantRequest.SignedCborHex)) {
			t.Errorf("%s: signed grant request differs", c.Name)
		}
		link, err := GrantRequestURL("https://home.example/prefix/", signedRequest)
		if err != nil {
			t.Fatalf("%s: grant request URL: %v", c.Name, err)
		}
		if want := "https://home.example/prefix/auth/act-as?signed_request=" + c.GrantRequest.URLParam; link != want {
			t.Errorf("%s: grant request URL\n got  %s\n want %s", c.Name, link, want)
		}

		rin := c.RefreshRequest.Inputs
		signedRefresh, err := SignRefreshRequest(api.ActAsRefreshRequest{
			GrantId:     rin.GrantID,
			Grantee:     grantee,
			RequestedAt: rin.RequestedAt,
			ExpiresAt:   rin.ExpiresAt,
			Nonce:       rin.Nonce,
		}, signer)
		if err != nil {
			t.Fatalf("%s: sign refresh request: %v", c.Name, err)
		}
		if !bytes.Equal(signedRefresh.Request, mustHex(t, c.RefreshRequest.RequestCborHex)) {
			t.Errorf("%s: refresh request bytes differ", c.Name)
		}
		if !bytes.Equal(api.EncodeSignedActAsRefreshRequest(signedRefresh), mustHex(t, c.RefreshRequest.SignedCborHex)) {
			t.Errorf("%s: signed refresh request differs", c.Name)
		}

		pin := c.Presentation.Inputs
		grant, err := api.DecodeSignedActAsGrant(mustHex(t, pin.GrantSignedCborHex))
		if err != nil {
			t.Fatalf("%s: decode grant: %v", c.Name, err)
		}
		if !bytes.Equal(GrantHash(grant.Grant), mustHex(t, c.Presentation.GrantHashHex)) {
			t.Errorf("%s: grant hash differs", c.Name)
		}
		credential, err := Present(grant, pin.Audience.toRef(), mustHex(t, pin.RequestDigestHex), mustTime(t, pin.PresentedAt), mustHex(t, pin.NonceHex), signer)
		if err != nil {
			t.Fatalf("%s: present: %v", c.Name, err)
		}
		if !bytes.Equal(credential.Presentation.Presentation, mustHex(t, c.Presentation.PresentationCborHex)) {
			t.Errorf("%s: presentation bytes differ", c.Name)
		}
		if !bytes.Equal(api.EncodeActAsCredential(credential), mustHex(t, c.Presentation.CredentialCborHex)) {
			t.Errorf("%s: credential differs", c.Name)
		}
	}
}
