package localrp

import (
	"fmt"
	"strings"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// CompleteLocalLogin (design doc: "SDK API Shape", "Flow" steps 12-13).
// Mirrors sdks/local-rp/rust/src/complete.rs.
//
// This is the SDK's full verification chain, run in the exact order the
// pure protocol helpers require:
//
//  1. decode the callback ciphertext from its URL-param encoding
//  2. open it (decrypt) — only with a suite this identity's own descriptor
//     advertises
//  3. fetch the pending domain's public keys + revocations, DNS-fp-pinned,
//     over TCP CSIL-RPC
//  4. verify the domain-signed envelope (key lookup, revocation/expiry,
//     signature, payload timestamp bounds) — only now is anything inside
//     the payload trusted
//  5. cross-check the cleartext header's routing fields against the
//     now-verified payload
//  6. audience / issuer / callback-URL / nonce-state checks
//  7. redeem the claim ticket over TCP CSIL-RPC (signed with the local RP's
//     own key — the possession proof), then assert the (unauthenticated)
//     redemption response's user_id/user_domain match the already-verified
//     payload's — fatal on mismatch
//  8. verify every returned claim's signatures against ITS signer domain's
//     keys (fetched the same pinned way), which also checks the claim's own
//     revocation/expiry, AND assert each claim's user_id matches the
//     verified payload's (fatal on mismatch), then enforce that every
//     required_claims entry from the pending login is covered by a claim
//     that passed all of the above (fatal if missing/insufficient)

// MaxClaimSignerDomains bounds the number of distinct claim-signer domains
// CompleteLocalLogin will fetch keys for per completion. The redemption
// response's claim signatures name their signing domains as plain,
// not-yet-verified strings — a malicious/compromised home IDP could
// otherwise list an unbounded number of distinct "signer domains" purely to
// make this SDK perform many outbound DNS/TCP calls to attacker-chosen
// targets before any signature is actually checked (an SSRF/DoS
// amplification vector against the app's own process). A legitimate claim
// set names very few (typically one: the home domain).
const MaxClaimSignerDomains = 8

// CompleteLocalLoginConfig is the input to CompleteLocalLogin. Every field
// is load-bearing (design doc: "complete_local_login inputs, spelled out
// because every one is load-bearing").
type CompleteLocalLoginConfig struct {
	// KeyMaterial is the same identity BeginLocalLogin used.
	KeyMaterial *LocalRpKeyMaterial
	// Pending is the pending-login state BeginLocalLogin returned, exactly
	// as the app persisted it. The app must treat this as single-use; this
	// package owns no storage and cannot enforce that itself.
	Pending *PendingLogin
	// EncryptedToken is the raw callback data — the `encrypted_token`
	// query-parameter value (base64url CBOR LocalRpEncryptedCallback).
	EncryptedToken string
	// ArrivedURL is the URL the callback actually arrived at (the app's own
	// HTTP handler's request URL, including the `encrypted_token` query
	// parameter this package strips before comparing against the signed
	// payload's callback_url).
	ArrivedURL string
	Now        time.Time
	// ClockSkewSeconds is the clock-skew tolerance for timestamp checks.
	// Defaults to DefaultClockSkewSeconds (±300s) when zero.
	ClockSkewSeconds int64
	// Transport is the TCP dial seam. Defaults to DefaultTransport() when
	// nil.
	Transport Transport
	// DNS is the DNS TXT lookup seam. Defaults to DefaultDNSResolver() when
	// nil.
	DNS DnsResolver
}

// VerifiedLocalLogin is what CompleteLocalLogin returns to app code (design
// doc: "SDKs ... should either return verified results or call registered
// callbacks with:" — this package returns rather than calling back).
type VerifiedLocalLogin struct {
	UserID     string
	UserDomain string
	// Claims are the verified claim values, current as of ticket redemption
	// (design doc: "Ticket semantics" — the claim *set* is frozen at
	// consent, but each redemption returns current *values*).
	Claims []api.Claim
	// DomainPublicKeys are the user's home domain's public keys used to
	// verify the callback envelope (audit/logging context — never the
	// whole trusted set for every claim signer domain).
	DomainPublicKeys   []api.DomainPublicKey
	LocalRpFingerprint string
	IssuedAt           time.Time
	ExpiresAt          time.Time
	// TicketExpiresAt is the ticket's own expiry (design doc: "Valid for a
	// bounded window, default 1 hour. Multi-use within the window").
	TicketExpiresAt time.Time
}

// stripEncryptedTokenParam undoes the exact `?`/`&` + `encrypted_token=`
// suffix construction the server uses to deliver the callback, so the
// recovered value can be compared against the signed payload's
// callback_url. If arrivedURL doesn't end with that exact suffix, returns it
// unchanged — the subsequent VerifyCallbackURL equality check will then
// correctly fail closed rather than this function guessing.
func stripEncryptedTokenParam(arrivedURL string) string {
	for _, sep := range []string{"?", "&"} {
		marker := sep + "encrypted_token="
		if idx := strings.LastIndex(arrivedURL, marker); idx != -1 {
			return arrivedURL[:idx]
		}
	}
	return arrivedURL
}

// CompleteLocalLogin implements `complete_local_login(config) ->
// VerifiedLocalLogin` (design doc, "SDK API Shape"). See the package docs
// above for the exact verification order.
func CompleteLocalLogin(config CompleteLocalLoginConfig) (*VerifiedLocalLogin, error) {
	skew := config.ClockSkewSeconds
	if skew == 0 {
		skew = DefaultClockSkewSeconds
	}
	tr := config.Transport
	if tr == nil {
		tr = DefaultTransport()
	}
	dns := config.DNS
	if dns == nil {
		dns = DefaultDNSResolver()
	}

	// 1. Decode the callback's URL-param encoding.
	encrypted, err := LocalRpEncryptedCallbackFromURLParam(config.EncryptedToken)
	if err != nil {
		return nil, err
	}

	// 2. Open it, restricted to suites THIS identity's own descriptor
	// advertises (Wire Precision: "The SDK must decrypt only with a suite
	// listed in its own descriptor").
	ownDescriptor, err := api.DecodeLocalRpDescriptor(config.KeyMaterial.Descriptor.Descriptor)
	if err != nil {
		return nil, &DecodeError{Detail: "own descriptor: " + err.Error()}
	}
	var allowedSuites []AeadSuite
	for _, s := range ownDescriptor.SupportedSuites {
		if suite, ok := ParseAeadSuite(string(s)); ok {
			allowedSuites = append(allowedSuites, suite)
		}
	}

	header, signedPayload, err := OpenLocalRpCallback(*encrypted, config.KeyMaterial.EncryptionPrivateKey, allowedSuites)
	if err != nil {
		return nil, err
	}

	// 3. Fetch the PENDING state's domain's keys + revocations, DNS-pinned,
	// over TCP CSIL-RPC (design doc: "fetches domain public keys and
	// revocations for the domain the login was begun with").
	userDomainKeys, err := FetchDomainKeys(tr, dns, config.Pending.UserDomain)
	if err != nil {
		return nil, err
	}

	// 4. Verify the domain-signed envelope against those keys. Nothing
	// inside payload is trusted before this succeeds.
	payload, err := VerifyLocalRpCallbackPayload(*signedPayload, userDomainKeys, config.Now, skew)
	if err != nil {
		return nil, err
	}

	// 5. Cross-check the cleartext header's routing twins against the
	// now-verified payload.
	if err := CheckCallbackHeaderMatchesPayload(*header, *payload); err != nil {
		return nil, err
	}

	// 6a. Audience: the callback names THIS local RP.
	if err := VerifyAudience(payload.AudienceFingerprint, config.KeyMaterial.Fingerprint); err != nil {
		return nil, err
	}

	// 6b. Issuer binding: the payload's user_domain must be the domain the
	// login was BEGUN with, not merely whichever domain's keys happened to
	// verify.
	if err := VerifyIssuer(payload.UserDomain, config.Pending.UserDomain); err != nil {
		return nil, err
	}

	// 6c. Callback URL binding against the URL the callback actually
	// arrived at.
	arrivedBaseURL := stripEncryptedTokenParam(config.ArrivedURL)
	if err := VerifyCallbackURL(payload.CallbackUrl, arrivedBaseURL); err != nil {
		return nil, err
	}

	// 6d. Nonce/state equality against the pending state.
	if err := VerifyNonceState(config.Pending.Nonce, config.Pending.State, payload.Nonce, payload.State); err != nil {
		return nil, err
	}

	// 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the local
	// RP's own key (the possession proof a stolen ticket can't satisfy).
	redemptionRequest := BuildLocalRpTicketRedemptionRequest(payload.ClaimTicket, config.KeyMaterial.Fingerprint, config.Now.UTC().Format(time.RFC3339Nano))
	signedRedemption := SignLocalRpTicketRedemptionRequest(redemptionRequest, config.KeyMaterial.SigningPrivateKey)

	redemption, err := RedeemClaimTicket(tr, dns, config.Pending.UserDomain, signedRedemption)
	if err != nil {
		return nil, err
	}

	// 7a. Redemption identity binding: the redemption response's user_id and
	// user_domain must match the domain-signature-VERIFIED callback
	// payload's — never merely trusted as-is. Everything up to this point in
	// step 7 is unauthenticated server response; without this check a
	// compromised/malicious IDP (or a stolen/substituted ticket) could
	// answer a redemption for a different user than the one who actually
	// completed the signed callback, and that identity would otherwise flow
	// straight into VerifiedLocalLogin. Fatal, never a success return.
	if redemption.UserId != payload.UserId || redemption.UserDomain != payload.UserDomain {
		return nil, &LocalRpError{Kind: ErrKindRedemptionIdentityMismatch}
	}

	// 8. Verify every returned claim's signatures against ITS signer
	// domain's keys, fetched the same pinned way (a claim may be attested
	// by a domain other than the user's home domain). Reuse the home
	// domain's already-fetched keys; fetch any additional signer domains on
	// demand, capped.
	domainKeySets := []DomainKeySet{{Domain: payload.UserDomain, Keys: userDomainKeys}}
	for _, claim := range redemption.Claims {
		for _, sig := range claim.Signatures {
			found := false
			for _, s := range domainKeySets {
				if s.Domain == sig.Domain {
					found = true
					break
				}
			}
			if found {
				continue
			}
			if len(domainKeySets) >= MaxClaimSignerDomains {
				return nil, &InvalidInputError{Detail: fmt.Sprintf("claim set names more than %d distinct signer domains; refusing to fetch further keys", MaxClaimSignerDomains)}
			}
			keys, err := FetchDomainKeys(tr, dns, sig.Domain)
			if err != nil {
				return nil, err
			}
			domainKeySets = append(domainKeySets, DomainKeySet{Domain: sig.Domain, Keys: keys})
		}
	}
	// verifiedClaimTypes tracks the claim types that passed EVERY check
	// below (subject binding, signature quorum, revocation, expiry) so
	// required_claims enforcement (7c below) can't be satisfied by a claim
	// that merely arrived in the response but never actually verified.
	verifiedClaimTypes := make(map[string]bool, len(redemption.Claims))
	for _, claim := range redemption.Claims {
		// Subject binding: a claim's user_id must match the
		// signature-verified payload's user_id — a claim about a different
		// user must never be attributed to this login, regardless of
		// whether its own signature checks out. Fatal.
		if claim.UserId != payload.UserId {
			return nil, &ClaimError{Kind: ClaimErrKindUserIDMismatch, Detail: claim.ClaimId}
		}
		if err := VerifyClaim(claim, payload.UserDomain, domainKeySets); err != nil {
			return nil, err
		}
		verifiedClaimTypes[claim.ClaimType] = true
	}

	// 7c. required_claims enforcement: every claim type the login demanded
	// (persisted on PendingLogin at begin_local_login time) must appear
	// among the claims that passed full verification above. An empty or
	// insufficient claim set is fatal — required_claims exists precisely so
	// the app can rely on these being present in a successful return.
	for _, required := range config.Pending.RequiredClaims {
		if !verifiedClaimTypes[required] {
			return nil, &ClaimError{Kind: ClaimErrKindRequiredClaimMissing, Detail: required}
		}
	}

	issuedAt, err := parseTimestamp("callback issued_at", payload.IssuedAt)
	if err != nil {
		return nil, err
	}
	expiresAt, err := parseTimestamp("callback expires_at", payload.ExpiresAt)
	if err != nil {
		return nil, err
	}
	ticketExpiresAt, err := parseTimestamp("ticket_expires_at", redemption.TicketExpiresAt)
	if err != nil {
		return nil, err
	}

	return &VerifiedLocalLogin{
		// Sourced from the verified signed payload, not the unauthenticated
		// redemption response (which was only just cross-checked against it
		// above) — the payload is the one value in this whole chain that
		// carries a domain signature over the identity fields.
		UserID:             payload.UserId,
		UserDomain:         payload.UserDomain,
		Claims:             redemption.Claims,
		DomainPublicKeys:   userDomainKeys,
		LocalRpFingerprint: config.KeyMaterial.Fingerprint,
		IssuedAt:           issuedAt,
		ExpiresAt:          expiresAt,
		TicketExpiresAt:    ticketExpiresAt,
	}, nil
}
