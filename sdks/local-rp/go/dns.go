package localrp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	api "github.com/catalystcommunity/linkkeys/sdks/local-rp/go/generated"
)

// DNS TXT record parsing, pinning, and vouch verification — mirrors
// crates/liblinkkeys/src/dns.rs. This module performs no I/O itself; the
// [DnsResolver] interface below is the network seam, per the design doc's
// "Required Network Access": every SDK needs a DNS TXT lookup capability,
// configurable, defaulting to the system resolver.

// DefaultTCPPort is the default TCP port for the LinkKeys protocol service.
// Advertised `tcp=` values omit the port when it equals this.
const DefaultTCPPort uint16 = 4987

// MaxTXTStringLen is the maximum length of a single DNS TXT character-string
// (RFC 1035).
const MaxTXTStringLen = 255

// LinkKeysRecord is a parsed `_linkkeys.{domain}` TXT record — the trust
// anchor. Format: `v=lk1 fp={fingerprint1} fp={fingerprint2} ...`.
type LinkKeysRecord struct {
	Fingerprints []string
}

// LinkKeysApis is a parsed `_linkkeys_apis.{domain}` TXT record — service
// endpoints. Format: `v=lk1 tcp={host[:port]} https={host[:port][/path]}`.
type LinkKeysApis struct {
	// TCP is `host:port` for the CSIL-RPC service, with the default port
	// filled in when omitted.
	TCP *string
	// HTTPSBase is the full `https://host[:port][/path]` base for the
	// browser-facing HTTPS API.
	HTTPSBase *string
}

// LinkKeysDNSName is the `_linkkeys` (trust-anchor) DNS name for a domain.
func LinkKeysDNSName(domain string) string { return "_linkkeys." + domain }

// LinkKeysApisDNSName is the `_linkkeys_apis` (service-endpoint) DNS name for
// a domain.
func LinkKeysApisDNSName(domain string) string { return "_linkkeys_apis." + domain }

func requireLK1Version(parts []string) error {
	var version string
	found := false
	for _, p := range parts {
		if strings.HasPrefix(p, "v=") {
			version = p[2:]
			found = true
			break
		}
	}
	if !found {
		return &DnsParseError{Kind: DnsErrMissingVersion}
	}
	if version != "lk1" {
		return &DnsParseError{Kind: DnsErrUnsupportedVersion, Detail: version}
	}
	return nil
}

// ParseLinkKeysTXT parses a single `_linkkeys` TXT record string. Errors if
// it isn't a LinkKeys v1 record (no `v=lk1` tag).
func ParseLinkKeysTXT(txt string) (*LinkKeysRecord, error) {
	parts := strings.Fields(txt)
	if err := requireLK1Version(parts); err != nil {
		return nil, err
	}
	var fingerprints []string
	for _, p := range parts {
		if strings.HasPrefix(p, "fp=") {
			fingerprints = append(fingerprints, p[3:])
		}
	}
	return &LinkKeysRecord{Fingerprints: fingerprints}, nil
}

// normalizeTCPEndpoint normalizes a published `tcp=` value (`host` or
// `host:port`) into an explicit `host:port`, filling in DefaultTCPPort when
// the port is omitted.
func normalizeTCPEndpoint(value string) string {
	if value == "" || strings.Contains(value, ":") {
		return value
	}
	return fmt.Sprintf("%s:%d", value, DefaultTCPPort)
}

// ParseLinkKeysApisTXT parses a single `_linkkeys_apis` TXT record string.
// Errors if it isn't a LinkKeys v1 record or carries no endpoint.
func ParseLinkKeysApisTXT(txt string) (*LinkKeysApis, error) {
	parts := strings.Fields(txt)
	if err := requireLK1Version(parts); err != nil {
		return nil, err
	}

	var tcp *string
	var httpsBase *string
	for _, p := range parts {
		if tcp == nil && strings.HasPrefix(p, "tcp=") {
			if v := normalizeTCPEndpoint(p[4:]); v != "" {
				tcp = &v
			}
		}
		if httpsBase == nil && strings.HasPrefix(p, "https=") {
			if v := p[6:]; v != "" {
				full := "https://" + v
				httpsBase = &full
			}
		}
	}

	if tcp == nil && httpsBase == nil {
		return nil, &DnsParseError{Kind: DnsErrMissingApisEndpoint}
	}
	return &LinkKeysApis{TCP: tcp, HTTPSBase: httpsBase}, nil
}

// IsValidFingerprint reports whether fp is a syntactically valid key
// fingerprint: 64 hex chars (a SHA-256 digest), case-insensitive.
func IsValidFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for i := 0; i < len(fp); i++ {
		b := fp[i]
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')) {
			return false
		}
	}
	return true
}

// PinKeysToFingerprints pins fetched keys to the DNS-published fingerprint
// set: for each candidate key it RECOMPUTES `Fingerprint(public_key)` (never
// trusting the wire `Fingerprint` field, which is attacker-controlled) and
// keeps only keys whose recomputed fingerprint is a member of pinned.
// Comparison is case-insensitive hex; invalid pinned entries are ignored. An
// empty result means "no trustworthy keys" — callers must fail closed.
func PinKeysToFingerprints(keys []api.DomainPublicKey, pinned []string) []api.DomainPublicKey {
	pinnedLower := make(map[string]struct{}, len(pinned))
	for _, f := range pinned {
		if IsValidFingerprint(f) {
			pinnedLower[strings.ToLower(f)] = struct{}{}
		}
	}
	var out []api.DomainPublicKey
	for _, k := range keys {
		fp := strings.ToLower(Fingerprint(k.PublicKey))
		if _, ok := pinnedLower[fp]; ok {
			out = append(out, k)
		}
	}
	return out
}

// keyVouchTag is the domain-separation tag for a signing key's vouch over an
// encryption key.
const keyVouchTag = "linkkeys-key-vouch-v1"

// keyVouchPayload builds the canonical bytes a signing key signs to vouch
// for an encryption key: `(tag, encrypt-key fingerprint, encrypt-key
// expires_at)`.
func keyVouchPayload(encFingerprint, encExpiresAt string) []byte {
	return cborTuple(cborText(keyVouchTag), cborText(encFingerprint), cborText(encExpiresAt))
}

// VerifyKeyVouch verifies that signingKey vouches for encKey: the encryption
// key names this signing key, the signing key is itself valid (not
// revoked/expired), and its signature covers the recomputed encrypt-key
// fingerprint + expiry.
func VerifyKeyVouch(encKey, signingKey api.DomainPublicKey) bool {
	if encKey.SignedByKeyId == nil || *encKey.SignedByKeyId != signingKey.KeyId {
		return false
	}
	if signingKeyValidity(signingKey.ExpiresAt, signingKey.RevokedAt) != keyValidityValid {
		return false
	}
	if encKey.KeySignature == nil {
		return false
	}
	recomputedFp := Fingerprint(encKey.PublicKey)
	payload := keyVouchPayload(recomputedFp, encKey.ExpiresAt)
	return resolveAndVerify(signingKey.Algorithm, payload, *encKey.KeySignature, signingKey.PublicKey) == nil
}

// TrustKeys establishes the trusted key set from a fetched key list and the
// DNS-pinned fingerprint set: signing keys (`key_usage == "sign"`) are
// pinned directly; encryption keys (`key_usage == "encrypt"`) are trusted
// only when a DNS-pinned signing key vouches for them. Anything not pinned
// or not vouched is dropped.
func TrustKeys(keys []api.DomainPublicKey, pinned []string) []api.DomainPublicKey {
	var signing []api.DomainPublicKey
	for _, k := range keys {
		if k.KeyUsage == "sign" {
			signing = append(signing, k)
		}
	}
	pinnedSigning := PinKeysToFingerprints(signing, pinned)

	trusted := append([]api.DomainPublicKey{}, pinnedSigning...)
	for _, k := range keys {
		if k.KeyUsage != "encrypt" {
			continue
		}
		for _, sk := range pinnedSigning {
			if VerifyKeyVouch(k, sk) {
				trusted = append(trusted, k)
				break
			}
		}
	}
	return trusted
}

// DnsResolver is the DNS TXT lookup seam (design doc: "Required Network
// Access" — the SDK needs a DNS TXT lookup capability; injectable so tests
// can supply canned answers and operators can supply a hardened resolver,
// e.g. a DoH client).
type DnsResolver interface {
	// TxtLookup resolves TXT records for a fully-qualified name (e.g.
	// `_linkkeys.example.com`). Each returned string is one TXT record's
	// content — the concatenation of its character-strings.
	TxtLookup(name string) ([]string, error)
}

// SystemDnsResolver is the default DnsResolver: the OS-configured system
// resolver (Go's net.Resolver). Per the design doc's "Decided" section:
// resolver spoofing on a LAN is an accepted, documented tradeoff for this
// mode; operators wanting hardening can inject their own DnsResolver.
type SystemDnsResolver struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// NewSystemDnsResolver builds the default resolver with a bounded per-lookup
// timeout so a black-holed/unresponsive resolver can't hang a login
// indefinitely.
func NewSystemDnsResolver() *SystemDnsResolver {
	return &SystemDnsResolver{resolver: net.DefaultResolver, timeout: 10 * time.Second}
}

func (s *SystemDnsResolver) TxtLookup(name string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	records, err := s.resolver.LookupTXT(ctx, name)
	if err != nil {
		return nil, &DNSError{Detail: fmt.Sprintf("%s: %s", name, err.Error())}
	}
	return records, nil
}

var (
	defaultDNSOnce sync.Once
	defaultDNSInst DnsResolver
)

// DefaultDNSResolver is the memoized default DnsResolver: the OS-configured
// system resolver.
func DefaultDNSResolver() DnsResolver {
	defaultDNSOnce.Do(func() { defaultDNSInst = NewSystemDnsResolver() })
	return defaultDNSInst
}
