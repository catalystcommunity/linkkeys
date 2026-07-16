package community.catalyst.linkkeys.localrp.dns;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;

/**
 * DNS TXT record parsing, pinning, and vouch verification &mdash; mirrors
 * {@code crates/liblinkkeys/src/dns.rs} / {@code sdks/local-rp/go/dns.go}.
 * This class performs no I/O itself; {@link DnsResolver} is the network
 * seam (design doc, "Required Network Access": every SDK needs a DNS TXT
 * lookup capability, configurable, defaulting to the system resolver).
 */
public final class Dns {
    private Dns() {}

    /** Default TCP port for the LinkKeys protocol service. Advertised {@code tcp=} values omit the port when it equals this. */
    public static final int DEFAULT_TCP_PORT = 4987;

    public static String linkkeysDnsName(String domain) {
        return "_linkkeys." + domain;
    }

    public static String linkkeysApisDnsName(String domain) {
        return "_linkkeys_apis." + domain;
    }

    /** A parsed {@code _linkkeys.{domain}} TXT record &mdash; the trust anchor. */
    public record LinkKeysRecord(List<String> fingerprints) {}

    /** A parsed {@code _linkkeys_apis.{domain}} TXT record &mdash; service endpoints. */
    public record LinkKeysApis(String tcp, String httpsBase) {}

    private static String requireLk1Version(List<String> parts) {
        String version = null;
        boolean found = false;
        for (String p : parts) {
            if (p.startsWith("v=")) {
                version = p.substring(2);
                found = true;
                break;
            }
        }
        if (!found) {
            throw new DnsParseError(DnsParseError.Kind.MISSING_VERSION, null);
        }
        if (!"lk1".equals(version)) {
            throw new DnsParseError(DnsParseError.Kind.UNSUPPORTED_VERSION, version);
        }
        return version;
    }

    private static List<String> fields(String txt) {
        List<String> out = new ArrayList<>();
        for (String p : txt.split("\\s+")) {
            if (!p.isEmpty()) {
                out.add(p);
            }
        }
        return out;
    }

    /** Parse a single {@code _linkkeys} TXT record string. Errors if it isn't a LinkKeys v1 record. */
    public static LinkKeysRecord parseLinkKeysTxt(String txt) {
        List<String> parts = fields(txt);
        requireLk1Version(parts);
        List<String> fingerprints = new ArrayList<>();
        for (String p : parts) {
            if (p.startsWith("fp=")) {
                fingerprints.add(p.substring(3));
            }
        }
        return new LinkKeysRecord(fingerprints);
    }

    private static String normalizeTcpEndpoint(String value) {
        if (value.isEmpty() || value.contains(":")) {
            return value;
        }
        return value + ":" + DEFAULT_TCP_PORT;
    }

    /** Parse a single {@code _linkkeys_apis} TXT record string. Errors if it isn't a LinkKeys v1 record or carries no endpoint. */
    public static LinkKeysApis parseLinkKeysApisTxt(String txt) {
        List<String> parts = fields(txt);
        requireLk1Version(parts);

        String tcp = null;
        String httpsBase = null;
        for (String p : parts) {
            if (tcp == null && p.startsWith("tcp=")) {
                String v = normalizeTcpEndpoint(p.substring(4));
                if (!v.isEmpty()) {
                    tcp = v;
                }
            }
            if (httpsBase == null && p.startsWith("https=")) {
                String v = p.substring(6);
                if (!v.isEmpty()) {
                    httpsBase = "https://" + v;
                }
            }
        }
        if (tcp == null && httpsBase == null) {
            throw new DnsParseError(DnsParseError.Kind.MISSING_APIS_ENDPOINT, null);
        }
        return new LinkKeysApis(tcp, httpsBase);
    }

    /** Whether {@code fp} is a syntactically valid key fingerprint: 64 hex chars (a SHA-256 digest), case-insensitive. */
    public static boolean isValidFingerprint(String fp) {
        if (fp.length() != 64) {
            return false;
        }
        for (int i = 0; i < fp.length(); i++) {
            char c = fp.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    /**
     * Pin fetched keys to the DNS-published fingerprint set: for each
     * candidate key, RECOMPUTE {@code fingerprint(public_key)} (never trust
     * the wire {@code fingerprint} field, which is attacker-controlled) and
     * keep only keys whose recomputed fingerprint is a member of
     * {@code pinned}.
     */
    public static List<DomainPublicKey> pinKeysToFingerprints(List<DomainPublicKey> keys, List<String> pinned) {
        Set<String> pinnedLower = new HashSet<>();
        for (String f : pinned) {
            if (isValidFingerprint(f)) {
                pinnedLower.add(f.toLowerCase(Locale.ROOT));
            }
        }
        List<DomainPublicKey> out = new ArrayList<>();
        for (DomainPublicKey k : keys) {
            String fp = Crypto.fingerprint(k.publicKey()).toLowerCase(Locale.ROOT);
            if (pinnedLower.contains(fp)) {
                out.add(k);
            }
        }
        return out;
    }

    private static final String KEY_VOUCH_TAG = "linkkeys-key-vouch-v1alpha";

    static byte[] keyVouchPayload(String encFingerprint, String encExpiresAt) {
        return Cbor.encode(Cbor.tuple(Cbor.vtext(KEY_VOUCH_TAG), Cbor.vtext(encFingerprint), Cbor.vtext(encExpiresAt)));
    }

    /**
     * Verify that {@code signingKey} vouches for {@code encKey}: the
     * encryption key names this signing key, the signing key is itself
     * valid, and its signature covers the recomputed encrypt-key
     * fingerprint + expiry.
     */
    public static boolean verifyKeyVouch(DomainPublicKey encKey, DomainPublicKey signingKey) {
        if (encKey.signedByKeyId() == null || !encKey.signedByKeyId().equals(signingKey.keyId())) {
            return false;
        }
        try {
            community.catalyst.linkkeys.localrp.LocalRp.checkSigningKeyValid(signingKey);
        } catch (RuntimeException e) {
            return false;
        }
        if (encKey.keySignature() == null) {
            return false;
        }
        if (!"ed25519".equals(signingKey.algorithm())) {
            return false;
        }
        String recomputedFp = Crypto.fingerprint(encKey.publicKey());
        byte[] payload = keyVouchPayload(recomputedFp, encKey.expiresAt());
        return Crypto.verifyEd25519(payload, encKey.keySignature(), signingKey.publicKey());
    }

    /**
     * Establish the trusted key set from a fetched key list and the
     * DNS-pinned fingerprint set: signing keys ({@code key_usage == "sign"})
     * are pinned directly; encryption keys ({@code key_usage == "encrypt"})
     * are trusted only when a DNS-pinned signing key vouches for them.
     */
    public static List<DomainPublicKey> trustKeys(List<DomainPublicKey> keys, List<String> pinned) {
        List<DomainPublicKey> signing = new ArrayList<>();
        for (DomainPublicKey k : keys) {
            if ("sign".equals(k.keyUsage())) {
                signing.add(k);
            }
        }
        List<DomainPublicKey> pinnedSigning = pinKeysToFingerprints(signing, pinned);

        List<DomainPublicKey> trusted = new ArrayList<>(pinnedSigning);
        for (DomainPublicKey k : keys) {
            if (!"encrypt".equals(k.keyUsage())) {
                continue;
            }
            for (DomainPublicKey sk : pinnedSigning) {
                if (verifyKeyVouch(k, sk)) {
                    trusted.add(k);
                    break;
                }
            }
        }
        return trusted;
    }
}
