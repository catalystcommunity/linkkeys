package community.catalyst.linkkeys.localrp.kt.protocol

import java.time.Instant
import community.catalyst.linkkeys.localrp.Claims as JClaims
import community.catalyst.linkkeys.localrp.Encoding as JEncoding
import community.catalyst.linkkeys.localrp.LocalRp as JLocalRp
import community.catalyst.linkkeys.localrp.Revocation as JRevocation
import community.catalyst.linkkeys.localrp.crypto.AeadSuite as JAeadSuite
import community.catalyst.linkkeys.localrp.crypto.Crypto as JCrypto
import community.catalyst.linkkeys.localrp.dns.Dns as JDns
import community.catalyst.linkkeys.localrp.wire.Codec as JCodec
import community.catalyst.linkkeys.localrp.wire.Types as JTypes
import community.catalyst.linkkeys.localrp.kt.Claim
import community.catalyst.linkkeys.localrp.kt.ClaimSignature
import community.catalyst.linkkeys.localrp.kt.DomainPublicKey
import community.catalyst.linkkeys.localrp.kt.formatRfc3339
import community.catalyst.linkkeys.localrp.kt.parseRfc3339
import community.catalyst.linkkeys.localrp.kt.runCatchingSdk
import community.catalyst.linkkeys.localrp.kt.toJava
import community.catalyst.linkkeys.localrp.kt.toKotlin

/**
 * Low-level pure protocol helpers, exposed as part of this package's own
 * public API so this SDK's conformance test suite (the JSON vector files
 * under `sdks/local-rp/conformance`) can exercise every wire construction
 * through Kotlin, not by reaching past this package into the underlying
 * Java dependency's classes.
 *
 * Most applications never need anything in this `protocol` sub-package --
 * [community.catalyst.linkkeys.localrp.kt.generateLocalRpIdentity],
 * [community.catalyst.linkkeys.localrp.kt.beginLocalLogin],
 * [community.catalyst.linkkeys.localrp.kt.completeLocalLogin], and
 * [community.catalyst.linkkeys.localrp.kt.checkExpirations] are the whole
 * "SDK API Shape" surface a login integration touches. This sub-package
 * exists for conformance testing, interop debugging, and advanced use (e.g.
 * an app that wants to pre-fetch/cache domain keys itself).
 */

/** The four mandatory, structure-specific signature context strings (design doc: "Signature Context Strings Are Mandatory"). */
object SignatureContexts {
    const val DESCRIPTOR = "linkkeys-local-rp-descriptor"
    const val LOGIN_REQUEST = "linkkeys-local-rp-login-request"
    const val CALLBACK = "linkkeys-local-rp-callback"
    const val TICKET_REDEMPTION = "linkkeys-local-rp-ticket-redemption"
}

/**
 * The signature input for every local-RP signed structure:
 * `CBOR([context, payload_bytes])` -- a two-element array with the
 * domain-separation context string first and the exact payload bytes second.
 * Deliberately NOT a bare `context || payload` concatenation (design doc,
 * Wire Precision: "Signature input bytes").
 */
fun envelopeSignatureInput(context: String, payloadBytes: ByteArray): ByteArray =
    JLocalRp.envelopeSignatureInput(context, payloadBytes)

/** Raw Ed25519/X25519/SHA-256 primitives, exposed for conformance tests and interop (`keys.json`, `tickets.json`). */
object Crypto {
    /** Sign `message` with an Ed25519 seed (raw 32-byte private key). Returns a 64-byte signature. */
    fun signEd25519(message: ByteArray, privateKeySeed: ByteArray): ByteArray = JCrypto.signEd25519(message, privateKeySeed)

    /** Verify an Ed25519 signature. Never throws for a malformed key/signature; returns `false` uniformly. */
    fun verifyEd25519(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean =
        JCrypto.verifyEd25519(message, signature, publicKey)

    /** `sha256(publicKeyBytes)`, lowercase hex -- the canonical LinkKeys fingerprint format, everywhere. */
    fun fingerprint(publicKeyBytes: ByteArray): String = JCrypto.fingerprint(publicKeyBytes)

    /** Derive the raw 32-byte X25519 public key for a raw 32-byte private scalar (RFC 7748 base-point trick). */
    fun derivePublicFromX25519Private(privateKey: ByteArray): ByteArray = JCrypto.derivePublicFromX25519Private(privateKey)
}

/** Bounded clock-skew tolerance check shared by descriptor/login-request/callback-payload freshness (`expirations.json`'s `check_timestamps`). */
fun checkTimestamps(issuedAt: Instant, expiresAt: Instant, now: Instant, skewSeconds: Long) {
    runCatchingSdk { JLocalRp.checkTimestamps(formatRfc3339(issuedAt), formatRfc3339(expiresAt), now, skewSeconds) }
}

// -----------------------------------------------------------------------
// Callback sealed box (open only -- sealing is an IDP/server-side operation;
// see community.catalyst.linkkeys.localrp.LocalRp's class docs for why this
// SDK never seals a callback in production, only test fixtures do).
// -----------------------------------------------------------------------

/** The cleartext routing/decryption metadata shipped alongside an encrypted callback (design doc: `LocalRpCallbackHeader`). */
data class CallbackHeader(
    val fingerprint: String,
    val nonce: ByteArray,
    val state: ByteArray,
    val suite: String,
    val ephemeralPublicKey: ByteArray,
    val aeadNonce: ByteArray,
    val issuedAt: String,
    val expiresAt: String,
) {
    override fun equals(other: Any?): Boolean =
        other is CallbackHeader && fingerprint == other.fingerprint && suite == other.suite &&
            issuedAt == other.issuedAt && expiresAt == other.expiresAt && nonce.contentEquals(other.nonce) &&
            state.contentEquals(other.state) && ephemeralPublicKey.contentEquals(other.ephemeralPublicKey) &&
            aeadNonce.contentEquals(other.aeadNonce)

    override fun hashCode(): Int =
        java.util.Objects.hash(
            fingerprint, suite, issuedAt, expiresAt, nonce.contentHashCode(), state.contentHashCode(),
            ephemeralPublicKey.contentHashCode(), aeadNonce.contentHashCode(),
        )
}

/** The still-domain-signature-unverified result of opening an encrypted callback -- see [CallbackBox.open]. */
data class OpenedCallback(val header: CallbackHeader, val signedPayloadCbor: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is OpenedCallback && header == other.header && signedPayloadCbor.contentEquals(other.signedPayloadCbor)

    override fun hashCode(): Int = java.util.Objects.hash(header, signedPayloadCbor.contentHashCode())
}

/** Opening (decrypting) an encrypted local-RP callback -- the client-side half of the callback sealed box (design doc, Wire Precision: "Callback sealed box"). */
object CallbackBox {
    /**
     * Open a `LocalRpEncryptedCallback` with the local RP's encryption
     * private key. [allowedSuiteIds] is the local RP's own supported-suite
     * list (from its descriptor): a header advertising a suite not in that
     * list is rejected even if it is otherwise a valid registry id.
     *
     * Returns the decoded header and the still domain-signature-unverified
     * signed callback payload envelope bytes -- callers must still verify
     * the domain signature (not exposed at this level; see
     * [community.catalyst.linkkeys.localrp.kt.completeLocalLogin] for the
     * full chain) before trusting the result.
     */
    fun open(headerBytes: ByteArray, ciphertext: ByteArray, recipientEncryptionPrivateKey: ByteArray, allowedSuiteIds: List<String>): OpenedCallback {
        val allowed = allowedSuiteIds.mapNotNull { JAeadSuite.parse(it) }
        val encrypted = JTypes.LocalRpEncryptedCallback(headerBytes, ciphertext)
        val opened = runCatchingSdk { JLocalRp.openLocalRpCallback(encrypted, recipientEncryptionPrivateKey, allowed) }
        val h = opened.header()
        return OpenedCallback(
            CallbackHeader(h.fingerprint(), h.nonce(), h.state(), h.suite(), h.ephemeralPublicKey(), h.aeadNonce(), h.issuedAt(), h.expiresAt()),
            JCodec.encodeSignedLocalRpCallbackPayload(opened.signedPayload()),
        )
    }
}

/**
 * Verify a domain-signed callback payload envelope directly (design doc,
 * "Flow" step 13's key-lookup/revocation/signature/timestamp check),
 * independent of decryption -- used by conformance's `revocations.json`
 * "application case" to show a revocation certificate must be *applied*
 * to the fetched key set, not merely verified.
 */
object CallbackPayload {
    fun verifySignedEnvelope(
        payloadCbor: ByteArray,
        signingKeyId: String,
        signature: ByteArray,
        domainKeys: List<DomainPublicKey>,
        now: Instant,
        skewSeconds: Long,
    ) {
        val signed = JTypes.SignedLocalRpCallbackPayload(payloadCbor, signingKeyId, signature)
        runCatchingSdk { JLocalRp.verifyLocalRpCallbackPayload(signed, domainKeys.map { it.toJava() }, now, skewSeconds) }
    }
}

// -----------------------------------------------------------------------
// Sibling-signed key revocation certificates (revocations.json)
// -----------------------------------------------------------------------

/**
 * A sibling-signed key revocation certificate (design doc: extension landing
 * alongside local-RP; `crates/liblinkkeys/src/revocation.rs`).
 *
 * [revokedAt] is kept as the raw RFC3339 wire string, not [Instant]: it is
 * one of the exact bytes the revocation payload's signature covers
 * (`CBOR([tag, target_key_id, target_fingerprint, revoked_at, signing_domain])`
 * -- conformance README, "revocations.json"), so parsing it to an [Instant]
 * and reformatting would silently change its byte representation (e.g.
 * `+00:00` -> `Z`) and break every signature in the certificate. Everywhere
 * else in this package, timestamps that are pure verification *inputs* (not
 * re-signed bytes) use [Instant] for an idiomatic surface; this is the one
 * exception, and it is an exception for a correctness reason, not a
 * convenience one.
 */
data class RevocationCertificate(
    val targetKeyId: String,
    val targetFingerprint: String,
    val revokedAt: String,
    val signatures: List<ClaimSignature>,
)

private fun RevocationCertificate.toJava(): JTypes.RevocationCertificate =
    JTypes.RevocationCertificate(targetKeyId, targetFingerprint, revokedAt, signatures.map { it.toJava() })

/**
 * Verification of sibling-signed key revocation certificates against a
 * domain's public key set. Minimum quorum: [QUORUM] distinct signers.
 *
 * Only the pass/fail outcome ([verify]) is part of this SDK's public surface
 * -- the underlying dependency's per-signer counting helper is a
 * package-private white-box hook for its own test suite, matching the
 * conformance README's own framing ("Exact error *types* are intentionally
 * not part of the contract... only pass/fail is portable"); the same applies
 * one level deeper to internal signer-counting.
 */
object Revocations {
    /** Minimum number of distinct sibling signatures required to revoke a key. */
    val QUORUM: Int = JRevocation.QUORUM

    /** @throws LocalRpException.Revocation if fewer than [QUORUM] distinct valid signers are found. */
    fun verify(cert: RevocationCertificate, domainKeys: List<DomainPublicKey>, domain: String) {
        runCatchingSdk { JRevocation.verifyRevocationCertificate(cert.toJava(), domainKeys.map { it.toJava() }, domain) }
    }
}

// -----------------------------------------------------------------------
// DNS TXT record parsing (dns.json)
// -----------------------------------------------------------------------

/** A parsed `_linkkeys.{domain}` TXT record -- the trust anchor (pinned signing-key fingerprints). */
data class LinkKeysRecord(val fingerprints: List<String>)

/** A parsed `_linkkeys_apis.{domain}` TXT record -- service endpoints. */
data class LinkKeysApis(val tcp: String?, val httpsBase: String?)

/** DNS TXT record parsing for the two LinkKeys record types (design doc, "SDK endpoint discovery and pinning"). */
object DnsRecords {
    /** Default TCP port for the LinkKeys protocol service. Advertised `tcp=` values omit the port when it equals this. */
    val DEFAULT_TCP_PORT: Int = JDns.DEFAULT_TCP_PORT

    fun linkkeysDnsName(domain: String): String = JDns.linkkeysDnsName(domain)

    fun linkkeysApisDnsName(domain: String): String = JDns.linkkeysApisDnsName(domain)

    /** @throws LocalRpException.Dns if [txt] isn't a LinkKeys v1 record. */
    fun parseLinkKeysTxt(txt: String): LinkKeysRecord =
        runCatchingSdk { JDns.parseLinkKeysTxt(txt) }.let { LinkKeysRecord(it.fingerprints()) }

    /** @throws LocalRpException.Dns if [txt] isn't a LinkKeys v1 record, or carries no endpoint. */
    fun parseLinkKeysApisTxt(txt: String): LinkKeysApis =
        runCatchingSdk { JDns.parseLinkKeysApisTxt(txt) }.let { LinkKeysApis(it.tcp(), it.httpsBase()) }
}

// -----------------------------------------------------------------------
// URL parameter (base64url-unpadded) envelope encoding (url_params.json)
// -----------------------------------------------------------------------

/** The `SignedLocalRpLoginRequest` envelope: `{ request, signature }`. */
data class SignedLoginRequestEnvelope(val request: ByteArray, val signature: ByteArray)

/** The `LocalRpEncryptedCallback` envelope: `{ header, ciphertext }`. */
data class EncryptedCallbackEnvelope(val header: ByteArray, val ciphertext: ByteArray)

/**
 * URL parameter (base64url, unpadded) encoding for the two envelope structs
 * carried in URLs (design doc, Wire Precision: "URL and parameter
 * conventions"). [community.catalyst.linkkeys.localrp.kt.beginLocalLogin]
 * and [community.catalyst.linkkeys.localrp.kt.completeLocalLogin] already
 * apply this internally; these are exposed for conformance testing and
 * advanced interop.
 */
object UrlParams {
    fun encodeSignedLoginRequest(envelope: SignedLoginRequestEnvelope): String =
        JEncoding.signedLocalRpLoginRequestToUrlParam(JTypes.SignedLocalRpLoginRequest(envelope.request, envelope.signature))

    /** @throws LocalRpException.InvalidInput if [param] isn't valid unpadded base64url, or doesn't decode to a well-formed envelope. */
    fun decodeSignedLoginRequest(param: String): SignedLoginRequestEnvelope =
        runCatchingSdk { JEncoding.signedLocalRpLoginRequestFromUrlParam(param) }
            .let { SignedLoginRequestEnvelope(it.request(), it.signature()) }

    /** Decode the raw CSIL CBOR bytes of a `SignedLocalRpLoginRequest` (not base64url-wrapped) -- for byte-level conformance checks. */
    fun decodeSignedLoginRequestFromCbor(cbor: ByteArray): SignedLoginRequestEnvelope =
        JCodec.decodeSignedLocalRpLoginRequest(cbor).let { SignedLoginRequestEnvelope(it.request(), it.signature()) }

    fun encodeEncryptedCallback(envelope: EncryptedCallbackEnvelope): String =
        JEncoding.localRpEncryptedCallbackToUrlParam(JTypes.LocalRpEncryptedCallback(envelope.header, envelope.ciphertext))

    /** @throws LocalRpException.InvalidInput if [param] isn't valid unpadded base64url, or doesn't decode to a well-formed envelope. */
    fun decodeEncryptedCallback(param: String): EncryptedCallbackEnvelope =
        runCatchingSdk { JEncoding.localRpEncryptedCallbackFromUrlParam(param) }
            .let { EncryptedCallbackEnvelope(it.header(), it.ciphertext()) }

    /** Decode the raw CSIL CBOR bytes of a `LocalRpEncryptedCallback` (not base64url-wrapped) -- for byte-level conformance checks. */
    fun decodeEncryptedCallbackFromCbor(cbor: ByteArray): EncryptedCallbackEnvelope =
        JCodec.decodeLocalRpEncryptedCallback(cbor).let { EncryptedCallbackEnvelope(it.header(), it.ciphertext()) }
}

// -----------------------------------------------------------------------
// Claim wire encoding and claim-signature verification (claims.json)
// -----------------------------------------------------------------------

/**
 * A domain and the set of its currently-known public keys -- the resolved
 * input claim-signature verification needs per signing domain (a claim may
 * carry signatures from several distinct signing domains; every one of them
 * must be satisfied -- conformance README, "claims.json", "Verification
 * rules").
 */
data class ClaimDomainKeySet(val domain: String, val keys: List<DomainPublicKey>)

private fun ClaimDomainKeySet.toJava(): JClaims.DomainKeySet = JClaims.DomainKeySet(domain, keys.map { it.toJava() })

/**
 * CBOR wire encoding and signature verification for [Claim] (design doc,
 * Wire Precision: "claims.json") -- what
 * [community.catalyst.linkkeys.localrp.kt.completeLocalLogin] delivers to
 * app code inside
 * [community.catalyst.linkkeys.localrp.kt.VerifiedLocalLogin.claims].
 *
 * Every function here takes/returns raw CBOR bytes rather than the friendly
 * [Claim] Kotlin type (which represents `attested_at`/`created_at`/
 * `expires_at`/`revoked_at` as [Instant]). A claim signature covers the
 * *exact* RFC3339 strings that were signed; reading them through [Instant]
 * and reformatting (e.g. `+00:00` -> `Z`, as [formatRfc3339] does) would
 * silently produce different bytes than what was signed, breaking
 * verification of an otherwise-valid signature and byte-exactness of an
 * otherwise-correct re-encode -- the same reasoning documented on
 * [RevocationCertificate.revokedAt].
 */
object Claims {
    /** Decode a claim's raw CBOR wire bytes into this package's own [Claim] type, for reading field values. Not for re-signing/re-verifying -- see class docs. */
    fun decode(data: ByteArray): Claim = JCodec.decodeClaim(data).toKotlin()

    /** Decode then re-encode a claim's raw CBOR wire bytes -- for byte-exact wire round-trip conformance checks. */
    fun reencodeCbor(data: ByteArray): ByteArray = JCodec.encodeClaim(JCodec.decodeClaim(data))

    /**
     * Cryptographic per-domain quorum only (no revocation/expiry check on
     * the claim itself): every distinct domain among the claim's signatures
     * must contribute at least one signature verifying against a
     * currently-valid signing key of that domain. [subjectDomain] must come
     * from authoritative context (e.g. the callback payload's
     * `user_domain`), never attacker-controlled input.
     *
     * @throws LocalRpException.ClaimVerification
     */
    fun verifyClaimSignatures(claimCbor: ByteArray, subjectDomain: String, domainKeys: List<ClaimDomainKeySet>) {
        runCatchingSdk { JClaims.verifyClaimSignatures(JCodec.decodeClaim(claimCbor), subjectDomain, domainKeys.map { it.toJava() }) }
    }

    /** Full claim verification: the signature quorum above, plus the claim's own `revoked_at`/`expires_at`. @throws LocalRpException.ClaimVerification */
    fun verifyClaim(claimCbor: ByteArray, subjectDomain: String, domainKeys: List<ClaimDomainKeySet>) {
        runCatchingSdk { JClaims.verifyClaim(JCodec.decodeClaim(claimCbor), subjectDomain, domainKeys.map { it.toJava() }) }
    }
}

// -----------------------------------------------------------------------
// LocalRpTicketRedemptionResponse (claims.json's ticket_redemption_response)
// -----------------------------------------------------------------------

/** The full redeem-claim-ticket response -- the wire message [community.catalyst.linkkeys.localrp.kt.completeLocalLogin] actually consumes [Claim]s from. */
data class TicketRedemptionResponse(
    val userId: String,
    val userDomain: String,
    val claims: List<Claim>,
    val ticketExpiresAt: Instant,
)

/** CBOR wire encoding for [TicketRedemptionResponse]. See [Claims]' class docs for why byte-exact round-tripping and per-claim signature verification both work from raw CBOR bytes, not the friendly [Claim] type. */
object TicketRedemptionResponses {
    /** Decode into the friendly [TicketRedemptionResponse] view, for reading field values. */
    fun decode(data: ByteArray): TicketRedemptionResponse {
        val r = JCodec.decodeLocalRpTicketRedemptionResponse(data)
        return TicketRedemptionResponse(
            r.userId(),
            r.userDomain(),
            r.claims().map { it.toKotlin() },
            parseRfc3339("ticket_expires_at", r.ticketExpiresAt()),
        )
    }

    /** Decode then re-encode the whole response -- for byte-exact wire round-trip conformance checks. */
    fun reencodeCbor(data: ByteArray): ByteArray =
        JCodec.encodeLocalRpTicketRedemptionResponse(JCodec.decodeLocalRpTicketRedemptionResponse(data))

    /** The embedded claims' own raw CBOR wire bytes, in order -- pass each to [Claims.verifyClaim]/[Claims.verifyClaimSignatures] without a lossy round-trip through [Claim]'s [Instant] fields. */
    fun claimCborBytes(data: ByteArray): List<ByteArray> =
        JCodec.decodeLocalRpTicketRedemptionResponse(data).claims().map { JCodec.encodeClaim(it) }
}
