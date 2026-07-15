package community.catalyst.linkkeys.localrp.kt

import java.time.Instant
import community.catalyst.linkkeys.localrp.Complete as JComplete
import community.catalyst.linkkeys.localrp.LocalRp as JLocalRp

/**
 * What [completeLocalLogin] returns to app code (design doc: "SDK API
 * Shape", "Flow" step 13). This SDK returns verified protocol facts only --
 * session creation, local user records, and authorization are entirely the
 * app's responsibility (design doc: "SDKs must not own application storage,
 * sessions, database writes, or local user authorization").
 */
data class VerifiedLocalLogin(
    val userId: String,
    val userDomain: String,
    val claims: List<Claim>,
    val domainPublicKeys: List<DomainPublicKey>,
    val localRpFingerprint: String,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val ticketExpiresAt: Instant,
)

/** Bound on the number of distinct claim-signer domains [completeLocalLogin] will fetch keys for per completion (SSRF/DoS guard). */
val MAX_CLAIM_SIGNER_DOMAINS: Int = JComplete.MAX_CLAIM_SIGNER_DOMAINS

/**
 * `complete_local_login(config) -> VerifiedLocalLogin` (design doc: "SDK API
 * Shape", "Flow" steps 12-13). Runs the full verification chain, in order:
 *
 * 1. decode the callback ciphertext from its URL-param encoding
 * 2. open it (decrypt), restricted to a suite [identity]'s own descriptor advertises
 * 3. fetch [pending]'s domain's public keys + revocations, DNS-`fp=`-pinned, over TCP CSIL-RPC
 * 4. verify the domain-signed envelope (key lookup, revocation/expiry, signature, payload timestamp bounds)
 * 5. cross-check the cleartext header's routing fields against the now-verified payload
 * 6. audience / issuer / callback-URL / nonce-state checks
 * 7. redeem the claim ticket over TCP CSIL-RPC, signed with the local RP's own key (the possession proof)
 * 8. verify every returned claim's signatures against its signer domain's keys (fetched the same pinned way)
 *
 * @param pending the state [beginLocalLogin] returned, exactly as the app persisted it. Single-use: discard after this call.
 * @param encryptedToken the raw callback data -- the `encrypted_token` query-parameter value.
 * @param arrivedUrl the URL the callback actually arrived at (the app's own HTTP handler's request URL).
 * @param clockSkewSeconds bounded clock-skew tolerance for timestamp checks. Defaults to the design doc's ±300 seconds.
 * @param transport the TCP dial seam. Defaults to [defaultTransport].
 * @param dns the DNS TXT lookup seam. Defaults to [defaultDnsResolver].
 * @throws LocalRpException on any verification failure -- see the sealed hierarchy for the specific kind.
 */
fun completeLocalLogin(
    identity: LocalRpIdentity,
    pending: PendingLogin,
    encryptedToken: String,
    arrivedUrl: String,
    now: Instant,
    clockSkewSeconds: Long = JLocalRp.DEFAULT_CLOCK_SKEW_SECONDS,
    transport: Transport = defaultTransport(),
    dns: DnsResolver = defaultDnsResolver(),
): VerifiedLocalLogin {
    val config = JComplete.CompleteLocalLoginConfig(identity.javaMaterial, pending.javaPending, encryptedToken, arrivedUrl, now)
    config.clockSkewSeconds = clockSkewSeconds
    config.transport = transport
    config.dns = dns

    val result = runCatchingSdk { JComplete.completeLocalLogin(config) }
    return VerifiedLocalLogin(
        userId = result.userId(),
        userDomain = result.userDomain(),
        claims = result.claims().map { it.toKotlin() },
        domainPublicKeys = result.domainPublicKeys().map { it.toKotlin() },
        localRpFingerprint = result.localRpFingerprint(),
        issuedAt = result.issuedAt(),
        expiresAt = result.expiresAt(),
        ticketExpiresAt = result.ticketExpiresAt(),
    )
}
