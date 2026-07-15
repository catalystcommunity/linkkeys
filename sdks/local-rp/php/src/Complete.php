<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\Claim;
use Csilgen\Generated\DomainPublicKey;

/**
 * `completeLocalLogin` (design doc: "SDK API Shape", "Flow" steps 12-13).
 *
 * This is the SDK's full verification chain, run in the exact order the
 * pure {@see LocalRp} helpers require:
 *
 * 1. decode the callback ciphertext from its URL-param encoding
 * 2. open it (decrypt) — only with a suite this identity's own descriptor
 *    advertises
 * 3. fetch the pending domain's public keys + revocations, DNS-`fp=`-pinned,
 *    over TCP CSIL-RPC
 * 4. verify the domain-signed envelope (key lookup, revocation/expiry,
 *    signature, payload timestamp bounds) — only now is anything inside the
 *    payload trusted
 * 5. cross-check the cleartext header's routing fields against the
 *    now-verified payload
 * 6. audience / issuer / callback-URL / nonce-state checks
 * 7. redeem the claim ticket over TCP CSIL-RPC (signed with the local RP's
 *    own key — the possession proof)
 * 8. verify every returned claim's signatures against ITS signer domain's
 *    keys (fetched the same pinned way), which also checks the claim's own
 *    revocation/expiry
 */
final class Complete
{
    /**
     * Bound on the number of distinct claim-signer domains
     * {@see self::completeLocalLogin} will fetch keys for per completion —
     * a malicious/compromised home IDP could otherwise list an unbounded
     * number of distinct "signer domains" purely to make this SDK perform
     * many outbound DNS/TCP calls to attacker-chosen targets before any
     * signature is actually checked (an SSRF/DoS amplification vector
     * against the app's own process).
     */
    private const MAX_CLAIM_SIGNER_DOMAINS = 8;

    public static function completeLocalLogin(CompleteLocalLoginConfig $config): VerifiedLocalLogin
    {
        $skew = $config->clockSkewSeconds ?? LocalRp::DEFAULT_CLOCK_SKEW_SECONDS;

        // 1. Decode the callback's URL-param encoding.
        $encrypted = Encoding::localRpEncryptedCallbackFromUrlParam($config->encryptedToken);

        // 2. Open it, restricted to suites THIS identity's own descriptor
        // advertises.
        $ownDescriptor = Wire::decodeLocalRpDescriptor($config->keyMaterial->descriptor->descriptor);
        $allowedSuites = [];
        foreach ($ownDescriptor->supportedSuites as $s) {
            $parsed = Crypto::parseAeadSuite($s);
            if ($parsed !== null) {
                $allowedSuites[] = $parsed;
            }
        }
        [$header, $signedPayload] = LocalRp::openLocalRpCallback($encrypted, $config->keyMaterial->encryptionPrivateKey, $allowedSuites);

        // 3. Fetch the PENDING state's domain's keys + revocations,
        // DNS-pinned, over TCP CSIL-RPC.
        $userDomainKeys = Rpc::fetchDomainKeys($config->transport, $config->dns, $config->pending->userDomain, $config->now);

        // 4. Verify the domain-signed envelope against those keys. Nothing
        // inside `$payload` is trusted before this succeeds.
        $payload = LocalRp::verifyLocalRpCallbackPayload($signedPayload, $userDomainKeys, $config->now, $skew);

        // 5. Cross-check the cleartext header's routing twins against the
        // now-verified payload.
        LocalRp::checkCallbackHeaderMatchesPayload($header, $payload);

        // 6a. Audience: the callback names THIS local RP.
        LocalRp::verifyAudience($payload->audienceFingerprint, $config->keyMaterial->fingerprint);

        // 6b. Issuer binding: the payload's user_domain must be the domain
        // the login was BEGUN with.
        LocalRp::verifyIssuer($payload->userDomain, $config->pending->userDomain);

        // 6c. Callback URL binding against the URL the callback actually
        // arrived at.
        $arrivedBaseUrl = self::stripEncryptedTokenParam($config->arrivedUrl);
        LocalRp::verifyCallbackUrl($payload->callbackUrl, $arrivedBaseUrl);

        // 6d. Nonce/state equality against the pending state.
        LocalRp::verifyNonceState($config->pending->nonce, $config->pending->state, $payload->nonce, $payload->state);

        // 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the
        // local RP's own key.
        $redemptionRequest = LocalRp::buildLocalRpTicketRedemptionRequest(
            $payload->claimTicket,
            $config->keyMaterial->fingerprint,
            Time::toRfc3339($config->now)
        );
        $signedRedemption = LocalRp::signLocalRpTicketRedemptionRequest($redemptionRequest, $config->keyMaterial->signingPrivateKey);
        $redemption = Rpc::redeemClaimTicket($config->transport, $config->dns, $config->pending->userDomain, $signedRedemption);

        // 7a. The ticket-redemption response CORROBORATES the verified
        // payload's identity — it never supplies it. The redemption
        // response is unsigned wire data; a mismatch here means the IDP
        // (or a MITM of the unauthenticated-TLS redemption call) is trying
        // to attach a different user's claims to this login. Fatal.
        if ($redemption->userId !== $payload->userId || $redemption->userDomain !== $payload->userDomain) {
            throw new LocalRpError(LocalRpError::REDEMPTION_IDENTITY_MISMATCH);
        }

        // 8. Verify every returned claim's signatures against ITS signer
        // domain's keys, fetched the same pinned way, capped at
        // MAX_CLAIM_SIGNER_DOMAINS distinct signer domains. The VERIFIED
        // payload's user_domain (never the redemption's) is the
        // subject-domain for every per-claim signature check.
        $domainKeySets = [new DomainKeySet($config->pending->userDomain, $userDomainKeys)];
        foreach ($redemption->claims as $claim) {
            foreach ($claim->signatures as $sig) {
                $known = false;
                foreach ($domainKeySets as $s) {
                    if ($s->domain === $sig->domain) {
                        $known = true;
                        break;
                    }
                }
                if (!$known) {
                    if (count($domainKeySets) >= self::MAX_CLAIM_SIGNER_DOMAINS) {
                        throw new \InvalidArgumentException(
                            'claim set names more than ' . self::MAX_CLAIM_SIGNER_DOMAINS . ' distinct signer domains; refusing to fetch further keys'
                        );
                    }
                    $keys = Rpc::fetchDomainKeys($config->transport, $config->dns, $sig->domain, $config->now);
                    $domainKeySets[] = new DomainKeySet($sig->domain, $keys);
                }
            }
        }
        $verifiedClaimTypes = [];
        foreach ($redemption->claims as $claim) {
            // 8a. Claim ownership: every returned claim must belong to the
            // verified payload's user, not merely to SOME user the IDP
            // decided to attach. Fatal on mismatch.
            if ($claim->userId !== $payload->userId) {
                throw new LocalRpError(LocalRpError::CLAIM_OWNERSHIP_MISMATCH);
            }
            Claims::verifyClaim($claim, $payload->userDomain, $domainKeySets, $config->now);
            $verifiedClaimTypes[] = $claim->claimType;
        }

        // 8b. required_claims enforcement: every claim type the app asked
        // to be required at begin_local_login time must appear among the
        // claims that just passed full signature verification above. An
        // empty or insufficient claim set when required_claims is
        // non-empty is fatal, never a silent partial success.
        foreach ($config->pending->requiredClaims as $requiredType) {
            if (!in_array($requiredType, $verifiedClaimTypes, true)) {
                throw new LocalRpError(LocalRpError::REQUIRED_CLAIMS_NOT_SATISFIED, $requiredType);
            }
        }

        // 8c. The verified identity returned to app code comes from the
        // SIGNED, envelope-verified, issuer-bound callback payload — never
        // from the unsigned ticket-redemption response (which was only
        // used above to corroborate, not supply, this identity).
        return new VerifiedLocalLogin(
            $payload->userId,
            $payload->userDomain,
            $redemption->claims,
            $userDomainKeys,
            $config->keyMaterial->fingerprint,
            Time::parseRfc3339($payload->issuedAt),
            Time::parseRfc3339($payload->expiresAt),
            Time::parseRfc3339($redemption->ticketExpiresAt)
        );
    }

    /**
     * Undo the exact `?`/`&` + `encrypted_token=` suffix construction the
     * server uses to deliver the callback, so the recovered value can be
     * compared against the signed payload's `callback_url`. If the arrived
     * URL doesn't end with that exact suffix, returns it unchanged — the
     * subsequent {@see LocalRp::verifyCallbackUrl} equality check then
     * correctly fails closed rather than this function guessing.
     */
    public static function stripEncryptedTokenParam(string $arrivedUrl): string
    {
        foreach (['?', '&'] as $sep) {
            $marker = "{$sep}encrypted_token=";
            $idx = strrpos($arrivedUrl, $marker);
            if ($idx !== false) {
                return substr($arrivedUrl, 0, $idx);
            }
        }
        return $arrivedUrl;
    }
}

/** Input to {@see Complete::completeLocalLogin}. Every field is load-bearing. */
final class CompleteLocalLoginConfig
{
    public LocalRpKeyMaterial $keyMaterial;
    public PendingLogin $pending;
    public string $encryptedToken;
    public string $arrivedUrl;
    public \DateTimeImmutable $now;
    public ?int $clockSkewSeconds;
    public Transport $transport;
    public DnsResolver $dns;

    public function __construct(
        LocalRpKeyMaterial $keyMaterial,
        PendingLogin $pending,
        string $encryptedToken,
        string $arrivedUrl,
        \DateTimeImmutable $now,
        ?Transport $transport = null,
        ?DnsResolver $dns = null,
        ?int $clockSkewSeconds = null
    ) {
        $this->keyMaterial = $keyMaterial;
        $this->pending = $pending;
        $this->encryptedToken = $encryptedToken;
        $this->arrivedUrl = $arrivedUrl;
        $this->now = $now;
        $this->clockSkewSeconds = $clockSkewSeconds;
        $this->transport = $transport ?? new StdTransport();
        $this->dns = $dns ?? new SystemDnsResolver();
    }
}

/** What `completeLocalLogin` returns to app code. */
final class VerifiedLocalLogin
{
    public string $userId;
    public string $userDomain;
    /** @var Claim[] Verified claim values, current as of ticket redemption. */
    public array $claims;
    /** @var DomainPublicKey[] The user's home domain's public keys used to verify the callback envelope. */
    public array $domainPublicKeys;
    public string $localRpFingerprint;
    public \DateTimeImmutable $issuedAt;
    public \DateTimeImmutable $expiresAt;
    public \DateTimeImmutable $ticketExpiresAt;

    /**
     * @param Claim[] $claims
     * @param DomainPublicKey[] $domainPublicKeys
     */
    public function __construct(
        string $userId,
        string $userDomain,
        array $claims,
        array $domainPublicKeys,
        string $localRpFingerprint,
        \DateTimeImmutable $issuedAt,
        \DateTimeImmutable $expiresAt,
        \DateTimeImmutable $ticketExpiresAt
    ) {
        $this->userId = $userId;
        $this->userDomain = $userDomain;
        $this->claims = $claims;
        $this->domainPublicKeys = $domainPublicKeys;
        $this->localRpFingerprint = $localRpFingerprint;
        $this->issuedAt = $issuedAt;
        $this->expiresAt = $expiresAt;
        $this->ticketExpiresAt = $ticketExpiresAt;
    }
}
