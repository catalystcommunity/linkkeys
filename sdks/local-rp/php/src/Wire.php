<?php

declare(strict_types=1);

namespace LinkKeys\LocalRp;

use Csilgen\Generated\Claim;
use Csilgen\Generated\ClaimSignature;
use Csilgen\Generated\DomainPublicKey;
use Csilgen\Generated\EmptyRequest;
use Csilgen\Generated\GetDomainKeysResponse;
use Csilgen\Generated\GetRevocationsRequest;
use Csilgen\Generated\GetRevocationsResponse;
use Csilgen\Generated\LocalRpCallbackHeader;
use Csilgen\Generated\LocalRpCallbackPayload;
use Csilgen\Generated\LocalRpDescriptor;
use Csilgen\Generated\LocalRpEncryptedCallback;
use Csilgen\Generated\LocalRpLoginRequest;
use Csilgen\Generated\LocalRpTicketRedemptionRequest;
use Csilgen\Generated\LocalRpTicketRedemptionResponse;
use Csilgen\Generated\RevocationCertificate;
use Csilgen\Generated\SignedLocalRpCallbackPayload;
use Csilgen\Generated\SignedLocalRpDescriptor;
use Csilgen\Generated\SignedLocalRpLoginRequest;
use Csilgen\Generated\SignedLocalRpTicketRedemptionRequest;

/**
 * Hand-written CBOR (de)serialization for the CSIL wire structures this SDK
 * uses, working around the confirmed `php-typesonly`/`php-client` generated
 * `codec.php` bug described in {@see Cbor}'s docblock (every list field's
 * `array_map` closures reference an undefined `$var` instead of `$field`).
 * The generated `src/Generated/types.php` classes ARE used as-is here as
 * plain data holders — only their (de)serialization is hand-written.
 *
 * Field names/shapes are taken directly from `csil/linkkeys.csil` (via the
 * checked-in `src/Generated/types.php`) — this file is a correctness patch
 * for the codec, not an independent reinterpretation of the schema.
 */
final class Wire
{
    // -------------------------------------------------------------------
    // EmptyRequest
    // -------------------------------------------------------------------

    public static function encodeEmptyRequest(EmptyRequest $v): string
    {
        return Cbor::encodeMap([]);
    }

    public static function decodeEmptyRequest(string $bytes): EmptyRequest
    {
        Cbor::decode($bytes);
        return new EmptyRequest();
    }

    // -------------------------------------------------------------------
    // DomainPublicKey
    // -------------------------------------------------------------------

    public static function encodeDomainPublicKey(DomainPublicKey $v): string
    {
        return Cbor::encodeMap(self::domainPublicKeyToMap($v));
    }

    /** @return array<string,mixed> */
    private static function domainPublicKeyToMap(DomainPublicKey $v): array
    {
        $out = [
            'key_id' => $v->keyId,
            'public_key' => Cbor::bytes($v->publicKey),
            'fingerprint' => $v->fingerprint,
            'algorithm' => $v->algorithm,
            'key_usage' => $v->keyUsage,
            'created_at' => $v->createdAt,
            'expires_at' => $v->expiresAt,
        ];
        if ($v->revokedAt !== null) {
            $out['revoked_at'] = $v->revokedAt;
        }
        if ($v->signedByKeyId !== null) {
            $out['signed_by_key_id'] = $v->signedByKeyId;
        }
        if ($v->keySignature !== null) {
            $out['key_signature'] = Cbor::bytes($v->keySignature);
        }
        return $out;
    }

    public static function decodeDomainPublicKey(string $bytes): DomainPublicKey
    {
        return self::domainPublicKeyFromMap(Cbor::decode($bytes));
    }

    /** @param array<string,mixed> $m */
    private static function domainPublicKeyFromMap(array $m): DomainPublicKey
    {
        return new DomainPublicKey([
            'key_id' => $m['key_id'] ?? null,
            'public_key' => $m['public_key'] ?? null,
            'fingerprint' => $m['fingerprint'] ?? null,
            'algorithm' => $m['algorithm'] ?? null,
            'key_usage' => $m['key_usage'] ?? null,
            'created_at' => $m['created_at'] ?? null,
            'expires_at' => $m['expires_at'] ?? null,
            'revoked_at' => $m['revoked_at'] ?? null,
            'signed_by_key_id' => $m['signed_by_key_id'] ?? null,
            'key_signature' => $m['key_signature'] ?? null,
        ]);
    }

    // -------------------------------------------------------------------
    // GetDomainKeysResponse / GetRevocationsRequest / GetRevocationsResponse
    // -------------------------------------------------------------------

    public static function decodeGetDomainKeysResponse(string $bytes): GetDomainKeysResponse
    {
        $m = Cbor::decode($bytes);
        $keys = array_map(fn ($k) => self::domainPublicKeyFromMap($k), $m['keys'] ?? []);
        return new GetDomainKeysResponse([
            'domain' => $m['domain'] ?? null,
            'keys' => $keys,
            'recent_revocations_available' => $m['recent_revocations_available'] ?? null,
        ]);
    }

    public static function encodeGetRevocationsRequest(GetRevocationsRequest $v): string
    {
        $out = [];
        if ($v->since !== null) {
            $out['since'] = $v->since;
        }
        return Cbor::encodeMap($out);
    }

    public static function decodeGetRevocationsResponse(string $bytes): GetRevocationsResponse
    {
        $m = Cbor::decode($bytes);
        $revocations = array_map(fn ($r) => self::revocationCertificateFromMap($r), $m['revocations'] ?? []);
        return new GetRevocationsResponse(['revocations' => $revocations]);
    }

    // -------------------------------------------------------------------
    // ClaimSignature / RevocationCertificate / Claim
    // -------------------------------------------------------------------

    public static function encodeClaimSignature(ClaimSignature $v): array
    {
        // Field order matches `csil_enc_claim_signature` in
        // `crates/liblinkkeys/src/generated/codec.gen.rs` (domain, signature,
        // signed_by_key_id) — required for {@see self::encodeClaim} and
        // {@see self::encodeLocalRpTicketRedemptionResponse} to reproduce
        // `conformance/claims.json`'s wire bytes exactly; PHP array/map key
        // order is otherwise not wire-significant (see {@see Cbor}'s
        // docblock) but must still match a byte-exact conformance vector.
        return [
            'domain' => $v->domain,
            'signature' => Cbor::bytes($v->signature),
            'signed_by_key_id' => $v->signedByKeyId,
        ];
    }

    public static function claimSignatureFromMap(array $m): ClaimSignature
    {
        return new ClaimSignature([
            'domain' => $m['domain'] ?? null,
            'signed_by_key_id' => $m['signed_by_key_id'] ?? null,
            'signature' => $m['signature'] ?? null,
        ]);
    }

    public static function encodeRevocationCertificate(RevocationCertificate $v): string
    {
        return Cbor::encodeMap(self::revocationCertificateToMap($v));
    }

    /** @return array<string,mixed> */
    public static function revocationCertificateToMap(RevocationCertificate $v): array
    {
        return [
            'target_key_id' => $v->targetKeyId,
            'target_fingerprint' => $v->targetFingerprint,
            'revoked_at' => $v->revokedAt,
            'signatures' => array_map(fn ($s) => self::encodeClaimSignature($s), $v->signatures ?? []),
        ];
    }

    public static function decodeRevocationCertificate(string $bytes): RevocationCertificate
    {
        return self::revocationCertificateFromMap(Cbor::decode($bytes));
    }

    /** @param array<string,mixed> $m */
    public static function revocationCertificateFromMap(array $m): RevocationCertificate
    {
        $sigs = array_map(fn ($s) => self::claimSignatureFromMap($s), $m['signatures'] ?? []);
        return new RevocationCertificate([
            'target_key_id' => $m['target_key_id'] ?? null,
            'target_fingerprint' => $m['target_fingerprint'] ?? null,
            'revoked_at' => $m['revoked_at'] ?? null,
            'signatures' => $sigs,
        ]);
    }

    /**
     * `Claim.claim_value` is a CBOR byte string (bstr, major type 2) — never
     * text (tstr) — per `csil/linkkeys.csil` and
     * `conformance/claims.json`'s note (the file exists specifically to
     * catch a codec that treats the two as interchangeable, since a
     * bstr-as-tstr bug is self-consistent and invisible to an SDK's own
     * sign/verify round trip). {@see Cbor::decode}'s generic recursive
     * decode cannot make this distinction (both major types collapse to a
     * plain PHP `string`), so this uses {@see Cbor::decodeMapWithValueTypes}
     * to check the wire type explicitly and reject a text-encoded
     * `claim_value` outright (`claim_value_as_cbor_text_rejected`).
     */
    public static function decodeClaim(string $bytes): Claim
    {
        [$m, $types] = Cbor::decodeMapWithValueTypes($bytes);
        self::assertClaimValueIsBytes($types);
        return self::claimFromMap($m);
    }

    /** @param array<string,int> $types keyed as returned by Cbor::decodeMapWithValueTypes */
    private static function assertClaimValueIsBytes(array $types): void
    {
        if (($types['claim_value'] ?? null) !== 2) {
            throw new CborException('Claim.claim_value must be a CBOR byte string (bstr, major type 2), not text');
        }
    }

    /** @param array<string,mixed> $m */
    public static function claimFromMap(array $m): Claim
    {
        $sigs = array_map(fn ($s) => self::claimSignatureFromMap($s), $m['signatures'] ?? []);
        return new Claim([
            'claim_id' => $m['claim_id'] ?? null,
            'user_id' => $m['user_id'] ?? null,
            'claim_type' => $m['claim_type'] ?? null,
            'claim_value' => $m['claim_value'] ?? null,
            'signatures' => $sigs,
            'attested_at' => $m['attested_at'] ?? null,
            'created_at' => $m['created_at'] ?? null,
            'expires_at' => $m['expires_at'] ?? null,
            'revoked_at' => $m['revoked_at'] ?? null,
        ]);
    }

    public static function encodeClaim(Claim $v): string
    {
        return Cbor::encodeMap(self::claimToMap($v));
    }

    /** @return array<string,mixed> */
    private static function claimToMap(Claim $v): array
    {
        // Field order matches `csil_enc_claim` in
        // `crates/liblinkkeys/src/generated/codec.gen.rs`: user_id, claim_id,
        // claim_type, created_at, [expires_at], [revoked_at], signatures,
        // attested_at, claim_value — required for byte-exact re-encoding
        // against `conformance/claims.json`. `claim_value` is wrapped in
        // {@see Cbor::bytes} to force a CBOR byte string (major type 2); a
        // bare PHP string would encode as text (major type 3) — the exact
        // encoder-side trap `conformance/claims.json` exists to catch, since
        // PHP does not distinguish "text" from "bytes" at the string level.
        $out = [
            'user_id' => $v->userId,
            'claim_id' => $v->claimId,
            'claim_type' => $v->claimType,
            'created_at' => $v->createdAt,
        ];
        if ($v->expiresAt !== null) {
            $out['expires_at'] = $v->expiresAt;
        }
        if ($v->revokedAt !== null) {
            $out['revoked_at'] = $v->revokedAt;
        }
        $out['signatures'] = array_map(fn ($s) => self::encodeClaimSignature($s), $v->signatures ?? []);
        $out['attested_at'] = $v->attestedAt;
        $out['claim_value'] = Cbor::bytes($v->claimValue);
        return $out;
    }

    // -------------------------------------------------------------------
    // Local RP descriptor
    // -------------------------------------------------------------------

    public static function encodeLocalRpDescriptor(LocalRpDescriptor $v): string
    {
        $out = [
            'app_name' => $v->appName,
        ];
        if ($v->localDomainHint !== null) {
            $out['local_domain_hint'] = $v->localDomainHint;
        }
        $out['signing_public_key'] = Cbor::bytes($v->signingPublicKey);
        $out['encryption_public_key'] = Cbor::bytes($v->encryptionPublicKey);
        $out['fingerprint'] = $v->fingerprint;
        $out['supported_suites'] = $v->supportedSuites ?? [];
        $out['created_at'] = $v->createdAt;
        $out['expires_at'] = $v->expiresAt;
        return Cbor::encodeMap($out);
    }

    public static function decodeLocalRpDescriptor(string $bytes): LocalRpDescriptor
    {
        $m = Cbor::decode($bytes);
        return new LocalRpDescriptor([
            'app_name' => $m['app_name'] ?? null,
            'local_domain_hint' => $m['local_domain_hint'] ?? null,
            'signing_public_key' => $m['signing_public_key'] ?? null,
            'encryption_public_key' => $m['encryption_public_key'] ?? null,
            'fingerprint' => $m['fingerprint'] ?? null,
            'supported_suites' => $m['supported_suites'] ?? [],
            'created_at' => $m['created_at'] ?? null,
            'expires_at' => $m['expires_at'] ?? null,
        ]);
    }

    public static function encodeSignedLocalRpDescriptor(SignedLocalRpDescriptor $v): string
    {
        return Cbor::encodeMap([
            'descriptor' => Cbor::bytes($v->descriptor),
            'signature' => Cbor::bytes($v->signature),
        ]);
    }

    public static function decodeSignedLocalRpDescriptor(string $bytes): SignedLocalRpDescriptor
    {
        $m = Cbor::decode($bytes);
        return new SignedLocalRpDescriptor([
            'descriptor' => $m['descriptor'] ?? null,
            'signature' => $m['signature'] ?? null,
        ]);
    }

    // -------------------------------------------------------------------
    // Login request
    // -------------------------------------------------------------------

    public static function encodeLocalRpLoginRequest(LocalRpLoginRequest $v): string
    {
        $out = [
            'descriptor' => self::signedLocalRpDescriptorToMap($v->descriptor),
            'callback_url' => $v->callbackUrl,
            'nonce' => Cbor::bytes($v->nonce),
            'state' => Cbor::bytes($v->state),
            'requested_claims' => $v->requestedClaims ?? [],
            'required_claims' => $v->requiredClaims ?? [],
            'issued_at' => $v->issuedAt,
            'expires_at' => $v->expiresAt,
        ];
        return Cbor::encodeMap($out);
    }

    /** @return array<string,mixed> */
    private static function signedLocalRpDescriptorToMap(SignedLocalRpDescriptor $v): array
    {
        return [
            'descriptor' => Cbor::bytes($v->descriptor),
            'signature' => Cbor::bytes($v->signature),
        ];
    }

    public static function decodeLocalRpLoginRequest(string $bytes): LocalRpLoginRequest
    {
        $m = Cbor::decode($bytes);
        $descMap = $m['descriptor'] ?? [];
        $descriptor = new SignedLocalRpDescriptor([
            'descriptor' => $descMap['descriptor'] ?? null,
            'signature' => $descMap['signature'] ?? null,
        ]);
        return new LocalRpLoginRequest([
            'descriptor' => $descriptor,
            'callback_url' => $m['callback_url'] ?? null,
            'nonce' => $m['nonce'] ?? null,
            'state' => $m['state'] ?? null,
            'requested_claims' => $m['requested_claims'] ?? [],
            'required_claims' => $m['required_claims'] ?? [],
            'issued_at' => $m['issued_at'] ?? null,
            'expires_at' => $m['expires_at'] ?? null,
        ]);
    }

    public static function encodeSignedLocalRpLoginRequest(SignedLocalRpLoginRequest $v): string
    {
        return Cbor::encodeMap([
            'request' => Cbor::bytes($v->request),
            'signature' => Cbor::bytes($v->signature),
        ]);
    }

    public static function decodeSignedLocalRpLoginRequest(string $bytes): SignedLocalRpLoginRequest
    {
        $m = Cbor::decode($bytes);
        return new SignedLocalRpLoginRequest([
            'request' => $m['request'] ?? null,
            'signature' => $m['signature'] ?? null,
        ]);
    }

    // -------------------------------------------------------------------
    // Callback header / encrypted envelope / payload
    // -------------------------------------------------------------------

    public static function encodeLocalRpCallbackHeader(LocalRpCallbackHeader $v): string
    {
        return Cbor::encodeMap([
            'fingerprint' => $v->fingerprint,
            'nonce' => Cbor::bytes($v->nonce),
            'state' => Cbor::bytes($v->state),
            'suite' => $v->suite,
            'ephemeral_public_key' => Cbor::bytes($v->ephemeralPublicKey),
            'aead_nonce' => Cbor::bytes($v->aeadNonce),
            'issued_at' => $v->issuedAt,
            'expires_at' => $v->expiresAt,
        ]);
    }

    public static function decodeLocalRpCallbackHeader(string $bytes): LocalRpCallbackHeader
    {
        $m = Cbor::decode($bytes);
        return new LocalRpCallbackHeader([
            'fingerprint' => $m['fingerprint'] ?? null,
            'nonce' => $m['nonce'] ?? null,
            'state' => $m['state'] ?? null,
            'suite' => $m['suite'] ?? null,
            'ephemeral_public_key' => $m['ephemeral_public_key'] ?? null,
            'aead_nonce' => $m['aead_nonce'] ?? null,
            'issued_at' => $m['issued_at'] ?? null,
            'expires_at' => $m['expires_at'] ?? null,
        ]);
    }

    public static function encodeLocalRpEncryptedCallback(LocalRpEncryptedCallback $v): string
    {
        return Cbor::encodeMap([
            'header' => Cbor::bytes($v->header),
            'ciphertext' => Cbor::bytes($v->ciphertext),
        ]);
    }

    public static function decodeLocalRpEncryptedCallback(string $bytes): LocalRpEncryptedCallback
    {
        $m = Cbor::decode($bytes);
        return new LocalRpEncryptedCallback([
            'header' => $m['header'] ?? null,
            'ciphertext' => $m['ciphertext'] ?? null,
        ]);
    }

    public static function encodeLocalRpCallbackPayload(LocalRpCallbackPayload $v): string
    {
        return Cbor::encodeMap([
            'user_id' => $v->userId,
            'user_domain' => $v->userDomain,
            'claim_ticket' => Cbor::bytes($v->claimTicket),
            'audience_fingerprint' => $v->audienceFingerprint,
            'callback_url' => $v->callbackUrl,
            'nonce' => Cbor::bytes($v->nonce),
            'state' => Cbor::bytes($v->state),
            'issued_at' => $v->issuedAt,
            'expires_at' => $v->expiresAt,
        ]);
    }

    public static function decodeLocalRpCallbackPayload(string $bytes): LocalRpCallbackPayload
    {
        $m = Cbor::decode($bytes);
        return new LocalRpCallbackPayload([
            'user_id' => $m['user_id'] ?? null,
            'user_domain' => $m['user_domain'] ?? null,
            'claim_ticket' => $m['claim_ticket'] ?? null,
            'audience_fingerprint' => $m['audience_fingerprint'] ?? null,
            'callback_url' => $m['callback_url'] ?? null,
            'nonce' => $m['nonce'] ?? null,
            'state' => $m['state'] ?? null,
            'issued_at' => $m['issued_at'] ?? null,
            'expires_at' => $m['expires_at'] ?? null,
        ]);
    }

    public static function encodeSignedLocalRpCallbackPayload(SignedLocalRpCallbackPayload $v): string
    {
        return Cbor::encodeMap(self::signedLocalRpCallbackPayloadToMap($v));
    }

    /** @return array<string,mixed> */
    private static function signedLocalRpCallbackPayloadToMap(SignedLocalRpCallbackPayload $v): array
    {
        return [
            'payload' => Cbor::bytes($v->payload),
            'signing_key_id' => $v->signingKeyId,
            'signature' => Cbor::bytes($v->signature),
        ];
    }

    public static function decodeSignedLocalRpCallbackPayload(string $bytes): SignedLocalRpCallbackPayload
    {
        $m = Cbor::decode($bytes);
        return new SignedLocalRpCallbackPayload([
            'payload' => $m['payload'] ?? null,
            'signing_key_id' => $m['signing_key_id'] ?? null,
            'signature' => $m['signature'] ?? null,
        ]);
    }

    // -------------------------------------------------------------------
    // Ticket redemption
    // -------------------------------------------------------------------

    public static function encodeLocalRpTicketRedemptionRequest(LocalRpTicketRedemptionRequest $v): string
    {
        return Cbor::encodeMap([
            'claim_ticket' => Cbor::bytes($v->claimTicket),
            'fingerprint' => $v->fingerprint,
            'issued_at' => $v->issuedAt,
        ]);
    }

    public static function decodeLocalRpTicketRedemptionRequest(string $bytes): LocalRpTicketRedemptionRequest
    {
        $m = Cbor::decode($bytes);
        return new LocalRpTicketRedemptionRequest([
            'claim_ticket' => $m['claim_ticket'] ?? null,
            'fingerprint' => $m['fingerprint'] ?? null,
            'issued_at' => $m['issued_at'] ?? null,
        ]);
    }

    public static function encodeSignedLocalRpTicketRedemptionRequest(SignedLocalRpTicketRedemptionRequest $v): string
    {
        return Cbor::encodeMap(self::signedLocalRpTicketRedemptionRequestToMap($v));
    }

    /** @return array<string,mixed> */
    public static function signedLocalRpTicketRedemptionRequestToMap(SignedLocalRpTicketRedemptionRequest $v): array
    {
        return [
            'request' => Cbor::bytes($v->request),
            'signature' => Cbor::bytes($v->signature),
        ];
    }

    public static function decodeSignedLocalRpTicketRedemptionRequest(string $bytes): SignedLocalRpTicketRedemptionRequest
    {
        $m = Cbor::decode($bytes);
        return new SignedLocalRpTicketRedemptionRequest([
            'request' => $m['request'] ?? null,
            'signature' => $m['signature'] ?? null,
        ]);
    }

    /**
     * `LocalRpTicketRedemptionResponse` is the wire message that actually
     * carries `Claim`s to `completeLocalLogin` (design doc; the response to
     * redeeming a claim ticket) — a home IDP that emits a text-typed
     * `claim_value` for one embedded claim is exactly as non-conformant as
     * one that does it for a standalone {@see self::decodeClaim}, so each
     * `claims[]` entry is re-decoded through {@see self::decodeClaim} off
     * its own exact byte span (via {@see Cbor::decodeArraySpans}) rather
     * than through the generic, type-collapsing {@see Cbor::decode} — this
     * keeps the same bstr-not-tstr enforcement on the path
     * `Complete::completeLocalLogin` actually uses at runtime.
     */
    public static function decodeLocalRpTicketRedemptionResponse(string $bytes): LocalRpTicketRedemptionResponse
    {
        [$m, , $spans] = Cbor::decodeMapWithValueTypes($bytes);
        $claimSpans = isset($spans['claims']) ? Cbor::decodeArraySpans($spans['claims']) : [];
        $claims = array_map(fn ($span) => self::decodeClaim($span), $claimSpans);
        return new LocalRpTicketRedemptionResponse([
            'user_id' => $m['user_id'] ?? null,
            'user_domain' => $m['user_domain'] ?? null,
            'claims' => $claims,
            'ticket_expires_at' => $m['ticket_expires_at'] ?? null,
        ]);
    }

    public static function encodeLocalRpTicketRedemptionResponse(LocalRpTicketRedemptionResponse $v): string
    {
        // Field order matches `csil_enc_local_rp_ticket_redemption_response`
        // in `crates/liblinkkeys/src/generated/codec.gen.rs`.
        return Cbor::encodeMap([
            'claims' => array_map(fn ($c) => self::claimToMap($c), $v->claims ?? []),
            'user_id' => $v->userId,
            'user_domain' => $v->userDomain,
            'ticket_expires_at' => $v->ticketExpiresAt,
        ]);
    }
}
