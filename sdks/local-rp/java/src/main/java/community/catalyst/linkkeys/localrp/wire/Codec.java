package community.catalyst.linkkeys.localrp.wire;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import community.catalyst.linkkeys.localrp.wire.Cbor.Entry;
import community.catalyst.linkkeys.localrp.wire.Cbor.Value;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsCredential;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsGrant;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsGrantRequest;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsPresentation;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsRefreshRequest;
import community.catalyst.linkkeys.localrp.wire.Types.ApplicationKeySignature;
import community.catalyst.linkkeys.localrp.wire.Types.ApplicationRef;
import community.catalyst.linkkeys.localrp.wire.Types.Claim;
import community.catalyst.linkkeys.localrp.wire.Types.ClaimSignature;
import community.catalyst.linkkeys.localrp.wire.Types.DomainPublicKey;
import community.catalyst.linkkeys.localrp.wire.Types.EmptyRequest;
import community.catalyst.linkkeys.localrp.wire.Types.GetDomainKeysResponse;
import community.catalyst.linkkeys.localrp.wire.Types.GetRevocationsRequest;
import community.catalyst.linkkeys.localrp.wire.Types.GetRevocationsResponse;
import community.catalyst.linkkeys.localrp.wire.Types.GranteeProof;
import community.catalyst.linkkeys.localrp.wire.Types.GranteeRef;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpCallbackHeader;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpCallbackPayload;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpDescriptor;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpEncryptedCallback;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpLoginRequest;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpTicketRedemptionRequest;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpTicketRedemptionResponse;
import community.catalyst.linkkeys.localrp.wire.Types.RefreshActAsGrantRequest;
import community.catalyst.linkkeys.localrp.wire.Types.RefreshActAsGrantResponse;
import community.catalyst.linkkeys.localrp.wire.Types.RevocationCertificate;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsGrant;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsGrantRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsPresentation;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsRefreshRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsScopeSet;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpCallbackPayload;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpDescriptor;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpLoginRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpTicketRedemptionRequest;

/**
 * Canonical CSIL CBOR encode/decode for every {@link Types} wire structure
 * this SDK needs. <b>Hand-written, pending a csilgen Java target</b> &mdash;
 * see {@link Cbor}'s class docs. Field order within each map is irrelevant
 * (the {@link Cbor} encoder always sorts to RFC 8949 canonical order), so
 * this file lists fields in natural struct order rather than hand-tracking
 * the canonical order the Go/Rust generators bake in at codegen time.
 */
public final class Codec {
    private Codec() {}

    // -----------------------------------------------------------------
    // EmptyRequest
    // -----------------------------------------------------------------

    public static byte[] encodeEmptyRequest(EmptyRequest v) {
        return Cbor.encode(Cbor.vmap(new ArrayList<>()));
    }

    public static EmptyRequest decodeEmptyRequest(byte[] data) {
        Cbor.decode(data);
        return new EmptyRequest();
    }

    // -----------------------------------------------------------------
    // DomainPublicKey
    // -----------------------------------------------------------------

    static Value encDomainPublicKey(DomainPublicKey v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "key_id", v.keyId());
        Cbor.putBytes(e, "public_key", v.publicKey());
        Cbor.putText(e, "fingerprint", v.fingerprint());
        Cbor.putText(e, "algorithm", v.algorithm());
        Cbor.putText(e, "key_usage", v.keyUsage());
        Cbor.putText(e, "created_at", v.createdAt());
        Cbor.putText(e, "expires_at", v.expiresAt());
        Cbor.putOptText(e, "revoked_at", v.revokedAt());
        Cbor.putOptText(e, "signed_by_key_id", v.signedByKeyId());
        Cbor.putOptBytes(e, "key_signature", v.keySignature());
        return Cbor.vmap(e);
    }

    static DomainPublicKey decDomainPublicKey(Value m) {
        return new DomainPublicKey(
                Cbor.requireText(m, "key_id"),
                Cbor.requireBytes(m, "public_key"),
                Cbor.requireText(m, "fingerprint"),
                Cbor.requireText(m, "algorithm"),
                Cbor.requireText(m, "key_usage"),
                Cbor.requireText(m, "created_at"),
                Cbor.requireText(m, "expires_at"),
                Cbor.optText(m, "revoked_at"),
                Cbor.optText(m, "signed_by_key_id"),
                Cbor.optBytes(m, "key_signature"));
    }

    public static byte[] encodeDomainPublicKey(DomainPublicKey v) {
        return Cbor.encode(encDomainPublicKey(v));
    }

    public static DomainPublicKey decodeDomainPublicKey(byte[] data) {
        return decDomainPublicKey(Cbor.decode(data));
    }

    // -----------------------------------------------------------------
    // GetDomainKeysResponse
    // -----------------------------------------------------------------

    public static byte[] encodeGetDomainKeysResponse(GetDomainKeysResponse v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "domain", v.domain());
        e.add(Cbor.entry("keys", encArray(v.keys(), Codec::encDomainPublicKey)));
        Cbor.putOptBool(e, "recent_revocations_available", v.recentRevocationsAvailable());
        return Cbor.encode(Cbor.vmap(e));
    }

    public static GetDomainKeysResponse decodeGetDomainKeysResponse(byte[] data) {
        Value m = Cbor.decode(data);
        return new GetDomainKeysResponse(
                Cbor.requireText(m, "domain"),
                decArray(Cbor.require(m, "keys"), Codec::decDomainPublicKey),
                Cbor.optBool(m, "recent_revocations_available"));
    }

    // -----------------------------------------------------------------
    // GetRevocationsRequest / GetRevocationsResponse
    // -----------------------------------------------------------------

    public static byte[] encodeGetRevocationsRequest(GetRevocationsRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putOptText(e, "since", v.since());
        return Cbor.encode(Cbor.vmap(e));
    }

    public static GetRevocationsRequest decodeGetRevocationsRequest(byte[] data) {
        Value m = Cbor.decode(data);
        return new GetRevocationsRequest(Cbor.optText(m, "since"));
    }

    static Value encClaimSignature(ClaimSignature v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "domain", v.domain());
        Cbor.putText(e, "signed_by_key_id", v.signedByKeyId());
        Cbor.putBytes(e, "signature", v.signature());
        return Cbor.vmap(e);
    }

    static ClaimSignature decClaimSignature(Value m) {
        return new ClaimSignature(
                Cbor.requireText(m, "domain"),
                Cbor.requireText(m, "signed_by_key_id"),
                Cbor.requireBytes(m, "signature"));
    }

    static Value encRevocationCertificate(RevocationCertificate v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "target_key_id", v.targetKeyId());
        Cbor.putText(e, "target_fingerprint", v.targetFingerprint());
        Cbor.putText(e, "revoked_at", v.revokedAt());
        e.add(Cbor.entry("signatures", encArray(v.signatures(), Codec::encClaimSignature)));
        return Cbor.vmap(e);
    }

    static RevocationCertificate decRevocationCertificate(Value m) {
        return new RevocationCertificate(
                Cbor.requireText(m, "target_key_id"),
                Cbor.requireText(m, "target_fingerprint"),
                Cbor.requireText(m, "revoked_at"),
                decArray(Cbor.require(m, "signatures"), Codec::decClaimSignature));
    }

    public static byte[] encodeGetRevocationsResponse(GetRevocationsResponse v) {
        List<Entry> e = new ArrayList<>();
        e.add(Cbor.entry("revocations", encArray(v.revocations(), Codec::encRevocationCertificate)));
        return Cbor.encode(Cbor.vmap(e));
    }

    public static GetRevocationsResponse decodeGetRevocationsResponse(byte[] data) {
        Value m = Cbor.decode(data);
        return new GetRevocationsResponse(
                decArray(Cbor.require(m, "revocations"), Codec::decRevocationCertificate));
    }

    // -----------------------------------------------------------------
    // Claim
    // -----------------------------------------------------------------

    static Value encClaim(Claim v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "claim_id", v.claimId());
        Cbor.putText(e, "user_id", v.userId());
        Cbor.putText(e, "claim_type", v.claimType());
        Cbor.putBytes(e, "claim_value", v.claimValue());
        e.add(Cbor.entry("signatures", encArray(v.signatures(), Codec::encClaimSignature)));
        Cbor.putText(e, "attested_at", v.attestedAt());
        Cbor.putText(e, "created_at", v.createdAt());
        Cbor.putOptText(e, "expires_at", v.expiresAt());
        Cbor.putOptText(e, "revoked_at", v.revokedAt());
        return Cbor.vmap(e);
    }

    static Claim decClaim(Value m) {
        return new Claim(
                Cbor.requireText(m, "claim_id"),
                Cbor.requireText(m, "user_id"),
                Cbor.requireText(m, "claim_type"),
                Cbor.requireBytes(m, "claim_value"),
                decArray(Cbor.require(m, "signatures"), Codec::decClaimSignature),
                Cbor.requireText(m, "attested_at"),
                Cbor.requireText(m, "created_at"),
                Cbor.optText(m, "expires_at"),
                Cbor.optText(m, "revoked_at"));
    }

    public static byte[] encodeClaim(Claim v) {
        return Cbor.encode(encClaim(v));
    }

    public static Claim decodeClaim(byte[] data) {
        return decClaim(Cbor.decode(data));
    }

    // -----------------------------------------------------------------
    // LocalRpDescriptor / SignedLocalRpDescriptor
    // -----------------------------------------------------------------

    static Value encLocalRpDescriptor(LocalRpDescriptor v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "app_name", v.appName());
        Cbor.putOptText(e, "local_domain_hint", v.localDomainHint());
        Cbor.putBytes(e, "signing_public_key", v.signingPublicKey());
        Cbor.putBytes(e, "encryption_public_key", v.encryptionPublicKey());
        Cbor.putText(e, "fingerprint", v.fingerprint());
        e.add(Cbor.entry(
                "supported_suites",
                Cbor.varray(v.supportedSuites().stream().<Value>map(Cbor::vtext).toList())));
        Cbor.putText(e, "created_at", v.createdAt());
        Cbor.putText(e, "expires_at", v.expiresAt());
        return Cbor.vmap(e);
    }

    static LocalRpDescriptor decLocalRpDescriptor(Value m) {
        List<Value> suites = Cbor.asArray(Cbor.require(m, "supported_suites"));
        return new LocalRpDescriptor(
                Cbor.requireText(m, "app_name"),
                Cbor.optText(m, "local_domain_hint"),
                Cbor.requireBytes(m, "signing_public_key"),
                Cbor.requireBytes(m, "encryption_public_key"),
                Cbor.requireText(m, "fingerprint"),
                suites.stream().map(Cbor::asText).toList(),
                Cbor.requireText(m, "created_at"),
                Cbor.requireText(m, "expires_at"));
    }

    public static byte[] encodeLocalRpDescriptor(LocalRpDescriptor v) {
        return Cbor.encode(encLocalRpDescriptor(v));
    }

    public static LocalRpDescriptor decodeLocalRpDescriptor(byte[] data) {
        return decLocalRpDescriptor(Cbor.decode(data));
    }

    static Value encSignedLocalRpDescriptor(SignedLocalRpDescriptor v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "descriptor", v.descriptor());
        Cbor.putBytes(e, "signature", v.signature());
        return Cbor.vmap(e);
    }

    static SignedLocalRpDescriptor decSignedLocalRpDescriptor(Value m) {
        return new SignedLocalRpDescriptor(
                Cbor.requireBytes(m, "descriptor"), Cbor.requireBytes(m, "signature"));
    }

    public static byte[] encodeSignedLocalRpDescriptor(SignedLocalRpDescriptor v) {
        return Cbor.encode(encSignedLocalRpDescriptor(v));
    }

    public static SignedLocalRpDescriptor decodeSignedLocalRpDescriptor(byte[] data) {
        return decSignedLocalRpDescriptor(Cbor.decode(data));
    }

    // -----------------------------------------------------------------
    // LocalRpLoginRequest / SignedLocalRpLoginRequest
    // -----------------------------------------------------------------

    static Value encLocalRpLoginRequest(LocalRpLoginRequest v) {
        List<Entry> e = new ArrayList<>();
        e.add(Cbor.entry("descriptor", encSignedLocalRpDescriptor(v.descriptor())));
        Cbor.putText(e, "callback_url", v.callbackUrl());
        Cbor.putBytes(e, "nonce", v.nonce());
        Cbor.putBytes(e, "state", v.state());
        e.add(Cbor.entry(
                "requested_claims",
                Cbor.varray(v.requestedClaims().stream().<Value>map(Cbor::vtext).toList())));
        e.add(Cbor.entry(
                "required_claims",
                Cbor.varray(v.requiredClaims().stream().<Value>map(Cbor::vtext).toList())));
        Cbor.putText(e, "issued_at", v.issuedAt());
        Cbor.putText(e, "expires_at", v.expiresAt());
        return Cbor.vmap(e);
    }

    static LocalRpLoginRequest decLocalRpLoginRequest(Value m) {
        return new LocalRpLoginRequest(
                decSignedLocalRpDescriptor(Cbor.require(m, "descriptor")),
                Cbor.requireText(m, "callback_url"),
                Cbor.requireBytes(m, "nonce"),
                Cbor.requireBytes(m, "state"),
                Cbor.asArray(Cbor.require(m, "requested_claims")).stream().map(Cbor::asText).toList(),
                Cbor.asArray(Cbor.require(m, "required_claims")).stream().map(Cbor::asText).toList(),
                Cbor.requireText(m, "issued_at"),
                Cbor.requireText(m, "expires_at"));
    }

    public static byte[] encodeLocalRpLoginRequest(LocalRpLoginRequest v) {
        return Cbor.encode(encLocalRpLoginRequest(v));
    }

    public static LocalRpLoginRequest decodeLocalRpLoginRequest(byte[] data) {
        return decLocalRpLoginRequest(Cbor.decode(data));
    }

    static Value encSignedLocalRpLoginRequest(SignedLocalRpLoginRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "request", v.request());
        Cbor.putBytes(e, "signature", v.signature());
        return Cbor.vmap(e);
    }

    static SignedLocalRpLoginRequest decSignedLocalRpLoginRequest(Value m) {
        return new SignedLocalRpLoginRequest(Cbor.requireBytes(m, "request"), Cbor.requireBytes(m, "signature"));
    }

    public static byte[] encodeSignedLocalRpLoginRequest(SignedLocalRpLoginRequest v) {
        return Cbor.encode(encSignedLocalRpLoginRequest(v));
    }

    public static SignedLocalRpLoginRequest decodeSignedLocalRpLoginRequest(byte[] data) {
        return decSignedLocalRpLoginRequest(Cbor.decode(data));
    }

    // -----------------------------------------------------------------
    // LocalRpCallbackHeader / LocalRpEncryptedCallback
    // -----------------------------------------------------------------

    static Value encLocalRpCallbackHeader(LocalRpCallbackHeader v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "fingerprint", v.fingerprint());
        Cbor.putBytes(e, "nonce", v.nonce());
        Cbor.putBytes(e, "state", v.state());
        Cbor.putText(e, "suite", v.suite());
        Cbor.putBytes(e, "ephemeral_public_key", v.ephemeralPublicKey());
        Cbor.putBytes(e, "aead_nonce", v.aeadNonce());
        Cbor.putText(e, "issued_at", v.issuedAt());
        Cbor.putText(e, "expires_at", v.expiresAt());
        return Cbor.vmap(e);
    }

    static LocalRpCallbackHeader decLocalRpCallbackHeader(Value m) {
        return new LocalRpCallbackHeader(
                Cbor.requireText(m, "fingerprint"),
                Cbor.requireBytes(m, "nonce"),
                Cbor.requireBytes(m, "state"),
                Cbor.requireText(m, "suite"),
                Cbor.requireBytes(m, "ephemeral_public_key"),
                Cbor.requireBytes(m, "aead_nonce"),
                Cbor.requireText(m, "issued_at"),
                Cbor.requireText(m, "expires_at"));
    }

    public static byte[] encodeLocalRpCallbackHeader(LocalRpCallbackHeader v) {
        return Cbor.encode(encLocalRpCallbackHeader(v));
    }

    public static LocalRpCallbackHeader decodeLocalRpCallbackHeader(byte[] data) {
        return decLocalRpCallbackHeader(Cbor.decode(data));
    }

    static Value encLocalRpEncryptedCallback(LocalRpEncryptedCallback v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "header", v.header());
        Cbor.putBytes(e, "ciphertext", v.ciphertext());
        return Cbor.vmap(e);
    }

    static LocalRpEncryptedCallback decLocalRpEncryptedCallback(Value m) {
        return new LocalRpEncryptedCallback(Cbor.requireBytes(m, "header"), Cbor.requireBytes(m, "ciphertext"));
    }

    public static byte[] encodeLocalRpEncryptedCallback(LocalRpEncryptedCallback v) {
        return Cbor.encode(encLocalRpEncryptedCallback(v));
    }

    public static LocalRpEncryptedCallback decodeLocalRpEncryptedCallback(byte[] data) {
        return decLocalRpEncryptedCallback(Cbor.decode(data));
    }

    // -----------------------------------------------------------------
    // LocalRpCallbackPayload / SignedLocalRpCallbackPayload
    // -----------------------------------------------------------------

    static Value encLocalRpCallbackPayload(LocalRpCallbackPayload v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "user_id", v.userId());
        Cbor.putText(e, "user_domain", v.userDomain());
        Cbor.putBytes(e, "claim_ticket", v.claimTicket());
        Cbor.putText(e, "audience_fingerprint", v.audienceFingerprint());
        Cbor.putText(e, "callback_url", v.callbackUrl());
        Cbor.putBytes(e, "nonce", v.nonce());
        Cbor.putBytes(e, "state", v.state());
        Cbor.putText(e, "issued_at", v.issuedAt());
        Cbor.putText(e, "expires_at", v.expiresAt());
        return Cbor.vmap(e);
    }

    static LocalRpCallbackPayload decLocalRpCallbackPayload(Value m) {
        return new LocalRpCallbackPayload(
                Cbor.requireText(m, "user_id"),
                Cbor.requireText(m, "user_domain"),
                Cbor.requireBytes(m, "claim_ticket"),
                Cbor.requireText(m, "audience_fingerprint"),
                Cbor.requireText(m, "callback_url"),
                Cbor.requireBytes(m, "nonce"),
                Cbor.requireBytes(m, "state"),
                Cbor.requireText(m, "issued_at"),
                Cbor.requireText(m, "expires_at"));
    }

    public static byte[] encodeLocalRpCallbackPayload(LocalRpCallbackPayload v) {
        return Cbor.encode(encLocalRpCallbackPayload(v));
    }

    public static LocalRpCallbackPayload decodeLocalRpCallbackPayload(byte[] data) {
        return decLocalRpCallbackPayload(Cbor.decode(data));
    }

    static Value encSignedLocalRpCallbackPayload(SignedLocalRpCallbackPayload v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "payload", v.payload());
        Cbor.putText(e, "signing_key_id", v.signingKeyId());
        Cbor.putBytes(e, "signature", v.signature());
        return Cbor.vmap(e);
    }

    static SignedLocalRpCallbackPayload decSignedLocalRpCallbackPayload(Value m) {
        return new SignedLocalRpCallbackPayload(
                Cbor.requireBytes(m, "payload"),
                Cbor.requireText(m, "signing_key_id"),
                Cbor.requireBytes(m, "signature"));
    }

    public static byte[] encodeSignedLocalRpCallbackPayload(SignedLocalRpCallbackPayload v) {
        return Cbor.encode(encSignedLocalRpCallbackPayload(v));
    }

    public static SignedLocalRpCallbackPayload decodeSignedLocalRpCallbackPayload(byte[] data) {
        return decSignedLocalRpCallbackPayload(Cbor.decode(data));
    }

    // -----------------------------------------------------------------
    // LocalRpTicketRedemptionRequest / SignedLocalRpTicketRedemptionRequest
    // -----------------------------------------------------------------

    static Value encLocalRpTicketRedemptionRequest(LocalRpTicketRedemptionRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "claim_ticket", v.claimTicket());
        Cbor.putText(e, "fingerprint", v.fingerprint());
        Cbor.putText(e, "issued_at", v.issuedAt());
        return Cbor.vmap(e);
    }

    static LocalRpTicketRedemptionRequest decLocalRpTicketRedemptionRequest(Value m) {
        return new LocalRpTicketRedemptionRequest(
                Cbor.requireBytes(m, "claim_ticket"),
                Cbor.requireText(m, "fingerprint"),
                Cbor.requireText(m, "issued_at"));
    }

    public static byte[] encodeLocalRpTicketRedemptionRequest(LocalRpTicketRedemptionRequest v) {
        return Cbor.encode(encLocalRpTicketRedemptionRequest(v));
    }

    public static LocalRpTicketRedemptionRequest decodeLocalRpTicketRedemptionRequest(byte[] data) {
        return decLocalRpTicketRedemptionRequest(Cbor.decode(data));
    }

    static Value encSignedLocalRpTicketRedemptionRequest(SignedLocalRpTicketRedemptionRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "request", v.request());
        Cbor.putBytes(e, "signature", v.signature());
        return Cbor.vmap(e);
    }

    static SignedLocalRpTicketRedemptionRequest decSignedLocalRpTicketRedemptionRequest(Value m) {
        return new SignedLocalRpTicketRedemptionRequest(
                Cbor.requireBytes(m, "request"), Cbor.requireBytes(m, "signature"));
    }

    public static byte[] encodeSignedLocalRpTicketRedemptionRequest(SignedLocalRpTicketRedemptionRequest v) {
        return Cbor.encode(encSignedLocalRpTicketRedemptionRequest(v));
    }

    public static SignedLocalRpTicketRedemptionRequest decodeSignedLocalRpTicketRedemptionRequest(byte[] data) {
        return decSignedLocalRpTicketRedemptionRequest(Cbor.decode(data));
    }

    // -----------------------------------------------------------------
    // LocalRpTicketRedemptionResponse
    // -----------------------------------------------------------------

    static Value encLocalRpTicketRedemptionResponse(LocalRpTicketRedemptionResponse v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "user_id", v.userId());
        Cbor.putText(e, "user_domain", v.userDomain());
        e.add(Cbor.entry("claims", encArray(v.claims(), Codec::encClaim)));
        Cbor.putText(e, "ticket_expires_at", v.ticketExpiresAt());
        return Cbor.vmap(e);
    }

    static LocalRpTicketRedemptionResponse decLocalRpTicketRedemptionResponse(Value m) {
        return new LocalRpTicketRedemptionResponse(
                Cbor.requireText(m, "user_id"),
                Cbor.requireText(m, "user_domain"),
                decArray(Cbor.require(m, "claims"), Codec::decClaim),
                Cbor.requireText(m, "ticket_expires_at"));
    }

    public static byte[] encodeLocalRpTicketRedemptionResponse(LocalRpTicketRedemptionResponse v) {
        return Cbor.encode(encLocalRpTicketRedemptionResponse(v));
    }

    public static LocalRpTicketRedemptionResponse decodeLocalRpTicketRedemptionResponse(byte[] data) {
        return decLocalRpTicketRedemptionResponse(Cbor.decode(data));
    }

    // -----------------------------------------------------------------
    // Act-as grants (grantee side). Shapes mirror csil/linkkeys.csil
    // "Act-as grants"; optional fields are omitted when null, exactly as
    // the generated Rust codec does.
    // -----------------------------------------------------------------

    static Value encApplicationRef(ApplicationRef v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "subject_user_id", v.subjectUserId());
        Cbor.putText(e, "subject_domain", v.subjectDomain());
        Cbor.putText(e, "application_id", v.applicationId());
        return Cbor.vmap(e);
    }

    static ApplicationRef decApplicationRef(Value m) {
        return new ApplicationRef(
                Cbor.requireText(m, "subject_user_id"),
                Cbor.requireText(m, "subject_domain"),
                Cbor.requireText(m, "application_id"));
    }

    public static byte[] encodeApplicationRef(ApplicationRef v) {
        return Cbor.encode(encApplicationRef(v));
    }

    public static ApplicationRef decodeApplicationRef(byte[] data) {
        return decApplicationRef(Cbor.decode(data));
    }

    static Value encGranteeRef(GranteeRef v) {
        List<Entry> e = new ArrayList<>();
        if (v.application() != null) {
            e.add(Cbor.entry("application", encApplicationRef(v.application())));
        }
        Cbor.putOptText(e, "local_rp_descriptor_fingerprint", v.localRpDescriptorFingerprint());
        return Cbor.vmap(e);
    }

    static GranteeRef decGranteeRef(Value m) {
        Value app = Cbor.mapGet(m, "application");
        return new GranteeRef(
                app == null ? null : decApplicationRef(app), Cbor.optText(m, "local_rp_descriptor_fingerprint"));
    }

    static Value encApplicationKeySignature(ApplicationKeySignature v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "signed_by_key_id", v.signedByKeyId());
        Cbor.putBytes(e, "signature", v.signature());
        return Cbor.vmap(e);
    }

    static ApplicationKeySignature decApplicationKeySignature(Value m) {
        return new ApplicationKeySignature(Cbor.requireText(m, "signed_by_key_id"), Cbor.requireBytes(m, "signature"));
    }

    static Value encGranteeProof(GranteeProof v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putOptText(e, "application_instance_id", v.applicationInstanceId());
        if (v.localRpDescriptor() != null) {
            e.add(Cbor.entry("local_rp_descriptor", encSignedLocalRpDescriptor(v.localRpDescriptor())));
        }
        e.add(Cbor.entry("signature", encApplicationKeySignature(v.signature())));
        return Cbor.vmap(e);
    }

    static GranteeProof decGranteeProof(Value m) {
        Value descriptor = Cbor.mapGet(m, "local_rp_descriptor");
        return new GranteeProof(
                Cbor.optText(m, "application_instance_id"),
                descriptor == null ? null : decSignedLocalRpDescriptor(descriptor),
                decApplicationKeySignature(Cbor.require(m, "signature")));
    }

    static Value encSignedActAsScopeSet(SignedActAsScopeSet v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "scope_set", v.scopeSet());
        Cbor.putText(e, "signer_instance_id", v.signerInstanceId());
        e.add(Cbor.entry("signatures", encArray(v.signatures(), Codec::encApplicationKeySignature)));
        return Cbor.vmap(e);
    }

    static SignedActAsScopeSet decSignedActAsScopeSet(Value m) {
        List<ApplicationKeySignature> signatures =
                decArray(Cbor.require(m, "signatures"), Codec::decApplicationKeySignature);
        if (signatures.isEmpty()) {
            // CSIL `signatures: [+ ApplicationKeySignature]`: at least one.
            throw new Cbor.CborDecodeException("SignedActAsScopeSet.signatures must not be empty");
        }
        return new SignedActAsScopeSet(
                Cbor.requireBytes(m, "scope_set"), Cbor.requireText(m, "signer_instance_id"), signatures);
    }

    public static byte[] encodeSignedActAsScopeSet(SignedActAsScopeSet v) {
        return Cbor.encode(encSignedActAsScopeSet(v));
    }

    public static SignedActAsScopeSet decodeSignedActAsScopeSet(byte[] data) {
        return decSignedActAsScopeSet(Cbor.decode(data));
    }

    static Value encSignedActAsGrant(SignedActAsGrant v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "grant", v.grant());
        e.add(Cbor.entry("signatures", encArray(v.signatures(), Codec::encClaimSignature)));
        return Cbor.vmap(e);
    }

    static SignedActAsGrant decSignedActAsGrant(Value m) {
        return new SignedActAsGrant(
                Cbor.requireBytes(m, "grant"), decArray(Cbor.require(m, "signatures"), Codec::decClaimSignature));
    }

    public static byte[] encodeSignedActAsGrant(SignedActAsGrant v) {
        return Cbor.encode(encSignedActAsGrant(v));
    }

    public static SignedActAsGrant decodeSignedActAsGrant(byte[] data) {
        return decSignedActAsGrant(Cbor.decode(data));
    }

    /** Decode only. A grantee never builds a grant; the home domain signs it. */
    public static ActAsGrant decodeActAsGrant(byte[] data) {
        Value m = Cbor.decode(data);
        return new ActAsGrant(
                Cbor.requireText(m, "grant_id"),
                Cbor.requireText(m, "user_id"),
                Cbor.requireText(m, "subject_domain"),
                decGranteeRef(Cbor.require(m, "grantee")),
                decApplicationRef(Cbor.require(m, "audience")),
                decSignedActAsScopeSet(Cbor.require(m, "scope_set")),
                Cbor.asArray(Cbor.require(m, "approved_scope")).stream().map(Cbor::asText).toList(),
                Cbor.requireText(m, "issued_at"),
                Cbor.requireText(m, "expires_at"),
                Cbor.requireText(m, "series_issued_at"),
                Cbor.requireText(m, "renewable_until"),
                Cbor.optText(m, "device_fingerprint"));
    }

    private static Long optInt(Value m, String key) {
        Value v = Cbor.mapGet(m, key);
        return v == null ? null : Cbor.asInt(v);
    }

    static Value encActAsGrantRequest(ActAsGrantRequest v) {
        // `grantee_handle_claim` is never written: it is a signed claim about
        // the account that enrolled an application grantee. A local RP has no
        // enrolling account, so it has no such claim.
        List<Entry> e = new ArrayList<>();
        e.add(Cbor.entry("grantee", encGranteeRef(v.grantee())));
        e.add(Cbor.entry("scope_set", encSignedActAsScopeSet(v.scopeSet())));
        if (v.requestedLifetimeSeconds() != null) {
            e.add(Cbor.entry("requested_lifetime_seconds", Cbor.vint(v.requestedLifetimeSeconds())));
        }
        if (v.requestedRenewalWindowSeconds() != null) {
            e.add(Cbor.entry("requested_renewal_window_seconds", Cbor.vint(v.requestedRenewalWindowSeconds())));
        }
        Cbor.putText(e, "callback_url", v.callbackUrl());
        Cbor.putText(e, "nonce", v.nonce());
        Cbor.putText(e, "requested_at", v.requestedAt());
        Cbor.putText(e, "expires_at", v.expiresAt());
        return Cbor.vmap(e);
    }

    static ActAsGrantRequest decActAsGrantRequest(Value m) {
        return new ActAsGrantRequest(
                decGranteeRef(Cbor.require(m, "grantee")),
                decSignedActAsScopeSet(Cbor.require(m, "scope_set")),
                optInt(m, "requested_lifetime_seconds"),
                optInt(m, "requested_renewal_window_seconds"),
                Cbor.requireText(m, "callback_url"),
                Cbor.requireText(m, "nonce"),
                Cbor.requireText(m, "requested_at"),
                Cbor.requireText(m, "expires_at"));
    }

    public static byte[] encodeActAsGrantRequest(ActAsGrantRequest v) {
        return Cbor.encode(encActAsGrantRequest(v));
    }

    public static ActAsGrantRequest decodeActAsGrantRequest(byte[] data) {
        return decActAsGrantRequest(Cbor.decode(data));
    }

    public static byte[] encodeSignedActAsGrantRequest(SignedActAsGrantRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "request", v.request());
        e.add(Cbor.entry("proof", encGranteeProof(v.proof())));
        return Cbor.encode(Cbor.vmap(e));
    }

    public static SignedActAsGrantRequest decodeSignedActAsGrantRequest(byte[] data) {
        Value m = Cbor.decode(data);
        return new SignedActAsGrantRequest(Cbor.requireBytes(m, "request"), decGranteeProof(Cbor.require(m, "proof")));
    }

    public static byte[] encodeActAsRefreshRequest(ActAsRefreshRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "grant_id", v.grantId());
        e.add(Cbor.entry("grantee", encGranteeRef(v.grantee())));
        Cbor.putText(e, "requested_at", v.requestedAt());
        Cbor.putText(e, "expires_at", v.expiresAt());
        Cbor.putText(e, "nonce", v.nonce());
        return Cbor.encode(Cbor.vmap(e));
    }

    public static ActAsRefreshRequest decodeActAsRefreshRequest(byte[] data) {
        Value m = Cbor.decode(data);
        return new ActAsRefreshRequest(
                Cbor.requireText(m, "grant_id"),
                decGranteeRef(Cbor.require(m, "grantee")),
                Cbor.requireText(m, "requested_at"),
                Cbor.requireText(m, "expires_at"),
                Cbor.requireText(m, "nonce"));
    }

    static Value encSignedActAsRefreshRequest(SignedActAsRefreshRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "request", v.request());
        e.add(Cbor.entry("proof", encGranteeProof(v.proof())));
        return Cbor.vmap(e);
    }

    static SignedActAsRefreshRequest decSignedActAsRefreshRequest(Value m) {
        return new SignedActAsRefreshRequest(Cbor.requireBytes(m, "request"), decGranteeProof(Cbor.require(m, "proof")));
    }

    public static byte[] encodeSignedActAsRefreshRequest(SignedActAsRefreshRequest v) {
        return Cbor.encode(encSignedActAsRefreshRequest(v));
    }

    public static SignedActAsRefreshRequest decodeSignedActAsRefreshRequest(byte[] data) {
        return decSignedActAsRefreshRequest(Cbor.decode(data));
    }

    public static byte[] encodeRefreshActAsGrantRequest(RefreshActAsGrantRequest v) {
        List<Entry> e = new ArrayList<>();
        e.add(Cbor.entry("request", encSignedActAsRefreshRequest(v.request())));
        return Cbor.encode(Cbor.vmap(e));
    }

    public static RefreshActAsGrantRequest decodeRefreshActAsGrantRequest(byte[] data) {
        return new RefreshActAsGrantRequest(decSignedActAsRefreshRequest(Cbor.require(Cbor.decode(data), "request")));
    }

    public static byte[] encodeRefreshActAsGrantResponse(RefreshActAsGrantResponse v) {
        List<Entry> e = new ArrayList<>();
        e.add(Cbor.entry("grant", encSignedActAsGrant(v.grant())));
        Cbor.putBool(e, "signed", v.signed());
        return Cbor.encode(Cbor.vmap(e));
    }

    public static RefreshActAsGrantResponse decodeRefreshActAsGrantResponse(byte[] data) {
        Value m = Cbor.decode(data);
        return new RefreshActAsGrantResponse(
                decSignedActAsGrant(Cbor.require(m, "grant")), Cbor.asBool(Cbor.require(m, "signed")));
    }

    public static byte[] encodeActAsPresentation(ActAsPresentation v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "grant_hash", v.grantHash());
        e.add(Cbor.entry("audience", encApplicationRef(v.audience())));
        Cbor.putBytes(e, "request_digest", v.requestDigest());
        Cbor.putText(e, "presented_at", v.presentedAt());
        Cbor.putBytes(e, "nonce", v.nonce());
        return Cbor.encode(Cbor.vmap(e));
    }

    public static ActAsPresentation decodeActAsPresentation(byte[] data) {
        Value m = Cbor.decode(data);
        return new ActAsPresentation(
                Cbor.requireBytes(m, "grant_hash"),
                decApplicationRef(Cbor.require(m, "audience")),
                Cbor.requireBytes(m, "request_digest"),
                Cbor.requireText(m, "presented_at"),
                Cbor.requireBytes(m, "nonce"));
    }

    static Value encSignedActAsPresentation(SignedActAsPresentation v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putBytes(e, "presentation", v.presentation());
        e.add(Cbor.entry("proof", encGranteeProof(v.proof())));
        return Cbor.vmap(e);
    }

    static SignedActAsPresentation decSignedActAsPresentation(Value m) {
        return new SignedActAsPresentation(
                Cbor.requireBytes(m, "presentation"), decGranteeProof(Cbor.require(m, "proof")));
    }

    public static byte[] encodeActAsCredential(ActAsCredential v) {
        List<Entry> e = new ArrayList<>();
        e.add(Cbor.entry("grant", encSignedActAsGrant(v.grant())));
        e.add(Cbor.entry("presentation", encSignedActAsPresentation(v.presentation())));
        return Cbor.encode(Cbor.vmap(e));
    }

    public static ActAsCredential decodeActAsCredential(byte[] data) {
        Value m = Cbor.decode(data);
        return new ActAsCredential(
                decSignedActAsGrant(Cbor.require(m, "grant")),
                decSignedActAsPresentation(Cbor.require(m, "presentation")));
    }

    // -----------------------------------------------------------------
    // Array helpers
    // -----------------------------------------------------------------

    private static <T> Value encArray(List<T> items, Function<T, Value> encOne) {
        List<Value> out = new ArrayList<>(items.size());
        for (T item : items) {
            out.add(encOne.apply(item));
        }
        return Cbor.varray(out);
    }

    private static <T> List<T> decArray(Value v, Function<Value, T> decOne) {
        List<Value> items = Cbor.asArray(v);
        List<T> out = new ArrayList<>(items.size());
        for (Value item : items) {
            out.add(decOne.apply(item));
        }
        return out;
    }
}
