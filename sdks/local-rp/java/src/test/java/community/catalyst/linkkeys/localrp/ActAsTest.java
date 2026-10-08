package community.catalyst.linkkeys.localrp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import community.catalyst.linkkeys.localrp.crypto.Crypto;
import community.catalyst.linkkeys.localrp.crypto.Hex;
import community.catalyst.linkkeys.localrp.dns.DnsResolver;
import community.catalyst.linkkeys.localrp.rpc.RpcEnvelope;
import community.catalyst.linkkeys.localrp.testutil.Fixtures;
import community.catalyst.linkkeys.localrp.testutil.MiniJson.JsonValue;
import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.ClaimSignature;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsCredential;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsGrantRequest;
import community.catalyst.linkkeys.localrp.wire.Types.ActAsRefreshRequest;
import community.catalyst.linkkeys.localrp.wire.Types.ApplicationRef;
import community.catalyst.linkkeys.localrp.wire.Types.GranteeRef;
import community.catalyst.linkkeys.localrp.wire.Types.LocalRpDescriptor;
import community.catalyst.linkkeys.localrp.wire.Types.RefreshActAsGrantRequest;
import community.catalyst.linkkeys.localrp.wire.Types.RefreshActAsGrantResponse;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsGrant;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsGrantRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsRefreshRequest;
import community.catalyst.linkkeys.localrp.wire.Types.SignedActAsScopeSet;
import community.catalyst.linkkeys.localrp.wire.Types.SignedLocalRpDescriptor;

/**
 * Act-as grantee support: byte-exact signing against
 * {@code sdks/regular-rp/conformance/act_as_grantee_signing.json}
 * ({@code local_rp_grantee} case), begin URL discovery, callback nonce
 * checks, and refresh over the fake pinned IDP from {@link FlowTest}. No test
 * here touches a live network: DNS is always a canned fake, and the IDP is a
 * loopback listener.
 */
class ActAsTest {
    private static final String IDENTITY_DOMAIN = "ident.example.test";
    private static final String CALLBACK_URL = "http://app.lan:8080/act-as/callback";

    private static JsonValue localRpCase(JsonValue v) {
        for (JsonValue c : v.get("cases").asArray()) {
            if (c.get("name").asString().equals("local_rp_grantee")) {
                return c;
            }
        }
        throw new IllegalStateException("no local_rp_grantee case");
    }

    /** Key material built from the vector's published seed and signed descriptor. */
    private static Identity.LocalRpKeyMaterial vectorKeyMaterial(JsonValue v) {
        JsonValue local = v.get("local_rp_grantee");
        SignedLocalRpDescriptor descriptor =
                Codec.decodeSignedLocalRpDescriptor(Hex.decode(local.get("signed_descriptor_cbor_hex").asString()));
        LocalRpDescriptor inner = Codec.decodeLocalRpDescriptor(descriptor.descriptor());
        return new Identity.LocalRpKeyMaterial(
                Hex.decode(local.get("signing_private_key_hex").asString()),
                inner.signingPublicKey(),
                new byte[32],
                inner.encryptionPublicKey(),
                descriptor,
                local.get("fingerprint").asString());
    }

    private static Long optLong(JsonValue obj, String key) {
        JsonValue v = obj.getOrNull(key);
        return v == null || v.isNull() ? null : v.asLong();
    }

    private static byte[] scopeSetCbor(JsonValue v) {
        return Hex.decode(localRpCase(v).get("grant_request").get("inputs").get("scope_set_signed_cbor_hex").asString());
    }

    // -----------------------------------------------------------------
    // Conformance vectors
    // -----------------------------------------------------------------

    @Test
    void signedScopeSetVectorDecodesWithAllSignaturesAndReencodesExactly() {
        byte[] cbor = scopeSetCbor(Fixtures.loadRegularRp("act_as_grantee_signing.json"));
        SignedActAsScopeSet decoded = Codec.decodeSignedActAsScopeSet(cbor);
        assertEquals(2, decoded.signatures().size());
        assertEquals("audience-key-1", decoded.signatures().get(0).signedByKeyId());
        assertEquals("audience-key-2", decoded.signatures().get(1).signedByKeyId());
        assertEquals("audience-instance-1", decoded.signerInstanceId());
        assertArrayEquals(cbor, Codec.encodeSignedActAsScopeSet(decoded));
    }

    @Test
    void signedScopeSetWithNoSignaturesIsRefused() {
        byte[] empty = Cbor.encode(Cbor.vmap(List.of(
                Cbor.entry("scope_set", Cbor.vbytes(new byte[] {(byte) 0xa0})),
                Cbor.entry("signer_instance_id", Cbor.vtext("audience-instance-1")),
                Cbor.entry("signatures", Cbor.varray(List.of())))));
        assertThrows(Cbor.CborDecodeException.class, () -> Codec.decodeSignedActAsScopeSet(empty));
    }

    @Test
    void localRpGranteeVectorsAreByteExact() {
        JsonValue v = Fixtures.loadRegularRp("act_as_grantee_signing.json");
        Identity.LocalRpKeyMaterial km = vectorKeyMaterial(v);
        JsonValue c = localRpCase(v);
        assertEquals(c.get("grantee").get("local_rp_descriptor_fingerprint").asString(), km.fingerprint());
        assertEquals(ActAs.GRANT_REQUEST_TAG, v.get("tags").get("grant_request").asString());
        assertEquals(ActAs.REFRESH_REQUEST_TAG, v.get("tags").get("refresh_request").asString());
        assertEquals(ActAs.PRESENTATION_TAG, v.get("tags").get("presentation").asString());
        GranteeRef grantee = ActAs.localRpGrantee(km);

        JsonValue g = c.get("grant_request");
        JsonValue gi = g.get("inputs");
        ActAsGrantRequest request = new ActAsGrantRequest(
                grantee,
                Codec.decodeSignedActAsScopeSet(Hex.decode(gi.get("scope_set_signed_cbor_hex").asString())),
                optLong(gi, "requested_lifetime_seconds"),
                optLong(gi, "requested_renewal_window_seconds"),
                gi.get("callback_url").asString(),
                gi.get("nonce").asString(),
                gi.get("requested_at").asString(),
                gi.get("expires_at").asString());
        SignedActAsGrantRequest signed = ActAs.signGrantRequest(request, km);
        assertEquals(g.get("request_cbor_hex").asString(), Hex.encode(signed.request()));
        assertEquals(
                g.get("signature_input_cbor_hex").asString(),
                Hex.encode(LocalRp.envelopeSignatureInput(ActAs.GRANT_REQUEST_TAG, signed.request())));
        assertEquals(g.get("signed_cbor_hex").asString(), Hex.encode(Codec.encodeSignedActAsGrantRequest(signed)));
        assertEquals(g.get("url_param").asString(), ActAs.signedGrantRequestToUrlParam(signed));

        JsonValue r = c.get("refresh_request");
        JsonValue ri = r.get("inputs");
        ActAsRefreshRequest refresh = new ActAsRefreshRequest(
                ri.get("grant_id").asString(),
                grantee,
                ri.get("requested_at").asString(),
                ri.get("expires_at").asString(),
                ri.get("nonce").asString());
        SignedActAsRefreshRequest signedRefresh = ActAs.signRefreshRequest(refresh, km);
        assertEquals(r.get("request_cbor_hex").asString(), Hex.encode(signedRefresh.request()));
        assertEquals(r.get("signed_cbor_hex").asString(), Hex.encode(Codec.encodeSignedActAsRefreshRequest(signedRefresh)));

        JsonValue p = c.get("presentation");
        JsonValue pi = p.get("inputs");
        SignedActAsGrant grant = Codec.decodeSignedActAsGrant(Hex.decode(pi.get("grant_signed_cbor_hex").asString()));
        JsonValue aud = pi.get("audience");
        ApplicationRef audience = new ApplicationRef(
                aud.get("subject_user_id").asString(),
                aud.get("subject_domain").asString(),
                aud.get("application_id").asString());
        ActAsCredential credential = ActAs.present(
                grant,
                audience,
                Hex.decode(pi.get("request_digest_hex").asString()),
                Instant.parse(pi.get("presented_at").asString()),
                Hex.decode(pi.get("nonce_hex").asString()),
                km);
        assertEquals(p.get("grant_hash_hex").asString(), Hex.encode(ActAs.grantHash(grant.grant())));
        assertEquals(p.get("presentation_cbor_hex").asString(), Hex.encode(credential.presentation().presentation()));
        assertEquals(p.get("credential_cbor_hex").asString(), Hex.encode(ActAs.encodeCredential(credential)));
    }

    @Test
    void formatTimeIsWholeSecondUtc() {
        assertEquals("2026-10-06T12:05:00Z", ActAs.formatTime(Instant.parse("2026-10-06T12:05:00.987654321Z")));
    }

    // -----------------------------------------------------------------
    // Begin
    // -----------------------------------------------------------------

    private static DnsResolver mapResolver(Map<String, List<String>> records) {
        return name -> {
            List<String> txts = records.get(name);
            if (txts == null) {
                throw new SdkException(SdkException.Kind.DNS, "no fake record for " + name);
            }
            return txts;
        };
    }

    private static ActAs.BeginActAsConfig beginConfig(Identity.LocalRpKeyMaterial km, DnsResolver dns, Instant now) {
        JsonValue v = Fixtures.loadRegularRp("act_as_grantee_signing.json");
        ActAs.BeginActAsConfig config =
                new ActAs.BeginActAsConfig(km, "alice@" + IDENTITY_DOMAIN, scopeSetCbor(v), CALLBACK_URL, now);
        config.requestedLifetimeSeconds = 1800L;
        config.dns = dns;
        return config;
    }

    private static Identity.LocalRpKeyMaterial freshIdentity(Instant now) {
        return Identity.generateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("act-as-test", now));
    }

    @Test
    void beginActAsUsesDiscoveredHostAndSignsTheRequest() {
        Instant now = Instant.parse("2026-10-06T11:59:00Z");
        Identity.LocalRpKeyMaterial km = freshIdentity(now);
        DnsResolver dns = mapResolver(Map.of(
                "_linkkeys_apis." + IDENTITY_DOMAIN, List.of("v=lk1 tcp=x.example.test https=login.example.test/lk")));
        ActAs.BeginActAsResult result = ActAs.beginActAs(beginConfig(km, dns, now));

        String prefix = "https://login.example.test/lk/auth/act-as?signed_request=";
        assertTrue(result.redirectUrl().startsWith(prefix), result.redirectUrl());
        assertEquals(IDENTITY_DOMAIN, result.pending().userDomain());
        assertEquals(CALLBACK_URL, result.pending().callbackUrl());
        assertEquals(43, result.pending().nonce().length());

        String param = result.redirectUrl().substring(prefix.length());
        SignedActAsGrantRequest signed = Codec.decodeSignedActAsGrantRequest(Encoding.decodeUrlParam(param));
        assertTrue(Crypto.verifyEd25519(
                LocalRp.envelopeSignatureInput(ActAs.GRANT_REQUEST_TAG, signed.request()),
                signed.proof().signature().signature(),
                km.signingPublicKey()));
        assertEquals(km.fingerprint(), signed.proof().signature().signedByKeyId());
        assertNull(signed.proof().applicationInstanceId());
        assertArrayEquals(
                Codec.encodeSignedLocalRpDescriptor(km.descriptor()),
                Codec.encodeSignedLocalRpDescriptor(signed.proof().localRpDescriptor()));

        ActAsGrantRequest request = Codec.decodeActAsGrantRequest(signed.request());
        assertNull(request.grantee().application());
        assertEquals(km.fingerprint(), request.grantee().localRpDescriptorFingerprint());
        assertEquals(result.pending().nonce(), request.nonce());
        assertEquals("2026-10-06T11:59:00Z", request.requestedAt());
        assertEquals("2026-10-06T12:04:00Z", request.expiresAt());
        assertEquals(1800L, request.requestedLifetimeSeconds());
        assertNull(request.requestedRenewalWindowSeconds());
        assertEquals(CALLBACK_URL, request.callbackUrl());
        JsonValue v = Fixtures.loadRegularRp("act_as_grantee_signing.json");
        assertArrayEquals(scopeSetCbor(v), Codec.encodeSignedActAsScopeSet(request.scopeSet()));
    }

    @Test
    void beginActAsFallsBackToIdentityDomain() {
        Instant now = Instant.parse("2026-10-06T11:59:00Z");
        DnsResolver failing = name -> {
            throw new SdkException(SdkException.Kind.DNS, "SERVFAIL");
        };
        ActAs.BeginActAsResult result = ActAs.beginActAs(beginConfig(freshIdentity(now), failing, now));
        assertTrue(
                result.redirectUrl().startsWith("https://" + IDENTITY_DOMAIN + "/auth/act-as?signed_request="),
                result.redirectUrl());
        assertTrue(!result.redirectUrl().contains("username="), result.redirectUrl());
    }

    @Test
    void beginActAsRejectsBadInput() {
        Instant now = Instant.parse("2026-10-06T11:59:00Z");
        Identity.LocalRpKeyMaterial km = freshIdentity(now);
        DnsResolver failing = name -> {
            throw new SdkException(SdkException.Kind.DNS, "SERVFAIL");
        };

        ActAs.BeginActAsConfig tooLong = beginConfig(km, failing, now);
        tooLong.requestWindow = Duration.ofSeconds(901);
        assertEquals(SdkException.Kind.INVALID_INPUT, assertThrows(SdkException.class, () -> ActAs.beginActAs(tooLong)).kind());

        ActAs.BeginActAsConfig maxWindow = beginConfig(km, failing, now);
        maxWindow.requestWindow = Duration.ofSeconds(900);
        ActAs.beginActAs(maxWindow);

        ActAs.BeginActAsConfig badScopeSet =
                new ActAs.BeginActAsConfig(km, IDENTITY_DOMAIN, new byte[] {0x01}, CALLBACK_URL, now);
        badScopeSet.dns = failing;
        assertEquals(
                SdkException.Kind.INVALID_INPUT,
                assertThrows(SdkException.class, () -> ActAs.beginActAs(badScopeSet)).kind());

        ActAs.BeginActAsConfig badCallback = new ActAs.BeginActAsConfig(
                km, IDENTITY_DOMAIN, scopeSetCbor(Fixtures.loadRegularRp("act_as_grantee_signing.json")), "ftp://x", now);
        badCallback.dns = failing;
        assertThrows(SdkException.class, () -> ActAs.beginActAs(badCallback));
    }

    // -----------------------------------------------------------------
    // Callback
    // -----------------------------------------------------------------

    @Test
    void callbackReturnsGrantIdWhenNonceMatches() {
        ActAs.PendingActAs pending = new ActAs.PendingActAs("n0nce-_value", IDENTITY_DOMAIN, CALLBACK_URL);
        assertEquals(
                "grant 1",
                ActAs.completeActAsCallback(pending, CALLBACK_URL + "?x=1&act_as_grant_id=grant%201&nonce=n0nce-_value"));
        assertEquals("g2", ActAs.completeActAsCallback(pending, "nonce=n0nce-_value&act_as_grant_id=g2"));
        assertEquals(pending, ActAs.PendingActAs.fromBytes(pending.toBytes()));
    }

    @Test
    void callbackRejectsNonceMismatchAndMissingFields() {
        ActAs.PendingActAs pending = new ActAs.PendingActAs("expected", IDENTITY_DOMAIN, CALLBACK_URL);
        LocalRpError mismatch = assertThrows(
                LocalRpError.class,
                () -> ActAs.completeActAsCallback(pending, CALLBACK_URL + "?act_as_grant_id=g&nonce=other"));
        assertEquals(LocalRpError.Kind.NONCE_MISMATCH, mismatch.kind());
        assertThrows(SdkException.class, () -> ActAs.completeActAsCallback(pending, CALLBACK_URL + "?act_as_grant_id=g"));
        assertThrows(SdkException.class, () -> ActAs.completeActAsCallback(pending, CALLBACK_URL + "?nonce=expected"));
        assertThrows(
                SdkException.class,
                () -> ActAs.completeActAsCallback(
                        pending, CALLBACK_URL + "?act_as_grant_id=g&nonce=expected&act_as_grant_id=h"));
    }

    // -----------------------------------------------------------------
    // Refresh
    // -----------------------------------------------------------------

    /**
     * A grant as a home domain stores it. Only the identifying fields matter
     * to the grantee; the audience checks the signature.
     */
    static SignedActAsGrant servedGrant(String grantId, String fingerprint, String subjectDomain) {
        List<Cbor.Entry> grantee = new ArrayList<>();
        Cbor.putText(grantee, "local_rp_descriptor_fingerprint", fingerprint);
        List<Cbor.Entry> audience = new ArrayList<>();
        Cbor.putText(audience, "subject_user_id", "audience-owner");
        Cbor.putText(audience, "subject_domain", "audience.test");
        Cbor.putText(audience, "application_id", "audience-app");
        List<Cbor.Entry> signature = new ArrayList<>();
        Cbor.putText(signature, "signed_by_key_id", "audience-key");
        Cbor.putBytes(signature, "signature", new byte[64]);
        List<Cbor.Entry> scopeSet = new ArrayList<>();
        Cbor.putBytes(scopeSet, "scope_set", new byte[] {(byte) 0xa0});
        Cbor.putText(scopeSet, "signer_instance_id", "audience-inst");
        scopeSet.add(Cbor.entry("signatures", Cbor.varray(List.of(Cbor.vmap(signature)))));
        List<Cbor.Entry> e = new ArrayList<>();
        Cbor.putText(e, "grant_id", grantId);
        Cbor.putText(e, "user_id", "user-1");
        Cbor.putText(e, "subject_domain", subjectDomain);
        e.add(Cbor.entry("grantee", Cbor.vmap(grantee)));
        e.add(Cbor.entry("audience", Cbor.vmap(audience)));
        e.add(Cbor.entry("scope_set", Cbor.vmap(scopeSet)));
        e.add(Cbor.entry("approved_scope", Cbor.varray(List.of(Cbor.vtext("read")))));
        Cbor.putText(e, "issued_at", "2026-10-06T12:00:00Z");
        Cbor.putText(e, "expires_at", "2026-10-06T13:00:00Z");
        Cbor.putText(e, "series_issued_at", "2026-10-06T12:00:00Z");
        Cbor.putText(e, "renewable_until", "2026-10-06T13:00:00Z");
        return new SignedActAsGrant(
                Cbor.encode(Cbor.vmap(e)), List.of(new ClaimSignature(subjectDomain, "domain-key", new byte[64])));
    }

    @Test
    void refreshRefusesAGrantForAnotherGrantIdGranteeOrDomain() throws Exception {
        Instant now = Instant.parse("2026-10-06T12:40:00Z");
        Identity.LocalRpKeyMaterial km = freshIdentity(now);
        for (SignedActAsGrant served : List.of(
                servedGrant("grant-2", km.fingerprint(), FlowTest.USER_DOMAIN),
                servedGrant("grant-1", "another-local-rp", FlowTest.USER_DOMAIN),
                servedGrant("grant-1", km.fingerprint(), "other.test"))) {
            Crypto.Ed25519KeyPair domain = Crypto.generateEd25519KeyPair();
            String addr = FlowTest.spawnFakeIdp(domain.privateKeySeed(), 1, (service, op, payload) ->
                    RpcEnvelope.Response.ok(
                            "RefreshActAsGrantResponse",
                            Codec.encodeRefreshActAsGrantResponse(new RefreshActAsGrantResponse(served, false))));
            ActAs.RefreshActAsGrantConfig config =
                    new ActAs.RefreshActAsGrantConfig(km, FlowTest.USER_DOMAIN, "grant-1", now);
            config.transport = new FlowTest.TestTransport();
            config.dns = new FlowTest.FakeDnsResolver(
                    "v=lk1 fp=" + Crypto.fingerprint(domain.publicKey()), "v=lk1 tcp=" + addr);
            LocalRpError e = assertThrows(LocalRpError.class, () -> ActAs.refreshActAsGrant(config));
            assertEquals(LocalRpError.Kind.GRANT_MISMATCH, e.kind());
        }
    }

    @Test
    void refreshCallsActAsRefreshGrantAndDecodesTheResponse() throws Exception {
        Instant now = Instant.parse("2026-10-06T12:40:00Z");
        Identity.LocalRpKeyMaterial km = freshIdentity(now);
        SignedActAsGrant grant = servedGrant("grant-1", km.fingerprint(), FlowTest.USER_DOMAIN);

        Crypto.Ed25519KeyPair domain = Crypto.generateEd25519KeyPair();
        List<String> routes = new ArrayList<>();
        List<byte[]> payloads = new ArrayList<>();
        String addr = FlowTest.spawnFakeIdp(domain.privateKeySeed(), 1, (service, op, payload) -> {
            routes.add(service + "/" + op);
            payloads.add(payload);
            return RpcEnvelope.Response.ok(
                    "RefreshActAsGrantResponse",
                    Codec.encodeRefreshActAsGrantResponse(new RefreshActAsGrantResponse(grant, true)));
        });

        ActAs.RefreshActAsGrantConfig config = new ActAs.RefreshActAsGrantConfig(km, FlowTest.USER_DOMAIN, "grant-1", now);
        config.transport = new FlowTest.TestTransport();
        config.dns = new FlowTest.FakeDnsResolver("v=lk1 fp=" + Crypto.fingerprint(domain.publicKey()), "v=lk1 tcp=" + addr);
        ActAs.RefreshedActAsGrant result = ActAs.refreshActAsGrant(config);

        assertTrue(result.signed());
        assertArrayEquals(Codec.encodeSignedActAsGrant(grant), Codec.encodeSignedActAsGrant(result.grant()));
        assertEquals("grant-1", ActAs.decodeGrantUnverified(result.grant()).grantId());
        assertEquals(List.of("ActAs/refresh-grant"), routes);

        RefreshActAsGrantRequest sent = Codec.decodeRefreshActAsGrantRequest(payloads.get(0));
        SignedActAsRefreshRequest signed = sent.request();
        assertTrue(Crypto.verifyEd25519(
                LocalRp.envelopeSignatureInput(ActAs.REFRESH_REQUEST_TAG, signed.request()),
                signed.proof().signature().signature(),
                km.signingPublicKey()));
        assertEquals(km.fingerprint(), signed.proof().signature().signedByKeyId());
        ActAsRefreshRequest request = Codec.decodeActAsRefreshRequest(signed.request());
        assertEquals("grant-1", request.grantId());
        assertEquals(km.fingerprint(), request.grantee().localRpDescriptorFingerprint());
        assertEquals("2026-10-06T12:40:00Z", request.requestedAt());
        assertEquals("2026-10-06T12:45:00Z", request.expiresAt());
        assertEquals(43, request.nonce().length());
    }

    @Test
    void refreshSurfacesTransportErrors() throws Exception {
        Instant now = Instant.parse("2026-10-06T12:40:00Z");
        Identity.LocalRpKeyMaterial km = freshIdentity(now);
        Crypto.Ed25519KeyPair domain = Crypto.generateEd25519KeyPair();
        String addr = FlowTest.spawnFakeIdp(
                domain.privateKeySeed(),
                1,
                (service, op, payload) -> RpcEnvelope.Response.transportError(RpcEnvelope.Status.FORBIDDEN, "not yours"));

        ActAs.RefreshActAsGrantConfig config = new ActAs.RefreshActAsGrantConfig(km, FlowTest.USER_DOMAIN, "grant-1", now);
        config.transport = new FlowTest.TestTransport();
        config.dns = new FlowTest.FakeDnsResolver("v=lk1 fp=" + Crypto.fingerprint(domain.publicKey()), "v=lk1 tcp=" + addr);
        SdkException e = assertThrows(SdkException.class, () -> ActAs.refreshActAsGrant(config));
        assertEquals(SdkException.Kind.SERVER, e.kind());
        assertEquals(RpcEnvelope.Status.FORBIDDEN, e.serverStatus());
    }
}
