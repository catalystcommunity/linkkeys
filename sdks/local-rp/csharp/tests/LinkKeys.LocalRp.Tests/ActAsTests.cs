using System.Text.Json;
using LinkKeys.LocalRp.Crypto;
using LinkKeys.LocalRp.Dns;
using LinkKeys.LocalRp.Rpc;
using LinkKeys.LocalRp.Tests.TestUtil;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Tests;

/// <summary>
/// Act-as grantee support: byte-exact signing against
/// <c>sdks/regular-rp/conformance/act_as_grantee_signing.json</c> (<c>local_rp_grantee</c>
/// case), begin URL discovery, callback nonce checks, and refresh over the
/// <see cref="FakeIdp"/> loopback <c>openssl s_server</c>. No live network: DNS is always a
/// canned fake.
/// </summary>
public class ActAsTests
{
    private const string IdentityDomain = "ident.example.test";
    private const string CallbackUrl = "http://app.lan:8080/act-as/callback";
    private const string UserDomain = "example.test";

    private static readonly JsonElement Vectors = Fixtures.LoadRegularRp("act_as_grantee_signing.json");

    private static JsonElement LocalRpCase() =>
        Vectors.Get("cases").AsArray().First(c => c.Get("name").AsString() == "local_rp_grantee");

    private static byte[] ScopeSetCbor() =>
        Fixtures.Hex(LocalRpCase().Get("grant_request").Get("inputs").Get("scope_set_signed_cbor_hex").AsString());

    private static Identity.LocalRpKeyMaterial VectorKeyMaterial()
    {
        var local = Vectors.Get("local_rp_grantee");
        var descriptor = Codec.DecodeSignedLocalRpDescriptor(Fixtures.Hex(local.Get("signed_descriptor_cbor_hex").AsString()));
        var inner = Codec.DecodeLocalRpDescriptor(descriptor.Descriptor);
        return new Identity.LocalRpKeyMaterial(
            Fixtures.Hex(local.Get("signing_private_key_hex").AsString()),
            inner.SigningPublicKey,
            new byte[32],
            inner.EncryptionPublicKey,
            descriptor,
            local.Get("fingerprint").AsString());
    }

    private static long? OptLong(JsonElement obj, string key)
    {
        var v = obj.GetOrNull(key);
        return v is null || v.Value.IsNull() ? null : v.Value.AsLong();
    }

    private static Identity.LocalRpKeyMaterial FreshIdentity(DateTimeOffset now) =>
        Identity.GenerateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("act-as-test", now));

    private static IDnsResolver FailingDns() => new FuncResolver(_ => throw new SdkException(SdkException.ErrorKind.Dns, "SERVFAIL"));

    private sealed class FuncResolver(Func<string, IReadOnlyList<string>> lookup) : IDnsResolver
    {
        public IReadOnlyList<string> TxtLookup(string name) => lookup(name);
    }

    [Fact]
    public void LocalRpGranteeVectorsAreByteExact()
    {
        var km = VectorKeyMaterial();
        var c = LocalRpCase();
        Assert.Equal(c.Get("grantee").Get("local_rp_descriptor_fingerprint").AsString(), km.Fingerprint);
        Assert.Equal(ActAs.GrantRequestTag, Vectors.Get("tags").Get("grant_request").AsString());
        Assert.Equal(ActAs.RefreshRequestTag, Vectors.Get("tags").Get("refresh_request").AsString());
        Assert.Equal(ActAs.PresentationTag, Vectors.Get("tags").Get("presentation").AsString());
        var grantee = ActAs.LocalRpGrantee(km);

        var g = c.Get("grant_request");
        var gi = g.Get("inputs");
        var request = new ActAsGrantRequest(
            grantee,
            Codec.DecodeSignedActAsScopeSet(Fixtures.Hex(gi.Get("scope_set_signed_cbor_hex").AsString())),
            OptLong(gi, "requested_lifetime_seconds"),
            OptLong(gi, "requested_renewal_window_seconds"),
            gi.Get("callback_url").AsString(),
            gi.Get("nonce").AsString(),
            gi.Get("requested_at").AsString(),
            gi.Get("expires_at").AsString());
        var signed = ActAs.SignGrantRequest(request, km);
        Assert.Equal(g.Get("request_cbor_hex").AsString(), Hex.Encode(signed.Request));
        Assert.Equal(
            g.Get("signature_input_cbor_hex").AsString(),
            Hex.Encode(LocalRp.EnvelopeSignatureInput(ActAs.GrantRequestTag, signed.Request)));
        Assert.Equal(g.Get("signed_cbor_hex").AsString(), Hex.Encode(Codec.EncodeSignedActAsGrantRequest(signed)));
        Assert.Equal(g.Get("url_param").AsString(), ActAs.SignedGrantRequestToUrlParam(signed));

        var r = c.Get("refresh_request");
        var ri = r.Get("inputs");
        var refresh = new ActAsRefreshRequest(
            ri.Get("grant_id").AsString(),
            grantee,
            ri.Get("requested_at").AsString(),
            ri.Get("expires_at").AsString(),
            ri.Get("nonce").AsString());
        var signedRefresh = ActAs.SignRefreshRequest(refresh, km);
        Assert.Equal(r.Get("request_cbor_hex").AsString(), Hex.Encode(signedRefresh.Request));
        Assert.Equal(r.Get("signed_cbor_hex").AsString(), Hex.Encode(Codec.EncodeSignedActAsRefreshRequest(signedRefresh)));

        var p = c.Get("presentation");
        var pi = p.Get("inputs");
        var grant = Codec.DecodeSignedActAsGrant(Fixtures.Hex(pi.Get("grant_signed_cbor_hex").AsString()));
        var aud = pi.Get("audience");
        var credential = ActAs.Present(
            grant,
            new ApplicationRef(aud.Get("subject_user_id").AsString(), aud.Get("subject_domain").AsString(), aud.Get("application_id").AsString()),
            Fixtures.Hex(pi.Get("request_digest_hex").AsString()),
            DateTimeOffset.Parse(pi.Get("presented_at").AsString(), System.Globalization.CultureInfo.InvariantCulture),
            Fixtures.Hex(pi.Get("nonce_hex").AsString()),
            km);
        Assert.Equal(p.Get("grant_hash_hex").AsString(), Hex.Encode(ActAs.GrantHash(grant.Grant)));
        Assert.Equal(p.Get("presentation_cbor_hex").AsString(), Hex.Encode(credential.Presentation.Presentation));
        Assert.Equal(p.Get("credential_cbor_hex").AsString(), Hex.Encode(ActAs.EncodeCredential(credential)));
    }

    [Fact]
    public void FormatTimeIsWholeSecondUtc()
    {
        var t = new DateTimeOffset(2026, 10, 6, 14, 5, 0, TimeSpan.FromHours(2)).AddTicks(9_876_543);
        Assert.Equal("2026-10-06T12:05:00Z", ActAs.FormatTime(t));
    }

    [Fact]
    public void BeginActAsUsesDiscoveredHostAndSignsTheRequest()
    {
        var now = new DateTimeOffset(2026, 10, 6, 11, 59, 0, TimeSpan.Zero);
        var km = FreshIdentity(now);
        var dns = new FuncResolver(name => name == $"_linkkeys_apis.{IdentityDomain}"
            ? ["v=lk1 tcp=x.example.test https=login.example.test/lk"]
            : throw new SdkException(SdkException.ErrorKind.Dns, $"no fake record for {name}"));
        var result = ActAs.BeginActAs(new ActAs.BeginActAsConfig(
            km, $"alice@{IdentityDomain}", ScopeSetCbor(), CallbackUrl, now, RequestedLifetimeSeconds: 1800, Dns: dns));

        const string prefix = "https://login.example.test/lk/auth/act-as?signed_request=";
        Assert.StartsWith(prefix, result.RedirectUrl);
        Assert.DoesNotContain("username=", result.RedirectUrl);
        Assert.Equal(IdentityDomain, result.Pending.UserDomain);
        Assert.Equal(CallbackUrl, result.Pending.CallbackUrl);
        Assert.Equal(43, result.Pending.Nonce.Length);
        Assert.Equal(result.Pending, ActAs.PendingActAs.FromBytes(result.Pending.ToBytes()));

        var signed = Codec.DecodeSignedActAsGrantRequest(UrlEncoding.DecodeUrlParam(result.RedirectUrl[prefix.Length..]));
        Assert.True(Crypto.Crypto.VerifyEd25519(
            LocalRp.EnvelopeSignatureInput(ActAs.GrantRequestTag, signed.Request),
            signed.Proof.Signature.Signature,
            km.SigningPublicKey));
        Assert.Equal(km.Fingerprint, signed.Proof.Signature.SignedByKeyId);
        Assert.Null(signed.Proof.ApplicationInstanceId);
        Assert.Equal(Codec.EncodeSignedLocalRpDescriptor(km.Descriptor), Codec.EncodeSignedLocalRpDescriptor(signed.Proof.LocalRpDescriptor!));

        var request = Codec.DecodeActAsGrantRequest(signed.Request);
        Assert.Null(request.Grantee.Application);
        Assert.Equal(km.Fingerprint, request.Grantee.LocalRpDescriptorFingerprint);
        Assert.Equal(result.Pending.Nonce, request.Nonce);
        Assert.Equal("2026-10-06T11:59:00Z", request.RequestedAt);
        Assert.Equal("2026-10-06T12:04:00Z", request.ExpiresAt);
        Assert.Equal(1800L, request.RequestedLifetimeSeconds);
        Assert.Null(request.RequestedRenewalWindowSeconds);
        Assert.Equal(ScopeSetCbor(), Codec.EncodeSignedActAsScopeSet(request.ScopeSet));
    }

    [Fact]
    public void BeginActAsFallsBackToIdentityDomain()
    {
        var now = new DateTimeOffset(2026, 10, 6, 11, 59, 0, TimeSpan.Zero);
        var result = ActAs.BeginActAs(new ActAs.BeginActAsConfig(
            FreshIdentity(now), IdentityDomain, ScopeSetCbor(), CallbackUrl, now, Dns: FailingDns()));
        Assert.StartsWith($"https://{IdentityDomain}/auth/act-as?signed_request=", result.RedirectUrl);
    }

    [Fact]
    public void BeginActAsRejectsBadInput()
    {
        var now = new DateTimeOffset(2026, 10, 6, 11, 59, 0, TimeSpan.Zero);
        var km = FreshIdentity(now);
        var tooLong = Assert.Throws<SdkException>(() => ActAs.BeginActAs(new ActAs.BeginActAsConfig(
            km, IdentityDomain, ScopeSetCbor(), CallbackUrl, now, RequestWindow: TimeSpan.FromSeconds(901), Dns: FailingDns())));
        Assert.Equal(SdkException.ErrorKind.InvalidInput, tooLong.Kind);

        ActAs.BeginActAs(new ActAs.BeginActAsConfig(
            km, IdentityDomain, ScopeSetCbor(), CallbackUrl, now, RequestWindow: TimeSpan.FromSeconds(900), Dns: FailingDns()));

        var badScopeSet = Assert.Throws<SdkException>(() => ActAs.BeginActAs(new ActAs.BeginActAsConfig(
            km, IdentityDomain, [0x01], CallbackUrl, now, Dns: FailingDns())));
        Assert.Equal(SdkException.ErrorKind.InvalidInput, badScopeSet.Kind);

        Assert.Throws<SdkException>(() => ActAs.BeginActAs(new ActAs.BeginActAsConfig(
            km, IdentityDomain, ScopeSetCbor(), "ftp://x", now, Dns: FailingDns())));
    }

    [Fact]
    public void CallbackReturnsGrantIdWhenNonceMatches()
    {
        var pending = new ActAs.PendingActAs("n0nce-_value", IdentityDomain, CallbackUrl);
        Assert.Equal("grant 1", ActAs.CompleteActAsCallback(pending, $"{CallbackUrl}?x=1&act_as_grant_id=grant%201&nonce=n0nce-_value"));
        Assert.Equal("g2", ActAs.CompleteActAsCallback(pending, "nonce=n0nce-_value&act_as_grant_id=g2"));
    }

    [Fact]
    public void CallbackRejectsNonceMismatchAndMissingFields()
    {
        var pending = new ActAs.PendingActAs("expected", IdentityDomain, CallbackUrl);
        var mismatch = Assert.Throws<LocalRpError>(() => ActAs.CompleteActAsCallback(pending, $"{CallbackUrl}?act_as_grant_id=g&nonce=other"));
        Assert.Equal(LocalRpError.ErrorKind.NonceMismatch, mismatch.Kind);
        Assert.Throws<SdkException>(() => ActAs.CompleteActAsCallback(pending, $"{CallbackUrl}?act_as_grant_id=g"));
        Assert.Throws<SdkException>(() => ActAs.CompleteActAsCallback(pending, $"{CallbackUrl}?nonce=expected"));
        Assert.Throws<SdkException>(() => ActAs.CompleteActAsCallback(pending, $"{CallbackUrl}?act_as_grant_id=g&nonce=expected&act_as_grant_id=h"));
        Assert.Throws<SdkException>(() => ActAs.CompleteActAsCallback(pending, $"{CallbackUrl}?act_as_grant_id=g%zz&nonce=expected"));
    }

    private static byte[] Frame(RpcEnvelope.Response response)
    {
        var data = response.Encode();
        var framed = new byte[4 + data.Length];
        framed[0] = (byte)(data.Length >> 24);
        framed[1] = (byte)(data.Length >> 16);
        framed[2] = (byte)(data.Length >> 8);
        framed[3] = (byte)data.Length;
        data.CopyTo(framed, 4);
        return framed;
    }

    /// <summary>
    /// A grant as a home domain stores it. Only the identifying fields matter to
    /// the grantee; the audience checks the signature.
    /// </summary>
    private static SignedActAsGrant ServedGrant(string grantId, string fingerprint, string subjectDomain)
    {
        static Cbor.Value Map(params (string Key, Cbor.Value Value)[] entries) =>
            Cbor.VMapOf(entries.Select(e => Cbor.EntryOf(e.Key, e.Value)).ToList());
        var grant = Map(
            ("grant_id", Cbor.VTextOf(grantId)),
            ("user_id", Cbor.VTextOf("user-1")),
            ("subject_domain", Cbor.VTextOf(subjectDomain)),
            ("grantee", Map(("local_rp_descriptor_fingerprint", Cbor.VTextOf(fingerprint)))),
            ("audience", Map(
                ("subject_user_id", Cbor.VTextOf("audience-owner")),
                ("subject_domain", Cbor.VTextOf("audience.test")),
                ("application_id", Cbor.VTextOf("audience-app")))),
            ("scope_set", Map(
                ("scope_set", Cbor.VBytesOf([0xa0])),
                ("signer_instance_id", Cbor.VTextOf("audience-inst")),
                ("signatures", Cbor.VArrayOf([Map(
                    ("signed_by_key_id", Cbor.VTextOf("audience-key")),
                    ("signature", Cbor.VBytesOf(new byte[64])))])))),
            ("approved_scope", Cbor.VArrayOf([Cbor.VTextOf("read")])),
            ("issued_at", Cbor.VTextOf("2026-10-06T12:00:00Z")),
            ("expires_at", Cbor.VTextOf("2026-10-06T13:00:00Z")),
            ("series_issued_at", Cbor.VTextOf("2026-10-06T12:00:00Z")),
            ("renewable_until", Cbor.VTextOf("2026-10-06T13:00:00Z")));
        return new SignedActAsGrant(Cbor.Encode(grant), [new ClaimSignature(subjectDomain, "domain-key", new byte[64])]);
    }

    [Theory]
    [InlineData("grant-2", null, UserDomain)]
    [InlineData("grant-1", "another-local-rp", UserDomain)]
    [InlineData("grant-1", null, "other.test")]
    public void RefreshRefusesAGrantForAnotherGrantIdGranteeOrDomain(string grantId, string? fingerprint, string subjectDomain)
    {
        var now = new DateTimeOffset(2026, 10, 6, 12, 40, 0, TimeSpan.Zero);
        var km = FreshIdentity(now);
        var served = ServedGrant(grantId, fingerprint ?? km.Fingerprint, subjectDomain);
        var domain = Crypto.Crypto.GenerateEd25519KeyPair();
        var response = Frame(RpcEnvelope.Response.Ok(
            "RefreshActAsGrantResponse", Codec.EncodeRefreshActAsGrantResponse(new RefreshActAsGrantResponse(served, false))));
        using var fakeIdp = FakeIdp.Start(UserDomain, domain.PrivateKeySeed, [response]);

        var e = Assert.Throws<LocalRpError>(() => ActAs.RefreshActAsGrant(new ActAs.RefreshActAsGrantConfig(
            km, UserDomain, "grant-1", now,
            Dns: new RotatingDnsResolver(UserDomain, Crypto.Crypto.Fingerprint(domain.PublicKey), fakeIdp.Ports))));
        Assert.Equal(LocalRpError.ErrorKind.GrantMismatch, e.Kind);
    }

    [Fact]
    public void RefreshCallsActAsRefreshGrantAndDecodesTheResponse()
    {
        var now = new DateTimeOffset(2026, 10, 6, 12, 40, 0, TimeSpan.Zero);
        var km = FreshIdentity(now);
        var grant = ServedGrant("grant-1", km.Fingerprint, UserDomain);
        var grantBytes = Codec.EncodeSignedActAsGrant(grant);
        var domain = Crypto.Crypto.GenerateEd25519KeyPair();
        var response = Frame(RpcEnvelope.Response.Ok(
            "RefreshActAsGrantResponse", Codec.EncodeRefreshActAsGrantResponse(new RefreshActAsGrantResponse(grant, true))));
        using var fakeIdp = FakeIdp.Start(UserDomain, domain.PrivateKeySeed, [response], captureRequests: true);

        var result = ActAs.RefreshActAsGrant(new ActAs.RefreshActAsGrantConfig(
            km, UserDomain, "grant-1", now,
            Dns: new RotatingDnsResolver(UserDomain, Crypto.Crypto.Fingerprint(domain.PublicKey), fakeIdp.Ports)));
        Assert.True(result.Signed);
        Assert.Equal(grantBytes, Codec.EncodeSignedActAsGrant(result.Grant));
        Assert.Equal("grant-1", ActAs.DecodeGrantUnverified(result.Grant).GrantId);

        var received = fakeIdp.ReceivedBytes(0, TimeSpan.FromSeconds(10));
        int len = (received[0] << 24) | (received[1] << 16) | (received[2] << 8) | received[3];
        var envelope = RpcEnvelope.DecodeRequest(received[4..(4 + len)]);
        Assert.Equal("ActAs", envelope.Service);
        Assert.Equal("refresh-grant", envelope.Op);

        var signed = Codec.DecodeRefreshActAsGrantRequest(envelope.Payload).Request;
        Assert.True(Crypto.Crypto.VerifyEd25519(
            LocalRp.EnvelopeSignatureInput(ActAs.RefreshRequestTag, signed.Request),
            signed.Proof.Signature.Signature,
            km.SigningPublicKey));
        Assert.Equal(km.Fingerprint, signed.Proof.Signature.SignedByKeyId);
        var request = Codec.DecodeActAsRefreshRequest(signed.Request);
        Assert.Equal("grant-1", request.GrantId);
        Assert.Equal(km.Fingerprint, request.Grantee.LocalRpDescriptorFingerprint);
        Assert.Equal("2026-10-06T12:40:00Z", request.RequestedAt);
        Assert.Equal("2026-10-06T12:45:00Z", request.ExpiresAt);
        Assert.Equal(43, request.Nonce.Length);
    }

    [Fact]
    public void RefreshSurfacesTransportErrors()
    {
        var now = new DateTimeOffset(2026, 10, 6, 12, 40, 0, TimeSpan.Zero);
        var km = FreshIdentity(now);
        var domain = Crypto.Crypto.GenerateEd25519KeyPair();
        var response = Frame(RpcEnvelope.Response.TransportError(RpcEnvelope.Status.Forbidden, "not yours"));
        using var fakeIdp = FakeIdp.Start(UserDomain, domain.PrivateKeySeed, [response]);

        var e = Assert.Throws<SdkException>(() => ActAs.RefreshActAsGrant(new ActAs.RefreshActAsGrantConfig(
            km, UserDomain, "grant-1", now,
            Dns: new RotatingDnsResolver(UserDomain, Crypto.Crypto.Fingerprint(domain.PublicKey), fakeIdp.Ports))));
        Assert.Equal(SdkException.ErrorKind.Server, e.Kind);
        Assert.Equal(RpcEnvelope.Status.Forbidden, e.ServerStatus);
    }
}
