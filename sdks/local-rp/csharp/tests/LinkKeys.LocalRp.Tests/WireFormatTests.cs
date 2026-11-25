using System.Text;
using LinkKeys.LocalRp.Tests.TestUtil;
using LinkKeys.LocalRp.Wire;
using static LinkKeys.LocalRp.Wire.Types;

namespace LinkKeys.LocalRp.Tests;

/// <summary>
/// The CSIL wire rules that the conformance vectors do not reject on their own:
/// timestamps are tag 0 + RFC 3339 text, closed vocabularies are numbers, and signed
/// tuple payloads refuse a fraction of a second.
/// </summary>
public class WireFormatTests
{
    private static readonly DateTimeOffset Created = Fixtures.Time("2026-01-01T00:00:00Z");
    private static readonly DateTimeOffset Expires = Fixtures.Time("2126-01-01T00:00:00Z");

    private static DomainPublicKey SigningKey(byte[] publicKey) =>
        new("key-1", publicKey, Crypto.Crypto.Fingerprint(publicKey), "ed25519", "sign", Created, Expires, null, null, null);

    [Fact]
    public void TimestampEncodesAsTagZeroUtcText()
    {
        var instant = new DateTimeOffset(2026, 1, 1, 2, 0, 0, TimeSpan.FromHours(2));
        Assert.Equal("c074323032362d30312d30315430303a30303a30305a", Crypto.Hex.Encode(Cbor.Encode(Cbor.VTimestamp(instant))));
        Assert.Equal("2026-01-01T00:00:00.500Z", Cbor.FormatTimestamp(instant.AddMilliseconds(500)));
    }

    [Fact]
    public void TimestampDecodeAcceptsAnyOffsetAndNormalizesToUtc()
    {
        var v = Cbor.VTagOf(0, Cbor.VTextOf("2026-01-01T02:00:00.123456789+02:00"));
        var t = Cbor.AsTimestamp(v);
        Assert.Equal(TimeSpan.Zero, t.Offset);
        Assert.Equal(Fixtures.Time("2026-01-01T00:00:00.1234567Z"), t);
    }

    [Theory]
    [InlineData(false, "2026-01-01T00:00:00Z")] // bare text, no tag 0
    [InlineData(true, "2026-01-01 00:00:00Z")] // not RFC 3339
    [InlineData(true, "2026-01-01T00:00:00")] // no offset
    public void TimestampDecodeRejectsWrongShape(bool tagged, string text)
    {
        Cbor.Value v = tagged ? Cbor.VTagOf(0, Cbor.VTextOf(text)) : Cbor.VTextOf(text);
        Assert.Throws<Cbor.CborDecodeException>(() => Cbor.AsTimestamp(v));
    }

    [Fact]
    public void TimestampDecodeRejectsOtherTags()
    {
        Assert.Throws<Cbor.CborDecodeException>(() => Cbor.AsTimestamp(Cbor.VTagOf(1, Cbor.VInteger(0))));
    }

    [Fact]
    public void EnumsAreNumbersOnTheWire()
    {
        var key = SigningKey(new byte[32]);
        var map = Cbor.Decode(Codec.EncodeDomainPublicKey(key));
        Assert.Equal(1, Cbor.AsInt(Cbor.Require(map, "algorithm")));
        Assert.Equal(1, Cbor.AsInt(Cbor.Require(map, "key_usage")));
        Assert.Equal(2, Cbor.AeadSuite.Number("chacha20-poly1305"));
        Assert.Equal("aes-256-gcm", Cbor.AeadSuite.Decode(Cbor.VInteger(1)));
        Assert.Throws<Cbor.CborDecodeException>(() => Cbor.KeyUsage.Decode(Cbor.VInteger(99)));
        Assert.Throws<Cbor.CborDecodeException>(() => Cbor.KeyUsage.Decode(Cbor.VTextOf("sign")));
    }

    [Fact]
    public void ClaimWithFractionalSignedTimeIsRefused()
    {
        var pair = Crypto.Crypto.GenerateEd25519KeyPair();
        var keys = new[] { new Claims.DomainKeySet("example.test", [SigningKey(pair.PublicKey)]) };
        var spec = new Claims.ClaimSpec(
            "claim-1", "handle", Encoding.UTF8.GetBytes("v"), "user-1", "example.test", null, Created.AddMilliseconds(500));
        var signer = new Claims.ClaimSigner("example.test", "key-1", pair.PrivateKeySeed);

        var signError = Assert.Throws<ClaimError>(() => Claims.SignClaim(spec, [signer]));
        Assert.Equal(ClaimError.ErrorKind.BadTimestamp, signError.Kind);

        var claim = Claims.SignClaim(spec with { AttestedAt = Created }, [signer]);
        Claims.VerifyClaim(claim, "example.test", keys);
        var verifyError = Assert.Throws<ClaimError>(
            () => Claims.VerifyClaim(claim with { AttestedAt = Created.AddMilliseconds(500) }, "example.test", keys));
        Assert.Equal(ClaimError.ErrorKind.BadTimestamp, verifyError.Kind);
    }

    [Fact]
    public void RevocationWithFractionalRevokedAtCountsNoSigners()
    {
        var a = Crypto.Crypto.GenerateEd25519KeyPair();
        var b = Crypto.Crypto.GenerateEd25519KeyPair();
        var keys = new List<DomainPublicKey>
        {
            SigningKey(a.PublicKey) with { KeyId = "a" },
            SigningKey(b.PublicKey) with { KeyId = "b" },
        };
        var payload = Revocation.RevocationPayload("target", "fp", Created.ToUnixTimeSeconds(), "example.test");
        var signatures = new List<ClaimSignature>
        {
            new("example.test", "a", Crypto.Crypto.SignEd25519(payload, a.PrivateKeySeed)),
            new("example.test", "b", Crypto.Crypto.SignEd25519(payload, b.PrivateKeySeed)),
        };
        var cert = new RevocationCertificate("target", "fp", Created, signatures);

        Assert.Equal(2, Revocation.CountValidSigners(cert, keys, "example.test"));
        Assert.Equal(0, Revocation.CountValidSigners(cert with { RevokedAt = Created.AddMilliseconds(500) }, keys, "example.test"));
    }
}
