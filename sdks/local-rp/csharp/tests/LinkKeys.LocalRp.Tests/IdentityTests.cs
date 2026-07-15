using LinkKeys.LocalRp.Crypto;
using LinkKeys.LocalRp.Wire;

namespace LinkKeys.LocalRp.Tests;

/// <summary>Unit tests for <see cref="Identity"/> (mirrors the Rust/Go/Java SDKs' own identity-module tests).</summary>
public class IdentityTests
{
    private static Identity.LocalRpKeyMaterial Material() =>
        Identity.GenerateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("Test App", DateTimeOffset.UtcNow));

    [Fact]
    public void GenerateIdentityDefaultsBothSuitesAndTenYearLifetime()
    {
        var identity = Material();
        Assert.Equal(64, identity.Fingerprint.Length);
        Assert.Equal(Crypto.Crypto.Fingerprint(identity.SigningPublicKey), identity.Fingerprint);

        var descriptor = Codec.DecodeLocalRpDescriptor(identity.Descriptor.Descriptor);
        Assert.Equal("Test App", descriptor.AppName);
        Assert.Equal(AeadSuiteExtensions.AllSupported, descriptor.SupportedSuites);
    }

    [Fact]
    public void GenerateIdentityRejectsEmptyAppName() =>
        Assert.Throws<SdkException>(() =>
            Identity.GenerateLocalRpIdentity(new Identity.GenerateLocalRpIdentityConfig("", DateTimeOffset.UtcNow)));

    [Fact]
    public void GenerateIdentityRejectsEmptySuiteList()
    {
        var config = new Identity.GenerateLocalRpIdentityConfig("Test App", DateTimeOffset.UtcNow, SupportedSuites: []);
        Assert.Throws<SdkException>(() => Identity.GenerateLocalRpIdentity(config));
    }

    [Fact]
    public void SigningAndEncryptionKeyByteRoundTrips()
    {
        var key = new byte[32];
        Array.Fill(key, (byte)7);
        Assert.Equal(key, Identity.SigningKeyFromBytes(Identity.SigningKeyToBytes(key)));
        Assert.Equal(key, Identity.EncryptionKeyFromBytes(Identity.EncryptionKeyToBytes(key)));
        Assert.Throws<SdkException>(() => Identity.SigningKeyFromBytes(new byte[31]));
        Assert.Throws<SdkException>(() => Identity.EncryptionKeyFromBytes(new byte[33]));
    }

    [Fact]
    public void FingerprintStringRoundTripValidatesHex()
    {
        var identity = Material();
        var s = Identity.FingerprintToString(identity.Fingerprint);
        Assert.Equal(identity.Fingerprint, Identity.FingerprintFromString(s));
        Assert.Throws<SdkException>(() => Identity.FingerprintFromString("not-hex"));
        Assert.Throws<SdkException>(() => Identity.FingerprintFromString(new string('a', 63)));
    }

    [Fact]
    public void IdentityBundleByteRoundTrip()
    {
        var identity = Material();
        var bytes = Identity.LocalRpIdentityToBytes(identity);
        var roundTripped = Identity.LocalRpIdentityFromBytes(bytes);

        Assert.Equal(identity.SigningPrivateKey, roundTripped.SigningPrivateKey);
        Assert.Equal(identity.SigningPublicKey, roundTripped.SigningPublicKey);
        Assert.Equal(identity.EncryptionPrivateKey, roundTripped.EncryptionPrivateKey);
        Assert.Equal(identity.EncryptionPublicKey, roundTripped.EncryptionPublicKey);
        Assert.Equal(identity.Fingerprint, roundTripped.Fingerprint);
        Assert.Equal(identity.Descriptor.Descriptor, roundTripped.Descriptor.Descriptor);
        Assert.Equal(identity.Descriptor.Signature, roundTripped.Descriptor.Signature);
    }

    [Fact]
    public void IdentityBundleRejectsBadMagicAndTruncation()
    {
        var identity = Material();
        var bytes = Identity.LocalRpIdentityToBytes(identity);
        var badMagic = (byte[])bytes.Clone();
        badMagic[0] ^= 0xff;
        Assert.Throws<SdkException>(() => Identity.LocalRpIdentityFromBytes(badMagic));

        var truncated = bytes[..10];
        Assert.Throws<SdkException>(() => Identity.LocalRpIdentityFromBytes(truncated));
    }

    [Fact]
    public void CheckExpirationsWrapsThresholds()
    {
        var config = new Identity.GenerateLocalRpIdentityConfig("Test App", DateTimeOffset.UtcNow, Lifetime: TimeSpan.FromDays(100));
        var identity = Identity.GenerateLocalRpIdentity(config);

        var status = LinkKeysLocalRp.CheckExpirations(identity, DateTimeOffset.UtcNow);
        Assert.Equal(LocalRp.ExpirationLevel.Notice, status.Level);

        var farFuture = DateTimeOffset.UtcNow + TimeSpan.FromDays(200);
        var expired = LinkKeysLocalRp.CheckExpirations(identity, farFuture);
        Assert.Equal(LocalRp.ExpirationLevel.Expired, expired.Level);
    }
}
