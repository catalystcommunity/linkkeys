using System.Text;
using LinkKeys.LocalRp.Crypto;
using LinkKeys.LocalRp.Tests.TestUtil;

namespace LinkKeys.LocalRp.Tests;

/// <summary>Conformance vectors: <c>keys.json</c>.</summary>
public class KeysConformanceTests
{
    [Fact]
    public void FingerprintsRoundTripThroughSdkFingerprintHelpers()
    {
        var d = Fixtures.Load("keys.json");

        foreach (var node in new[] { d.Get("local_rp").Get("signing"), d.Get("domain_signing_key") })
        {
            var seed = Fixtures.Hex(node.Get("seed_hex").AsString());
            var expectedPublic = Fixtures.Hex(node.Get("public_key_hex").AsString());
            var expectedFp = node.Get("fingerprint_hex").AsString();

            // Confirm seed and public key correspond to the same Ed25519 keypair:
            // signing with the seed and verifying against the fixture's public key
            // must succeed.
            var message = Encoding.UTF8.GetBytes("conformance-check");
            var sig = Crypto.Crypto.SignEd25519(message, seed);
            Assert.True(Crypto.Crypto.VerifyEd25519(message, sig, expectedPublic));

            var computed = Crypto.Crypto.Fingerprint(expectedPublic);
            Assert.Equal(expectedFp, computed);

            // Round-trip through the SDK's own fingerprint string helpers.
            var s = Identity.FingerprintToString(computed);
            Assert.Equal(expectedFp, Identity.FingerprintFromString(s));

            Assert.Equal(32, seed.Length);
        }

        // FingerprintFromString must reject non-fingerprint strings even when they
        // happen to be valid hex of the wrong length.
        Assert.Throws<SdkException>(() => Identity.FingerprintFromString("deadbeef"));
    }

    [Fact]
    public void X25519PublicKeysDeriveFromPrivateKeys()
    {
        var d = Fixtures.Load("keys.json");
        foreach (var node in new[] { d.Get("local_rp").Get("encryption"), d.Get("domain_encryption_recipient") })
        {
            var priv = Fixtures.Hex(node.Get("private_key_hex").AsString());
            var expectedPublic = Fixtures.Hex(node.Get("public_key_hex").AsString());
            Assert.Equal(expectedPublic, Crypto.Crypto.DerivePublicFromX25519Private(priv));
        }
    }
}
