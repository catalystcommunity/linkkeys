using LinkKeys.LocalRp.Tests.TestUtil;

namespace LinkKeys.LocalRp.Tests;

/// <summary>Conformance vectors: <c>expirations.json</c>.</summary>
public class ExpirationsConformanceTests
{
    [Fact]
    public void CheckExpirationsThresholdsViaSdkWrapper()
    {
        var d = Fixtures.Load("expirations.json").Get("check_expirations");
        var expiresAt = d.Get("expires_at").AsString();
        var cases = d.Get("cases").AsArray().ToList();
        Assert.Equal(11, cases.Count);

        // Build an identity whose descriptor expires at exactly `expiresAt`, exercising
        // LinkKeysLocalRp.CheckExpirations end to end (identity -> descriptor ->
        // threshold logic), not the underlying LocalRp function directly.
        var expires = DateTimeOffset.Parse(expiresAt);
        var createdAt = expires - TimeSpan.FromDays(3650);
        var config = new Identity.GenerateLocalRpIdentityConfig(
            "Conformance Test App", createdAt, Lifetime: expires - createdAt);
        var identity = Identity.GenerateLocalRpIdentity(config);

        foreach (var c in cases)
        {
            var now = DateTimeOffset.Parse(c.Get("now").AsString());
            var status = LinkKeysLocalRp.CheckExpirations(identity, now);
            Assert.Equal(c.Get("expected_level").AsString(), status.Level.WireName());
        }
    }

    [Fact]
    public void CheckTimestampsSkewBoundariesAreExact()
    {
        var d = Fixtures.Load("expirations.json").Get("check_timestamps");
        var issuedAt = d.Get("issued_at").AsString();
        var expiresAt = d.Get("expires_at").AsString();
        var skew = d.Get("skew_seconds").AsLong();
        var cases = d.Get("cases").AsArray().ToList();
        Assert.Equal(4, cases.Count);

        foreach (var c in cases)
        {
            var now = DateTimeOffset.Parse(c.Get("now").AsString());
            var expectedValid = c.Get("expected_valid").AsBoolean();
            bool valid;
            try
            {
                LocalRp.CheckTimestamps(issuedAt, expiresAt, now, skew);
                valid = true;
            }
            catch (LocalRpError)
            {
                valid = false;
            }

            Assert.Equal(expectedValid, valid);
        }
    }
}
