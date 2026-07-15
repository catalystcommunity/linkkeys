using LinkKeys.LocalRp.Tests.TestUtil;

namespace LinkKeys.LocalRp.Tests;

/// <summary>Conformance vectors: <c>tickets.json</c>.</summary>
public class TicketsConformanceTests
{
    [Fact]
    public void HashPairsMatchFingerprintRoutine()
    {
        var d = Fixtures.Load("tickets.json");
        var cases = d.Get("cases").AsArray().ToList();
        Assert.NotEmpty(cases);
        foreach (var c in cases)
        {
            var ticket = Fixtures.Hex(c.Get("ticket_hex").AsString());
            Assert.Equal(32, ticket.Length);
            Assert.Equal(c.Get("sha256_hex").AsString(), Crypto.Crypto.Fingerprint(ticket));
        }
    }
}
