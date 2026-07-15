using LinkKeys.LocalRp.Dns;
using LinkKeys.LocalRp.Tests.TestUtil;

namespace LinkKeys.LocalRp.Tests;

/// <summary>Conformance vectors: <c>dns.json</c>.</summary>
public class DnsConformanceTests
{
    [Fact]
    public void LinkKeysTxtCases()
    {
        var d = Fixtures.Load("dns.json").Get("linkkeys_txt");

        foreach (var c in d.Get("valid_cases").AsArray())
        {
            var txt = c.Get("txt").AsString();
            var record = LinkKeys.LocalRp.Dns.Dns.ParseLinkKeysTxt(txt);
            var expected = c.Get("expected_fingerprints").AsArray().Select(v => v.AsString()).ToList();
            Assert.Equal(expected, record.Fingerprints);
        }

        foreach (var c in d.Get("invalid_cases").AsArray())
        {
            var txt = c.Get("txt").AsString();
            var err = Assert.Throws<DnsParseError>(() => LinkKeys.LocalRp.Dns.Dns.ParseLinkKeysTxt(txt));
            Assert.Equal(c.Get("expected_error").AsString(), err.Symbol);
        }

        Assert.True(d.Get("no_record_case").Get("documentation_only").AsBoolean());
    }

    [Fact]
    public void LinkKeysApisTxtCases()
    {
        var d = Fixtures.Load("dns.json").Get("linkkeys_apis_txt");

        foreach (var c in d.Get("valid_cases").AsArray())
        {
            var txt = c.Get("txt").AsString();
            var apis = LinkKeys.LocalRp.Dns.Dns.ParseLinkKeysApisTxt(txt);
            var expectedTcp = c.Get("expected_tcp").IsNull() ? null : c.Get("expected_tcp").AsString();
            var expectedHttps = c.Get("expected_https_base").IsNull() ? null : c.Get("expected_https_base").AsString();
            Assert.Equal(expectedTcp, apis.Tcp);
            Assert.Equal(expectedHttps, apis.HttpsBase);
        }

        foreach (var c in d.Get("invalid_cases").AsArray())
        {
            var txt = c.Get("txt").AsString();
            var err = Assert.Throws<DnsParseError>(() => LinkKeys.LocalRp.Dns.Dns.ParseLinkKeysApisTxt(txt));
            Assert.Equal(c.Get("expected_error").AsString(), err.Symbol);
        }

        Assert.Equal((long)LinkKeys.LocalRp.Dns.Dns.DefaultTcpPort, Fixtures.Load("dns.json").Get("default_tcp_port").AsLong());
    }
}
