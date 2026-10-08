//! Browser endpoint discovery: resolve an identity domain's browser-facing
//! HTTPS base from its `_linkkeys_apis` TXT record, and build browser route
//! URLs against it. Mirrors `sdks/local-rp/go/browser.go`.
//!
//! The identity domain (the domain the user selected, e.g. `todandlorna.com`)
//! is a trust and discovery domain. It is not necessarily the host that
//! serves the browser login routes — the `https=` endpoint of
//! `_linkkeys_apis.<identity-domain>` is (docs/spec/trust-and-anchors.md:
//! "`https=` is the browser-facing endpoint"). These helpers are shared by
//! `beginLocalLogin` (route `browser_route_local_rp`) and by regular-RP
//! application glue (route `browser_route_authorize`), so discovery is
//! implemented once.
//!
//! URLs are parsed and emitted with `std.Uri`; the path join is the only
//! hand-written piece (`std.Uri` has no append-path helper), and it is
//! covered by the tests below.

const std = @import("std");
const dnsmod = @import("dns.zig");

/// The browser route for the DNS-less local-RP login flow.
pub const browser_route_local_rp = "/auth/local-rp";

/// The browser route for the regular (domain-keyed) RP login flow.
pub const browser_route_authorize = "/auth/authorize";

/// The browser route where a grantee asks the user's home domain for an
/// act-as grant (`act_as.zig`).
pub const browser_route_act_as = "/auth/act-as";

pub const BrowserEndpointError = error{
    /// The base is not `https://host[:port][/path]`.
    InvalidBrowserBase,
    /// The route does not start with `/`.
    InvalidRoute,
    /// No `_linkkeys_apis` record yielded a valid `https=` base.
    NoBrowserBase,
};

fn componentSlice(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |s| s,
    };
}

/// Checks that `base` is a usable https browser base URL: parseable, https
/// scheme, a host, an optional path prefix, and nothing else. A TXT record
/// value must never smuggle in userinfo, a query, a fragment, or (via
/// `parseLinkKeysApisTxt`'s unconditional `https://` prefix plus this check)
/// a non-HTTPS scheme.
fn validateBrowserBase(base: []const u8) error{InvalidBrowserBase}!std.Uri {
    // `std.Uri.parse` is lenient about character classes; a TXT value is
    // whitespace-tokenized already, but the exported builder takes any
    // string, so reject control characters and whitespace outright.
    for (base) |c| {
        if (c <= ' ' or c == 0x7f) return error.InvalidBrowserBase;
    }
    const uri = std.Uri.parse(base) catch return error.InvalidBrowserBase;
    if (!std.mem.eql(u8, uri.scheme, "https")) return error.InvalidBrowserBase;
    const host = uri.host orelse return error.InvalidBrowserBase;
    if (componentSlice(host).len == 0) return error.InvalidBrowserBase;
    if (uri.user != null or uri.password != null or uri.query != null or uri.fragment != null) {
        return error.InvalidBrowserBase;
    }
    return uri;
}

/// Resolves `identity_domain`'s browser-facing HTTPS base URL (e.g.
/// `https://linkkeys.todandlorna.com` or
/// `https://login.example.com/linkkeys`) from its
/// `_linkkeys_apis.<identity_domain>` TXT record.
///
/// It selects the first LinkKeys v1 record whose `https=` endpoint is a
/// valid browser base; invalid TXT records and records without `https=` are
/// skipped. It returns an error when the lookup fails or no record yields a
/// valid base — the caller decides the fallback (`beginLocalLogin` falls
/// back to `https://<identity_domain>`).
///
/// The resolved base is a service location only. Identity verification
/// stays bound to the identity domain — never bind trust decisions to the
/// host this returns.
pub fn resolveBrowserBase(allocator: std.mem.Allocator, dns: dnsmod.DnsResolver, identity_domain: []const u8) ![]const u8 {
    const name = try dnsmod.linkKeysApisDnsName(allocator, identity_domain);
    defer allocator.free(name);
    const txts = try dns.txtLookup(allocator, name);
    for (txts) |txt| {
        const apis = dnsmod.parseLinkKeysApisTxt(allocator, txt) catch continue;
        const base = apis.https_base orelse continue;
        _ = validateBrowserBase(base) catch continue;
        return base;
    }
    return error.NoBrowserBase;
}

fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

/// Builds the full browser URL for `route` (e.g. `browser_route_local_rp`)
/// under `browser_base`, carrying `signed_request` as the `signed_request`
/// query parameter. A path prefix in the base is preserved: base
/// `https://login.example.com/linkkeys` and route `/auth/local-rp` produce
/// `https://login.example.com/linkkeys/auth/local-rp?...`.
///
/// The URL is emitted with `std.Uri.writeToStream`. `signed_request` values
/// are URL-param-encoded (unpadded base64url) by construction; the query
/// value is percent-encoded with the unreserved set, which passes base64url
/// through byte-identically and can never corrupt the query.
pub fn buildBrowserEndpoint(allocator: std.mem.Allocator, browser_base: []const u8, route: []const u8, signed_request: []const u8) ![]u8 {
    var uri = try validateBrowserBase(browser_base);
    if (route.len == 0 or route[0] != '/') return error.InvalidRoute;

    const base_path = std.mem.trimRight(u8, componentSlice(uri.path), "/");
    const joined_path = try std.mem.concat(allocator, u8, &.{ base_path, route });
    defer allocator.free(joined_path);

    var query = std.ArrayList(u8).init(allocator);
    defer query.deinit();
    try query.appendSlice("signed_request=");
    try std.Uri.Component.percentEncode(query.writer(), signed_request, isUnreserved);

    uri.path = .{ .percent_encoded = joined_path };
    uri.query = .{ .percent_encoded = query.items };

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try uri.writeToStream(.{ .scheme = true, .authority = true, .path = true, .query = true }, out.writer());
    return out.toOwnedSlice();
}

/// The begin-flow composition: discover the identity domain's browser base
/// and build the route URL, falling back to `https://<identity_domain>` when
/// DNS lookup fails, no valid record carries `https=`, or the discovered
/// base is invalid. `dns` may be null when no resolver could be constructed
/// at all (the system resolver found no nameserver); that is treated as a
/// lookup failure. The fallback preserves the pre-discovery behavior, so a
/// domain that serves its browser routes at the apex keeps working without
/// a `_linkkeys_apis` record.
pub fn resolveBrowserEndpoint(allocator: std.mem.Allocator, dns: ?dnsmod.DnsResolver, identity_domain: []const u8, route: []const u8, signed_request: []const u8) ![]u8 {
    const discovered: ?[]const u8 = if (dns) |resolver| resolveBrowserBase(allocator, resolver, identity_domain) catch null else null;
    if (discovered) |base| return buildBrowserEndpoint(allocator, base, route, signed_request);
    const fallback = try std.fmt.allocPrint(allocator, "https://{s}", .{identity_domain});
    defer allocator.free(fallback);
    return buildBrowserEndpoint(allocator, fallback, route, signed_request);
}

// ---------------------------------------------------------------------
// Test support: a hermetic resolver with canned TXT answers. No test that
// uses it performs a live DNS request. Also used by begin.zig's tests.
// ---------------------------------------------------------------------

pub const FakeDnsResolver = struct {
    /// Answer for `_linkkeys_apis.<domain>`; null means "lookup fails".
    apis_txts: ?[]const []const u8,

    pub fn failing() FakeDnsResolver {
        return .{ .apis_txts = null };
    }

    pub fn resolver(self: *FakeDnsResolver) dnsmod.DnsResolver {
        return .{ .ptr = self, .txtLookupFn = txtLookupImpl };
    }

    fn txtLookupImpl(ptr: *anyopaque, allocator: std.mem.Allocator, name: []const u8) anyerror![]const []const u8 {
        const self: *FakeDnsResolver = @ptrCast(@alignCast(ptr));
        const txts = self.apis_txts orelse return error.FakeServfail;
        if (!std.mem.startsWith(u8, name, "_linkkeys_apis.")) return error.NoFakeRecordForName;
        return allocator.dupe([]const u8, txts);
    }
};

const test_domain = "ident.example.test";

test "resolveBrowserBase selects the first valid https= record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fake = FakeDnsResolver{ .apis_txts = &.{"v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys"} };
    const base = try resolveBrowserBase(a, fake.resolver(), test_domain);
    try std.testing.expectEqualStrings("https://login.example.test:8443/linkkeys", base);
}

test "resolveBrowserBase skips hostile records and errors without https=" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // A record whose https= value smuggles URL structure is skipped; with
    // no other candidate, resolution errors so the caller can fall back.
    for ([_][]const u8{
        "v=lk1 https=user@evil.example.test",
        "v=lk1 https=evil.example.test/x?y=1",
        "v=lk1 https=evil.example.test/x#frag",
    }) |hostile| {
        var fake = FakeDnsResolver{ .apis_txts = &.{hostile} };
        try std.testing.expectError(error.NoBrowserBase, resolveBrowserBase(a, fake.resolver(), test_domain));
    }
    var tcp_only = FakeDnsResolver{ .apis_txts = &.{"v=lk1 tcp=only.example.test"} };
    try std.testing.expectError(error.NoBrowserBase, resolveBrowserBase(a, tcp_only.resolver(), test_domain));
    var failing = FakeDnsResolver.failing();
    try std.testing.expectError(error.FakeServfail, resolveBrowserBase(a, failing.resolver(), test_domain));
}

test "buildBrowserEndpoint joins base, route and query" {
    const a = std.testing.allocator;

    const plain = try buildBrowserEndpoint(a, "https://h.example.test", browser_route_local_rp, "PAYLOAD-123_abc");
    defer a.free(plain);
    try std.testing.expectEqualStrings("https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc", plain);

    // Path prefix, with and without a trailing slash, and the regular-RP
    // route — the same helper serves /auth/authorize glue.
    for ([_][]const u8{ "https://h.example.test/pfx", "https://h.example.test/pfx/" }) |base| {
        const got = try buildBrowserEndpoint(a, base, browser_route_authorize, "s");
        defer a.free(got);
        try std.testing.expectEqualStrings("https://h.example.test/pfx/auth/authorize?signed_request=s", got);
    }

    const with_port = try buildBrowserEndpoint(a, "https://h.example.test:8443/x", browser_route_local_rp, "s");
    defer a.free(with_port);
    try std.testing.expectEqualStrings("https://h.example.test:8443/x/auth/local-rp?signed_request=s", with_port);

    // A value that is not base64url is escaped rather than corrupting the
    // query.
    const escaped = try buildBrowserEndpoint(a, "https://h.example.test", browser_route_local_rp, "a&b#c");
    defer a.free(escaped);
    try std.testing.expectEqualStrings("https://h.example.test/auth/local-rp?signed_request=a%26b%23c", escaped);
}

test "buildBrowserEndpoint rejects invalid bases and routes" {
    const a = std.testing.allocator;
    // A non-HTTPS scheme must never be selectable.
    for ([_][]const u8{
        "http://h.example.test",
        "ftp://h.example.test",
        "https://",
        "https://u:p@h.example.test",
        "https://h.example.test/x?y=1",
        "https://h.example.test/x#f",
        "https://h.example.test:notaport",
        "https://h.example .test",
        "h.example.test",
    }) |bad| {
        try std.testing.expectError(error.InvalidBrowserBase, buildBrowserEndpoint(a, bad, browser_route_local_rp, "s"));
    }
    try std.testing.expectError(error.InvalidRoute, buildBrowserEndpoint(a, "https://h.example.test", "auth/no-leading-slash", "s"));
}

test "resolveBrowserEndpoint falls back to the identity domain" {
    const a = std.testing.allocator;
    var failing = FakeDnsResolver.failing();
    const got = try resolveBrowserEndpoint(a, failing.resolver(), test_domain, browser_route_local_rp, "s");
    defer a.free(got);
    try std.testing.expectEqualStrings("https://ident.example.test/auth/local-rp?signed_request=s", got);

    const no_resolver = try resolveBrowserEndpoint(a, null, test_domain, browser_route_local_rp, "s");
    defer a.free(no_resolver);
    try std.testing.expectEqualStrings("https://ident.example.test/auth/local-rp?signed_request=s", no_resolver);
}
