//! The TCP dial seam. Mirrors `sdks/local-rp/rust/src/transport.rs` /
//! `sdks/local-rp/go/transport.go`.
//!
//! dns-less-local-rp-design.md's "SDK API Shape" / "Required Network Access"
//! sections ask for a Transport seam the SDK embeds its CSIL-RPC calls over,
//! with a default implementation and the whole thing injectable for tests.
//! Deliberately narrow: `Transport` only *connects a byte stream* to
//! `host:port`. TLS (certificate-pin verification against DNS `fp=`
//! records) is layered on top in `rpc.zig`, not here, so a test double can
//! swap out "how do I open a socket" without also having to fake a TLS
//! handshake — see `rpc.zig`'s module docs and this SDK's README for why
//! the *default* secure-dial path fails closed rather than silently
//! skipping the pin check.
//!
//! Wire Precision is explicit that this package must NOT inherit
//! `linkkeys-rpc-client`'s non-public-address refusal as a *default*: that
//! refusal is a server-side SSRF guard, and "connecting from a LAN box to
//! wherever `_linkkeys_apis` points is the entire point of this mode." The
//! default policy here is `.permissive`. `.public_only` is offered as an
//! opt-in for integrators who specifically want that stricter posture.

const std = @import("std");

/// Dials `host_port` and returns a byte stream. Vtable-style interface
/// (idiomatic Zig dynamic dispatch), injectable so tests can hand the RPC
/// layer a loopback socket instead of relying on real DNS-driven
/// addressing.
pub const Transport = struct {
    ptr: *anyopaque,
    dialFn: *const fn (ptr: *anyopaque, host_port: []const u8) anyerror!std.net.Stream,

    pub fn dial(self: Transport, host_port: []const u8) !std.net.Stream {
        return self.dialFn(self.ptr, host_port);
    }
};

/// Controls which destination addresses `StdTransport` is willing to dial.
/// Default is `.permissive` — see the module docs for why.
pub const AddressPolicy = enum {
    /// Dials anything the OS resolver returns. Correct default for this
    /// mode: a LAN/loopback local RP talking to its LinkKeys domain's
    /// published `_linkkeys_apis` `tcp=` endpoint is routinely a private
    /// address.
    permissive,
    /// Refuses loopback/private/link-local/CGNAT/ULA/documentation and
    /// unspecified addresses, mirroring (not sharing code with) the
    /// server-side SSRF guard. Opt-in only.
    public_only,
};

fn splitHostPort(host_port: []const u8) !struct { host: []const u8, port: u16 } {
    if (host_port.len > 0 and host_port[0] == '[') {
        const end = std.mem.indexOfScalar(u8, host_port, ']') orelse return error.InvalidHostPort;
        const host = host_port[1..end];
        if (end + 2 > host_port.len or host_port[end + 1] != ':') return error.InvalidHostPort;
        const port = std.fmt.parseInt(u16, host_port[end + 2 ..], 10) catch return error.InvalidHostPort;
        return .{ .host = host, .port = port };
    }
    const idx = std.mem.lastIndexOfScalar(u8, host_port, ':') orelse return error.InvalidHostPort;
    const host = host_port[0..idx];
    const port = std.fmt.parseInt(u16, host_port[idx + 1 ..], 10) catch return error.InvalidHostPort;
    return .{ .host = host, .port = port };
}

fn isNonPublicAddress(addr: std.net.Address) bool {
    switch (addr.any.family) {
        std.posix.AF.INET => {
            const b = std.mem.asBytes(&addr.in.sa.addr);
            // Loopback 127.0.0.0/8
            if (b[0] == 127) return true;
            // Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if (b[0] == 10) return true;
            if (b[0] == 172 and b[1] >= 16 and b[1] <= 31) return true;
            if (b[0] == 192 and b[1] == 168) return true;
            // Link-local 169.254.0.0/16
            if (b[0] == 169 and b[1] == 254) return true;
            // CGNAT 100.64.0.0/10
            if (b[0] == 100 and (b[1] & 0xC0) == 64) return true;
            // Documentation ranges
            if (b[0] == 192 and b[1] == 0 and b[2] == 2) return true;
            if (b[0] == 198 and b[1] == 51 and b[2] == 100) return true;
            if (b[0] == 203 and b[1] == 0 and b[2] == 113) return true;
            // Unspecified / broadcast
            if (b[0] == 0) return true;
            if (b[0] == 255 and b[1] == 255 and b[2] == 255 and b[3] == 255) return true;
            return false;
        },
        std.posix.AF.INET6 => {
            const b = addr.in6.sa.addr;
            const all_zero = std.mem.allEqual(u8, b[0..15], 0) and b[15] <= 1;
            if (all_zero) return true; // ::  or ::1
            if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true; // link-local
            if ((b[0] & 0xfe) == 0xfc) return true; // fc00::/7 ULA
            return false;
        },
        else => return true,
    }
}

/// The default `Transport`: a plain blocking dialer, gated only by `policy`
/// (permissive unless the caller opts into `.public_only`).
pub const StdTransport = struct {
    policy: AddressPolicy = .permissive,

    pub fn transport(self: *StdTransport) Transport {
        return .{ .ptr = self, .dialFn = dialImpl };
    }

    fn dialImpl(ptr: *anyopaque, host_port: []const u8) anyerror!std.net.Stream {
        const self: *StdTransport = @ptrCast(@alignCast(ptr));
        return self.dial(host_port);
    }

    pub fn dial(self: *StdTransport, host_port: []const u8) !std.net.Stream {
        const hp = try splitHostPort(host_port);

        if (self.policy == .public_only) {
            const gpa = std.heap.page_allocator;
            const list = try std.net.getAddressList(gpa, hp.host, hp.port);
            defer list.deinit();
            for (list.addrs) |addr| {
                if (isNonPublicAddress(addr)) return error.NonPublicAddressRefused;
            }
        }

        return std.net.tcpConnectToHost(std.heap.page_allocator, hp.host, hp.port);
    }
};

var default_transport_storage: StdTransport = .{};

/// The default `Transport` for the process lifetime.
pub fn defaultTransport() Transport {
    return default_transport_storage.transport();
}

test "splitHostPort handles IPv4 and bracketed IPv6" {
    const a = try splitHostPort("example.com:4987");
    try std.testing.expectEqualStrings("example.com", a.host);
    try std.testing.expectEqual(@as(u16, 4987), a.port);

    const b = try splitHostPort("[::1]:4987");
    try std.testing.expectEqualStrings("::1", b.host);
    try std.testing.expectEqual(@as(u16, 4987), b.port);
}

test "isNonPublicAddress flags loopback and private ranges" {
    try std.testing.expect(isNonPublicAddress(try std.net.Address.parseIp("127.0.0.1", 0)));
    try std.testing.expect(isNonPublicAddress(try std.net.Address.parseIp("10.1.2.3", 0)));
    try std.testing.expect(isNonPublicAddress(try std.net.Address.parseIp("192.168.1.1", 0)));
    try std.testing.expect(!isNonPublicAddress(try std.net.Address.parseIp("8.8.8.8", 0)));
}
