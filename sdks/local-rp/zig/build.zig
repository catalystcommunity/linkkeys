const std = @import("std");

// Zig SDK for LinkKeys' DNS-less local RP identity mode. See README.md and
// dns-less-local-rp-design.md (repo root) for the protocol; this file only
// wires the module + test binaries.
//
// `zig build test` runs:
//   - in-source unit tests across every src/*.zig file (module-internal
//     coverage: CBOR canonicalization, crypto primitive mappings, DNS TXT
//     parsing, TLS SPKI pin-extraction against a real openssl-minted
//     fixture, etc.)
//   - tests/conformance.zig: every vector in sdks/local-rp/conformance/,
//     positive and negative cases
//   - tests/flow.zig: end-to-end begin/complete against a fake IDP at the
//     Transport seam (see README's "TLS evaluation outcome" for why this is
//     plaintext-at-the-seam rather than real pinned TLS)

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("linkkeys_local_rp", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run unit + conformance + flow tests");

    // In-source unit tests (every src/*.zig `test { ... }` block reachable
    // from root.zig).
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    test_step.dependOn(&b.addRunArtifact(mod_tests).step);

    // The conformance vectors live one level up, outside this package's
    // root (sdks/local-rp/conformance/, shared by every SDK) — @embedFile
    // cannot reach outside the package, so tests/conformance.zig reads them
    // at runtime instead. Resolve an absolute path at build time (robust
    // regardless of the cwd `zig build test` happens to run with) and pass
    // it in via a build-options module.
    const conformance_dir = b.pathResolve(&.{ b.build_root.path orelse ".", "..", "conformance" });
    const options = b.addOptions();
    options.addOption([]const u8, "conformance_dir", conformance_dir);

    // Out-of-module test binaries: each imports the module by name, exactly
    // as an app dependency would.
    inline for (.{
        "tests/conformance.zig",
        "tests/flow.zig",
    }) |test_file| {
        const t_mod = b.createModule(.{
            .root_source_file = b.path(test_file),
            .target = target,
            .optimize = optimize,
        });
        t_mod.addImport("linkkeys_local_rp", mod);
        t_mod.addOptions("build_options", options);
        const t = b.addTest(.{ .root_module = t_mod });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }
}
