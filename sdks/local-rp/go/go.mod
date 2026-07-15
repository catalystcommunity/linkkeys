module github.com/catalystcommunity/linkkeys/sdks/local-rp/go

go 1.26.4

// Dependency justification (AGENTS.md: "Every dependency is a liability.
// Justify each one."):
//
//   - github.com/catalystcommunity/csilgen/transports/go: the CSIL-RPC
//     envelope codec (RpcRequest/RpcResponse encode/decode) and stream
//     framing (StreamCarrier, 4-byte length-prefix) this SDK's rpc.go builds
//     its TLS-pinned calls over. This is csilgen's own hand-maintained
//     reference transport library for the language (see
//     dns-less-local-rp-design.md, "SDK Layout and Tooling" /
//     csilgen/transports/README.md) — the same pattern the Rust reference
//     SDK follows via `csilgen-transport` (vendored there; resolved here as
//     a normal, tagged-by-commit Go module dependency straight from the
//     public catalystcommunity/csilgen repo, since Go's module proxy
//     resolves nested-module subdirectories by commit pseudo-version without
//     needing a vendored copy or a release tag). Reused rather than
//     reimplemented because hand-rolling CSIL-RPC framing a second time would
//     be exactly the kind of duplicated, easy-to-drift wire logic this
//     library exists to prevent.
//   - golang.org/x/crypto: needed for its chacha20poly1305 package — the
//     design doc's Language Crypto Matrix Go row is "Strong, zero deps" for
//     the mandatory aes-256-gcm baseline (crypto/ed25519, crypto/ecdh X25519,
//     crypto/hkdf, crypto/aes+cipher are all standard library as of Go
//     1.24+), and calls out "x/crypto/chacha20poly1305 only if the optional
//     suite is implemented" — which this SDK does (both registry suites,
//     matching the Rust reference SDK and the conformance vectors). This is
//     the golang.org/x/ suite maintained by the Go team itself, not a
//     third-party crate; no alternative avoids a dependency here since the
//     standard library has no ChaCha20-Poly1305 implementation.
require (
	github.com/catalystcommunity/csilgen/transports/go v0.0.0-20260713013116-a661c8727022
	golang.org/x/crypto v0.54.0
)

// golang.org/x/sys is chacha20poly1305's own transitive dependency (its
// assembly-optimized code paths on some architectures) — not something this
// SDK calls directly.
require golang.org/x/sys v0.47.0 // indirect
