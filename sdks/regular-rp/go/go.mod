module github.com/catalystcommunity/linkkeys/sdks/regular-rp/go

go 1.26.4

// Dependency justification (AGENTS.md: "Every dependency is a liability.
// Justify each one."):
//
//   - github.com/catalystcommunity/csilgen/transports/go: the CSIL-RPC
//     envelope codec (RpcRequest/RpcResponse encode/decode) and stream
//     framing (StreamCarrier, 4-byte length-prefix) this SDK's transport.go
//     builds its TLS-pinned, API-key-authenticated calls over. Pinned to the
//     same commit sdks/local-rp/go already depends on, for one shared,
//     already-proven version across both LinkKeys Go SDKs rather than two
//     independently-drifting pins.
//   - golang.org/x/crypto: needed for its chacha20poly1305 package —
//     liblinkkeys::application_keys::CHALLENGE_SEAL_SUITE (the sealed X25519
//     proof-of-possession challenge) is fixed to chacha20-poly1305, not
//     negotiated, and the standard library has no ChaCha20-Poly1305
//     implementation. Everything else this package needs (crypto/ed25519,
//     crypto/ecdh X25519, crypto/hkdf, crypto/sha256) is standard library.
require (
	github.com/catalystcommunity/csilgen/transports/go v0.0.0-20260713013116-a661c8727022
	golang.org/x/crypto v0.54.0
)

require golang.org/x/sys v0.47.0 // indirect
