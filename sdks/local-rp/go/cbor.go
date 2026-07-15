package localrp

import "encoding/binary"

// This file implements the minimal canonical CBOR encoding this SDK needs to
// build signature-input and payload bytes for constructions that predate CSIL
// (envelope signature input, claim signatures, revocation certificates, key
// vouches) — see crates/liblinkkeys/src/local_rp.rs's `envelope_signature_input`,
// crates/liblinkkeys/src/claims.rs's `claim_sign_payload`,
// crates/liblinkkeys/src/revocation.rs's `revocation_payload`, and
// crates/liblinkkeys/src/dns.rs's `key_vouch_payload`. Every one of these is,
// on the wire, a definite-length CBOR array of a fixed, known arity built
// from `ciborium::ser::into_writer` over a Rust tuple — never a map, never
// indefinite-length, never anything requiring general-purpose CBOR. This file
// deliberately does NOT attempt to be a general CBOR encoder (the generated
// `generated/codec.gen.go` already owns that for CSIL types); it only builds
// the specific "array of text/bytes/optional-text items" shape these four
// constructions need, using RFC 8949's shortest-form (preferred) length
// encoding — the same encoding `ciborium` produces, and the same the
// generated codec's own hand-rolled encoder uses. This is verified
// byte-for-byte against sdks/local-rp/conformance/envelopes.json in
// conformance_test.go.

// cborHead builds a CBOR major-type head (and, for major types with a length,
// the RFC 8949 shortest-form length encoding).
func cborHead(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n <= 0xff:
		return []byte{m | 24, byte(n)}
	case n <= 0xffff:
		b := make([]byte, 3)
		b[0] = m | 25
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	case n <= 0xffffffff:
		b := make([]byte, 5)
		b[0] = m | 26
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = m | 27
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
}

// cborItem is a fully-encoded CBOR value used as one tuple element.
type cborItem []byte

// cborText encodes a CBOR text string (major type 3).
func cborText(s string) cborItem {
	return append(cborHead(3, uint64(len(s))), []byte(s)...)
}

// cborBytesVal encodes a CBOR byte string (major type 2) — the wire form
// `serde_bytes::Bytes` produces for a `&[u8]` field in a signed tuple.
func cborBytesVal(b []byte) cborItem {
	return append(cborHead(2, uint64(len(b))), b...)
}

// cborOptText encodes `Option<&str>`: `Some(s)` as a text string, `None` as
// CBOR null (major type 7, simple value 22 -> single byte 0xf6) — matching
// how serde/ciborium serializes an `Option` field inside a tuple.
func cborOptText(s *string) cborItem {
	if s == nil {
		return cborItem{0xf6}
	}
	return cborText(*s)
}

// cborTuple encodes a definite-length CBOR array (major type 4) of the given
// pre-encoded items, in order — the wire shape of every Rust tuple this SDK
// needs to reproduce (`(context, payload)`, `(tag, ...)`, etc).
func cborTuple(items ...cborItem) []byte {
	out := cborHead(4, uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}
