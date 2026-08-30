package regularrp

import (
	"encoding/binary"
	"fmt"
)

// This file implements the minimal canonical CBOR encoding/decoding this SDK
// needs for the two application-key constructions that are NOT CSIL wire
// types (everything else — ApplicationKeyAddition, ApplicationKeyRenewal,
// ApplicationKeyRevocation, ApplicationKeyAttestation, ... — is a generated
// CSIL type with its own Encode*/Decode* in generated/codec.gen.go, used
// directly):
//
//   - The envelope signature input every signed structure except the
//     revocation is verified over: `CBOR([tag: tstr, payload: bstr])`, a
//     two-element array — see crates/liblinkkeys/src/local_rp.rs's
//     `envelope_signature_input`, reused by
//     crates/liblinkkeys/src/application_keys.rs for the attestation,
//     addition, possession, and renewal tags.
//   - The revocation's own eight-element tagged tuple (built from fields,
//     not stored bytes — see crates/liblinkkeys/src/application_keys.rs's
//     `revocation_payload`).
//   - The sealed-challenge tuple (`CBOR([suite: tstr, ephemeral_public_key:
//     bstr, aead_nonce: bstr, ciphertext: bstr])`, a four-element array) —
//     this one is decoded as well as encoded, since this SDK is the
//     recipient side (`open_challenge`), not the sealing side.
//
// This file deliberately does NOT attempt to be a general CBOR
// encoder/decoder (the generated codec already owns that for CSIL types); it
// only builds/reads the specific "array of text/bytes items" shape these
// three constructions need, using RFC 8949's shortest-form (preferred)
// length encoding for output — the same encoding `ciborium` produces on the
// Rust side. Verified byte-for-byte against sdks/regular-rp/conformance/ in
// conformance_test.go.

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

// cborHead builds a CBOR major-type head (and, for major types with a
// length, the RFC 8949 shortest-form length encoding).
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

// cborTuple encodes a definite-length CBOR array (major type 4) of the given
// pre-encoded items, in order — the wire shape of every Rust tuple this SDK
// needs to reproduce (`(tag, payload)`, `(tag, ...fields)`, etc).
func cborTuple(items ...cborItem) []byte {
	out := cborHead(4, uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Decoding — only what's needed to read a sealed-challenge tuple back
// ---------------------------------------------------------------------------

// cborReadHead reads one CBOR head: major type, argument value, and the
// remaining bytes after the head. Handles every additional-info form
// (0-23 inline, 24/25/26/27 for 1/2/4/8-byte lengths) regardless of whether
// the producer used shortest form — a decoder is permissive on input length
// encoding even though this package's own encoder always emits shortest
// form.
func cborReadHead(b []byte) (major byte, arg uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, 0, nil, fmt.Errorf("cbor: unexpected end of input reading head")
	}
	major = b[0] >> 5
	info := b[0] & 0x1f
	b = b[1:]
	switch {
	case info < 24:
		return major, uint64(info), b, nil
	case info == 24:
		if len(b) < 1 {
			return 0, 0, nil, fmt.Errorf("cbor: truncated 1-byte length")
		}
		return major, uint64(b[0]), b[1:], nil
	case info == 25:
		if len(b) < 2 {
			return 0, 0, nil, fmt.Errorf("cbor: truncated 2-byte length")
		}
		return major, uint64(binary.BigEndian.Uint16(b)), b[2:], nil
	case info == 26:
		if len(b) < 4 {
			return 0, 0, nil, fmt.Errorf("cbor: truncated 4-byte length")
		}
		return major, uint64(binary.BigEndian.Uint32(b)), b[4:], nil
	case info == 27:
		if len(b) < 8 {
			return 0, 0, nil, fmt.Errorf("cbor: truncated 8-byte length")
		}
		return major, binary.BigEndian.Uint64(b), b[8:], nil
	default:
		return 0, 0, nil, fmt.Errorf("cbor: unsupported additional info %d", info)
	}
}

// cborReadArray reads a definite-length array head and returns its element
// count and the remaining bytes.
func cborReadArray(b []byte) (count uint64, rest []byte, err error) {
	major, n, rest, err := cborReadHead(b)
	if err != nil {
		return 0, nil, err
	}
	if major != 4 {
		return 0, nil, fmt.Errorf("cbor: expected array (major type 4), got major type %d", major)
	}
	return n, rest, nil
}

// cborReadText reads one CBOR text string (major type 3).
func cborReadText(b []byte) (string, []byte, error) {
	major, n, rest, err := cborReadHead(b)
	if err != nil {
		return "", nil, err
	}
	if major != 3 {
		return "", nil, fmt.Errorf("cbor: expected text string (major type 3), got major type %d", major)
	}
	if uint64(len(rest)) < n {
		return "", nil, fmt.Errorf("cbor: truncated text string")
	}
	return string(rest[:n]), rest[n:], nil
}

// cborReadBytes reads one CBOR byte string (major type 2).
func cborReadBytes(b []byte) ([]byte, []byte, error) {
	major, n, rest, err := cborReadHead(b)
	if err != nil {
		return nil, nil, err
	}
	if major != 2 {
		return nil, nil, fmt.Errorf("cbor: expected byte string (major type 2), got major type %d", major)
	}
	if uint64(len(rest)) < n {
		return nil, nil, fmt.Errorf("cbor: truncated byte string")
	}
	out := make([]byte, n)
	copy(out, rest[:n])
	return out, rest[n:], nil
}
