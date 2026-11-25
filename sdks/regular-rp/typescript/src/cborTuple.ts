// A tiny, hand-written CBOR encoder for exactly one shape: a definite-length
// array ("tuple") of text/byte-string/integer/null elements, in a fixed caller-given
// order. This is the house pattern liblinkkeys uses for every
// domain-separated signature payload — see
// `crates/liblinkkeys/src/local_rp.rs`'s `envelope_signature_input`,
// `crates/liblinkkeys/src/claims.rs`'s `claim_sign_payload`,
// `crates/liblinkkeys/src/dns.rs`'s `key_vouch_payload`, and
// `crates/liblinkkeys/src/revocation.rs`'s `revocation_payload` — all of
// which CBOR-encode a Rust tuple via ciborium, which is exactly "a
// definite-length CBOR array of the tuple's elements, in order". There is no
// map/canonical-sort concern here (arrays have no key-ordering ambiguity),
// so this needs none of the generated codec's or the vendored transport
// codec's machinery — just array/text/bytes/integer/null framing. Signed
// timestamps are integers of whole Unix seconds (see `signedTime.ts`).
//
// This is NOT the CSIL-RPC envelope codec (see src/vendor/csilgen-transport/)
// and NOT the generated CSIL type codec (see src/generated/codec.gen.ts) —
// both of those exist for other purposes. Keeping this separate avoids
// hand-editing either vendored or generated code to add a "null" variant
// neither currently needs.

export type TupleElem =
  | { readonly t: "text"; readonly v: string }
  | { readonly t: "bytes"; readonly v: Uint8Array }
  | { readonly t: "int"; readonly v: number }
  | { readonly t: "null" };

export const text = (v: string): TupleElem => ({ t: "text", v });
export const bytes = (v: Uint8Array): TupleElem => ({ t: "bytes", v });
/** A CBOR integer. `v` must be a safe integer (whole Unix seconds always is). */
export const int = (v: number): TupleElem => {
  if (!Number.isSafeInteger(v)) throw new RangeError("CBOR tuple integer must be a safe integer");
  return { t: "int", v };
};
export const nullElem = (): TupleElem => ({ t: "null" });
export const textOrNull = (v: string | undefined | null): TupleElem =>
  v === undefined || v === null ? nullElem() : text(v);
export const intOrNull = (v: number | undefined | null): TupleElem =>
  v === undefined || v === null ? nullElem() : int(v);

const TEXT_ENCODER = new TextEncoder();

function head(major: number, n: number, out: number[]): void {
  const mt = major << 5;
  if (n < 24) {
    out.push(mt | n);
  } else if (n < 0x100) {
    out.push(mt | 24, n);
  } else if (n < 0x10000) {
    out.push(mt | 25, (n >>> 8) & 0xff, n & 0xff);
  } else if (n < 0x1_0000_0000) {
    out.push(mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  } else {
    // A 64-bit head. `n` is a safe integer, so BigInt keeps every bit.
    let big = BigInt(n);
    const bytes: number[] = [];
    for (let i = 0; i < 8; i++) {
      bytes.unshift(Number(big & 0xffn));
      big >>= 8n;
    }
    out.push(mt | 27, ...bytes);
  }
}

function writeElem(e: TupleElem, out: number[]): void {
  switch (e.t) {
    case "text": {
      const utf8 = TEXT_ENCODER.encode(e.v);
      head(3, utf8.length, out);
      for (const b of utf8) out.push(b);
      return;
    }
    case "bytes": {
      head(2, e.v.length, out);
      for (const b of e.v) out.push(b);
      return;
    }
    case "int": {
      // Major type 0 for n >= 0; major type 1 carries -1 - n for n < 0.
      if (e.v >= 0) head(0, e.v, out);
      else head(1, -1 - e.v, out);
      return;
    }
    case "null": {
      out.push(0xf6);
      return;
    }
  }
}

/** Encode a fixed-order tuple of text/bytes/integer/null elements as a definite-length CBOR array. */
export function encodeCborTuple(elems: readonly TupleElem[]): Uint8Array {
  const out: number[] = [];
  head(4, elems.length, out);
  for (const e of elems) writeElem(e, out);
  return Uint8Array.from(out);
}
