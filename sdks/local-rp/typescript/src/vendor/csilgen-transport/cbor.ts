// VENDORED from catalystcommunity/csilgen @ a661c8727022ee8987c92020a5667f116b92ff78
// (transports/typescript/src/cbor.ts). Only the RPC-relevant modules
// (cbor.ts, conventions.ts, carrier.ts, rpc.ts) are vendored here — this SDK
// needs CSIL-RPC only, not CSIL-Events/CSIL-Datagrams. Temporary: re-sync
// from upstream by re-copying these four files rather than hand-editing, the
// same convention `crates/csilgen-transport/Cargo.toml` uses for the Rust
// vendoring. Do NOT hand-edit beyond this banner.
//
// Minimal canonical CBOR codec (RFC 8949) — by hand, zero dependencies.
//
// Only the subset the CSIL transports use is implemented: unsigned and negative
// integers, text strings, byte strings, arrays, maps, and tags. Maps are emitted
// with RFC 8949 §4.2.1 core deterministic encoding — entries sorted by the
// bytewise lexicographic order of their *encoded* keys — so the bytes match the
// conformance vectors and the Rust reference's `canon_map`. Everything works in
// `Uint8Array`; there is no `Buffer` and no Node-only surface here so the codec
// runs identically in the browser, in a WASM client, and in Node.

// The value model. A single `int` covers both CBOR major type 0 (unsigned) and 1
// (negative); the encoder picks the major type by sign, matching how ciborium's
// `Value::Integer` collapses the two on the Rust side.
export type Cbor =
  | { readonly t: "int"; readonly v: number }
  | { readonly t: "bytes"; readonly v: Uint8Array }
  | { readonly t: "text"; readonly v: string }
  | { readonly t: "array"; readonly v: Cbor[] }
  | { readonly t: "map"; readonly v: ReadonlyArray<readonly [Cbor, Cbor]> }
  | { readonly t: "tag"; readonly tag: number; readonly v: Cbor };

export const int = (v: number): Cbor => ({ t: "int", v });
export const bytes = (v: Uint8Array): Cbor => ({ t: "bytes", v });
export const text = (v: string): Cbor => ({ t: "text", v });
export const array = (v: Cbor[]): Cbor => ({ t: "array", v });
export const map = (v: ReadonlyArray<readonly [Cbor, Cbor]>): Cbor => ({ t: "map", v });
export const tag = (tagNum: number, v: Cbor): Cbor => ({ t: "tag", tag: tagNum, v });

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true });

// A growable byte sink. Kept as a number[] and frozen into a Uint8Array at the
// end so the hot path avoids repeated typed-array reallocation.
class Writer {
  private readonly out: number[] = [];

  byte(b: number): void {
    this.out.push(b & 0xff);
  }

  raw(src: Uint8Array): void {
    for (const b of src) this.out.push(b);
  }

  // Emit a CBOR head: the major type in the top three bits, then the shortest
  // additional-information encoding of `arg` that fits — the determinism rule.
  head(major: number, arg: number): void {
    const mt = major << 5;
    if (arg < 24) {
      this.byte(mt | arg);
    } else if (arg < 0x100) {
      this.byte(mt | 24);
      this.byte(arg);
    } else if (arg < 0x10000) {
      this.byte(mt | 25);
      this.byte(arg >>> 8);
      this.byte(arg);
    } else if (arg < 0x100000000) {
      this.byte(mt | 26);
      this.byte(arg >>> 24);
      this.byte(arg >>> 16);
      this.byte(arg >>> 8);
      this.byte(arg);
    } else {
      // Beyond 2^32 we split via BigInt so we stay exact up to 2^53.
      this.byte(mt | 27);
      const big = BigInt(arg);
      for (let shift = 56n; shift >= 0n; shift -= 8n) {
        this.byte(Number((big >> shift) & 0xffn));
      }
    }
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.out);
  }
}

function writeValue(w: Writer, value: Cbor): void {
  switch (value.t) {
    case "int": {
      if (!Number.isSafeInteger(value.v)) {
        throw new Error(`integer ${value.v} is not a safe integer`);
      }
      if (value.v >= 0) {
        w.head(0, value.v);
      } else {
        w.head(1, -1 - value.v);
      }
      return;
    }
    case "bytes": {
      w.head(2, value.v.length);
      w.raw(value.v);
      return;
    }
    case "text": {
      const utf8 = TEXT_ENCODER.encode(value.v);
      w.head(3, utf8.length);
      w.raw(utf8);
      return;
    }
    case "array": {
      w.head(4, value.v.length);
      for (const item of value.v) writeValue(w, item);
      return;
    }
    case "map": {
      // Core deterministic encoding: sort entries by the bytewise lexicographic
      // order of their *encoded* keys, then emit. This is the TS twin of the
      // Rust reference's `canon_map`, so a logically equal envelope is byte-equal.
      const encoded = value.v.map(([k, v]) => ({
        key: encode(k),
        val: encode(v),
      }));
      encoded.sort((a, b) => compareBytes(a.key, b.key));
      w.head(5, value.v.length);
      for (const e of encoded) {
        w.raw(e.key);
        w.raw(e.val);
      }
      return;
    }
    case "tag": {
      w.head(6, value.tag);
      writeValue(w, value.v);
      return;
    }
  }
}

export function encode(value: Cbor): Uint8Array {
  const w = new Writer();
  writeValue(w, value);
  return w.finish();
}

// Bytewise lexicographic comparison; shorter run that is a prefix of the longer
// sorts first, matching `Vec<u8>::cmp` on the Rust side.
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

class Reader {
  private readonly data: Uint8Array;
  private pos: number;

  constructor(data: Uint8Array) {
    this.data = data;
    this.pos = 0;
  }

  atEnd(): boolean {
    return this.pos === this.data.length;
  }

  private byte(): number {
    if (this.pos >= this.data.length) {
      throw new Error("unexpected end of CBOR input");
    }
    return this.data[this.pos++];
  }

  private take(n: number): Uint8Array {
    if (this.pos + n > this.data.length) {
      throw new Error("unexpected end of CBOR input");
    }
    const slice = this.data.subarray(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }

  // Read the additional-information argument for a head byte. Indefinite-length
  // (ai 31) is rejected outright — the conventions forbid it inside an envelope.
  private argument(ai: number): number {
    if (ai < 24) return ai;
    if (ai === 24) return this.byte();
    if (ai === 25) return (this.byte() << 8) | this.byte();
    if (ai === 26) {
      // Assemble unsigned so the high bit does not turn the result negative.
      return (
        this.byte() * 0x1000000 +
        (this.byte() << 16) +
        (this.byte() << 8) +
        this.byte()
      );
    }
    if (ai === 27) {
      let big = 0n;
      for (let i = 0; i < 8; i++) big = (big << 8n) | BigInt(this.byte());
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("CBOR integer exceeds safe integer range");
      }
      return Number(big);
    }
    throw new Error(`unsupported CBOR additional info ${ai} (indefinite lengths are not allowed)`);
  }

  value(): Cbor {
    const head = this.byte();
    const major = head >> 5;
    const arg = this.argument(head & 0x1f);
    switch (major) {
      case 0:
        return int(arg);
      case 1:
        return int(-1 - arg);
      case 2:
        return bytes(this.take(arg).slice());
      case 3:
        return text(TEXT_DECODER.decode(this.take(arg)));
      case 4: {
        const items: Cbor[] = [];
        for (let i = 0; i < arg; i++) items.push(this.value());
        return array(items);
      }
      case 5: {
        const entries: [Cbor, Cbor][] = [];
        for (let i = 0; i < arg; i++) entries.push([this.value(), this.value()]);
        return map(entries);
      }
      case 6:
        return tag(arg, this.value());
      default:
        throw new Error(`unsupported CBOR major type ${major}`);
    }
  }
}

// Decode a single CBOR data item from `data`. An envelope is a single
// self-contained CBOR item (conventions doc §1), so any bytes left after the
// item are rejected rather than silently ignored — matching the Rust
// `decode_value` and the Python decoder.
export function decode(data: Uint8Array): Cbor {
  const reader = new Reader(data);
  const value = reader.value();
  if (!reader.atEnd()) {
    throw new Error("trailing bytes after CBOR item");
  }
  return value;
}
