// VENDORED from catalystcommunity/csilgen @ a661c8727022ee8987c92020a5667f116b92ff78
// (transports/typescript/src/conventions.ts). Do NOT hand-edit; re-sync from
// upstream instead (see cbor.ts's banner in this same directory).
//
// Conventions shared by every CSIL transport — see `csil-transport-conventions.md`.
//
// The parts the three transports agree on: the CBOR rules (deterministic
// encoding lives in `cbor.ts`, tag-24 payloads here), the version constant, the
// transport status registry, the max-frame guard, and the small map-navigation
// helpers the decoders share. Transport modules build their envelopes from these
// helpers so the bytes match the conformance vectors regardless of object shape.

import { type Cbor, bytes, decode, encode, tag, text, int } from "./cbor.ts";

// Current transport version. A new value is minted only for a breaking change to
// envelope layout or semantics.
export const VERSION = 1;

// CBOR semantic tag wrapping an embedded, opaque CBOR data item (RFC 8949 §3.4.5.1).
export const TAG_ENCODED_CBOR = 24;

// Reserved service ordinal for the transport control plane (Events lifecycle).
export const CONTROL_SERVICE_ORD = 0;

// Default max encoded envelope size for stream/message carriers (16 MiB). A
// carrier rejects anything larger before allocating for it.
export const MAX_FRAME_DEFAULT = 16 * 1024 * 1024;

// Transport-level status. Distinct from application errors, which ride inside the
// payload as a declared `/ ErrorType` arm. See the conventions doc registry.
// Modeled as a numeric code (with named constants) rather than a closed enum so
// host-defined extension codes (>= 64) and unknown codes pass through unchanged.
export const Status = {
  Ok: 0,
  MalformedEnvelope: 1,
  UnknownServiceOrOp: 2,
  Unauthenticated: 3,
  Forbidden: 4,
  VersionUnsupported: 5,
  Internal: 6,
  Unavailable: 7,
  DeadlineExceeded: 8,
} as const;

const STATUS_NAMES: Record<number, string> = {
  0: "ok",
  1: "malformed-envelope",
  2: "unknown-service-or-op",
  3: "unauthenticated",
  4: "forbidden",
  5: "version-unsupported",
  6: "internal",
  7: "unavailable",
  8: "deadline-exceeded",
};

export function statusName(code: number): string {
  return STATUS_NAMES[code] ?? "other";
}

export function statusIsOk(code: number): boolean {
  return code === 0;
}

// The kinds a `TransportError` can take, so callers can branch on the failure
// without string-matching messages.
export type TransportErrorKind =
  | "encode"
  | "decode"
  | "malformed"
  | "frame-too-large"
  | "unsupported-version"
  | "status"
  | "carrier";

// Errors surfaced by the transport layer (the wire), distinct from a host's
// application errors. A non-zero peer status arrives as `kind: "status"` with the
// registry `code`, so a generated client can route it to its transport-error path.
export class TransportError extends Error {
  readonly kind: TransportErrorKind;
  readonly code?: number;

  constructor(kind: TransportErrorKind, message: string, code?: number) {
    super(message);
    this.name = "TransportError";
    this.kind = kind;
    this.code = code;
  }

  static malformed(message: string): TransportError {
    return new TransportError("malformed", message);
  }

  static frameTooLarge(got: number, max: number): TransportError {
    return new TransportError(
      "frame-too-large",
      `frame of ${got} bytes exceeds max-frame guard of ${max} bytes`,
    );
  }

  static unsupportedVersion(v: number): TransportError {
    return new TransportError("unsupported-version", `unsupported transport version ${v}`);
  }

  // A non-zero transport status returned by the peer.
  static status(code: number, message?: string): TransportError {
    const name = statusName(code);
    const detail = message ? `: ${message}` : "";
    return new TransportError("status", `transport status ${name} (${code})${detail}`, code);
  }

  static carrier(message: string): TransportError {
    return new TransportError("carrier", `carrier error: ${message}`);
  }
}

// Wrap opaque payload bytes (themselves a CBOR item) in tag 24.
export function tag24(payload: Uint8Array): Cbor {
  return tag(TAG_ENCODED_CBOR, bytes(payload));
}

// Extract the opaque payload bytes from a tag-24 value.
export function untag24(value: Cbor): Uint8Array {
  if (value.t === "tag" && value.tag === TAG_ENCODED_CBOR) {
    if (value.v.t === "bytes") return value.v.v;
    throw TransportError.malformed("tag-24 payload is not a byte string");
  }
  throw TransportError.malformed("expected a tag-24 (encoded-cbor) payload");
}

export { decode as decodeValue, encode as encodeValue };

// Build a deterministically-keyed CBOR map from text-keyed entries. The codec
// sorts at encode time (RFC 8949 §4.2.1), so this just constructs the value; the
// result is byte-identical to the Rust reference's `canon_map`.
export function canonMap(entries: ReadonlyArray<readonly [string, Cbor]>): Cbor {
  return {
    t: "map",
    v: entries.map(([k, v]) => [text(k), v] as const),
  };
}

export function intValue(n: number): Cbor {
  return int(n);
}

export function textValue(s: string): Cbor {
  return text(s);
}

// --- map navigation, mirroring the Rust `map_get` / `get_*` helpers ---

export function mapGet(value: Cbor, key: string): Cbor | undefined {
  if (value.t !== "map") return undefined;
  for (const [k, v] of value.v) {
    if (k.t === "text" && k.v === key) return v;
  }
  return undefined;
}

export function getUint(value: Cbor, key: string): number {
  const f = mapGet(value, key);
  if (f && f.t === "int" && f.v >= 0) return f.v;
  throw TransportError.malformed(`missing or non-integer field '${key}'`);
}

export function getInt(value: Cbor, key: string): number {
  const f = mapGet(value, key);
  if (f && f.t === "int") return f.v;
  throw TransportError.malformed(`missing or non-integer field '${key}'`);
}

export function getText(value: Cbor, key: string): string {
  const f = mapGet(value, key);
  if (f && f.t === "text") return f.v;
  throw TransportError.malformed(`missing or non-text field '${key}'`);
}

export function getTextOpt(value: Cbor, key: string): string | undefined {
  const f = mapGet(value, key);
  return f && f.t === "text" ? f.v : undefined;
}

export function getUintOpt(value: Cbor, key: string): number | undefined {
  const f = mapGet(value, key);
  return f && f.t === "int" && f.v >= 0 ? f.v : undefined;
}

// Verify a decoded envelope's version field, throwing a clear error otherwise.
export function checkVersion(v: number): void {
  if (v !== VERSION) throw TransportError.unsupportedVersion(v);
}

// hex <-> bytes helpers (used by the conformance vectors and for debugging).
export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const byte of b) s += byte.toString(16).padStart(2, "0");
  return s;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex string has odd length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
