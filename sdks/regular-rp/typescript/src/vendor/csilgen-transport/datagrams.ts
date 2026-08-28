// CSIL-Datagrams transport — unreliable, unordered, message-oriented — see
// `csil-datagrams-transport.md`. CBOR-array (default), compact fixed-header, and
// payload-only profiles. A datagram channel is single-service: the service is
// bound at channel setup, so datagrams carry no service ordinal.

import { type Cbor, array as cborArray, int as cborInt } from "./cbor.ts";
import {
  TransportError,
  VERSION,
  checkVersion,
  decodeValue,
  encodeValue,
  tag24,
  untag24,
} from "./conventions.ts";

// Conservative max datagram size (envelope + payload) safe across UDP/WebRTC/QUIC.
export const MAX_DATAGRAM_DEFAULT = 1200;

// A datagram in the CBOR-array (default) profile: `[v, op_ord, seq, payload]`.
export class Datagram {
  op_ord: number;
  seq: number; // per-channel sequence; 0 means "unsequenced"
  payload: Uint8Array; // opaque CBOR(message type) bytes

  constructor(op_ord: number, seq: number, payload: Uint8Array) {
    this.op_ord = op_ord;
    this.seq = seq;
    this.payload = payload;
  }

  encode(): Uint8Array {
    const arr: Cbor[] = [
      cborInt(VERSION),
      cborInt(this.op_ord),
      cborInt(this.seq),
      tag24(this.payload),
    ];
    return encodeValue(cborArray(arr));
  }

  static decode(bytes: Uint8Array): Datagram {
    const v = decodeValue(bytes);
    if (v.t !== "array") throw TransportError.malformed("datagram is not an array");
    const arr = v.v;
    // Fixed 4-element array — a 3- or 5-element array is rejected, never coerced.
    if (arr.length !== 4) {
      throw TransportError.malformed(
        `datagram array has ${arr.length} elements, expected 4`,
      );
    }
    const asUint = (val: Cbor): number => {
      if (val.t === "int" && val.v >= 0) return val.v;
      throw TransportError.malformed("datagram field is not a non-negative integer");
    };
    checkVersion(asUint(arr[0]));
    return new Datagram(asUint(arr[1]), asUint(arr[2]), untag24(arr[3]));
  }
}

const COMPACT_VER = 1;
const FLAG_EPOCH = 0b0001;

// A datagram in the compact fixed-header profile. Header layout:
// `[ver|flags][op_ord:u8][seq:u16 BE]([epoch:u8])` then the opaque body.
export class CompactDatagram {
  op_ord: number; // 0..255
  seq: number; // u16, wraps mod 2^16
  epoch?: number; // present when the sender tracks restarts (sets the flags epoch bit)
  body: Uint8Array; // opaque body (tag-24 CBOR or a raw media frame, by channel agreement)

  constructor(op_ord: number, seq: number, body: Uint8Array) {
    this.op_ord = op_ord;
    this.seq = seq;
    this.body = body;
  }

  withEpoch(epoch: number): this {
    this.epoch = epoch;
    return this;
  }

  encode(): Uint8Array {
    const hasEpoch = this.epoch !== undefined;
    const flags = hasEpoch ? FLAG_EPOCH : 0;
    const headerLen = hasEpoch ? 5 : 4;
    const out = new Uint8Array(headerLen + this.body.length);
    out[0] = (COMPACT_VER << 4) | (flags & 0x0f);
    out[1] = this.op_ord & 0xff;
    out[2] = (this.seq >>> 8) & 0xff;
    out[3] = this.seq & 0xff;
    if (hasEpoch) out[4] = this.epoch! & 0xff;
    out.set(this.body, headerLen);
    return out;
  }

  static decode(bytes: Uint8Array): CompactDatagram {
    if (bytes.length < 4) {
      throw TransportError.malformed("compact datagram shorter than the 4-byte header");
    }
    const ver = bytes[0] >> 4;
    if (ver !== COMPACT_VER) throw TransportError.unsupportedVersion(ver);
    const flags = bytes[0] & 0x0f;
    const op_ord = bytes[1];
    const seq = (bytes[2] << 8) | bytes[3];
    let epoch: number | undefined;
    let bodyStart: number;
    if ((flags & FLAG_EPOCH) !== 0) {
      if (bytes.length < 5) {
        throw TransportError.malformed(
          "compact datagram flags claim an epoch byte that is absent",
        );
      }
      epoch = bytes[4];
      bodyStart = 5;
    } else {
      bodyStart = 4;
    }
    const d = new CompactDatagram(op_ord, seq, bytes.slice(bodyStart));
    if (epoch !== undefined) d.epoch = epoch;
    return d;
  }
}

// Classification of an incoming sequence number relative to what was last seen,
// for loss/reorder/restart detection. The transport detects; the app decides.
export type SeqEvent =
  | { kind: "first" }
  | { kind: "advanced"; gap: number }
  | { kind: "late-or-duplicate" }
  | { kind: "restart" };

export const SeqEvent = {
  first: (): SeqEvent => ({ kind: "first" }),
  advanced: (gap: number): SeqEvent => ({ kind: "advanced", gap }),
  lateOrDuplicate: (): SeqEvent => ({ kind: "late-or-duplicate" }),
  restart: (): SeqEvent => ({ kind: "restart" }),
} as const;

// Tracks the last sequence/epoch per channel to classify arrivals. The transport
// provides the information to detect loss/reorder/restart and nothing more — no
// recovery, per the spec's design constraints.
export class SeqTracker {
  private lastSeq?: number;
  private lastEpoch?: number;

  observe(seq: number, epoch?: number): SeqEvent {
    // An epoch change after a first observation means the sender restarted and
    // reset its sequence numbering — distinct from a huge reorder.
    if (epoch !== this.lastEpoch && this.lastEpoch !== undefined) {
      this.lastEpoch = epoch;
      this.lastSeq = seq;
      return SeqEvent.restart();
    }
    this.lastEpoch = epoch;
    // seq 0 marks an unsequenced datagram: it carries no ordering information,
    // so it is never late or duplicate. Report a zero-gap advance and leave the
    // running sequence untouched (a mix of sequenced and unsequenced still
    // tracks the sequenced ones).
    if (seq === 0) {
      return SeqEvent.advanced(0);
    }
    if (this.lastSeq === undefined) {
      this.lastSeq = seq;
      return SeqEvent.first();
    }
    if (seq > this.lastSeq) {
      const gap = seq - this.lastSeq - 1;
      this.lastSeq = seq;
      return SeqEvent.advanced(gap);
    }
    return SeqEvent.lateOrDuplicate();
  }
}
