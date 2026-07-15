// VENDORED from catalystcommunity/csilgen @ a661c8727022ee8987c92020a5667f116b92ff78
// (transports/typescript/src/carrier.ts). Do NOT hand-edit; re-sync from
// upstream instead (see cbor.ts's banner in this same directory).
//
// Carrier seams — the bring-your-own-carrier boundary (conventions doc §7).
//
// The library owns envelope codecs, framing, and lifecycle; the byte/datagram
// transport (the *carrier*) is injected. A host supplies a WebSocket, a
// WebTransport stream, a WebRTC unreliable DataChannel, QUIC datagrams, raw UDP,
// or anything else by implementing one of these interfaces — WITHOUT changing the
// library. That is the whole point of the seam, and it is why the conformance
// vectors (which test the codecs above the seam) need no real socket.
//
// HOW A HOST PLUGS IN A REAL CARRIER
// ----------------------------------
// The interfaces are deliberately tolerant of sync *or* async returns, so the
// in-memory loopbacks below stay synchronous for the codec tests while a real
// browser carrier returns Promises. RpcClient/RpcServer `await` every call, so
// both work unchanged.
//
// Browser WebSocket (CSIL-RPC / CSIL-Events — one envelope per binary frame):
//
//   class WebSocketCarrier implements FrameCarrier {
//     private inbox: Uint8Array[] = [];
//     private waiters: ((f: Uint8Array | null) => void)[] = [];
//     constructor(private ws: WebSocket) {
//       ws.binaryType = "arraybuffer";
//       ws.onmessage = (e) => this.deliver(new Uint8Array(e.data as ArrayBuffer));
//       ws.onclose = () => this.deliver(null);
//     }
//     private deliver(f: Uint8Array | null) {
//       const w = this.waiters.shift();
//       if (w) w(f); else if (f) this.inbox.push(f);
//     }
//     sendFrame(b: Uint8Array) { this.ws.send(b); }           // WS frames its own length
//     recvFrame(): Promise<Uint8Array | null> {
//       const f = this.inbox.shift();
//       return f ? Promise.resolve(f) : new Promise((res) => this.waiters.push(res));
//     }
//   }
//
// Note WebSocket already delimits messages, so no length prefix is added there.
// On a raw byte stream (TCP/TLS/Unix socket / a WebTransport bidi stream) the
// host instead uses `frameLengthPrefixed` on send and a `LengthPrefixedDeframer`
// fed by inbound chunks on receive — see those helpers below.
//
// WebRTC unreliable DataChannel / WebTransport datagrams (CSIL-Datagrams):
//
//   const dc = pc.createDataChannel("voice", { ordered: false, maxRetransmits: 0 });
//   class DataChannelCarrier implements DatagramCarrier {
//     // identical inbox/waiter pattern; dc.onmessage delivers one datagram each.
//     sendDatagram(b: Uint8Array) { dc.send(b); }
//     recvDatagram() { ... }
//   }
//
// In every case the library code is untouched; only this thin adapter changes.

import { MAX_FRAME_DEFAULT, TransportError } from "./conventions.ts";

// A stream/frame carrier: sends and receives one *delimited message* at a time.
// Used by CSIL-RPC and CSIL-Events. `recvFrame` resolves to `null` at a clean end
// of stream. Implementations may be synchronous (the loopback) or asynchronous (a
// real WebSocket); consumers always `await`.
export interface FrameCarrier {
  sendFrame(bytes: Uint8Array): void | Promise<void>;
  recvFrame(): Uint8Array | null | Promise<Uint8Array | null>;
}

// A datagram carrier: sends and receives one self-contained datagram (each within
// the channel MTU), with no delivery or ordering guarantee. Used by CSIL-Datagrams.
export interface DatagramCarrier {
  sendDatagram(bytes: Uint8Array): void | Promise<void>;
  recvDatagram(): Uint8Array | null | Promise<Uint8Array | null>;
}

// Prefix `bytes` with a 4-byte big-endian length (CSIL stream framing), enforcing
// the max-frame guard before producing the frame.
export function frameLengthPrefixed(bytes: Uint8Array, max: number = MAX_FRAME_DEFAULT): Uint8Array {
  if (bytes.length > max) throw TransportError.frameTooLarge(bytes.length, max);
  const out = new Uint8Array(4 + bytes.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, bytes.length, false); // big-endian
  out.set(bytes, 4);
  return out;
}

// An incremental deframer for the 4-byte big-endian length-prefix wire. A host
// wiring a byte stream (TCP/TLS/WebTransport) feeds inbound chunks via `push` and
// drains complete frames via `next`. The max-frame guard rejects a hostile length
// prefix BEFORE buffering its claimed body, so a corrupt prefix cannot exhaust
// memory. This is the TS twin of the Rust `read_length_prefixed`.
export class LengthPrefixedDeframer {
  private buf: Uint8Array = new Uint8Array(0);
  private readonly max: number;

  constructor(max: number = MAX_FRAME_DEFAULT) {
    this.max = max;
  }

  push(chunk: Uint8Array): void {
    const merged = new Uint8Array(this.buf.length + chunk.length);
    merged.set(this.buf, 0);
    merged.set(chunk, this.buf.length);
    this.buf = merged;
  }

  // Return the next complete frame, or `null` if not enough bytes have arrived.
  next(): Uint8Array | null {
    if (this.buf.length < 4) return null;
    const len = new DataView(this.buf.buffer, this.buf.byteOffset, 4).getUint32(0, false);
    if (len > this.max) throw TransportError.frameTooLarge(len, this.max);
    if (this.buf.length < 4 + len) return null;
    const frame = this.buf.slice(4, 4 + len);
    this.buf = this.buf.slice(4 + len);
    return frame;
  }
}

// An in-memory FrameCarrier backed by frame queues — for tests and for driving the
// codec without a socket. `outbound` collects what was sent; `inbound` feeds recv.
export class LoopbackFrameCarrier implements FrameCarrier {
  readonly outbound: Uint8Array[] = [];
  readonly inbound: Uint8Array[] = [];

  pushInbound(bytes: Uint8Array): void {
    this.inbound.push(bytes);
  }

  takeOutbound(): Uint8Array | undefined {
    return this.outbound.shift();
  }

  sendFrame(bytes: Uint8Array): void {
    this.outbound.push(bytes);
  }

  recvFrame(): Uint8Array | null {
    return this.inbound.shift() ?? null;
  }
}

// An in-memory DatagramCarrier — for tests and codec drives.
export class LoopbackDatagramCarrier implements DatagramCarrier {
  readonly outbound: Uint8Array[] = [];
  readonly inbound: Uint8Array[] = [];

  pushInbound(bytes: Uint8Array): void {
    this.inbound.push(bytes);
  }

  takeOutbound(): Uint8Array | undefined {
    return this.outbound.shift();
  }

  sendDatagram(bytes: Uint8Array): void {
    this.outbound.push(bytes);
  }

  recvDatagram(): Uint8Array | null {
    return this.inbound.shift() ?? null;
  }
}
