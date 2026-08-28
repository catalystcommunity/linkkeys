// csilgen-transport (TypeScript) — reference implementation of the CSIL transport
// family: CSIL-RPC, CSIL-Events, and CSIL-Datagrams. It owns the envelope codecs,
// framing, and connection lifecycle; the byte/datagram carrier is injected
// (bring-your-own-carrier), so a host plugs a browser WebSocket, WebTransport,
// a WebRTC unreliable DataChannel, QUIC, or anything else without changing this
// library. Targets both browser/WASM clients and Node — the codecs touch only
// Uint8Array and standard Web APIs (TextEncoder/TextDecoder/DataView).
//
// See the spec docs at the repo root: csil-transport-conventions.md,
// csil-rpc-transport.md, csil-events-transport.md, csil-datagrams-transport.md.
// The byte layout is pinned by the conformance vectors in transports/conformance/.

export * from "./cbor.ts";
export * from "./conventions.ts";
export * from "./carrier.ts";
export * from "./rpc.ts";
export * from "./events.ts";
export * from "./datagrams.ts";
