# Accepting regular (DNS-pinned) LinkKeys logins from Node/TypeScript

This document is **not** about the `@linkkeys/local-rp` package that lives in
this directory. That SDK implements the DNS-less **local RP** mode
(`dns-less-local-rp-design.md`) — for a LAN box or desktop app with no public
domain of its own. This document is the opposite case: an ordinary web app
whose users log in with LinkKeys identities that *are* DNS-pinned domains
(`alice@example.com`), via the app's own RP server. There is no packaged
Node client for that flow, so this is a worked example of writing one,
cribbing protocol plumbing from this SDK's source where it's useful and
inlining the rest. See "Local RP vs. regular RP" near the end if you're not
sure which mode you actually need.

Everything below was compile-checked with `tsc --noEmit` against this
package's own `tsconfig.json` compiler options, importing `@linkkeys/local-rp`
as a real dependency (not a path hack), and the hand-written CBOR codec was
round-tripped at runtime against this SDK's own generated
`src/generated/codec.gen.ts` (an independent implementation generated from
the same CSIL) to confirm wire compatibility. The code quoted here is what
compiled — nothing was simplified afterward for prose.

## Regular RP vs. local RP — which one do you need?

| | This SDK (`@linkkeys/local-rp`) | This document |
|---|---|---|
| User's identity | DNS-less: fingerprint of a locally-generated key | A real LinkKeys domain (`user@example.com`) |
| Your app's identity | A locally-generated signing key, self-asserted, admin-approved per IDP | A full LinkKeys domain with its own DNS records |
| Deployment | Import the SDK directly; no server of your own needed | Run your own LinkKeys server in RP mode alongside your app |
| Transport | TCP CSIL-RPC, unauthenticated at the transport layer (the login *request* is signed) | TCP CSIL-RPC, API-key authenticated, talking to your own RP server |
| Where the domain/signing key lives | In your app's own storage (`LocalRpKeyMaterial`) | Inside your RP server; your app **never** touches it |

If your users already have LinkKeys identities at real domains and you don't
want to run your own IDP, keep reading. If you're building something with no
public DNS of its own (a LAN tool, a desktop app), use this directory's SDK
instead — its `README.md` and `dns-less-local-rp-design.md` (repo root) are
the right starting point, not this file.

## Prerequisites

### 1. Deploy your own RP server

A relying party (RP) is a LinkKeys server deployed in RP mode — same Docker
image and Helm chart as a full IDP, just configured to hold domain keys and
sign/decrypt on your app's behalf without serving a login UI of its own. Full
instructions: `docs/DEPLOYING-RP.md`. Your Node app talks only to this RP
server; it never holds a domain private key.

### 2. Create a service account and grant it `api_access`

The `Rp` CSIL service (`sign-request`, `decrypt-token`, `verify-assertion`,
`userinfo-fetch`) requires the caller's API key to hold the **`api_access`**
relation on the RP's domain — a valid API key alone is not enough
(`crates/linkkeys/src/services/authorization.rs`: `required_relation_for_op`
maps every `Rp` op to `RELATION_API_ACCESS`, "so any active user's key can[not]
drive those oracles"). This is not auto-provisioned.

One-shot, for a brand new service account (exec into the RP pod):

```sh
linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
# Save the printed API key — it will not be shown again.
```

Or, to grant `api_access` to an **existing** user/key without minting a new
one (`crates/linkkeys/src/cli/mod.rs`'s `RelationCommands::GrantLocal`, and
`deploy/live.sh`'s `cmd_grant` helper, which documents this exact case —
"granting api_access to a demo app's existing RP key"):

```sh
linkkeys relation grant-local my-webapp api_access
```

Both are DB-direct/break-glass commands, run where the RP's database lives
(inside the RP pod), idempotent, and require no prior admin key.

### 3. DNS

Publish the RP's `_linkkeys` (trust-anchor fingerprints) and `_linkkeys_apis`
(`tcp=` endpoint) TXT records — see `docs/DEPLOYING-RP.md`'s "DNS" section.
Run `linkkeys domain dns-check` on the RP to print the exact records,
including the fingerprints you'll need for `RP_FINGERPRINTS` below (join the
`fp=...` values from the `_linkkeys` record with commas).

### 4. Toolchain

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"   # Node v26
```

## Architecture at a glance

```
Browser ──HTTP──> Your Node App ──TCP CSIL-RPC (pinned TLS, API key)──> Your RP server
                        |                                                     |
                        |                                          holds the domain key,
                        |                                          signs/decrypts/verifies
                   sessions, nonces,
                   API key storage
```

Your app redirects the browser to the *user's* IDP for the actual login; the
IDP redirects back to your app's `/callback` with an encrypted token; your
app hands that token to its own RP server to decrypt and verify. The RP
server, in turn, does its own DNS-pinned lookup of the user's IDP's keys —
your app never talks to the user's IDP directly.

## The login flow over TCP CSIL-RPC

The `Rp` service (`csil/linkkeys.csil`) exposes four operations your app
drives in sequence, all over one TCP CSIL-RPC connection per call,
API-key-authenticated via the envelope's `auth` field
(`crates/linkkeys/src/tcp/mod.rs`'s `authenticate_tcp_request`):

1. **`Rp/sign-request`** `{callback_url, nonce}` → `{signed_request}` — the RP
   server signs an auth request with the domain key it holds.
2. Redirect the browser to `https://<user's IDP>/auth/authorize?signed_request=<...>`
   (optionally `&user_hint=<local-part>` if the user typed `user@domain`).
3. The browser comes back to your `/callback` carrying `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** `{encrypted_token}` → `{signed_assertion}`.
5. **`Rp/verify-assertion`** `{signed_assertion, expected_domain}` →
   `{assertion, verified}` — the RP server fetches `expected_domain`'s
   DNS-pinned keys and checks the signature. `expected_domain` **must** come
   from something your app trusts (its own session state from step 1), never
   from the callback URL — see `server.ts` below for why.
6. **`Rp/userinfo-fetch`** (optional) `{token, api_base, domain}` → `UserInfo`
   — redeems the claim ticket via your RP server, which is the only party
   holding the domain key needed to do so.

This sequencing, including the two application-level checks in step 5
(assertion nonce matches what you issued, assertion domain matches what you
expected) mirrors the reference integration at `demoappsite/src/main.rs`,
which drives this exact flow from a real Rocket app.

### Why this example hand-writes protocol code instead of importing it

`@linkkeys/local-rp`'s `package.json` only exports `"."` (`src/index.ts`);
its vendored CSIL-RPC envelope codec (`src/vendor/csilgen-transport/`), its
generated payload codecs (`src/generated/codec.gen.ts`), and its DNS
TXT-record parsing (`src/dnsRecords.ts`) are not part of the package's public
surface, so a consuming app cannot import them — and shouldn't; they exist to
implement *this* SDK's DNS-less flow, not to be a general RPC client. What
**is** exported and reused directly below: `NodeTransport` (raw TCP dial),
`SystemDnsResolver` (DNS TXT lookup), and the `Transport`/`DnsResolver`
types. Everything protocol-specific (the CBOR codec, the envelope, TLS pin
verification, framing, and the `Rp` service's own request/response shapes)
is reimplemented here at the wire level described in `csil/linkkeys.csil`
and cribbed from `src/rpc.ts`'s TLS-pinning approach — not copy-pasted, since
none of it is reachable by import, but built the same way for the same
reasons (documented inline below).

## The TypeScript walkthrough

### Project setup

```json
{
  "name": "my-webapp",
  "type": "module",
  "dependencies": {
    "@linkkeys/local-rp": "file:../path/to/sdks/local-rp/typescript"
  },
  "devDependencies": {
    "typescript": "^5.7.0",
    "@types/node": "^22.10.0"
  }
}
```

Only `NodeTransport`, `SystemDnsResolver`, and their associated types come
from this dependency; see the previous section for why the rest is inlined.

### `cbor.ts` — minimal CBOR

Just the major types the `Rp` service's shapes use: unsigned integers, text,
bytes, booleans, arrays, maps, and tag 24 (the envelope's opaque-payload
wrapper). Structurally the same shape as this SDK's own
`src/generated/codec.gen.ts`, independently written.

```ts
// Minimal canonical-enough CBOR codec, hand-written to the same shape as
// @linkkeys/local-rp's own `src/generated/codec.gen.ts` (itself
// zero-dependency, self-contained). Not exported by the SDK's package.json
// ("exports": {".": "./src/index.ts"} only), so a consuming app cannot
// `import` it — this is a deliberately small reimplementation of just the
// CBOR major types the Rp service's request/response shapes use: unsigned
// integers, text strings, byte strings, booleans, arrays, maps, and tag 24
// (RFC 8949 §3.4.5.1, used to wrap the opaque envelope `payload`).

export type CborTag = { readonly tag: number; readonly value: CborValue };

export type CborValue =
  | number
  | boolean
  | null
  | string
  | Uint8Array
  | CborValue[]
  | Map<CborValue, CborValue>
  | CborTag;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function head(major: number, n: number, out: number[]): void {
  const mt = major << 5;
  if (n < 24) {
    out.push(mt | n);
  } else if (n < 0x100) {
    out.push(mt | 24, n);
  } else if (n < 0x10000) {
    out.push(mt | 25, (n >>> 8) & 0xff, n & 0xff);
  } else {
    out.push(mt | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
  }
}

function encInto(v: CborValue, out: number[]): void {
  if (typeof v === "number") {
    head(0, v, out);
  } else if (typeof v === "boolean") {
    out.push(v ? 0xf5 : 0xf4);
  } else if (v === null) {
    out.push(0xf6);
  } else if (typeof v === "string") {
    const bytes = textEncoder.encode(v);
    head(3, bytes.length, out);
    for (const b of bytes) out.push(b);
  } else if (v instanceof Uint8Array) {
    head(2, v.length, out);
    for (const b of v) out.push(b);
  } else if (Array.isArray(v)) {
    head(4, v.length, out);
    for (const item of v) encInto(item, out);
  } else if (v instanceof Map) {
    head(5, v.size, out);
    for (const [k, val] of v) {
      encInto(k, out);
      encInto(val, out);
    }
  } else {
    head(6, v.tag, out);
    encInto(v.value, out);
  }
}

/** Encode a CBOR value tree to bytes. */
export function encodeValue(value: CborValue): Uint8Array {
  const out: number[] = [];
  encInto(value, out);
  return Uint8Array.from(out);
}

type Cursor = { b: Uint8Array; pos: number };

function readArg(st: Cursor, low: number): number {
  if (low < 24) {
    st.pos += 1;
    return low;
  }
  if (low === 24) {
    const v = st.b[st.pos + 1]!;
    st.pos += 2;
    return v;
  }
  if (low === 25) {
    const v = (st.b[st.pos + 1]! << 8) | st.b[st.pos + 2]!;
    st.pos += 3;
    return v;
  }
  if (low === 26) {
    const v =
      st.b[st.pos + 1]! * 0x1000000 + (st.b[st.pos + 2]! << 16) + (st.b[st.pos + 3]! << 8) + st.b[st.pos + 4]!;
    st.pos += 5;
    return v;
  }
  throw new Error("unsupported CBOR argument width (indefinite/64-bit lengths not needed here)");
}

function decInto(st: Cursor): CborValue {
  const ib = st.b[st.pos]!;
  const major = ib >> 5;
  const low = ib & 0x1f;
  if (major === 7) {
    st.pos += 1;
    if (low === 20) return false;
    if (low === 21) return true;
    if (low === 22 || low === 23) return null;
    throw new Error("unsupported CBOR simple value");
  }
  const arg = readArg(st, low);
  switch (major) {
    case 0:
      return arg;
    case 2: {
      const slice = st.b.slice(st.pos, st.pos + arg);
      st.pos += arg;
      return slice;
    }
    case 3: {
      const text = textDecoder.decode(st.b.subarray(st.pos, st.pos + arg));
      st.pos += arg;
      return text;
    }
    case 4: {
      const arr: CborValue[] = [];
      for (let i = 0; i < arg; i++) arr.push(decInto(st));
      return arr;
    }
    case 5: {
      const m = new Map<CborValue, CborValue>();
      for (let i = 0; i < arg; i++) {
        const k = decInto(st);
        const val = decInto(st);
        m.set(k, val);
      }
      return m;
    }
    case 6: {
      const inner = decInto(st);
      return { tag: arg, value: inner };
    }
    default:
      throw new Error("malformed CBOR major type");
  }
}

/** Decode a single CBOR value from `bytes`. */
export function decode(bytes: Uint8Array): CborValue {
  const st: Cursor = { b: bytes, pos: 0 };
  const v = decInto(st);
  if (st.pos !== bytes.length) throw new Error("trailing bytes after CBOR value");
  return v;
}

export function mapGet(value: CborValue, key: string): CborValue | undefined {
  return value instanceof Map ? value.get(key) : undefined;
}

export function requireKey(value: CborValue, key: string): CborValue {
  const v = mapGet(value, key);
  if (v === undefined) throw new Error(`missing required field: ${key}`);
  return v;
}

export function asNumber(value: CborValue): number {
  if (typeof value === "number") return value;
  throw new Error("expected a number");
}

export function asString(value: CborValue): string {
  if (typeof value === "string") return value;
  throw new Error("expected a text string");
}

export function asBytes(value: CborValue): Uint8Array {
  if (value instanceof Uint8Array) return value;
  throw new Error("expected a byte string");
}

export function asBool(value: CborValue): boolean {
  if (typeof value === "boolean") return value;
  throw new Error("expected a boolean");
}

export function asArray(value: CborValue): CborValue[] {
  if (Array.isArray(value)) return value;
  throw new Error("expected an array");
}

function isCborTag(value: CborValue): value is CborTag {
  return (
    typeof value === "object" &&
    value !== null &&
    !(value instanceof Uint8Array) &&
    !(value instanceof Map) &&
    !Array.isArray(value) &&
    "tag" in value
  );
}

/** Wrap opaque payload bytes (themselves a CBOR item) in tag 24. */
export function tag24(payload: Uint8Array): CborTag {
  return { tag: 24, value: payload };
}

/** Extract the opaque payload bytes from a tag-24 value. */
export function untag24(value: CborValue): Uint8Array {
  if (isCborTag(value) && value.tag === 24) return asBytes(value.value);
  throw new Error("expected a tag-24 (encoded-cbor) payload");
}
```

### `envelope.ts` — the CSIL-RPC envelope

A request carries `{v, service, op, payload, ?auth}`; a response carries
`{v, status, payload, ?variant, ?error}` (`csil-rpc-transport.md` §2.3, and
this SDK's own `src/vendor/csilgen-transport/rpc.ts` for the same shape).
Field-lookup-by-key means encode order doesn't need to match any canonical
sort for the server to decode it correctly — this SDK's own generated codec
doesn't sort either (compare `src/generated/codec.gen.ts`'s `encInto` for
maps), so this file doesn't bother.

```ts
// The CSIL-RPC envelope (`csil-rpc-transport.md` §2.3) — a request carries
// {v, service, op, payload, ?auth}; a response carries {v, status, payload,
// ?variant, ?error}. `payload` is tag-24-wrapped opaque CBOR (the Rp-specific
// request/response bytes from rpProtocol.ts).
//
// This mirrors @linkkeys/local-rp's vendored `src/vendor/csilgen-transport/`
// (rpc.ts + conventions.ts + cbor.ts), which the SDK does not export from its
// package.json "exports" map — only "." (src/index.ts) is importable, so a
// consuming app cannot deep-import the vendored envelope codec. This file is
// the app-side reimplementation of the same wire format, trimmed to request/
// response (no push frames, no multiplexed ids — the Rp calls in this example
// are always one-request-per-connection).

import { type CborValue, asNumber, asString, decode, encodeValue, mapGet, requireKey, tag24, untag24 } from "./cbor.ts";

const VERSION = 1;

/** Transport-level status registry (`csil-rpc-transport.md`); 0 is success. */
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

export function encodeRpcRequest(service: string, op: string, payload: Uint8Array, auth?: string): Uint8Array {
  const m = new Map<CborValue, CborValue>();
  m.set("v", VERSION);
  m.set("service", service);
  m.set("op", op);
  m.set("payload", tag24(payload));
  if (auth !== undefined) m.set("auth", auth);
  return encodeValue(m);
}

export interface RpcResponse {
  status: number;
  payload: Uint8Array;
  variant?: string;
  error?: string;
}

export function decodeRpcResponse(bytes: Uint8Array): RpcResponse {
  const v = decode(bytes);
  const status = asNumber(requireKey(v, "status"));
  const payloadField = mapGet(v, "payload");
  const payload = payloadField !== undefined ? untag24(payloadField) : new Uint8Array(0);
  const variantField = mapGet(v, "variant");
  const errorField = mapGet(v, "error");
  return {
    status,
    payload,
    variant: variantField !== undefined ? asString(variantField) : undefined,
    error: errorField !== undefined ? asString(errorField) : undefined,
  };
}

/** Thrown for a non-Ok transport status (distinct from a network/TLS failure). */
export class RpcServerError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(`RP server rejected the call (status ${status}): ${message}`);
    this.name = "RpcServerError";
    this.status = status;
  }
}
```

### `rpcTransport.ts` — TLS-pinned dial and framing

This is the one piece that genuinely differs from the local-RP SDK's own
`src/rpc.ts`, and it's worth understanding why: that file re-discovers a
peer's TCP endpoint via DNS on **every** call, because it talks to whatever
IDP domain a user happens to name. Your app talks to exactly one peer it
operates itself — its own RP server — so the endpoint and fingerprints are
pinned once, out of band, the same way `demoappsite/src/main.rs` takes them
as `RP_TCP_ADDR`/`RP_FINGERPRINTS` config instead of re-resolving DNS per
request. The TLS pin *verification* logic, though, is identical in spirit to
`src/rpc.ts`'s `verifyPeerCertificatePin` and reused conceptually here.

```ts
// TLS-pinned dial + length-prefixed framing for one CSIL-RPC call to the
// app's own RP server. Cribbed from @linkkeys/local-rp's `src/rpc.ts`
// (`dialPinnedTls`, `verifyPeerCertificatePin`, `sendFrame`/`readFrame`),
// which is exported by the SDK only as *behavior* (fetchDomainKeys,
// redeemClaimTicket) — the dial/framing internals themselves are not part of
// the package's public surface (package.json "exports" only names
// "./src/index.ts"). `NodeTransport` (the raw socket dialer) *is* exported,
// so that part is reused directly rather than reimplemented.
//
// Unlike the local-rp SDK — which discovers a peer's TCP endpoint fresh via
// DNS on every call, because it talks to whatever IDP domain a user names —
// this app talks to exactly one peer it operates itself: its own RP server.
// The operator pins that RP's endpoint and DNS fingerprints once, out of
// band (`linkkeys domain dns-check` on the RP, see example.md's
// Prerequisites), the same way `demoappsite/src/main.rs` takes them as
// `RP_TCP_ADDR` / `RP_FINGERPRINTS` config rather than re-resolving DNS per
// request.

import * as nodeCrypto from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import { NodeTransport, type Transport } from "@linkkeys/local-rp";
import { decodeRpcResponse, encodeRpcRequest, RpcServerError, Status } from "./envelope.ts";

const MAX_FRAME_SIZE = 1024 * 1024;

export class TlsPinError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "TlsPinError";
  }
}

export interface RpServerConfig {
  /** `host:port` of the app's own RP server's CSIL-RPC TCP listener. */
  tcpAddr: string;
  /** DNS `_linkkeys` `fp=` fingerprints pinning the RP server's TLS cert. */
  fingerprints: readonly string[];
  /** The API key for a user holding the `api_access` relation on the RP. */
  apiKey: string;
}

function extractHostname(hostPort: string): string {
  const idx = hostPort.lastIndexOf(":");
  return idx < 0 ? hostPort : hostPort.slice(0, idx);
}

/**
 * Verify the connected peer's certificate SPKI fingerprint is pinned and its
 * validity window covers now — see `src/rpc.ts`'s module docs in the local-rp
 * SDK for why `rejectUnauthorized: false` (used when dialing below) is safe
 * here: LinkKeys domain certs are self-signed by design, and this check
 * *replaces* WebPKI chain validation with the DNS-published fingerprint pin.
 */
function verifyPeerCertificatePin(socket: tls.TLSSocket, fingerprints: readonly string[]): void {
  const peerCert = socket.getPeerCertificate(true);
  if (!peerCert || !peerCert.raw || peerCert.raw.length === 0) {
    throw new TlsPinError("RP server presented no certificate");
  }
  const x509 = new nodeCrypto.X509Certificate(peerCert.raw);
  const now = Date.now();
  if (now < x509.validFromDate.getTime() || now > x509.validToDate.getTime()) {
    throw new TlsPinError(`RP server certificate is outside its validity window (${x509.validFrom} .. ${x509.validTo})`);
  }
  if (x509.publicKey.asymmetricKeyType !== "ed25519") {
    throw new TlsPinError(`unexpected RP server certificate key type: ${x509.publicKey.asymmetricKeyType ?? "unknown"}`);
  }
  const jwk = x509.publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) throw new TlsPinError("could not extract Ed25519 public key from RP server certificate");
  const rawPublicKey = Buffer.from(jwk.x, "base64url");
  const fp = nodeCrypto.createHash("sha256").update(rawPublicKey).digest("hex");
  const pinned = new Set(fingerprints.map((f) => f.toLowerCase()));
  if (!pinned.has(fp.toLowerCase())) {
    throw new TlsPinError(`RP server certificate fingerprint ${fp} is not in the pinned set`);
  }
}

async function dialPinned(transport: Transport, tcpAddr: string, fingerprints: readonly string[]): Promise<tls.TLSSocket> {
  const rawSocket: net.Socket = await transport.dial(tcpAddr);
  const hostname = extractHostname(tcpAddr);
  return new Promise((resolve, reject) => {
    const tlsSocket = tls.connect({
      socket: rawSocket,
      servername: net.isIP(hostname) !== 0 ? undefined : hostname,
      // No CA to validate against — see this module's docs above.
      rejectUnauthorized: false,
    });
    tlsSocket.once("secureConnect", () => {
      try {
        verifyPeerCertificatePin(tlsSocket, fingerprints);
      } catch (e) {
        tlsSocket.destroy();
        reject(e);
        return;
      }
      resolve(tlsSocket);
    });
    tlsSocket.once("error", (e) => reject(new TlsPinError(`TLS handshake to RP server failed: ${e.message}`, { cause: e })));
  });
}

function writeAsync(socket: tls.TLSSocket, data: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.write(data, (err) => (err ? reject(err) : resolve()));
  });
}

async function sendFrame(socket: tls.TLSSocket, data: Uint8Array): Promise<void> {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  await writeAsync(socket, len);
  await writeAsync(socket, data);
}

/** Buffers inbound bytes until one length-prefixed frame is complete. One call in flight per connection — this example dials fresh per RPC, like the local-rp SDK's own `call()`. */
function readFrame(socket: tls.TLSSocket): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (fn: () => void) => {
      if (done) return;
      done = true;
      socket.removeListener("data", onData);
      socket.removeListener("close", onClose);
      socket.removeListener("error", onError);
      fn();
    };
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 4 + MAX_FRAME_SIZE) {
        finish(() => reject(new Error(`RP server sent more than ${4 + MAX_FRAME_SIZE} bytes without completing a frame`)));
        socket.destroy();
        return;
      }
      if (buf.length < 4) return;
      const len = buf.readUInt32BE(0);
      if (buf.length < 4 + len) return;
      finish(() => resolve(new Uint8Array(buf.subarray(4, 4 + len))));
    };
    const onClose = () => finish(() => reject(new Error("connection closed before a full frame arrived")));
    const onError = (e: Error) => finish(() => reject(e));
    socket.on("data", onData);
    socket.on("close", onClose);
    socket.on("error", onError);
  });
}

/**
 * Call `Rp/<op>` on the app's own RP server over a fresh pinned-TLS
 * connection, authenticated with the API key. Throws `RpcServerError` for a
 * non-Ok transport status, `TlsPinError` for a pin/cert failure.
 */
export async function callRp(config: RpServerConfig, op: string, payload: Uint8Array, transport: Transport = new NodeTransport()): Promise<Uint8Array> {
  const socket = await dialPinned(transport, config.tcpAddr, config.fingerprints);
  try {
    await sendFrame(socket, encodeRpcRequest("Rp", op, payload, config.apiKey));
    const frame = await readFrame(socket);
    const resp = decodeRpcResponse(frame);
    if (resp.status !== Status.Ok) {
      throw new RpcServerError(resp.status, resp.error ?? "unknown error");
    }
    return resp.payload;
  } finally {
    socket.destroy();
  }
}
```

`NodeTransport` defaults to `AddressPolicy: "permissive"` (exported from
`@linkkeys/local-rp`), which is what you want here — your RP server is
typically on a private/cluster-internal address, and the permissive default
is the same one this SDK itself ships. `net.isIP` guards against passing an
IP literal as TLS SNI, matching `src/rpc.ts`'s `isIpAddressLiteral`.

### `rpProtocol.ts` — the `Rp` service's request/response shapes

Field names and wire shapes mirror this SDK's generated
`src/generated/types.gen.ts`/`codec.gen.ts` (also not exported), trimmed to
the four ops this flow uses. `RpSignRequest` also has optional
`requestedClaims`/`flowContext` fields in the full CSIL type; this example
omits them (the RP server falls back to its own `RP_CLAIMS_CONFIG`) to keep
the codec short — extend it the same way `claims`/`signatures` arrays are
handled below if you need to vary requested claims per call.

```ts
// Typed request/response shapes for the `Rp` CSIL service (`csil/linkkeys.csil`,
// "Relying Party (Rp) helper Types") plus their CBOR encode/decode functions,
// and thin wrappers that drive them over `callRp`. Field shapes and wire
// names (snake_case on the wire, camelCase in TS) mirror
// @linkkeys/local-rp's generated `src/generated/types.gen.ts` /
// `codec.gen.ts` — which the SDK does not export (see rpcTransport.ts's
// module docs) — trimmed to only the four ops this flow uses:
// sign-request, decrypt-token, verify-assertion, userinfo-fetch.
//
// `RpSignRequest` also has optional `requestedClaims` / `flowContext` fields
// in the full CSIL type; this example omits them (the RP server falls back
// to its own `RP_CLAIMS_CONFIG`) to keep the codec short. Add them the same
// way `signatures`/`claims` arrays are handled below if your app needs to
// vary requested claims per call.

import { type CborValue, asArray, asBool, asBytes, asString, decode, encodeValue, mapGet, requireKey } from "./cbor.ts";
import { callRp, type RpServerConfig } from "./rpcTransport.ts";
import type { Transport } from "@linkkeys/local-rp";

function optString(value: CborValue | undefined): string | undefined {
  return value === undefined ? undefined : asString(value);
}

// -- sign-request --

export interface RpSignRequest {
  callbackUrl: string;
  nonce: string;
}

function encodeRpSignRequest(v: RpSignRequest): Uint8Array {
  const m = new Map<CborValue, CborValue>();
  m.set("nonce", v.nonce);
  m.set("callback_url", v.callbackUrl);
  return encodeValue(m);
}

export interface RpSignResponse {
  signedRequest: string;
}

function decodeRpSignResponse(bytes: Uint8Array): RpSignResponse {
  const v = decode(bytes);
  return { signedRequest: asString(requireKey(v, "signed_request")) };
}

// -- decrypt-token --

export interface RpDecryptRequest {
  encryptedToken: string;
}

function encodeRpDecryptRequest(v: RpDecryptRequest): Uint8Array {
  const m = new Map<CborValue, CborValue>();
  m.set("encrypted_token", v.encryptedToken);
  return encodeValue(m);
}

export interface RpDecryptResponse {
  signedAssertion: string;
}

function decodeRpDecryptResponse(bytes: Uint8Array): RpDecryptResponse {
  const v = decode(bytes);
  return { signedAssertion: asString(requireKey(v, "signed_assertion")) };
}

// -- verify-assertion --

export interface RpVerifyRequest {
  signedAssertion: string;
  expectedDomain: string;
}

function encodeRpVerifyRequest(v: RpVerifyRequest): Uint8Array {
  const m = new Map<CborValue, CborValue>();
  m.set("expected_domain", v.expectedDomain);
  m.set("signed_assertion", v.signedAssertion);
  return encodeValue(m);
}

export interface IdentityAssertion {
  userId: string;
  domain: string;
  audience: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  authorizedClaims: string[];
  displayName?: string;
}

function decodeIdentityAssertion(value: CborValue): IdentityAssertion {
  return {
    userId: asString(requireKey(value, "user_id")),
    domain: asString(requireKey(value, "domain")),
    audience: asString(requireKey(value, "audience")),
    nonce: asString(requireKey(value, "nonce")),
    issuedAt: asString(requireKey(value, "issued_at")),
    expiresAt: asString(requireKey(value, "expires_at")),
    authorizedClaims: asArray(requireKey(value, "authorized_claims")).map(asString),
    displayName: optString(mapGet(value, "display_name")),
  };
}

export interface RpVerifyResponse {
  assertion: IdentityAssertion;
  verified: boolean;
}

function decodeRpVerifyResponse(bytes: Uint8Array): RpVerifyResponse {
  const v = decode(bytes);
  return {
    assertion: decodeIdentityAssertion(requireKey(v, "assertion")),
    verified: asBool(requireKey(v, "verified")),
  };
}

// -- userinfo-fetch --

export interface RpUserInfoRequest {
  /** URL-param-encoded SignedIdentityAssertion — pass through `RpDecryptResponse.signedAssertion` unchanged. */
  token: string;
  /** The IDP's HTTPS API base (used only to detect the single-instance self-call case). */
  apiBase: string;
  domain: string;
}

function encodeRpUserInfoRequest(v: RpUserInfoRequest): Uint8Array {
  const m = new Map<CborValue, CborValue>();
  m.set("token", v.token);
  m.set("domain", v.domain);
  m.set("api_base", v.apiBase);
  return encodeValue(m);
}

export interface ClaimSignature {
  domain: string;
  signedByKeyId: string;
  signature: Uint8Array;
}

function decodeClaimSignature(value: CborValue): ClaimSignature {
  return {
    domain: asString(requireKey(value, "domain")),
    signedByKeyId: asString(requireKey(value, "signed_by_key_id")),
    signature: asBytes(requireKey(value, "signature")),
  };
}

export interface Claim {
  claimId: string;
  userId: string;
  claimType: string;
  claimValue: Uint8Array;
  signatures: ClaimSignature[];
  attestedAt: string;
  createdAt: string;
  expiresAt?: string;
  revokedAt?: string;
}

function decodeClaim(value: CborValue): Claim {
  return {
    claimId: asString(requireKey(value, "claim_id")),
    userId: asString(requireKey(value, "user_id")),
    claimType: asString(requireKey(value, "claim_type")),
    claimValue: asBytes(requireKey(value, "claim_value")),
    signatures: asArray(requireKey(value, "signatures")).map(decodeClaimSignature),
    attestedAt: asString(requireKey(value, "attested_at")),
    createdAt: asString(requireKey(value, "created_at")),
    expiresAt: optString(mapGet(value, "expires_at")),
    revokedAt: optString(mapGet(value, "revoked_at")),
  };
}

export interface UserInfo {
  userId: string;
  domain: string;
  displayName: string;
  claims: Claim[];
}

function decodeUserInfo(bytes: Uint8Array): UserInfo {
  const v = decode(bytes);
  return {
    userId: asString(requireKey(v, "user_id")),
    domain: asString(requireKey(v, "domain")),
    displayName: asString(requireKey(v, "display_name")),
    claims: asArray(requireKey(v, "claims")).map(decodeClaim),
  };
}

// -- wrappers: one call each, driven over callRp() --

export async function signRequest(rp: RpServerConfig, req: RpSignRequest, transport?: Transport): Promise<RpSignResponse> {
  const payload = await callRp(rp, "sign-request", encodeRpSignRequest(req), transport);
  return decodeRpSignResponse(payload);
}

export async function decryptToken(rp: RpServerConfig, req: RpDecryptRequest, transport?: Transport): Promise<RpDecryptResponse> {
  const payload = await callRp(rp, "decrypt-token", encodeRpDecryptRequest(req), transport);
  return decodeRpDecryptResponse(payload);
}

export async function verifyAssertion(rp: RpServerConfig, req: RpVerifyRequest, transport?: Transport): Promise<RpVerifyResponse> {
  const payload = await callRp(rp, "verify-assertion", encodeRpVerifyRequest(req), transport);
  return decodeRpVerifyResponse(payload);
}

export async function fetchUserInfo(rp: RpServerConfig, req: RpUserInfoRequest, transport?: Transport): Promise<UserInfo> {
  const payload = await callRp(rp, "userinfo-fetch", encodeRpUserInfoRequest(req), transport);
  return decodeUserInfo(payload);
}
```

### `resolveIdpBase.ts` — finding the user's IDP HTTPS base

This is a different DNS lookup from anything above: it resolves the
**user's** IDP (wherever `user@example.com` actually lives), not your own RP
server, so the browser knows where to go for step 2 of the flow. Browsers
reach this over ordinary WebPKI TLS — DNS `fp=` pinning only applies to the
TCP protocol, not this HTTPS redirect target
(`docs/DEPLOYING-RP.md`: "`https=` is the browser-adjacent API base"). This
reuses `SystemDnsResolver` (exported) for the actual lookup and inlines the
small amount of `_linkkeys_apis` parsing that isn't exported
(`src/dnsRecords.ts`'s `parseLinkkeysApisTxt`).

```ts
// Resolve the HTTPS API base of the IDP the *user* is logging into (not the
// app's own RP — that endpoint is pinned config, see rpcTransport.ts). This
// is the redirect target for `/auth/authorize`; browsers reach it over
// ordinary WebPKI TLS; DNS TXT `fp=` pinning is not needed here (that pin
// only applies to the TCP protocol — see DEPLOYING-RP.md's "Gateway" and
// "DNS" sections: `https=` is "the browser-adjacent API base").
//
// Reuses `SystemDnsResolver` from @linkkeys/local-rp (exported) for the TXT
// lookup itself; the `_linkkeys_apis` record parsing is inlined (~10 lines)
// because `parseLinkkeysApisTxt` lives in the SDK's `src/dnsRecords.ts`,
// which is not re-exported from the package's public entry point.

import { SystemDnsResolver, type DnsResolver } from "@linkkeys/local-rp";

/** Parse the `https=` field out of a `_linkkeys_apis` TXT record string. */
function parseHttpsBase(txt: string): string | undefined {
  const parts = txt.split(/\s+/).filter((p) => p.length > 0);
  if (!parts.some((p) => p === "v=lk1")) return undefined;
  const httpsPart = parts.find((p) => p.startsWith("https="));
  return httpsPart ? `https://${httpsPart.slice("https=".length)}` : undefined;
}

/**
 * Resolve `domain`'s HTTPS API base via its `_linkkeys_apis` DNS TXT record,
 * falling back to `https://{domain}` if no usable record is found — matching
 * `demoappsite/src/main.rs`'s `resolve_api_base`.
 */
export async function resolveIdpApiBase(domain: string, dns: DnsResolver = new SystemDnsResolver()): Promise<string> {
  try {
    const txts = await dns.txtLookup(`_linkkeys_apis.${domain}`);
    for (const txt of txts) {
      const base = parseHttpsBase(txt);
      if (base) return base;
    }
  } catch {
    // Fall through to the direct fallback below.
  }
  return `https://${domain}`;
}
```

### `server.ts` — the app

Plain `node:http` — no framework dependency, per this codebase's "every
dependency is a liability" stance — but `handleLogin`/`handleCallback` are
ordinary `(req, res)` handlers; porting them to Express/Fastify/etc. is
mechanical.

```ts
// A minimal Node app accepting REGULAR (DNS-pinned) LinkKeys logins via its
// own RP server (docs/DEPLOYING-RP.md). Plain `node:http` — no framework
// dependency — but the two routes (`login`/`callback`) are ordinary request
// handlers, so dropping this into Express/Fastify/etc. is a direct port.
//
// App responsibilities this file owns (the RP server proves none of these):
//   - nonce single-use (`consumeNonce` deletes on first read — a replayed
//     callback finds nothing and is rejected)
//   - correlating a callback to the login attempt that began it, and
//     re-checking the verified assertion's nonce/domain against that attempt
//     (an HMAC-signed `auth_state` cookie carries the correlation across the
//     browser round-trip to the IDP and back — the callback URL itself
//     carries only `encrypted_token`, nothing else)
//   - session issuance and storage (in-memory `Map` here for a runnable
//     example; use a real session store in production)
//   - API key storage (`RP_API_KEY` env var; never hold a domain private key
//     — that stays inside the RP server, see DEPLOYING-RP.md)

import crypto from "node:crypto";
import http from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { decryptToken, fetchUserInfo, signRequest, verifyAssertion } from "./rpProtocol.ts";
import type { RpServerConfig } from "./rpcTransport.ts";
import { resolveIdpApiBase } from "./resolveIdpBase.ts";

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env var ${name}`);
  return v;
}

const rpConfig: RpServerConfig = {
  tcpAddr: requireEnv("RP_TCP_ADDR"), // e.g. "127.0.0.1:4987" — see Prerequisites
  fingerprints: requireEnv("RP_FINGERPRINTS").split(",").map((s) => s.trim()).filter(Boolean),
  apiKey: requireEnv("RP_API_KEY"),
};
// HMAC key for the `auth_state` cookie (below) — a separate secret from the
// RP API key. Must be stable across restarts/replicas in production (an env
// var, not regenerated per process) or in-flight logins break.
const cookieSecret = Buffer.from(requireEnv("AUTH_COOKIE_SECRET"), "base64url");
const publicOrigin = process.env.PUBLIC_ORIGIN ?? "http://localhost:8080";
const callbackUrl = `${publicOrigin}/callback`;

// -- Nonce single-use tracking (app responsibility #1) --

interface PendingLogin {
  domain: string;
  apiBase: string;
  expiresAt: number;
}

const pendingLogins = new Map<string, PendingLogin>();

function rememberNonce(nonce: string, domain: string, apiBase: string): void {
  pendingLogins.set(nonce, { domain, apiBase, expiresAt: Date.now() + 5 * 60_000 });
}

/** Single-use: deletes on read. A replayed callback (same nonce twice) finds nothing the second time. */
function consumeNonce(nonce: string): PendingLogin | undefined {
  const entry = pendingLogins.get(nonce);
  if (!entry) return undefined;
  pendingLogins.delete(nonce);
  if (entry.expiresAt < Date.now()) return undefined;
  return entry;
}

// -- auth_state cookie: HMAC-signed correlation between /login and /callback --

interface AuthState {
  nonce: string;
  domain: string;
}

function hmac(value: string): string {
  return crypto.createHmac("sha256", cookieSecret).update(value).digest("base64url");
}

function packAuthState(state: AuthState): string {
  const body = Buffer.from(JSON.stringify(state), "utf8").toString("base64url");
  return `${body}.${hmac(body)}`;
}

/** Verifies the HMAC before trusting the JSON inside — an unsigned cookie value must never reach `expectedDomain`. */
function unpackAuthState(cookieValue: string): AuthState | undefined {
  const dot = cookieValue.lastIndexOf(".");
  if (dot < 0) return undefined;
  const body = cookieValue.slice(0, dot);
  const sig = cookieValue.slice(dot + 1);
  const expected = hmac(body);
  const sigBuf = Buffer.from(sig, "base64url");
  const expectedBuf = Buffer.from(expected, "base64url");
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) return undefined;
  try {
    const parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (typeof parsed?.nonce === "string" && typeof parsed?.domain === "string") return parsed;
  } catch {
    // fall through
  }
  return undefined;
}

// -- Session storage (app responsibility #2; swap for a real store) --

interface Session {
  userId: string;
  domain: string;
  displayName: string;
  claimTypes: string[];
}

const sessions = new Map<string, Session>();

function readCookie(req: IncomingMessage, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return undefined;
}

// -- Routes --

function loginForm(res: ServerResponse, error?: string): void {
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><html><body>
    ${error ? `<p style="color:red">${error}</p>` : ""}
    <form method="POST" action="/login">
      <label>Your identity (you@example.com or example.com)
        <input name="identity" autofocus />
      </label>
      <button type="submit">Log in with LinkKeys</button>
    </form>
  </body></html>`);
}

/** Parse "user@domain" or a bare "domain" into (userHint, domain). */
function parseIdentity(input: string): { userHint: string | undefined; domain: string } {
  const at = input.lastIndexOf("@");
  if (at > 0 && at < input.length - 1) {
    return { userHint: input.slice(0, at), domain: input.slice(at + 1) };
  }
  return { userHint: undefined, domain: input };
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

async function handleLogin(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = new URLSearchParams(await readBody(req));
  const identity = (body.get("identity") ?? "").trim();
  if (!identity) return loginForm(res, "Enter an identity to log in with.");
  const { userHint, domain } = parseIdentity(identity);

  // 1. Rp/sign-request — the RP server signs the auth request with the
  // domain key it holds; this app never sees a private key.
  const nonce = crypto.randomUUID();
  let signed;
  try {
    signed = await signRequest(rpConfig, { callbackUrl, nonce });
  } catch (e) {
    return loginForm(res, `Could not contact the RP service: ${(e as Error).message}`);
  }

  const apiBase = await resolveIdpApiBase(domain);
  rememberNonce(nonce, domain, apiBase);

  // 2. Redirect the browser to the IDP's login form. The auth_state cookie
  // is how /callback later learns which domain/nonce this attempt was for —
  // the callback URL itself carries only `encrypted_token`.
  const target = new URL("/auth/authorize", apiBase);
  target.searchParams.set("signed_request", signed.signedRequest);
  if (userHint) target.searchParams.set("user_hint", userHint);

  res.writeHead(302, {
    location: target.toString(),
    "set-cookie": `auth_state=${packAuthState({ nonce, domain })}; HttpOnly; Secure; SameSite=Lax; Path=/`,
  });
  res.end();
}

async function handleCallback(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", publicOrigin);
  const encryptedToken = url.searchParams.get("encrypted_token");
  if (!encryptedToken) {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("missing encrypted_token");
    return;
  }

  const stateCookie = readCookie(req, "auth_state");
  const authState = stateCookie ? unpackAuthState(stateCookie) : undefined;
  if (!authState) {
    res.writeHead(400, { "content-type": "text/plain" });
    res.end("no (valid) auth_state cookie — login flow may have expired or the cookie was tampered with");
    return;
  }

  // Clear the auth_state cookie immediately; it's single-shot regardless of
  // what happens next.
  const clearAuthState = "auth_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

  // Nonce single-use — look up (and delete) what /login remembered for it.
  const pending = consumeNonce(authState.nonce);
  if (!pending || pending.domain !== authState.domain) {
    res.writeHead(401, { "content-type": "text/plain", "set-cookie": clearAuthState });
    res.end("no matching pending login (expired, already used, or replayed)");
    return;
  }

  // 3. Rp/decrypt-token — the RP server decrypts with the domain key.
  let decrypted;
  try {
    decrypted = await decryptToken(rpConfig, { encryptedToken });
  } catch (e) {
    res.writeHead(400, { "content-type": "text/plain", "set-cookie": clearAuthState });
    res.end(`could not decrypt token: ${(e as Error).message}`);
    return;
  }

  // 4. Rp/verify-assertion — `expectedDomain` comes from our own signed
  // cookie, never from the callback URL or the token itself, so an attacker
  // can't redirect verification at a domain of their choosing.
  let verified;
  try {
    verified = await verifyAssertion(rpConfig, {
      signedAssertion: decrypted.signedAssertion,
      expectedDomain: pending.domain,
    });
  } catch (e) {
    res.writeHead(401, { "content-type": "text/plain", "set-cookie": clearAuthState });
    res.end(`assertion verification failed: ${(e as Error).message}`);
    return;
  }

  // Belt-and-suspenders: the RP server already refuses to hand back a
  // non-`verified` result on success, but checking explicitly costs nothing
  // and doesn't rely on that being true forever.
  if (!verified.verified || verified.assertion.nonce !== authState.nonce || verified.assertion.domain !== pending.domain) {
    res.writeHead(401, { "content-type": "text/plain", "set-cookie": clearAuthState });
    res.end("assertion nonce/domain did not match this login attempt");
    return;
  }

  // 5. Rp/userinfo-fetch (optional) — only our RP server holds the domain
  // key needed to redeem the claim ticket, so we delegate to it rather than
  // calling the IDP directly.
  let userInfo;
  try {
    userInfo = await fetchUserInfo(rpConfig, {
      token: decrypted.signedAssertion,
      apiBase: pending.apiBase,
      domain: pending.domain,
    });
  } catch (e) {
    res.writeHead(502, { "content-type": "text/plain", "set-cookie": clearAuthState });
    res.end(`could not fetch user info: ${(e as Error).message}`);
    return;
  }

  // 6. Mint our own session — the RP server never does this for us.
  const sessionId = crypto.randomUUID();
  sessions.set(sessionId, {
    userId: userInfo.userId,
    domain: userInfo.domain,
    displayName: userInfo.displayName,
    claimTypes: userInfo.claims.map((c) => c.claimType),
  });

  res.writeHead(302, {
    location: "/",
    "set-cookie": [clearAuthState, `session=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/`],
  });
  res.end();
}

const server = http.createServer((req, res) => {
  const path = (req.url ?? "/").split("?")[0];
  if (req.method === "GET" && path === "/") {
    const sessionId = readCookie(req, "session");
    const session = sessionId ? sessions.get(sessionId) : undefined;
    if (session) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      return res.end(`<html><body>Welcome, ${session.displayName} (${session.userId}@${session.domain})</body></html>`);
    }
    return loginForm(res);
  }
  if (req.method === "POST" && path === "/login") {
    return void handleLogin(req, res);
  }
  if (req.method === "GET" && path === "/callback") {
    return void handleCallback(req, res);
  }
  res.writeHead(404);
  res.end();
});

server.listen(Number(process.env.PORT ?? 8080));
```

## Running it

```sh
export RP_TCP_ADDR="127.0.0.1:4987"
export RP_FINGERPRINTS="<fp1>,<fp2>,<fp3>"   # from `linkkeys domain dns-check` on the RP
export RP_API_KEY="<the api_access key from Prerequisites>"
export AUTH_COOKIE_SECRET="$(node -e 'console.log(require("crypto").randomBytes(32).toString("base64url"))')"
export PUBLIC_ORIGIN="https://myapp.example.com"   # or http://localhost:8080 for local dev
tsc --noEmit && node --experimental-strip-types src/server.ts
```

Visit `/`, submit an identity, and you'll be redirected to that domain's
LinkKeys login; on success you land back on `/` with a session.

## Callback handling recap

The only thing the browser round-trip *guarantees* your `/callback` receives
is `?encrypted_token=<...>` — nothing else in the URL is trustworthy input
(`csil/linkkeys.csil`'s `RpDecryptRequest` comment: "URL-param-encoded
encrypted token"; the server's own callback route,
`#[rocket::get("/callback?<encrypted_token>")]` in
`crates/linkkeys/src/web/mod.rs`, reads nothing else either). Everything
`handleCallback` needs to know about *which* login this answers —
which domain, which nonce — has to come from state your app itself
established at `/login` time and can trust. That's the `auth_state` cookie:
HMAC-signed so a tampered value is rejected outright, read back and
consumed exactly once, and its `domain` field is the only source
`expectedDomain` is ever allowed to come from.

## App responsibilities

The RP server proves cryptographic facts (a signature is valid, a token
decrypts). It does not, and cannot, know about your app's sessions, so these
remain entirely your job — the same allocation of responsibility this
directory's own SDK documents in its README's "App responsibilities" section
for the local-RP case:

- **Nonce single-use** — `pendingLogins`/`consumeNonce` in `server.ts`.
  Deletes on first read; a replayed `encrypted_token` (or a replayed
  `auth_state` cookie) finds nothing the second time.
- **Sessions** — `sessions` in `server.ts`. Swap the `Map` for a real store
  (Redis, a database table, signed JWTs) in production; the shape of what
  goes in one is unchanged.
- **API key storage** — `RP_API_KEY` (and separately, `AUTH_COOKIE_SECRET`)
  are ordinary application secrets: environment variables backed by your
  platform's secret manager, not source control. Neither is a domain private
  key — that stays inside the RP server (`docs/DEPLOYING-RP.md`: "the web app
  NEVER touches private keys").

## The deprecated HTTP API

`docs/DEPLOYING-RP.md`'s "Web App Integration" section documents
`POST /v1alpha/sign-request.json` etc. — bearer-token-authed HTTP endpoints
on the RP server. Those routes still exist but are **deprecated**; new
integrations should use the TCP CSIL-RPC `Rp` service shown in this document.
The request/response field shapes are the same either way (same underlying
`RpSignRequest`/etc. types); only the transport differs.

## Node only — the browser is out of the question

Everything above runs on your app's **server**. An API key that can drive
`Rp/sign-request`/`decrypt-token` is exactly as sensitive as a domain private
key in terms of blast radius — anyone holding it can mint and decrypt login
tokens for your RP — so it must never reach client-side JavaScript, and the
raw-TLS-socket TCP protocol this document implements has no browser
equivalent to begin with (no raw sockets, no custom certificate-pin
verification API). This is the same posture this directory's own SDK takes
for local-RP identities, stated in its README without softening: the browser
only ever carries opaque signed/encrypted blobs through redirects; it never
holds a key or a credential.
