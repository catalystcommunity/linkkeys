// CSIL-RPC over the injected `Transport`, TLS-pinned to a domain's DNS `fp=`
// records — this SDK's only network surface (design doc, "Required Network
// Access"): domain public keys, revocations, and claim-ticket redemption,
// all unauthenticated-TLS TCP CSIL-RPC calls pinned the same way
// `crates/linkkeys/src/tcp/tls.rs` pins the S2S path.
//
// Frame format: 4-byte big-endian length prefix + one CSIL-RPC envelope
// (`csil-rpc-transport.md` §2.3), matching `sdks/local-rp/rust/src/rpc.rs`.
// The envelope codec itself is the vendored `csilgen-transport` reference
// library (`src/vendor/csilgen-transport/`) — this file supplies only the
// TCP socket + TLS pinning around it, per the design doc: "the SDK
// hand-provides only the TCP socket transport."
//
// ## TLS pinning: why `rejectUnauthorized: false` is safe here
//
// LinkKeys domain certificates are self-signed (`generate_domain_tls_cert`,
// `crates/linkkeys-rpc-client/src/tls.rs`) — there is no CA to validate
// against, by design. The trust anchor is the DNS `_linkkeys` TXT record's
// `fp=` set, exactly as `crates/linkkeys/src/tcp/tls.rs` pins the
// server-to-server path: SHA-256 hex over the certificate's
// SubjectPublicKeyInfo `subject_public_key` BIT STRING contents (the raw
// Ed25519 public key). WebPKI chain-of-trust validity is simply not the
// question this protocol asks; the pin IS the trust anchor. Disabling
// Node's normal CA verification (`rejectUnauthorized: false`) is therefore
// not "skipping" security — it is required, because there is no CA to
// verify against — and it is made safe by *replacing* it with the mandatory
// manual pin check below, performed before any RPC bytes are sent.
//
// `crypto.X509Certificate` (not `tls.TLSSocket#getPeerCertificate().pubkey`)
// is used to extract the public key: empirically, Node's legacy peer
// certificate object leaves `.pubkey` `undefined` for Ed25519 certificates,
// while `X509Certificate`'s `.publicKey` correctly parses them. The public
// key is exported as JWK to recover the raw 32-byte key (see `crypto.ts`'s
// module docs on the raw-key-import footgun) and hashed exactly like the
// existing DNS `fp=`/domain-key fingerprint format.

import * as nodeCrypto from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import { DnsLookupError, type DnsResolver } from "./dns.ts";
import { linkkeysApisDnsName, linkkeysDnsName, parseLinkkeysApisTxt, parseLinkkeysTxt } from "./dnsRecords.ts";
import { trustKeys } from "./dnsRecords.ts";
import { verifyRevocationCertificate } from "./revocation.ts";
import type { Transport } from "./transport.ts";
import * as generated from "./generated/codec.gen.ts";
import type {
  DomainPublicKey,
  LocalRpTicketRedemptionResponse,
  SignedLocalRpTicketRedemptionRequest,
} from "./generated/types.gen.ts";
import { RpcRequest, RpcResponse, Status, statusName, statusIsOk } from "./vendor/csilgen-transport/index.ts";

/** Mirrors the server's own cap (`crates/linkkeys-rpc-client`) so a malicious/compromised peer cannot drive this client to an unbounded allocation via a forged length prefix. */
const MAX_FRAME_SIZE = 1024 * 1024;

export class TlsError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "TlsError";
  }
}

export class ProtocolError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ProtocolError";
  }
}

export class RpcServerError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(`server RPC error (${statusName(status)}/${status}): ${message}`);
    this.name = "RpcServerError";
    this.status = status;
  }
}

export class NoTrustedDomainKeysError extends Error {
  constructor(domain: string) {
    super(`no trusted public keys could be established for domain: ${domain}`);
    this.name = "NoTrustedDomainKeysError";
  }
}

/** Discovered endpoint for a domain: its pinned trust-anchor fingerprints (`_linkkeys`) and its CSIL-RPC TCP address (`_linkkeys_apis` `tcp=`). */
export interface DomainEndpoint {
  fingerprints: string[];
  tcpAddr: string;
}

/**
 * Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails closed:
 * a missing/unparseable record, or a `_linkkeys` record with no `fp=`
 * entries, or a `_linkkeys_apis` record with no `tcp=` entry, is an error —
 * this SDK never proceeds without a fingerprint set to pin to.
 */
export async function discoverDomainEndpoint(
  dns: DnsResolver,
  domain: string,
): Promise<DomainEndpoint> {
  const anchorName = linkkeysDnsName(domain);
  const anchorTxts = await dns.txtLookup(anchorName);
  let fingerprints: string[] | undefined;
  for (const txt of anchorTxts) {
    try {
      const record = parseLinkkeysTxt(txt);
      if (record.fingerprints.length > 0) {
        fingerprints = record.fingerprints;
        break;
      }
    } catch {
      // Try the next TXT string; a domain may publish several.
    }
  }
  if (!fingerprints) {
    throw new DnsLookupError(`no usable ${anchorName} TXT record with fp= entries`);
  }

  const apisName = linkkeysApisDnsName(domain);
  const apisTxts = await dns.txtLookup(apisName);
  let tcpAddr: string | undefined;
  for (const txt of apisTxts) {
    try {
      const apis = parseLinkkeysApisTxt(txt);
      if (apis.tcp) {
        tcpAddr = apis.tcp;
        break;
      }
    } catch {
      // Try the next TXT string.
    }
  }
  if (!tcpAddr) {
    throw new DnsLookupError(`no usable ${apisName} TXT record with tcp= entry`);
  }

  return { fingerprints, tcpAddr };
}

function extractHostname(hostPort: string): string {
  const idx = hostPort.lastIndexOf(":");
  return idx < 0 ? hostPort : hostPort.slice(0, idx);
}

/**
 * True for an IPv4 dotted-quad or an IPv6 literal. Node's `tls.connect`
 * rejects `servername` set to an IP address literal (SNI, RFC 6066, is
 * hostname-only) — and since this SDK never validates the peer certificate
 * against the hostname anyway (the pin, not the hostname, is the trust
 * anchor), SNI is simply omitted when dialing a raw IP address. This is not
 * a test-only accommodation: `_linkkeys_apis` `tcp=` values are ordinarily
 * hostnames, but nothing forbids an operator (or a test fake IDP) from
 * publishing a bare IP.
 */
function isIpAddressLiteral(host: string): boolean {
  return net.isIP(host) !== 0;
}

/**
 * Verify the connected TLS peer's certificate SPKI fingerprint is in
 * `fingerprints`, AND that the certificate's own validity window covers
 * `now` — mirroring `crates/linkkeys-rpc-client/src/tls.rs`'s
 * `FingerprintVerifier::verify_server_cert`, which checks both. The pin is
 * the trust anchor (not WebPKI chain validity), but the certificate's own
 * `notBefore`/`notAfter` window is still a signal worth honoring: it lets an
 * operator bound how long a given domain TLS cert is presented for, exactly
 * like the Rust reference does. Throws `TlsError` otherwise. Called once
 * per connection, before any RPC bytes are sent.
 */
function verifyPeerCertificatePin(
  socket: tls.TLSSocket,
  fingerprints: readonly string[],
  now: Date = new Date(),
): void {
  const peerCert = socket.getPeerCertificate(true);
  if (!peerCert || !peerCert.raw || peerCert.raw.length === 0) {
    throw new TlsError("peer presented no certificate");
  }

  const x509 = new nodeCrypto.X509Certificate(peerCert.raw);

  if (now.getTime() < x509.validFromDate.getTime() || now.getTime() > x509.validToDate.getTime()) {
    throw new TlsError(
      `peer certificate is outside its validity window (${x509.validFrom} .. ${x509.validTo})`,
    );
  }

  if (x509.publicKey.asymmetricKeyType !== "ed25519") {
    throw new TlsError(
      `unexpected peer certificate key type: ${x509.publicKey.asymmetricKeyType ?? "unknown"} (expected ed25519)`,
    );
  }
  const jwk = x509.publicKey.export({ format: "jwk" }) as { x?: string };
  if (!jwk.x) {
    throw new TlsError("could not extract Ed25519 public key from peer certificate");
  }
  const rawPublicKey = Buffer.from(jwk.x, "base64url");
  const fp = nodeCrypto.createHash("sha256").update(rawPublicKey).digest("hex");

  const pinned = new Set(fingerprints.map((f) => f.toLowerCase()));
  if (!pinned.has(fp.toLowerCase())) {
    throw new TlsError(`peer certificate fingerprint ${fp} is not in the pinned set for this domain`);
  }
}

/** Dial `endpoint.tcpAddr` via the injected `Transport`, then wrap in TLS and enforce the DNS `fp=` pin before returning the socket. */
async function dialPinnedTls(transport: Transport, endpoint: DomainEndpoint): Promise<tls.TLSSocket> {
  const rawSocket: net.Socket = await transport.dial(endpoint.tcpAddr);
  const hostname = extractHostname(endpoint.tcpAddr);

  return new Promise<tls.TLSSocket>((resolve, reject) => {
    const tlsSocket = tls.connect({
      socket: rawSocket,
      ...(isIpAddressLiteral(hostname) ? {} : { servername: hostname }),
      // No CA to validate against — self-signed domain certs are pinned by
      // DNS fp=, verified manually below. See this module's docs.
      rejectUnauthorized: false,
    });
    tlsSocket.once("secureConnect", () => {
      try {
        verifyPeerCertificatePin(tlsSocket, endpoint.fingerprints);
      } catch (e) {
        tlsSocket.destroy();
        reject(e);
        return;
      }
      resolve(tlsSocket);
    });
    tlsSocket.once("error", (e) => {
      reject(new TlsError(`TLS handshake failed: ${e.message}`, { cause: e }));
    });
  });
}

/**
 * Buffers inbound socket data and resolves `readExact` calls for byte-exact
 * frame reads.
 *
 * Node delivers `"data"` events for whatever the peer sends, regardless of
 * how much a caller actually asked for — unlike the Rust reference SDK's
 * blocking `read_exact`, which never pulls more than requested off the
 * socket, so an oversized peer stream simply sits unread in the OS receive
 * buffer. To give this async reader the same "never buffer past the guard"
 * property, `MAX_BUFFERED` caps how much unread data this reader will hold
 * before treating the connection as misbehaving and failing closed — a
 * peer cannot force unbounded user-space buffering just by streaming bytes
 * before ever completing a valid length-prefixed frame.
 */
class ChunkReader {
  private buf = Buffer.alloc(0);
  private readonly waiters: Array<{
    n: number;
    resolve: (b: Buffer) => void;
    reject: (e: unknown) => void;
  }> = [];
  private closedError: unknown = null;

  constructor(socket: tls.TLSSocket) {
    socket.on("data", (chunk: Buffer) => {
      if (this.closedError !== null) return;
      this.buf = Buffer.concat([this.buf, chunk]);
      if (this.buf.length > 4 + MAX_FRAME_SIZE) {
        this.finish(
          new ProtocolError(
            `peer sent more than ${4 + MAX_FRAME_SIZE} bytes without completing a valid frame`,
          ),
        );
        socket.destroy();
        return;
      }
      this.tryResolve();
    });
    const onClose = () =>
      this.finish(new ProtocolError("connection closed before a full frame arrived"));
    socket.on("end", onClose);
    socket.on("close", onClose);
    socket.on("error", (e) => this.finish(e));
  }

  private tryResolve(): void {
    while (this.waiters.length > 0) {
      const w = this.waiters[0]!;
      if (this.buf.length < w.n) break;
      this.waiters.shift();
      w.resolve(Buffer.from(this.buf.subarray(0, w.n)));
      this.buf = this.buf.subarray(w.n);
    }
  }

  private finish(err: unknown): void {
    if (this.closedError === null) this.closedError = err;
    while (this.waiters.length > 0) {
      this.waiters.shift()!.reject(err);
    }
  }

  readExact(n: number): Promise<Buffer> {
    if (this.buf.length >= n) {
      const bytes = Buffer.from(this.buf.subarray(0, n));
      this.buf = this.buf.subarray(n);
      return Promise.resolve(bytes);
    }
    if (this.closedError !== null) {
      return Promise.reject(this.closedError);
    }
    return new Promise((resolve, reject) => {
      this.waiters.push({ n, resolve, reject });
    });
  }
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

async function readFrame(reader: ChunkReader): Promise<Uint8Array> {
  const lenBuf = await reader.readExact(4);
  const len = lenBuf.readUInt32BE(0);
  if (len > MAX_FRAME_SIZE) {
    throw new ProtocolError(`peer frame too large (${len} bytes, max ${MAX_FRAME_SIZE})`);
  }
  const body = await reader.readExact(len);
  return new Uint8Array(body);
}

/** Send one CSIL-RPC request over a fresh pinned-TLS connection and return the decoded success payload. A non-Ok status becomes `RpcServerError`. */
async function call(
  transport: Transport,
  endpoint: DomainEndpoint,
  service: string,
  op: string,
  payload: Uint8Array,
): Promise<Uint8Array> {
  const socket = await dialPinnedTls(transport, endpoint);
  try {
    const request = new RpcRequest(service, op, payload);
    await sendFrame(socket, request.encode());

    const reader = new ChunkReader(socket);
    const respBytes = await readFrame(reader);
    const resp = RpcResponse.decode(respBytes);

    if (!statusIsOk(resp.status)) {
      throw new RpcServerError(resp.status, resp.error ?? "unknown error");
    }
    return resp.payload;
  } finally {
    socket.destroy();
  }
}

/**
 * Fetch `domain`'s currently-trusted public keys:
 * `DomainKeys/get-domain-keys` over TCP CSIL-RPC, pinned to the domain's DNS
 * `fp=` set, with signing keys pinned directly and encryption keys trusted
 * only via a pinned signing key's vouch (`trustKeys`). ALWAYS also fetches
 * `DomainKeys/get-revocations` — regardless of the (unauthenticated,
 * server-asserted) `recentRevocationsAvailable` hint, which a
 * compromised/malicious IDP could simply omit to suppress delivery of a
 * revocation this client needs to see — and drops any key a
 * quorum-verified sibling revocation certificate targets. A
 * `get-revocations` fetch/decode failure is FATAL (fail closed): this SDK
 * must never proceed on a domain's keys without having successfully asked
 * whether any of them were revoked. An empty revocations list is a normal,
 * successful outcome. An empty trusted-keys result (before or after
 * revocation filtering) is `NoTrustedDomainKeysError` — also fail closed.
 */
export async function fetchDomainKeys(
  transport: Transport,
  dns: DnsResolver,
  domain: string,
): Promise<DomainPublicKey[]> {
  const endpoint = await discoverDomainEndpoint(dns, domain);

  const payload = generated.toEmptyRequestCbor({});
  const respBytes = await call(transport, endpoint, "DomainKeys", "get-domain-keys", payload);
  const resp = generated.fromGetDomainKeysResponseCbor(respBytes);

  let trusted = trustKeys(resp.keys, endpoint.fingerprints);
  if (trusted.length === 0) {
    throw new NoTrustedDomainKeysError(domain);
  }

  const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const reqPayload = generated.toGetRevocationsRequestCbor({ since });
  // No try/catch: any failure here (RPC error status, transport/decode
  // failure) propagates as a fatal error out of this function. Revocation
  // delivery is load-bearing for key trust, not best-effort.
  const revRespBytes = await call(transport, endpoint, "DomainKeys", "get-revocations", reqPayload);
  const revResp = generated.fromGetRevocationsResponseCbor(revRespBytes);
  for (const cert of revResp.revocations) {
    if (verifyRevocationCertificate(cert, trusted, domain)) {
      trusted = trusted.filter((k) => k.keyId !== cert.targetKeyId);
    }
  }

  if (trusted.length === 0) {
    throw new NoTrustedDomainKeysError(domain);
  }
  return trusted;
}

/**
 * Redeem a claim ticket with `domain`'s IDP: `LocalRp/redeem-claim-ticket`
 * over TCP CSIL-RPC, pinned via the domain's DNS `fp=` set. Unauthenticated
 * at the transport layer (no client cert) — the redemption request itself
 * is signed with the local RP's signing key, which is the possession proof
 * the server checks.
 */
export async function redeemClaimTicket(
  transport: Transport,
  dns: DnsResolver,
  domain: string,
  signedRequest: SignedLocalRpTicketRedemptionRequest,
): Promise<LocalRpTicketRedemptionResponse> {
  const endpoint = await discoverDomainEndpoint(dns, domain);
  const payload = generated.toSignedLocalRpTicketRedemptionRequestCbor(signedRequest);
  const respBytes = await call(transport, endpoint, "LocalRp", "redeem-claim-ticket", payload);
  return generated.fromLocalRpTicketRedemptionResponseCbor(respBytes);
}

export { Status };
