// The TCP dial seam. `dns-less-local-rp-design.md`'s "SDK API Shape" /
// "Required Network Access" sections ask for a `Transport` seam the SDK
// embeds its CSIL-RPC client over, with a default implementation and the
// whole thing injectable for tests. Deliberately narrow: this interface only
// *connects a byte stream* to `host:port`. TLS (certificate-pin verification
// against DNS `fp=` records) is layered on top in `src/rpc.ts`, not here, so
// a test double can swap out "how do I open a socket" without also having to
// fake a TLS handshake.
//
// Wire Precision is explicit that this SDK must NOT inherit the server-side
// non-public-address SSRF refusal as a *default*: "connecting from a LAN box
// to wherever `_linkkeys_apis` points is the entire point of this mode." The
// default policy here is `"permissive"`. `"public-only"` is offered as an
// opt-in for integrators who specifically want that stricter posture.

import net from "node:net";

export type AddressPolicy = "permissive" | "public-only";

export class TransportError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "TransportError";
  }
}

/** Dials `host:port` and returns a connected duplex socket. Injectable so tests can hand the RPC layer a fake/in-memory duplex instead of a real socket. */
export interface Transport {
  dial(hostPort: string): Promise<net.Socket>;
}

export interface NodeTransportOptions {
  policy?: AddressPolicy;
  connectTimeoutMs?: number;
}

const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

function parseHostPort(hostPort: string): { host: string; port: number } {
  const idx = hostPort.lastIndexOf(":");
  if (idx < 0) {
    throw new TransportError(`expected host:port, got: ${JSON.stringify(hostPort)}`);
  }
  const host = hostPort.slice(0, idx);
  const port = Number.parseInt(hostPort.slice(idx + 1), 10);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new TransportError(`invalid port in ${JSON.stringify(hostPort)}`);
  }
  return { host, port };
}

/**
 * True for loopback/private/link-local/CGNAT/documentation/unspecified
 * addresses. Only consulted under `"public-only"`, never by default.
 */
function isNonPublicIp(ip: string): boolean {
  // IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    const octets = ip.split(".").map((n) => Number.parseInt(n, 10));
    const [a, b] = octets;
    if (a === undefined || b === undefined) return true;
    if (a === 127) return true; // loopback
    if (a === 10) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 169 && b === 254) return true; // link-local
    if (a === 0) return true; // unspecified/this-network
    if (a === 255 && b === 255) return true; // broadcast-ish
    if (a === 192 && b === 0) return true; // documentation (192.0.2.0/24 lives here too)
    if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
    return false;
  }
  // IPv6 (best-effort textual checks; good enough for the opt-in guard).
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fe80:")) return true; // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // ULA fc00::/7
  return false;
}

/** Default `Transport`: a plain Node `net.Socket`, gated only by `policy` (permissive unless the caller opts into `"public-only"`). */
export class NodeTransport implements Transport {
  readonly policy: AddressPolicy;
  private readonly connectTimeoutMs: number;

  constructor(options: NodeTransportOptions = {}) {
    this.policy = options.policy ?? "permissive";
    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
  }

  dial(hostPort: string): Promise<net.Socket> {
    const { host, port } = parseHostPort(hostPort);

    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host, port });
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new TransportError(`connect timed out: ${hostPort}`));
      }, this.connectTimeoutMs);

      socket.once("connect", () => {
        clearTimeout(timer);
        if (this.policy === "public-only") {
          const remoteAddress = socket.remoteAddress;
          if (remoteAddress && isNonPublicIp(remoteAddress)) {
            socket.destroy();
            reject(
              new TransportError(
                `${remoteAddress}: refusing non-public address under AddressPolicy "public-only"`,
              ),
            );
            return;
          }
        }
        resolve(socket);
      });
      socket.once("error", (e) => {
        clearTimeout(timer);
        reject(new TransportError(`connect failed: ${hostPort}: ${e.message}`, { cause: e }));
      });
    });
  }
}
