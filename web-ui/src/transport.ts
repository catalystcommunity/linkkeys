import { AsyncApiClient, type AsyncServiceTransport } from "./generated/client.async.gen";
import { decode, encodeValue, type CborTag, type CborValue } from "./generated/codec.gen";

export class CsilTransportError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "CsilTransportError";
  }
}

export const CsilStatus = {
  malformedEnvelope: 1,
  unauthenticated: 3,
  forbidden: 4,
} as const;

function field(map: Map<CborValue, CborValue>, name: string): CborValue | undefined {
  for (const [key, value] of map) if (key === name) return value;
  return undefined;
}

export class BrowserCsilTransport implements AsyncServiceTransport {
  async call(service: string, op: string, payload: Uint8Array): Promise<Uint8Array> {
    // This insertion order is the canonical encoded-key order for these fields.
    const envelope = new Map<CborValue, CborValue>([
      ["v", 1],
      ["op", op],
      ["payload", { tag: 24, value: payload }],
      ["service", service]
    ]);
    const encoded = encodeValue(envelope);
    const response = await fetch("/csil/v1/rpc", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/cbor" },
      body: encoded.buffer as ArrayBuffer
    });
    if (!response.ok) throw new CsilTransportError(response.status, "The LinkKeys service is unavailable.");
    const decoded = decode(new Uint8Array(await response.arrayBuffer()));
    if (!(decoded instanceof Map)) throw new CsilTransportError(6, "The LinkKeys response is invalid.");
    const status = Number(field(decoded, "status") ?? 6);
    const error = field(decoded, "error");
    if (status !== 0) {
      throw new CsilTransportError(status, typeof error === "string" ? error : "The request failed.");
    }
    const tagged = field(decoded, "payload") as CborTag | undefined;
    if (!tagged || tagged.tag !== 24 || !(tagged.value instanceof Uint8Array)) {
      throw new CsilTransportError(6, "The LinkKeys response payload is invalid.");
    }
    return tagged.value;
  }
}

export const api = new AsyncApiClient(new BrowserCsilTransport());
