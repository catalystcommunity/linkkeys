import assert from "node:assert/strict";
import net from "node:net";
import tls from "node:tls";
import test from "node:test";

import { RpAsyncClient } from "../generated/client.async.gen.ts";
import {
  fromGetRevocationsRequestCbor,
  toGetDomainKeysResponseCbor,
  toGetRevocationsResponseCbor,
  toRpSignResponseCbor,
} from "../generated/codec.gen.ts";
import { derivePublicKeyFromEd25519PrivateKey, fingerprint } from "../src/crypto.ts";
import type { DnsResolver } from "../src/dns.ts";
import { fetchDomainKeys, PinnedRpcTransport, RpcTimeoutError, TlsError } from "../src/rpc.ts";
import type { Transport } from "../src/socket.ts";
import { RpcRequest, RpcResponse } from "../src/vendor/csilgen-transport/index.ts";

const DOMAIN_SEED = new Uint8Array(32).fill(3);
const TEST_KEY = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD
-----END PRIVATE KEY-----
`;
const TEST_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIBQDCB86ADAgECAhR4P4dcbAWz87LMOoy7/4mcWm2bFDAFBgMrZXAwFjEUMBIG
A1UEAwwLYXBwLmV4YW1wbGUwHhcNMjYwODI4MDEwOTI0WhcNMzYwODI1MDEwOTI0
WjAWMRQwEgYDVQQDDAthcHAuZXhhbXBsZTAqMAUGAytlcAMhAO1JKMYo0cLG6ukD
OJBZlWEpWSc6XGP5NjbBRhSshzfRo1MwUTAdBgNVHQ4EFgQUPYU0PZXNNikwhy4Z
mywyTeQEtWowHwYDVR0jBBgwFoAUPYU0PZXNNikwhy4ZmywyTeQEtWowDwYDVR0T
AQH/BAUwAwEB/zAFBgMrZXADQQDPMrz1BqzyY6U+RakVGh6qloC1uAoQh6yP8Odv
JdNrMd9BGkEzoE0pLCX8a1rgsAupeiaQAsBvPpD3qdVz4fwO
-----END CERTIFICATE-----
`;

class LoopbackTransport implements Transport {
  constructor(private readonly port: number) {}
  dial(): Promise<net.Socket> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: "127.0.0.1", port: this.port });
      socket.once("connect", () => resolve(socket));
      socket.once("error", reject);
    });
  }
}

async function server(): Promise<{ port: number; close: () => Promise<void>; auth: () => string | undefined }> {
  let receivedAuth: string | undefined;
  const listener = tls.createServer({ key: TEST_KEY, cert: TEST_CERTIFICATE }, (socket) => {
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 4) return;
      const length = buffer.readUInt32BE(0);
      if (buffer.length < length + 4) return;
      const request = RpcRequest.decode(buffer.subarray(4, length + 4));
      receivedAuth = request.auth;
      assert.equal(request.service, "Rp");
      assert.equal(request.op, "sign-request");
      const response = RpcResponse.ok("", toRpSignResponseCbor({ signedRequest: "from-rp" })).encode();
      const frame = Buffer.alloc(4 + response.length);
      frame.writeUInt32BE(response.length, 0);
      frame.set(response, 4);
      socket.end(frame);
    });
  });
  listener.on("tlsClientError", () => undefined);
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  return {
    port: address.port,
    close: () => new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve())),
    auth: () => receivedAuth,
  };
}

test("generated client uses pinned TLS and puts the API key in RPC auth", async () => {
  const fake = await server();
  try {
    const transport = new PinnedRpcTransport({
      tcpAddress: `ignored.example:${fake.port}`,
      fingerprints: [fingerprint(derivePublicKeyFromEd25519PrivateKey(DOMAIN_SEED))],
      apiKey: "application-api-key",
      socketTransport: new LoopbackTransport(fake.port),
    });
    const response = await new RpAsyncClient(transport).signRequest({
      callbackUrl: "https://app.example/callback",
      nonce: "nonce",
    });
    assert.equal(response.signedRequest, "from-rp");
    assert.equal(fake.auth(), "application-api-key");
  } finally {
    await fake.close();
  }
});

test("transport rejects a TLS key that is outside the pin set", async () => {
  const fake = await server();
  try {
    const transport = new PinnedRpcTransport({
      tcpAddress: `ignored.example:${fake.port}`,
      fingerprints: ["00".repeat(32)],
      apiKey: "application-api-key",
      socketTransport: new LoopbackTransport(fake.port),
    });
    await assert.rejects(
      new RpAsyncClient(transport).signRequest({ callbackUrl: "https://app.example/callback", nonce: "nonce" }),
      (error: unknown) => error instanceof TlsError,
    );
  } finally {
    await fake.close();
  }
});

test("request timeout covers a stalled TLS handshake", async () => {
  const sockets = new Set<net.Socket>();
  const listener = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  try {
    const transport = new PinnedRpcTransport({
      tcpAddress: `ignored.example:${address.port}`,
      fingerprints: [fingerprint(derivePublicKeyFromEd25519PrivateKey(DOMAIN_SEED))],
      apiKey: "application-api-key",
      socketTransport: new LoopbackTransport(address.port),
      requestTimeoutMs: 50,
    });
    await assert.rejects(
      new RpAsyncClient(transport).signRequest({ callbackUrl: "https://app.example/callback", nonce: "nonce" }),
      (error: unknown) => error instanceof RpcTimeoutError,
    );
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  }
});

async function stalledResponseServer(): Promise<{ port: number; close: () => Promise<void> }> {
  const sockets = new Set<tls.TLSSocket>();
  const listener = tls.createServer({ key: TEST_KEY, cert: TEST_CERTIFICATE }, (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.on("data", () => undefined);
  });
  listener.on("tlsClientError", () => undefined);
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  return {
    port: address.port,
    close: () => {
      for (const socket of sockets) socket.destroy();
      return new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    },
  };
}

test("request timeout covers a stalled response", async () => {
  const fake = await stalledResponseServer();
  try {
    const transport = new PinnedRpcTransport({
      tcpAddress: `ignored.example:${fake.port}`,
      fingerprints: [fingerprint(derivePublicKeyFromEd25519PrivateKey(DOMAIN_SEED))],
      apiKey: "application-api-key",
      socketTransport: new LoopbackTransport(fake.port),
      requestTimeoutMs: 50,
    });
    await assert.rejects(
      new RpAsyncClient(transport).signRequest({ callbackUrl: "https://app.example/callback", nonce: "nonce" }),
      (error: unknown) => error instanceof RpcTimeoutError,
    );
  } finally {
    await fake.close();
  }
});

test("an abort signal cancels a live RPC", async () => {
  const fake = await stalledResponseServer();
  try {
    const transport = new PinnedRpcTransport({
      tcpAddress: `ignored.example:${fake.port}`,
      fingerprints: [fingerprint(derivePublicKeyFromEd25519PrivateKey(DOMAIN_SEED))],
      apiKey: "application-api-key",
      socketTransport: new LoopbackTransport(fake.port),
    });
    const controller = new AbortController();
    const reason = new Error("application request ended");
    const request = transport.callWithOptions(
      "Rp",
      "sign-request",
      new Uint8Array(),
      { signal: controller.signal },
    );
    setTimeout(() => controller.abort(reason), 25);
    await assert.rejects(request, (error: unknown) => error === reason);
  } finally {
    await fake.close();
  }
});

test("revocation lookup starts at the oldest presented key", async () => {
  const publicKey = derivePublicKeyFromEd25519PrivateKey(DOMAIN_SEED);
  const keyFingerprint = fingerprint(publicKey);
  let requestedSince: string | undefined;
  const listener = tls.createServer({ key: TEST_KEY, cert: TEST_CERTIFICATE }, (socket) => {
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 4) return;
      const length = buffer.readUInt32BE(0);
      if (buffer.length < length + 4) return;
      const request = RpcRequest.decode(buffer.subarray(4, length + 4));
      let payload: Uint8Array;
      if (request.op === "get-domain-keys") {
        payload = toGetDomainKeysResponseCbor({
          domain: "old.example",
          keys: [{
            keyId: "old-key",
            publicKey,
            fingerprint: keyFingerprint,
            algorithm: "ed25519",
            keyUsage: "sign",
            createdAt: "1999-03-04T05:06:07.000Z",
            expiresAt: "2099-01-01T00:00:00.000Z",
          }],
        });
      } else {
        assert.equal(request.op, "get-revocations");
        requestedSince = fromGetRevocationsRequestCbor(request.payload).since;
        payload = toGetRevocationsResponseCbor({ revocations: [] });
      }
      const response = RpcResponse.ok("", payload).encode();
      const frame = Buffer.alloc(4 + response.length);
      frame.writeUInt32BE(response.length, 0);
      frame.set(response, 4);
      socket.end(frame);
    });
  });
  listener.on("tlsClientError", () => undefined);
  await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const address = listener.address();
  assert.ok(address && typeof address === "object");
  const dns: DnsResolver = {
    async txtLookup(name: string): Promise<string[]> {
      if (name === "_linkkeys.old.example") return [`v=lk1 fp=${keyFingerprint}`];
      return ["v=lk1 tcp=old.example:4987"];
    },
  };
  try {
    const keys = await fetchDomainKeys(
      new LoopbackTransport(address.port),
      dns,
      "old.example",
    );
    assert.equal(keys.length, 1);
    assert.equal(requestedSince, "1999-03-04T05:06:07.000Z");
  } finally {
    await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
  }
});
