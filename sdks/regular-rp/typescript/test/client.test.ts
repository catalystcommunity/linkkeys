import assert from "node:assert/strict";
import test from "node:test";

import type { Claim, IdentityAssertion, UserInfo } from "../generated/types.gen.ts";
import { requestLoginRedirect, startLinkKeysLogin } from "../src/browser.ts";
import { RegularRpClient, LoginError, type RegularRpOperations } from "../src/client.ts";
import type { DnsResolver } from "../src/dns.ts";
import { parseIdentityInput } from "../src/identityInput.ts";
import type { PendingLogin, PendingLoginStore } from "../src/pending.ts";

const NOW = new Date("2026-08-27T12:00:00Z");

class RecordingStore implements PendingLoginStore {
  login?: PendingLogin;
  latest?: PendingLogin;
  async save(login: PendingLogin): Promise<void> {
    this.login = structuredClone(login);
    this.latest = structuredClone(login);
  }
  async take(state: string): Promise<PendingLogin | undefined> {
    if (this.login?.state !== state) return undefined;
    const login = this.login;
    this.login = undefined;
    return structuredClone(login);
  }
}

class FakeDns implements DnsResolver {
  async txtLookup(name: string): Promise<string[]> {
    assert.equal(name, "_linkkeys_apis.id.example");
    return ["unrelated=record", "v=lk1 tcp=id.example:4987 https=login.id.example/linkkeys"];
  }
}

function claim(): Claim {
  return {
    claimId: "claim-1",
    userId: "user-1",
    claimType: "email",
    claimValue: new TextEncoder().encode("user@example.com"),
    signatures: [{ domain: "id.example", signedByKeyId: "key-1", signature: new Uint8Array(64) }],
    attestedAt: NOW.toISOString(),
    createdAt: NOW.toISOString(),
  };
}

function operations(store: RecordingStore, changes: Partial<IdentityAssertion> = {}, infoChanges: Partial<UserInfo> = {}): RegularRpOperations {
  return {
    async signRequest() { return { signedRequest: "signed-request" }; },
    async decryptToken() { return { signedAssertion: "signed-assertion" }; },
    async verifyAssertion() {
      const assertion: IdentityAssertion = {
        userId: "user-1",
        domain: "id.example",
        audience: "app.example",
        nonce: store.latest!.nonce,
        issuedAt: NOW.toISOString(),
        expiresAt: new Date(NOW.getTime() + 5 * 60_000).toISOString(),
        authorizedClaims: ["email"],
        displayName: "Alice",
        ...changes,
      };
      return { assertion, verified: true };
    },
    async userinfoFetch() {
      return {
        userId: "user-1",
        domain: "id.example",
        displayName: "Alice",
        claims: [claim()],
        ...infoChanges,
      };
    },
  };
}

function client(store: RecordingStore, changes: Partial<IdentityAssertion> = {}, infoChanges: Partial<UserInfo> = {}): RegularRpClient {
  return new RegularRpClient({
    rpDomain: "app.example",
    pendingStore: store,
    rpOperations: operations(store, changes, infoChanges),
    dnsResolver: new FakeDns(),
    now: () => new Date(NOW),
    stateFactory: () => "state-1",
    claimVerifier: async (claims) => claims.map((value) => ({ claim: value, signingDomains: ["id.example"] })),
  });
}

test("begin and complete a login through the high-level API", async () => {
  const store = new RecordingStore();
  const sdk = client(store);
  const begun = await sdk.beginLogin({
    identity: "Alice.Tag+dev@ID.Example",
    callbackUrl: "https://auth.app.example/callback?return=%2Faccount",
    sessionBinding: "browser-session-1",
    requestedClaims: {
      required: [{ claimType: "email", datatype: "text" }],
      optional: [],
    },
  });

  const redirect = new URL(begun.redirectUrl);
  assert.equal(redirect.origin, "https://login.id.example");
  assert.equal(redirect.pathname, "/linkkeys/auth/authorize");
  assert.equal(redirect.searchParams.get("username"), "Alice.Tag+dev");
  assert.equal(redirect.searchParams.get("relying_party"), "app.example");
  assert.equal(redirect.searchParams.get("signed_request"), "signed-request");
  assert.equal(new URL(redirect.searchParams.get("callback_url")!).searchParams.get("lk_state"), "state-1");

  const completed = await sdk.completeLogin({ state: begun.state, encryptedToken: "encrypted-token", sessionBinding: "browser-session-1" });
  assert.equal(completed.userId, "user-1");
  assert.equal(completed.domain, "id.example");
  assert.deepEqual(completed.claims[0]!.signingDomains, ["id.example"]);

  await assert.rejects(
    sdk.completeLogin({ state: begun.state, encryptedToken: "encrypted-token", sessionBinding: "browser-session-1" }),
    (error: unknown) => error instanceof LoginError && error.code === "missing-state",
  );
});

test("rejects a callback outside the RP domain", async () => {
  const sdk = client(new RecordingStore());
  await assert.rejects(
    sdk.beginLogin({ identity: "id.example", callbackUrl: "https://app.example.attacker.test/callback", sessionBinding: "browser-session-1" }),
    (error: unknown) => error instanceof LoginError && error.code === "invalid-callback",
  );
});

test("rejects a callback from a different application session", async () => {
  const store = new RecordingStore();
  const sdk = client(store);
  const begun = await sdk.beginLogin({
    identity: "id.example",
    callbackUrl: "https://app.example/callback",
    sessionBinding: "browser-session-1",
  });
  await assert.rejects(
    sdk.completeLogin({ state: begun.state, encryptedToken: "token", sessionBinding: "browser-session-2" }),
    (error: unknown) => error instanceof LoginError && error.code === "session-mismatch",
  );
});

test("rejects missing required and over-released claims", async () => {
  const missingStore = new RecordingStore();
  const missingSdk = client(missingStore, { authorizedClaims: [] }, { claims: [] });
  const missing = await missingSdk.beginLogin({
    identity: "id.example",
    callbackUrl: "https://app.example/callback",
    sessionBinding: "browser-session-1",
    requestedClaims: { required: [{ claimType: "email", datatype: "text" }], optional: [] },
  });
  await assert.rejects(
    missingSdk.completeLogin({ state: missing.state, encryptedToken: "token", sessionBinding: "browser-session-1" }),
    (error: unknown) => error instanceof LoginError && error.code === "required-claim-missing",
  );

  const extraStore = new RecordingStore();
  const extraSdk = client(extraStore, { authorizedClaims: [] });
  const extra = await extraSdk.beginLogin({ identity: "id.example", callbackUrl: "https://app.example/callback", sessionBinding: "browser-session-1" });
  await assert.rejects(
    extraSdk.completeLogin({ state: extra.state, encryptedToken: "token", sessionBinding: "browser-session-1" }),
    (error: unknown) => error instanceof LoginError && error.code === "unauthorized-claim",
  );
});

test("parses full identities and development domains", () => {
  assert.deepEqual(parseIdentityInput(" Alice.Tag+dev@ID.Example "), { username: "Alice.Tag+dev", domain: "id.example" });
  assert.deepEqual(parseIdentityInput("localhost:8443"), { username: undefined, domain: "localhost:8443" });
  for (const value of ["alice", "alice@@example.com", "https://example.com", "example.com:0"]) {
    assert.throws(() => parseIdentityInput(value));
  }
});

test("browser helper asks only the application backend and redirects", async () => {
  const calls: string[] = [];
  const fakeFetch = (async (url: string | URL | Request) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ redirectUrl: "https://id.example/auth/authorize?x=1" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  assert.equal(
    await requestLoginRedirect({ backendUrl: "/api/linkkeys/login", identity: "id.example", fetch: fakeFetch }),
    "https://id.example/auth/authorize?x=1",
  );
  let destination = "";
  await startLinkKeysLogin({
    backendUrl: "/api/linkkeys/login",
    identity: "id.example",
    fetch: fakeFetch,
    navigate: (url) => { destination = url; },
  });
  assert.deepEqual(calls, ["/api/linkkeys/login", "/api/linkkeys/login"]);
  assert.equal(destination, "https://id.example/auth/authorize?x=1");
});

test("high-level calls pass cancellation to every backend operation", async () => {
  const store = new RecordingStore();
  const base = operations(store);
  const seen: Array<AbortSignal | undefined> = [];
  const wrapped: RegularRpOperations = {
    signRequest: (request, options) => {
      seen.push(options?.signal);
      return base.signRequest(request, options);
    },
    decryptToken: (request, options) => {
      seen.push(options?.signal);
      return base.decryptToken(request, options);
    },
    verifyAssertion: (request, options) => {
      seen.push(options?.signal);
      return base.verifyAssertion(request, options);
    },
    userinfoFetch: (request, options) => {
      seen.push(options?.signal);
      return base.userinfoFetch(request, options);
    },
  };
  const sdk = new RegularRpClient({
    rpDomain: "app.example",
    pendingStore: store,
    rpOperations: wrapped,
    dnsResolver: new FakeDns(),
    now: () => new Date(NOW),
    stateFactory: () => "state-with-signal",
    claimVerifier: async (claims, _domain, _now, signal) => {
      seen.push(signal);
      return claims.map((value) => ({ claim: value, signingDomains: ["id.example"] }));
    },
  });
  const controller = new AbortController();
  const begun = await sdk.beginLogin({
    identity: "id.example",
    callbackUrl: "https://app.example/callback",
    sessionBinding: "browser-session-1",
    signal: controller.signal,
  });
  await sdk.completeLogin({
    state: begun.state,
    encryptedToken: "encrypted-token",
    sessionBinding: "browser-session-1",
    signal: controller.signal,
  });
  assert.equal(seen.length, 5);
  assert.ok(seen.every((signal) => signal === controller.signal));
});

test("a callback canceled before work starts does not consume pending state", async () => {
  const store = new RecordingStore();
  const sdk = client(store);
  const begun = await sdk.beginLogin({
    identity: "id.example",
    callbackUrl: "https://app.example/callback",
    sessionBinding: "browser-session-1",
  });
  const controller = new AbortController();
  const reason = new Error("application request ended");
  controller.abort(reason);
  await assert.rejects(
    sdk.completeLogin({
      state: begun.state,
      encryptedToken: "encrypted-token",
      sessionBinding: "browser-session-1",
      signal: controller.signal,
    }),
    (error: unknown) => error === reason,
  );
  const completed = await sdk.completeLogin({
    state: begun.state,
    encryptedToken: "encrypted-token",
    sessionBinding: "browser-session-1",
  });
  assert.equal(completed.userId, "user-1");
});
