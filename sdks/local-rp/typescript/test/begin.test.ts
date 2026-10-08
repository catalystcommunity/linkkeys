import assert from "node:assert/strict";
import test from "node:test";
import { beginLocalLogin } from "../src/begin.ts";
import type { DnsResolver } from "../src/dns.ts";
import { generateLocalRpIdentity } from "../src/identity.ts";

const now = new Date("2026-01-01T00:00:00Z");
const keyMaterial = generateLocalRpIdentity({ appName: "Test App", now });

// Discovery is exercised in browser.test.ts; here a resolver that fails
// keeps the redirect on the identity domain and keeps the test offline.
const offlineDns: DnsResolver = { txtLookup: async () => { throw new Error("offline"); } };

test("full login adds a username hint and bare domain does not", async () => {
  const full = await beginLocalLogin({ keyMaterial, callbackUrl: "http://localhost/callback", userDomain: "Alice+work@ID.Example.TEST", now, dns: offlineDns });
  assert.equal(new URL(full.redirect.redirectUrl).searchParams.get("username"), "Alice+work");
  assert.equal(full.pending.userDomain, "id.example.test");

  const bare = await beginLocalLogin({ keyMaterial, callbackUrl: "http://localhost/callback", userDomain: "example.test", now, dns: offlineDns });
  assert.equal(new URL(bare.redirect.redirectUrl).searchParams.has("username"), false);
});

test("malformed identity input is rejected", async () => {
  for (const userDomain of ["alice", "alice@@example.test", "https://example.test"]) {
    await assert.rejects(beginLocalLogin({ keyMaterial, callbackUrl: "http://localhost/callback", userDomain, now, dns: offlineDns }));
  }
});
