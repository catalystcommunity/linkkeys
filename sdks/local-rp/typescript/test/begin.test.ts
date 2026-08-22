import assert from "node:assert/strict";
import test from "node:test";
import { beginLocalLogin } from "../src/begin.ts";
import { generateLocalRpIdentity } from "../src/identity.ts";

const now = new Date("2026-01-01T00:00:00Z");
const keyMaterial = generateLocalRpIdentity({ appName: "Test App", now });

test("full login adds a username hint and bare domain does not", () => {
  const full = beginLocalLogin({ keyMaterial, callbackUrl: "http://localhost/callback", userDomain: "Alice+work@ID.Example.TEST", now });
  assert.equal(new URL(full.redirect.redirectUrl).searchParams.get("username"), "Alice+work");
  assert.equal(full.pending.userDomain, "id.example.test");

  const bare = beginLocalLogin({ keyMaterial, callbackUrl: "http://localhost/callback", userDomain: "example.test", now });
  assert.equal(new URL(bare.redirect.redirectUrl).searchParams.has("username"), false);
});

test("malformed identity input is rejected", () => {
  for (const userDomain of ["alice", "alice@@example.test", "https://example.test"]) {
    assert.throws(() => beginLocalLogin({ keyMaterial, callbackUrl: "http://localhost/callback", userDomain, now }));
  }
});
