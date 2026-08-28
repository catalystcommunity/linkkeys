import assert from "node:assert/strict";
import test from "node:test";

import { MemoryPendingLoginStore, RegularRpClient } from "../src/index.ts";

const required = [
  "LINKKEYS_LIVE_RP_DOMAIN",
  "LINKKEYS_LIVE_RP_TCP_ADDRESS",
  "LINKKEYS_LIVE_RP_FINGERPRINTS",
  "LINKKEYS_LIVE_RP_API_KEY",
  "LINKKEYS_LIVE_IDENTITY",
] as const;
const enabled = required.every((name) => process.env[name]);

test("a live RP server begins a login through RegularRpClient", { skip: !enabled }, async () => {
  const rpDomain = process.env.LINKKEYS_LIVE_RP_DOMAIN!;
  const identity = process.env.LINKKEYS_LIVE_IDENTITY!;
  const identityDomain = identity.includes("@") ? identity.slice(identity.lastIndexOf("@") + 1) : identity;
  const client = new RegularRpClient({
    rpDomain,
    pendingStore: new MemoryPendingLoginStore(),
    rpServer: {
      tcpAddress: process.env.LINKKEYS_LIVE_RP_TCP_ADDRESS!,
      fingerprints: process.env.LINKKEYS_LIVE_RP_FINGERPRINTS!.split(","),
      apiKey: process.env.LINKKEYS_LIVE_RP_API_KEY!,
      requestTimeoutMs: 15_000,
    },
  });

  const result = await client.beginLogin({
    identity,
    callbackUrl: `https://${rpDomain}/auth/linkkeys/live-sdk-callback`,
    sessionBinding: "live-sdk-test-session",
  });
  const redirect = new URL(result.redirectUrl);
  assert.equal(redirect.protocol, "https:");
  assert.ok(redirect.hostname === identityDomain || redirect.hostname.endsWith(`.${identityDomain}`));
  assert.equal(redirect.searchParams.get("relying_party"), rpDomain);
  assert.ok(redirect.searchParams.get("signed_request"));
  assert.ok(redirect.searchParams.get("nonce"));
});
