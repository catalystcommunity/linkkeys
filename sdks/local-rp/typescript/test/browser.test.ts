// Browser endpoint discovery tests, ported from
// `sdks/local-rp/go/browser_test.go`. Every resolver here is a hermetic
// fake with canned TXT answers — no test in this file performs a live DNS
// request.

import assert from "node:assert/strict";
import test from "node:test";
import { beginLocalLogin, type BeginLocalLoginConfig } from "../src/begin.ts";
import {
  BROWSER_ROUTE_AUTHORIZE,
  BROWSER_ROUTE_LOCAL_RP,
  buildBrowserEndpoint,
  resolveBrowserBase,
} from "../src/browser.ts";
import { defaultDnsResolver } from "../src/defaults.ts";
import type { DnsResolver } from "../src/dns.ts";
import { signedLocalRpLoginRequestFromUrlParam } from "../src/encoding.ts";
import { fromLocalRpLoginRequestCbor } from "../src/generated/codec.gen.ts";
import { generateLocalRpIdentity } from "../src/identity.ts";

/** A hermetic `DnsResolver` with canned TXT answers per name. */
class MapDnsResolver implements DnsResolver {
  private readonly records: Record<string, string[]>;
  private readonly error?: Error;

  constructor(records: Record<string, string[]>, error?: Error) {
    this.records = records;
    this.error = error;
  }

  async txtLookup(name: string): Promise<string[]> {
    if (this.error) throw this.error;
    const txts = this.records[name];
    if (txts) return txts;
    throw new Error(`no fake record for ${name}`);
  }
}

const BROWSER_TEST_DOMAIN = "ident.example.test";
const CALLBACK_URL = "http://app.lan:8080/cb";
const now = new Date("2026-08-17T12:00:00Z");
const keyMaterial = generateLocalRpIdentity({ appName: "browser-test", now });

function apisResolver(...txts: string[]): MapDnsResolver {
  return new MapDnsResolver({ [`_linkkeys_apis.${BROWSER_TEST_DOMAIN}`]: txts });
}

function failingResolver(): MapDnsResolver {
  return new MapDnsResolver({}, new Error("SERVFAIL"));
}

async function beginWith(dns: DnsResolver) {
  const config: BeginLocalLoginConfig = { keyMaterial, callbackUrl: CALLBACK_URL, userDomain: BROWSER_TEST_DOMAIN, now, dns };
  const { redirect, pending } = await beginLocalLogin(config);
  return { redirect, pending, config };
}

// Case 1: a valid https= host is used for the redirect instead of the
// identity domain. Case 8: pending.userDomain stays the identity domain —
// verification stays bound to it, not to the service host.
test("begin uses the discovered https host", async () => {
  const { redirect, pending } = await beginWith(
    apisResolver("v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test"),
  );
  assert.ok(redirect.redirectUrl.startsWith("https://linkkeys.ident.example.test/auth/local-rp?signed_request="), redirect.redirectUrl);
  assert.ok(!redirect.redirectUrl.startsWith(`https://${BROWSER_TEST_DOMAIN}/`), redirect.redirectUrl);
  assert.equal(pending.userDomain, BROWSER_TEST_DOMAIN);
});

// Case 2: an https= value with a path prefix preserves that prefix.
test("begin preserves an https= path prefix", async () => {
  const { redirect } = await beginWith(apisResolver("v=lk1 https=login.example.test/linkkeys"));
  assert.ok(redirect.redirectUrl.startsWith("https://login.example.test/linkkeys/auth/local-rp?signed_request="), redirect.redirectUrl);
});

// Case 3: a record with only tcp= falls back to the identity domain.
test("begin falls back to the identity domain for a tcp-only record", async () => {
  const { redirect } = await beginWith(apisResolver("v=lk1 tcp=linkkeys.ident.example.test"));
  assert.ok(redirect.redirectUrl.startsWith(`https://${BROWSER_TEST_DOMAIN}/auth/local-rp?signed_request=`), redirect.redirectUrl);
});

// Case 4: a DNS lookup error falls back to the identity domain.
test("begin falls back to the identity domain on a DNS error", async () => {
  const { redirect } = await beginWith(failingResolver());
  assert.ok(redirect.redirectUrl.startsWith(`https://${BROWSER_TEST_DOMAIN}/auth/local-rp?signed_request=`), redirect.redirectUrl);
});

// Cases 5 + 6: invalid TXT records are ignored, and across several records
// the FIRST valid record with https= is selected.
test("begin selects the first valid https= record across several records", async () => {
  const { redirect } = await beginWith(
    apisResolver(
      "not a linkkeys record",
      "v=lk2 https=wrong-version.example.test",
      "v=lk1 tcp=tcp-only.example.test",
      "v=lk1 https=first.example.test",
      "v=lk1 https=second.example.test",
    ),
  );
  assert.ok(redirect.redirectUrl.startsWith("https://first.example.test/auth/local-rp?signed_request="), redirect.redirectUrl);
});

// Case 7: signed_request rides the discovered URL unchanged — it decodes to
// the signed login request whose fields match this login.
test("signed_request survives the discovered URL", async () => {
  const { redirect, pending, config } = await beginWith(apisResolver("v=lk1 https=login.example.test/linkkeys"));
  const param = new URL(redirect.redirectUrl).searchParams.get("signed_request");
  assert.ok(param, "signed_request query parameter missing");
  const signed = signedLocalRpLoginRequestFromUrlParam(param);
  const request = fromLocalRpLoginRequestCbor(signed.request);
  assert.equal(request.callbackUrl, config.callbackUrl);
  assert.equal(Buffer.from(request.nonce).toString("hex"), pending.nonceHex);
});

// Case 9: a config without a `dns` field still type-checks (this test is
// that caller) and the default is the memoized system resolver. The default
// path is not executed here — that would be a live DNS request.
test("a config without a resolver still compiles and has a default", () => {
  const config: BeginLocalLoginConfig = { keyMaterial, callbackUrl: CALLBACK_URL, userDomain: BROWSER_TEST_DOMAIN, now };
  assert.equal(config.dns, undefined);
  assert.ok(defaultDnsResolver());
});

// ---------------------------------------------------------------------
// Direct tests for the exported helpers
// ---------------------------------------------------------------------

test("resolveBrowserBase selects a valid https= base and rejects hostile ones", async () => {
  const base = await resolveBrowserBase(
    apisResolver("v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys"),
    BROWSER_TEST_DOMAIN,
  );
  assert.equal(base, "https://login.example.test:8443/linkkeys");

  // A record whose https= value smuggles URL structure is skipped; with no
  // other candidate, resolution rejects so the caller can fall back.
  for (const hostile of [
    "v=lk1 https=user@evil.example.test",
    "v=lk1 https=evil.example.test/x?y=1",
    "v=lk1 https=evil.example.test/x#frag",
  ]) {
    await assert.rejects(resolveBrowserBase(apisResolver(hostile), BROWSER_TEST_DOMAIN), Error, hostile);
  }

  await assert.rejects(resolveBrowserBase(apisResolver("v=lk1 tcp=only.example.test"), BROWSER_TEST_DOMAIN));
  await assert.rejects(resolveBrowserBase(failingResolver(), BROWSER_TEST_DOMAIN));
});

test("buildBrowserEndpoint joins base, route and signed_request", () => {
  assert.equal(
    buildBrowserEndpoint("https://h.example.test", BROWSER_ROUTE_LOCAL_RP, "PAYLOAD-123_abc"),
    "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc",
  );

  // Path prefix, with and without a trailing slash, and the regular-RP
  // route — the same helper serves /auth/authorize glue.
  for (const [base, want] of [
    ["https://h.example.test/pfx", "https://h.example.test/pfx/auth/authorize?signed_request=s"],
    ["https://h.example.test/pfx/", "https://h.example.test/pfx/auth/authorize?signed_request=s"],
  ]) {
    assert.equal(buildBrowserEndpoint(base, BROWSER_ROUTE_AUTHORIZE, "s"), want);
  }

  // A non-HTTPS scheme must never be selectable.
  for (const bad of ["http://h.example.test", "ftp://h.example.test", "https://", "https://u:p@h.example.test"]) {
    assert.throws(() => buildBrowserEndpoint(bad, BROWSER_ROUTE_LOCAL_RP, "s"), Error, bad);
  }
  assert.throws(() => buildBrowserEndpoint("https://h.example.test", "auth/no-leading-slash", "s"));
});
