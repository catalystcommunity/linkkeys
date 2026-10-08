// Browser endpoint discovery: resolve an identity domain's browser-facing
// HTTPS base from its `_linkkeys_apis` TXT record, and build browser route
// URLs against it. Mirrors `sdks/local-rp/go/browser.go`.
//
// The identity domain (the domain the user selected, e.g. `todandlorna.com`)
// is a trust and discovery domain. It is not necessarily the host that
// serves the browser login routes — the `https=` endpoint of
// `_linkkeys_apis.<identity-domain>` is (docs/spec/trust-and-anchors.md:
// "`https=` is the browser-facing endpoint"). These helpers are shared by
// `beginLocalLogin` (route `BROWSER_ROUTE_LOCAL_RP`) and by regular-RP
// application glue (route `BROWSER_ROUTE_AUTHORIZE`), so discovery is
// implemented once.

import { DnsLookupError, type DnsResolver } from "./dns.ts";
import { linkkeysApisDnsName, parseLinkkeysApisTxt } from "./dnsRecords.ts";
import { InvalidInputError } from "./identity.ts";

/** The browser route for the DNS-less local-RP login flow. */
export const BROWSER_ROUTE_LOCAL_RP = "/auth/local-rp";

/** The browser route for the regular (domain-keyed) RP login flow. */
export const BROWSER_ROUTE_AUTHORIZE = "/auth/authorize";

/** The browser route where a grantee asks the user for an act-as grant. */
export const BROWSER_ROUTE_ACT_AS = "/auth/act-as";

/**
 * Check that `base` is a usable https browser base URL: parseable, https
 * scheme, a host, an optional path prefix, and nothing else. A TXT record
 * value must never smuggle in userinfo, a query, a fragment, or (via
 * `parseLinkkeysApisTxt`'s unconditional `https://` prefix plus this check)
 * a non-HTTPS scheme.
 */
function validateBrowserBase(base: string): URL {
  let u: URL;
  try {
    u = new URL(base);
  } catch (e) {
    throw new InvalidInputError(`browser base ${JSON.stringify(base)} is not a valid URL: ${e}`);
  }
  if (u.protocol !== "https:") {
    throw new InvalidInputError(`browser base ${JSON.stringify(base)} must use https`);
  }
  if (u.hostname === "") {
    throw new InvalidInputError(`browser base ${JSON.stringify(base)} has no host`);
  }
  if (u.username !== "" || u.password !== "" || u.search !== "" || u.hash !== "" || base.includes("?") || base.includes("#")) {
    throw new InvalidInputError(`browser base ${JSON.stringify(base)} must be host[:port][/path] only`);
  }
  return u;
}

/**
 * Resolve `identityDomain`'s browser-facing HTTPS base URL (e.g.
 * `https://linkkeys.todandlorna.com` or `https://login.example.com/linkkeys`)
 * from its `_linkkeys_apis.<identityDomain>` TXT record.
 *
 * Selects the first LinkKeys v1 record whose `https=` endpoint is a valid
 * browser base; invalid TXT records and records without `https=` are
 * skipped. Rejects when the lookup fails or no record yields a valid base —
 * the caller decides the fallback (`beginLocalLogin` falls back to
 * `https://<identityDomain>`).
 *
 * The resolved base is a service location only. Identity verification stays
 * bound to the identity domain — never bind trust decisions to the host
 * this returns.
 */
export async function resolveBrowserBase(dns: DnsResolver, identityDomain: string): Promise<string> {
  const name = linkkeysApisDnsName(identityDomain);
  const txts = await dns.txtLookup(name);
  for (const txt of txts) {
    let httpsBase: string | undefined;
    try {
      httpsBase = parseLinkkeysApisTxt(txt).httpsBase;
    } catch {
      continue;
    }
    if (httpsBase === undefined) continue;
    try {
      validateBrowserBase(httpsBase);
    } catch {
      continue;
    }
    return httpsBase;
  }
  throw new DnsLookupError(`no usable ${name} TXT record with an https= endpoint`);
}

/**
 * Build the full browser URL for `route` (e.g. `BROWSER_ROUTE_LOCAL_RP`)
 * under `browserBase`, carrying `signedRequest` as the `signed_request`
 * query parameter. A path prefix in the base is preserved: base
 * `https://login.example.com/linkkeys` and route `/auth/local-rp` produce
 * `https://login.example.com/linkkeys/auth/local-rp?...`.
 *
 * The URL is assembled with WHATWG `URL`. `signed_request` values are
 * URL-param-encoded (unpadded base64url) by construction, so query encoding
 * passes them through byte-identically.
 */
export function buildBrowserEndpoint(browserBase: string, route: string, signedRequest: string): string {
  const u = validateBrowserBase(browserBase);
  if (!route.startsWith("/")) {
    throw new InvalidInputError(`route ${JSON.stringify(route)} must start with /`);
  }
  u.pathname = u.pathname.replace(/\/+$/, "") + route;
  u.searchParams.set("signed_request", signedRequest);
  return u.toString();
}

/**
 * The begin-flow composition: discover the identity domain's browser base
 * and build the route URL, falling back to `https://<identityDomain>` when
 * DNS lookup fails, no valid record carries `https=`, or the discovered base
 * is invalid. The fallback preserves the pre-discovery behavior, so a domain
 * that serves its browser routes at the apex keeps working without a
 * `_linkkeys_apis` record.
 */
export async function resolveBrowserEndpoint(
  dns: DnsResolver,
  identityDomain: string,
  route: string,
  signedRequest: string,
): Promise<string> {
  let base: string;
  try {
    base = await resolveBrowserBase(dns, identityDomain);
  } catch {
    base = `https://${identityDomain}`;
  }
  return buildBrowserEndpoint(base, route, signedRequest);
}
