import type { DnsResolver } from "./dns.ts";
import { linkkeysApisDnsName, parseLinkkeysApisTxt } from "./dnsRecords.ts";

function validBrowserBase(raw: string): URL | undefined {
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.search || url.hash) {
      return undefined;
    }
    return url;
  } catch {
    return undefined;
  }
}

/** Resolve the browser HTTPS endpoint. DNS errors use the identity domain. */
export async function resolveBrowserBase(dns: DnsResolver, identityDomain: string): Promise<URL> {
  try {
    for (const txt of await dns.txtLookup(linkkeysApisDnsName(identityDomain))) {
      try {
        const base = parseLinkkeysApisTxt(txt).httpsBase;
        if (base) {
          const valid = validBrowserBase(base);
          if (valid) return valid;
        }
      } catch {
        // A DNS name can contain unrelated TXT records. Try the next record.
      }
    }
  } catch {
    // Endpoint discovery has a protocol-defined direct-domain fallback.
  }
  return new URL(`https://${identityDomain}`);
}

/** Add a LinkKeys route without discarding an endpoint path prefix. */
export function buildBrowserUrl(base: URL, route: string): URL {
  const url = new URL(base.href);
  const prefix = url.pathname.replace(/\/$/, "");
  url.pathname = `${prefix}/${route.replace(/^\//, "")}`;
  return url;
}
