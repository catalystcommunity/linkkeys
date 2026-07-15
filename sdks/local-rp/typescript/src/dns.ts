// The DNS TXT lookup seam. `dns-less-local-rp-design.md`'s "Required Network
// Access" / Wire Precision sections require every SDK to look up
// `_linkkeys.{domain}` (trust anchor `fp=` pins) and `_linkkeys_apis.{domain}`
// (the `tcp=` endpoint) TXT records, with a configurable resolver defaulting
// to the system resolver. `DnsResolver` is that seam; `SystemDnsResolver` is
// the default, using Node's stdlib `dns.promises`.

import { promises as dnsPromises } from "node:dns";

export class DnsLookupError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "DnsLookupError";
  }
}

/**
 * Resolve TXT records for a fully-qualified name (e.g.
 * `_linkkeys.example.com`). Each returned string is one TXT record's full
 * content — the concatenation of its character-strings — matching the Rust
 * reference SDK's `DnsResolver` contract, so
 * `parseLinkkeysTxt`/`parseLinkkeysApisTxt` can parse it unchanged.
 */
export interface DnsResolver {
  txtLookup(name: string): Promise<string[]>;
}

/**
 * Default `DnsResolver`: the OS-configured resolver (`dns.promises.resolveTxt`,
 * Node's own stdlib, itself backed by c-ares which reads `/etc/resolv.conf`
 * or the platform equivalent). Per the design doc's "Decided" section:
 * resolver spoofing on a LAN is an accepted, documented tradeoff for this
 * mode; operators wanting hardening can inject their own `DnsResolver` (e.g.
 * a DoH client) instead. `servers` optionally overrides which resolver(s) to
 * query (design doc: "configurable ... e.g. a DoH endpoint" — a plain
 * resolver-IP override is the simplest form of that for Node's stdlib).
 */
export class SystemDnsResolver implements DnsResolver {
  private readonly servers?: readonly string[];

  constructor(options?: { servers?: readonly string[] }) {
    this.servers = options?.servers;
  }

  async txtLookup(name: string): Promise<string[]> {
    try {
      let records: string[][];
      if (this.servers) {
        const resolver = new dnsPromises.Resolver();
        resolver.setServers([...this.servers]);
        records = await resolver.resolveTxt(name);
      } else {
        records = await dnsPromises.resolveTxt(name);
      }
      // Node returns one array of character-strings per TXT record; the Rust
      // resolver (hickory) instead hands back each record's character-strings
      // already concatenated (`TXT::to_string()`), so join here to match.
      return records.map((rec) => rec.join(""));
    } catch (e) {
      throw new DnsLookupError(`TXT lookup failed for ${name}: ${e}`, { cause: e });
    }
  }
}
