// Memoized default network seams (design doc: "Both get default
// implementations where the language stdlib allows"). Kept in their own
// module (rather than inline in `complete.ts` or `index.ts`) so both can
// import the same singletons without a circular import between the barrel
// (`index.ts`) and `complete.ts`.

import { SystemDnsResolver, type DnsResolver } from "./dns.ts";
import { NodeTransport, type Transport } from "./transport.ts";

let defaultTransportInstance: Transport | undefined;
let defaultDnsResolverInstance: DnsResolver | undefined;

/** The default `Transport`: a permissive-by-default Node `net.Socket` dialer. Memoized for the process lifetime. */
export function defaultTransport(): Transport {
  if (!defaultTransportInstance) {
    defaultTransportInstance = new NodeTransport();
  }
  return defaultTransportInstance;
}

/** The default `DnsResolver`: the OS-configured system resolver. Memoized for the process lifetime. */
export function defaultDnsResolver(): DnsResolver {
  if (!defaultDnsResolverInstance) {
    defaultDnsResolverInstance = new SystemDnsResolver();
  }
  return defaultDnsResolverInstance;
}
