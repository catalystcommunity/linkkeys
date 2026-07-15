package community.catalyst.linkkeys.localrp.kt

import community.catalyst.linkkeys.localrp.LinkKeysLocalRp as JFacade
import community.catalyst.linkkeys.localrp.dns.DnsResolver as JDnsResolver
import community.catalyst.linkkeys.localrp.dns.SystemDnsResolver as JSystemDnsResolver
import community.catalyst.linkkeys.localrp.rpc.AddressPolicy as JAddressPolicy
import community.catalyst.linkkeys.localrp.rpc.StdTransport as JStdTransport
import community.catalyst.linkkeys.localrp.rpc.Transport as JTransport

/**
 * The TCP dial seam (design doc: "Required Network Access", "SDK endpoint
 * discovery and pinning"). Deliberately narrow: implementations only *connect
 * a byte-stream socket* to `host:port`; TLS (certificate-pin verification
 * against DNS `fp=` records) is layered on top inside [completeLocalLogin],
 * not here.
 *
 * A Java functional interface, so a Kotlin lambda SAM-converts to it, e.g.
 * `Transport { hostPort -> mySocket(hostPort) }`.
 */
typealias Transport = JTransport

/**
 * The DNS TXT lookup seam (design doc: "Required Network Access" -- every
 * SDK needs a DNS TXT lookup capability, configurable, defaulting to the
 * system resolver). SAM-convertible from a Kotlin lambda, e.g.
 * `DnsResolver { name -> listOf(...) }`.
 */
typealias DnsResolver = JDnsResolver

/** Which destination addresses the default [Transport] ([stdTransport]) is willing to dial. Default is [PERMISSIVE]. */
typealias AddressPolicy = JAddressPolicy

/** `AddressPolicy.PERMISSIVE`: dial anything the OS resolver returns -- the correct default for this mode (design doc). */
val PERMISSIVE: AddressPolicy = JAddressPolicy.PERMISSIVE

/** `AddressPolicy.PUBLIC_ONLY`: refuse loopback/private/link-local/CGNAT/documentation/unspecified addresses. Opt-in only. */
val PUBLIC_ONLY: AddressPolicy = JAddressPolicy.PUBLIC_ONLY

/** The default [Transport]: a permissive-by-default blocking socket dialer. Memoized for the process lifetime. */
fun defaultTransport(): Transport = JFacade.defaultTransport()

/** The default [DnsResolver]: the OS-configured system resolver. Memoized for the process lifetime. */
fun defaultDnsResolver(): DnsResolver = JFacade.defaultDnsResolver()

/**
 * Construct a [Transport] with an explicit [AddressPolicy] and/or timeouts,
 * for callers who want [PUBLIC_ONLY] or non-default timeouts rather than
 * [defaultTransport]'s memoized [PERMISSIVE] instance.
 */
fun stdTransport(
    policy: AddressPolicy = PERMISSIVE,
    connectTimeoutMillis: Int = 10_000,
    ioTimeoutMillis: Int = 30_000,
): Transport = JStdTransport(policy, connectTimeoutMillis, ioTimeoutMillis)

/**
 * Construct a [DnsResolver] against explicit DNS server(s) rather than the OS
 * resolver configuration, e.g. for a hardened/pinned-resolver deployment.
 * Entries are `host` or `host:port` (DNS server port, default 53).
 */
fun systemDnsResolver(servers: List<String>? = null, timeoutMillis: Long = 10_000): DnsResolver =
    if (servers == null) JSystemDnsResolver() else JSystemDnsResolver(servers, timeoutMillis)
