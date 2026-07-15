package community.catalyst.linkkeys.localrp.dns;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import community.catalyst.linkkeys.localrp.SdkException;

/**
 * Default {@link DnsResolver}: TXT lookups via JNDI's built-in DNS service
 * provider ({@code com.sun.jndi.dns.DnsContextFactory}) &mdash; standard
 * library, no dependency, matching the design doc's Java column note "DNS
 * TXT via JNDI (com.sun.jndi.dns InitialDirContext -- stdlib, no
 * dependency)". Per the design doc's "Decided" section: resolver spoofing on
 * a LAN is an accepted, documented tradeoff for this mode; operators wanting
 * hardening can inject their own {@link DnsResolver} (e.g. a DoH client)
 * instead of this one.
 *
 * <p>Configurable DNS servers: pass explicit {@code host[:port]} server
 * addresses to {@link #SystemDnsResolver(List)}; the no-arg constructor uses
 * whatever the OS resolver configuration provides (JNDI's default when no
 * {@code java.naming.provider.url} is set).
 */
public final class SystemDnsResolver implements DnsResolver {
    private final List<String> servers;
    private final long timeoutMillis;

    public SystemDnsResolver() {
        this(null, 10_000);
    }

    /** {@code servers} entries are {@code host} or {@code host:port} (DNS server port, default 53). */
    public SystemDnsResolver(List<String> servers) {
        this(servers, 10_000);
    }

    public SystemDnsResolver(List<String> servers, long timeoutMillis) {
        this.servers = servers;
        this.timeoutMillis = timeoutMillis;
    }

    @Override
    public List<String> txtLookup(String name) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        env.put("com.sun.jndi.dns.timeout.initial", Long.toString(timeoutMillis));
        env.put("com.sun.jndi.dns.timeout.retries", "1");
        if (servers != null && !servers.isEmpty()) {
            StringBuilder url = new StringBuilder();
            for (String s : servers) {
                if (url.length() > 0) {
                    url.append(' ');
                }
                url.append("dns://").append(s);
            }
            env.put("java.naming.provider.url", url.toString());
        }

        try {
            DirContext ctx = new InitialDirContext(env);
            try {
                Attributes attrs = ctx.getAttributes(name, new String[] {"TXT"});
                Attribute txt = attrs.get("TXT");
                List<String> out = new ArrayList<>();
                if (txt != null) {
                    NamingEnumeration<?> values = txt.getAll();
                    try {
                        while (values.hasMore()) {
                            out.add(unquote(String.valueOf(values.next())));
                        }
                    } finally {
                        values.close();
                    }
                }
                return out;
            } finally {
                ctx.close();
            }
        } catch (NamingException e) {
            throw new SdkException(SdkException.Kind.DNS, name + ": " + e.getMessage(), e);
        }
    }

    /**
     * JNDI's DNS provider wraps a TXT record's value in double quotes when
     * it round-trips it as an attribute string; strip a single matching pair
     * if present. A raw record never legitimately begins and ends with
     * {@code "} in this protocol's format ({@code v=lk1 fp=...}), so this is
     * unambiguous.
     */
    private static String unquote(String s) {
        if (s.length() >= 2 && s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"') {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }
}
