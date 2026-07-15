package community.catalyst.linkkeys.localrp.dns;

import java.util.List;

/**
 * The DNS TXT lookup seam (design doc: "Required Network Access" &mdash; the
 * SDK needs a DNS TXT lookup capability; injectable so tests can supply
 * canned answers and operators can supply a hardened resolver, e.g. a DoH
 * client).
 */
public interface DnsResolver {
    /**
     * Resolve TXT records for a fully-qualified name (e.g.
     * {@code _linkkeys.example.com}). Each returned string is one TXT
     * record's content &mdash; the concatenation of its character-strings.
     */
    List<String> txtLookup(String name);
}
