// The DNS TXT lookup seam (design doc: "Required Network Access" -- the SDK
// needs a DNS TXT lookup capability; injectable so tests can supply canned
// answers and operators can supply a hardened resolver, e.g. a DoH client).
library;

/// Resolve TXT records for a fully-qualified name (e.g.
/// `_linkkeys.example.com`). Each returned string is one TXT record's
/// content -- the concatenation of its character-strings.
abstract class DnsResolver {
  Future<List<String>> txtLookup(String name);
}
