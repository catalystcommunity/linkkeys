namespace LinkKeys.LocalRp.Dns;

/// <summary>
/// The DNS TXT lookup seam (design doc: "Required Network Access" — the SDK needs a DNS
/// TXT lookup capability; injectable so tests can supply canned answers and operators can
/// supply a hardened resolver, e.g. a DoH client).
/// </summary>
public interface IDnsResolver
{
    /// <summary>
    /// Resolve TXT records for a fully-qualified name (e.g. <c>_linkkeys.example.com</c>).
    /// Each returned string is one TXT record's content — the concatenation of its
    /// character-strings.
    /// </summary>
    IReadOnlyList<string> TxtLookup(string name);
}
