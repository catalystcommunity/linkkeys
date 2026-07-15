namespace LinkKeys.LocalRp;

/// <summary>A sibling-signed revocation certificate failed to meet quorum. Mirrors <c>liblinkkeys::revocation::RevocationError</c>.</summary>
public class RevocationError(int got, int need) : Exception($"revocation certificate has {got} valid distinct signer(s), needs {need}");
