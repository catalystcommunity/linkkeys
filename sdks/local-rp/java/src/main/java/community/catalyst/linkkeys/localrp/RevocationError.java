package community.catalyst.linkkeys.localrp;

/** A sibling-signed revocation certificate failed to meet quorum. Mirrors {@code liblinkkeys::revocation::RevocationError}. */
public class RevocationError extends RuntimeException {
    public RevocationError(int got, int need) {
        super("revocation certificate has " + got + " valid distinct signer(s), needs " + need);
    }
}
