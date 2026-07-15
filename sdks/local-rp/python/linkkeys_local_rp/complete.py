"""`complete_local_login` (design doc: "SDK API Shape", "Flow" steps 12-13).

This is the SDK's full verification chain, run in the exact order the pure
`local_rp` helpers require (see each step's comment for which design-doc /
security-checklist bullet it satisfies):

1. decode the callback ciphertext from its URL-param encoding
2. open it (decrypt) — only with a suite this identity's own descriptor
   advertises
3. fetch the pending domain's public keys, DNS-`fp=`-pinned, over TCP
   CSIL-RPC
4. verify the domain-signed envelope (key lookup, revocation/expiry,
   signature, payload timestamp bounds) — only now is anything inside the
   payload trusted
5. cross-check the cleartext header's routing fields against the
   now-verified payload
6. audience / issuer / callback-URL / nonce-state checks
7. redeem the claim ticket over TCP CSIL-RPC (signed with the local RP's
   own key — the possession proof)
7b. bind the redemption response to the VERIFIED payload identity:
   `redemption.user_id`/`redemption.user_domain` must equal
   `payload.user_id`/`payload.user_domain` — the redemption response is
   just an unsigned RPC reply, so it is never itself a trust root
8. verify every returned claim's signatures against ITS signer domain's
   keys (fetched the same pinned way), which also checks the claim's own
   revocation/expiry, AND that `claim.user_id == payload.user_id`
9. enforce `pending.required_claims`: every required claim type must be
   present among the claims that passed step 8

The identity this function returns (`user_id`/`user_domain`) is always
sourced from the SIGNED, domain-verified `payload` — never from the
unsigned ticket-redemption response — because step 7b already proved they
agree, and the payload is the only one of the two that is cryptographically
bound to the domain's signing key.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from . import claims as claims_mod
from . import encoding, local_rp, rpc
from .crypto import AeadSuite
from .dns import DnsResolver
from .generated.types import Claim, DomainPublicKey
from .begin import PendingLogin
from .identity import LocalRpKeyMaterial
from .timeutil import parse_rfc3339, to_rfc3339
from .transport import Transport

# Bound on the number of distinct claim-signer domains `complete_local_login`
# will fetch keys for per completion — see the comment at its use site for
# why this exists.
MAX_CLAIM_SIGNER_DOMAINS = 8


class CompleteLoginError(Exception):
    pass


class IdentityMismatch(CompleteLoginError):
    """The ticket-redemption response, or a redeemed claim, names a
    different `user_id`/`user_domain` than the signed callback payload
    already proved. Always fatal — never partially trust either side."""


class RequiredClaimsNotSatisfied(CompleteLoginError):
    """One or more of `pending.required_claims` has no corresponding
    verified claim in the redemption response (missing entirely, or present
    but failed signature/revocation/expiry verification)."""


@dataclass
class VerifiedLocalLogin:
    """What `complete_local_login` returns to app code (design doc: "SDKs
    ... should either return verified results or call registered callbacks
    with:" — this package returns rather than calling back)."""

    user_id: str
    user_domain: str
    claims: List[Claim]
    domain_public_keys: List[DomainPublicKey]
    local_rp_fingerprint: str
    issued_at: datetime
    expires_at: datetime
    ticket_expires_at: datetime


def _strip_encrypted_token_param(arrived_url: str) -> str:
    """Undo the exact `?`/`&` + `encrypted_token=` suffix construction the
    IDP uses to deliver the callback, so the recovered value can be compared
    against the signed payload's `callback_url` (Wire Precision, "URL and
    parameter conventions"). If the arrived URL doesn't end with that exact
    suffix, returns it unchanged — the subsequent `verify_callback_url`
    equality check then correctly fails closed rather than this function
    guessing."""
    for sep in ("?", "&"):
        marker = f"{sep}encrypted_token="
        idx = arrived_url.rfind(marker)
        if idx != -1:
            return arrived_url[:idx]
    return arrived_url


def complete_local_login(
    key_material: LocalRpKeyMaterial,
    pending: PendingLogin,
    encrypted_token: str,
    arrived_url: str,
    now: datetime,
    *,
    clock_skew_seconds: int = local_rp.DEFAULT_CLOCK_SKEW_SECONDS,
    transport: Optional[Transport] = None,
    dns: Optional[DnsResolver] = None,
) -> VerifiedLocalLogin:
    """`complete_local_login(config) -> VerifiedLocalLogin` (design doc,
    "SDK API Shape"). Every argument is load-bearing (design doc:
    "`complete_local_login` inputs, spelled out because every one is
    load-bearing"):

    - `key_material`: the same identity `begin_local_login` used.
    - `pending`: the pending-login state `begin_local_login` returned,
      exactly as the app persisted it. Treat as single-use.
    - `encrypted_token`: the `encrypted_token` query-parameter's raw value.
    - `arrived_url`: the full URL the callback actually arrived at.
    - `now`: the current time (never read from the system clock internally).
    - `transport` / `dns`: the network seams. Defaults to
      `transport.StdTransport()` / `dns.SystemDnsResolver()` when omitted.
    """
    if transport is None:
        from .transport import StdTransport

        transport = StdTransport()
    if dns is None:
        from .dns import SystemDnsResolver

        dns = SystemDnsResolver()

    # 1. Decode the callback's URL-param encoding.
    encrypted = encoding.local_rp_encrypted_callback_from_url_param(encrypted_token)

    # 2. Open it, restricted to suites THIS identity's own descriptor
    # advertises (Wire Precision: "The SDK must decrypt only with a suite
    # listed in its own descriptor").
    from .generated.types import LocalRpDescriptor

    own_descriptor = LocalRpDescriptor.from_cbor(key_material.descriptor.descriptor)
    allowed_suites = [s for s in (AeadSuite.parse_str(x) for x in own_descriptor.supported_suites) if s is not None]
    header, signed_payload = local_rp.open_local_rp_callback(
        encrypted, key_material.encryption_private_key, allowed_suites
    )

    # 3. Fetch the PENDING state's domain's keys, DNS-pinned, over TCP
    # CSIL-RPC (design doc: "fetches domain public keys ... for the domain
    # the login was begun with").
    user_domain_keys = rpc.fetch_domain_keys(transport, dns, pending.user_domain)

    # 4. Verify the domain-signed envelope against those keys (key lookup,
    # revocation/expiry, signature, payload timestamp bounds). Nothing
    # inside `payload` is trusted before this succeeds.
    payload = local_rp.verify_local_rp_callback_payload(signed_payload, user_domain_keys, now, clock_skew_seconds)

    # 5. Cross-check the cleartext header's routing twins against the
    # now-verified payload.
    local_rp.check_callback_header_matches_payload(header, payload)

    # 6a. Audience: the callback names THIS local RP.
    local_rp.verify_audience(payload.audience_fingerprint, key_material.fingerprint)

    # 6b. Issuer binding: the payload's user_domain must be the domain the
    # login was BEGUN with, not merely whichever domain's keys happened to
    # verify.
    local_rp.verify_issuer(payload.user_domain, pending.user_domain)

    # 6c. Callback URL binding against the URL the callback actually
    # arrived at (not merely the URL originally requested).
    arrived_base_url = _strip_encrypted_token_param(arrived_url)
    local_rp.verify_callback_url(payload.callback_url, arrived_base_url)

    # 6d. Nonce/state equality against the pending state. Single-use replay
    # protection at the app boundary is the app's job.
    local_rp.verify_nonce_state(pending.nonce, pending.state, payload.nonce, payload.state)

    # 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the local
    # RP's own key (the possession proof a stolen ticket can't satisfy).
    redemption_request = local_rp.build_local_rp_ticket_redemption_request(
        payload.claim_ticket, key_material.fingerprint, to_rfc3339(now)
    )
    signed_redemption = local_rp.sign_local_rp_ticket_redemption_request(
        redemption_request, key_material.signing_private_key
    )
    redemption = rpc.redeem_claim_ticket(transport, dns, pending.user_domain, signed_redemption)

    # 7b. The ticket-redemption response is an UNSIGNED RPC reply — nothing
    # about it is cryptographically bound to the domain's signing key. The
    # only identity this function may trust is the one the SIGNED callback
    # `payload` already proved (step 4). A malicious/compromised IDP (or a
    # man-in-the-middle that only controls the unauthenticated RPC leg)
    # could otherwise redeem a ticket and hand back claims for a completely
    # different user than the one the browser actually authenticated as.
    # Cross-check and abort fatally on any mismatch — never proceed with
    # either side's identity alone.
    if redemption.user_id != payload.user_id or redemption.user_domain != payload.user_domain:
        raise IdentityMismatch(
            "ticket redemption identity does not match the signed callback payload"
        )

    # 8. Verify every returned claim's signatures against ITS signer
    # domain's keys, fetched the same pinned way (a claim may be attested by
    # a domain other than the user's home domain). Reuse the home domain's
    # already-fetched keys; fetch any additional signer domains on demand.
    #
    # The redemption response's claim signatures name their signing domains
    # as plain, not-yet-verified strings — a malicious/compromised home IDP
    # could otherwise list an unbounded number of distinct "signer domains"
    # purely to make this SDK perform many outbound DNS/TCP calls to
    # attacker-chosen targets before any signature is actually checked (an
    # SSRF/DoS amplification vector against the app's own process). Cap the
    # number of distinct signer domains this SDK will fetch keys for per
    # completion; a legitimate claim set names very few (typically one: the
    # home domain).
    domain_key_sets = [claims_mod.DomainKeySet(domain=pending.user_domain, keys=user_domain_keys)]
    for claim in redemption.claims:
        for sig in claim.signatures:
            if any(s.domain == sig.domain for s in domain_key_sets):
                continue
            if len(domain_key_sets) >= MAX_CLAIM_SIGNER_DOMAINS:
                raise CompleteLoginError(
                    f"claim set names more than {MAX_CLAIM_SIGNER_DOMAINS} distinct signer domains; "
                    "refusing to fetch further keys"
                )
            keys = rpc.fetch_domain_keys(transport, dns, sig.domain)
            domain_key_sets.append(claims_mod.DomainKeySet(domain=sig.domain, keys=keys))

    # Verify every claim against the VERIFIED payload's user_domain (not
    # redemption.user_domain — equal per the 7b check above, but the
    # payload's copy is the one that's actually signature-bound), and
    # cross-check each claim's own user_id against the payload's before
    # trusting it: a claim naming a different user_id is never partially
    # accepted, it aborts the whole completion. Track which claim types
    # survive full verification so `pending.required_claims` can be
    # enforced against only the claims actually proven good.
    verified_claim_types = set()
    for claim in redemption.claims:
        if claim.user_id != payload.user_id:
            raise IdentityMismatch("claim user_id does not match the signed callback payload")
        claims_mod.verify_claim(claim, payload.user_domain, domain_key_sets, now)
        verified_claim_types.add(claim.claim_type)

    # 9. Enforce pending.required_claims: this is what the login actually
    # demanded at begin_local_login time. Missing or insufficient (including
    # an entirely empty claim set) is fatal — an IDP cannot silently drop a
    # required claim and still have the login succeed.
    missing_required = sorted(set(pending.required_claims) - verified_claim_types)
    if missing_required:
        raise RequiredClaimsNotSatisfied(
            "required claim types not satisfied by verified claims: " + ", ".join(missing_required)
        )

    return VerifiedLocalLogin(
        user_id=payload.user_id,
        user_domain=payload.user_domain,
        claims=redemption.claims,
        domain_public_keys=user_domain_keys,
        local_rp_fingerprint=key_material.fingerprint,
        issued_at=parse_rfc3339(payload.issued_at),
        expires_at=parse_rfc3339(payload.expires_at),
        ticket_expires_at=parse_rfc3339(redemption.ticket_expires_at),
    )
