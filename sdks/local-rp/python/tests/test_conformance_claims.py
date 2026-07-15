"""claims.json: Claim wire encoding and claim-signature verification.

THE TRAP THIS FILE EXISTS TO CATCH: `Claim.claim_value` is CBOR bytes (bstr,
major type 2), never a text string (tstr, major type 3) -- both on the wire
and inside the signed payload. An SDK that wires it as text passes its own
self-tests perfectly (sign-wrong/verify-wrong is self-consistent) and only
cross-implementation vectors expose the bug. Every case here runs through the
SDK's own claim verification path (`linkkeys_local_rp/claims.py`), the same
module `complete_local_login` uses.
"""

from datetime import datetime, timezone

import pytest
from conftest import hex_decode, load_vector

from linkkeys_local_rp import claims as claims_mod
from linkkeys_local_rp.generated import codec as _codec  # noqa: F401  (attaches to_cbor/from_cbor)
from linkkeys_local_rp.generated.types import Claim, ClaimSignature, DomainPublicKey

# All fixture timestamps are fixed 2026-01-01 constants with far-future
# (2126) or absent expiry; any fixed "now" between issuance and 2126 works
# for every case here.
NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)

_ERROR_KIND_BY_CLASS = {
    claims_mod.SignatureInvalid: "signature_invalid",
    claims_mod.KeyNotFound: "key_not_found",
}


@pytest.fixture(scope="module")
def claims_vectors():
    return load_vector("claims.json")


def _claim_signature_from_case(s: dict) -> ClaimSignature:
    return ClaimSignature(
        domain=s["domain"],
        signed_by_key_id=s["signed_by_key_id"],
        signature=hex_decode(s["signature_hex"]),
    )


def _claim_from_case(case: dict) -> Claim:
    c = case["claim"]
    return Claim(
        claim_id=c["claim_id"],
        user_id=c["user_id"],
        claim_type=c["claim_type"],
        claim_value=hex_decode(c["claim_value_hex"]),
        signatures=[_claim_signature_from_case(s) for s in c["signatures"]],
        attested_at=c["attested_at"],
        created_at=c["created_at"],
        expires_at=c["expires_at"],
        revoked_at=c["revoked_at"],
    )


def _domain_public_key(k: dict) -> DomainPublicKey:
    return DomainPublicKey(
        key_id=k["key_id"],
        public_key=hex_decode(k["public_key_hex"]),
        fingerprint=k["fingerprint_hex"],
        algorithm=k["algorithm"],
        key_usage=k["key_usage"],
        created_at=k["created_at"],
        expires_at=k["expires_at"],
        revoked_at=k["revoked_at"],
        signed_by_key_id=None,
        key_signature=None,
    )


def _domain_key_sets(entries: list) -> list:
    """Group flat `domain_keys` entries by their `domain` field into the
    `DomainKeySet` list `verify_claim`/`verify_claim_signatures` expect."""
    by_domain: dict = {}
    for k in entries:
        by_domain.setdefault(k["domain"], []).append(_domain_public_key(k))
    return [claims_mod.DomainKeySet(domain=d, keys=ks) for d, ks in by_domain.items()]


def _error_kind(exc: Exception) -> str:
    for cls, name in _ERROR_KIND_BY_CLASS.items():
        if isinstance(exc, cls):
            return name
    raise AssertionError(f"unmapped claim error type: {type(exc)!r}: {exc}")


def test_registry_constants(claims_vectors):
    assert claims_vectors["tag"] == claims_mod.CLAIM_PAYLOAD_TAG == "linkkeys-claim-v2"


def test_positive_cases_round_trip_and_verify(claims_vectors):
    """Byte-exact wire round trip, exact per-signature signed-payload bytes,
    and full `verify_claim` success -- for every positive case, through the
    SDK's own decode/verify path."""
    cases = claims_vectors["cases"]
    assert len(cases) == 3
    domain_keys = _domain_key_sets(claims_vectors["domain_keys"])

    for case in cases:
        wire = hex_decode(case["claim_cbor_hex"])
        expected = _claim_from_case(case)

        decoded = claims_mod.decode_claim(wire)
        assert decoded == expected, case["name"]
        assert isinstance(decoded.claim_value, bytes), case["name"]

        # Byte-exact re-encode via the generated codec.
        assert decoded.to_cbor() == wire, case["name"]

        # Exact per-signature signed-payload bytes (the 8-element tag-first
        # array, subject as the single '@'-joined string).
        for sig_case, sig in zip(case["claim"]["signatures"], decoded.signatures):
            payload = claims_mod.claim_sign_payload(
                decoded.claim_id,
                decoded.claim_type,
                decoded.claim_value,
                decoded.user_id,
                case["subject_domain"],
                sig.domain,
                decoded.expires_at,
                decoded.attested_at,
            )
            assert payload == hex_decode(sig_case["signed_payload_cbor_hex"]), case["name"]

        assert case["expected_valid"] is True
        claims_mod.verify_claim(decoded, case["subject_domain"], domain_keys, NOW)


def test_claim_non_utf8_binary_value_is_not_valid_utf8(claims_vectors):
    """The discriminator case: its value bytes are not valid UTF-8, so a
    tstr-based codec could not even represent them."""
    case = next(c for c in claims_vectors["cases"] if c["name"] == "claim_non_utf8_binary_value")
    value = hex_decode(case["claim"]["claim_value_hex"])
    with pytest.raises(UnicodeDecodeError):
        value.decode("utf-8")


def test_claim_value_as_cbor_text_rejected(claims_vectors):
    """The wire trap: byte-identical to claim_utf8_text_value's CBOR except
    claim_value is encoded as a CBOR text string (major type 3) instead of a
    byte string (major type 2). A strict bstr codec must refuse to decode
    this at all -- not merely mis-verify it."""
    cases = claims_vectors["decode_negative_cases"]
    assert len(cases) == 1
    case = cases[0]
    assert case["expected_decode_ok"] is False
    assert case["name"] == "claim_value_as_cbor_text_rejected"

    wire = hex_decode(case["claim_cbor_hex"])
    with pytest.raises(_codec.CsilDecodeError):
        claims_mod.decode_claim(wire)


def test_verification_negative_cases(claims_vectors):
    cases = claims_vectors["negative_cases"]
    assert len(cases) == 4
    default_domain_keys = _domain_key_sets(claims_vectors["domain_keys"])

    for case in cases:
        wire = hex_decode(case["claim_cbor_hex"])
        claim = claims_mod.decode_claim(wire)
        domain_keys = _domain_key_sets(case["domain_keys"]) if "domain_keys" in case else default_domain_keys

        with pytest.raises(claims_mod.ClaimError) as exc_info:
            claims_mod.verify_claim(claim, case["subject_domain"], domain_keys, NOW)
        assert _error_kind(exc_info.value) == case["expected_error"], case["name"]


def test_ticket_redemption_response_round_trips_and_verifies(claims_vectors):
    """The wire message `complete_local_login` actually consumes Claims
    from. Decoding must reproduce each claim byte-exactly (claim_value as
    raw bytes), re-encoding must reproduce response_cbor_hex, and every
    embedded claim's signatures must verify."""
    trr = claims_vectors["ticket_redemption_response"]
    wire = hex_decode(trr["response_cbor_hex"])

    decoded = claims_mod.decode_ticket_redemption_response(wire)

    assert decoded.user_id == trr["user_id"]
    assert decoded.user_domain == trr["user_domain"]
    assert decoded.ticket_expires_at == trr["ticket_expires_at"]

    expected_claims = [_claim_from_case(c) for c in claims_vectors["cases"]]
    assert decoded.claims == expected_claims
    for claim in decoded.claims:
        assert isinstance(claim.claim_value, bytes)

    # Byte-exact re-encode.
    assert decoded.to_cbor() == wire

    domain_keys = _domain_key_sets(claims_vectors["domain_keys"])
    for claim in decoded.claims:
        claims_mod.verify_claim(claim, decoded.user_domain, domain_keys, NOW)


def test_ticket_redemption_response_with_text_claim_value_is_rejected(claims_vectors):
    """The bstr/tstr check must apply to every claim embedded in a
    `LocalRpTicketRedemptionResponse` -- the path `redeem_claim_ticket`
    actually uses -- so a compromised/malicious IDP smuggling a text-encoded
    claim_value inside a real redemption response is rejected. The generated
    codec is now strict at every decode layer, so the malicious wire bytes
    are spliced together at the raw-CBOR level (as an attacker would), not
    via the typed API (which can no longer represent them)."""
    trr = claims_vectors["ticket_redemption_response"]
    bad_claim_wire = hex_decode(claims_vectors["decode_negative_cases"][0]["claim_cbor_hex"])

    # Sanity: the bad claim can't even be decoded standalone anymore -- the
    # generated codec itself rejects the text-typed claim_value.
    with pytest.raises(_codec.CsilDecodeError):
        Claim.from_cbor(bad_claim_wire)

    # Splice the raw bad-claim tree into an otherwise-valid response tree and
    # re-encode with the generic (untyped) CBOR encoder.
    response_tree = _codec.cbor_decode(hex_decode(trr["response_cbor_hex"]))
    bad_claim_tree = _codec.cbor_decode(bad_claim_wire)
    response_tree["claims"].append(bad_claim_tree)
    wire = _codec.cbor_encode(response_tree)

    with pytest.raises(_codec.CsilDecodeError):
        claims_mod.decode_ticket_redemption_response(wire)
