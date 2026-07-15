"""revocations.json: sibling-signed key revocation certificates -- all nine
certificate cases (with exact counted-signer expectations) plus the
application case proving certificates are APPLIED to the key set, not merely
verified."""

from datetime import datetime, timezone

import pytest
from conftest import hex_decode, load_vector

from linkkeys_local_rp import revocation as revocation_mod
from linkkeys_local_rp.generated import codec as _codec  # noqa: F401
from linkkeys_local_rp.generated.types import (
    ClaimSignature,
    DomainPublicKey,
    RevocationCertificate,
    SignedLocalRpCallbackPayload,
)
from linkkeys_local_rp.local_rp import LocalRpError, verify_local_rp_callback_payload


@pytest.fixture(scope="module")
def revocations():
    return load_vector("revocations.json")


def _domain_keys(revocations) -> list:
    keys = []
    for k in revocations["domain_keys"]:
        keys.append(
            DomainPublicKey(
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
        )
    return keys


def _certificate(case: dict) -> RevocationCertificate:
    c = case["certificate"]
    return RevocationCertificate(
        target_key_id=c["target_key_id"],
        target_fingerprint=c["target_fingerprint"],
        revoked_at=c["revoked_at"],
        signatures=[
            ClaimSignature(
                domain=s["domain"],
                signed_by_key_id=s["signed_by_key_id"],
                signature=hex_decode(s["signature_hex"]),
            )
            for s in c["signatures"]
        ],
    )


def test_registry_constants(revocations):
    assert revocations["quorum"] == revocation_mod.REVOCATION_QUORUM
    assert revocations["tag"] == "linkkeys-key-revocation-v1"


def test_certificate_cbor_round_trips(revocations):
    """The expanded `certificate` fields and `certificate_cbor_hex` describe
    the same object, and the generated codec reproduces the wire bytes."""
    for case in revocations["certificate_cases"]:
        wire = hex_decode(case["certificate_cbor_hex"])
        decoded = RevocationCertificate.from_cbor(wire)
        expected = _certificate(case)
        assert decoded == expected, case["name"]
        assert decoded.to_cbor() == wire, case["name"]


def test_revocation_payload_matches_vectors(revocations):
    """Recompute the five-element CBOR tuple for the valid case's signatures
    and confirm it equals the published signed_payload_cbor_hex exactly --
    this is the construction every signature covers (tag first, NOT the
    two-element envelope framing)."""
    case = next(c for c in revocations["certificate_cases"] if c["name"] == "valid_quorum_two_siblings")
    cert = case["certificate"]
    for sig in cert["signatures"]:
        computed = revocation_mod.revocation_payload(
            cert["target_key_id"], cert["target_fingerprint"], cert["revoked_at"], sig["domain"]
        )
        assert computed == hex_decode(sig["signed_payload_cbor_hex"])


def test_all_certificate_cases(revocations):
    keys = _domain_keys(revocations)
    cases = revocations["certificate_cases"]
    assert len(cases) == 9

    for case in cases:
        cert = _certificate(case)
        domain = case["verify_domain"]

        counted = revocation_mod.count_valid_signers(cert, keys, domain)
        assert counted == case["expected_counted_signers"], case["name"]

        try:
            revocation_mod.verify_revocation_certificate(cert, keys, domain)
            valid = True
        except revocation_mod.RevocationError as e:
            valid = False
            assert e.got == case["expected_counted_signers"], case["name"]
        assert valid == case["expected_valid"], case["name"]


def test_application_case_certificates_are_applied_not_just_verified(revocations):
    """The fetched key entry for the target looks perfectly valid on its own
    (no revoked_at); only applying the certificate reveals it is dead. An
    implementation that verifies certificates but forgets to apply them to
    the key set fails here."""
    keys = _domain_keys(revocations)
    app = revocations["application_case"]
    env = app["envelope"]
    assert env["structure"] == "callback_payload"

    signed = SignedLocalRpCallbackPayload(
        payload=hex_decode(env["payload_cbor_hex"]),
        signing_key_id=env["signing_key_id"],
        signature=hex_decode(env["signature_hex"]),
    )
    verify_now = datetime.fromisoformat(app["verify_now"]).astimezone(timezone.utc)
    skew = app["clock_skew_seconds"]

    # Before applying the revocation certificate: the envelope verifies,
    # because the fetched key list shows the target with NO revoked_at.
    assert app["expected_valid_before_revocation"] is True
    payload = verify_local_rp_callback_payload(signed, keys, verify_now, skew)
    assert payload.user_domain == revocations["domain"]

    # Apply the referenced certificate (valid_quorum_two_siblings) exactly
    # the way fetch_domain_keys does, then re-verify: must now fail.
    cert_case = next(c for c in revocations["certificate_cases"] if c["name"] == "valid_quorum_two_siblings")
    cert = _certificate(cert_case)
    applied = revocation_mod.apply_revocations(keys, [cert], revocations["domain"])
    assert all(k.key_id != cert.target_key_id for k in applied)

    assert app["expected_valid_after_revocation"] is False
    with pytest.raises(LocalRpError):
        verify_local_rp_callback_payload(signed, applied, verify_now, skew)
