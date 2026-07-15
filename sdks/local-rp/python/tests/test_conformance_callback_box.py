"""callback_box.json: the local-RP callback sealed box, per suite, positive
and negative (13) cases -- header-field-flip AAD tamper, unadvertised suite,
unknown suite id, low-order ephemeral key, wrong recipient key, truncated
ciphertext."""

import pytest
from conftest import hex_decode

from linkkeys_local_rp import crypto
from linkkeys_local_rp.generated.types import LocalRpEncryptedCallback
from linkkeys_local_rp.local_rp import open_local_rp_callback


def _allowed_suites(case: dict):
    return [crypto.AeadSuite.parse_str(s) for s in case["allowed_suites"]]


def test_callback_box_positive_cases_open(callback_box):
    cases = callback_box["positive_cases"]
    assert len(cases) == 2

    for case in cases:
        header_bytes = hex_decode(case["header_cbor_hex"])
        ciphertext = hex_decode(case["ciphertext_hex"])
        decrypt_key = hex_decode(case["decrypt_private_key_hex"])
        allowed = _allowed_suites(case)

        encrypted = LocalRpEncryptedCallback(header=header_bytes, ciphertext=ciphertext)
        header, signed_payload = open_local_rp_callback(encrypted, decrypt_key, allowed)

        assert header.suite == case["suite"]
        assert header.fingerprint == case["fingerprint"]
        assert header.nonce == hex_decode(case["nonce_hex"])
        assert header.state == hex_decode(case["state_hex"])
        assert header.issued_at == case["issued_at"]
        assert header.expires_at == case["expires_at"]

        plaintext = signed_payload.to_cbor()
        assert plaintext == hex_decode(case["plaintext_cbor_hex"])


def test_callback_box_negative_cases_fail(callback_box):
    cases = callback_box["negative_cases"]
    assert len(cases) == 13

    for case in cases:
        header_bytes = hex_decode(case["header_cbor_hex"])
        ciphertext = hex_decode(case["ciphertext_hex"])
        decrypt_key = hex_decode(case["decrypt_private_key_hex"])
        allowed = _allowed_suites(case)

        encrypted = LocalRpEncryptedCallback(header=header_bytes, ciphertext=ciphertext)
        with pytest.raises(Exception):
            open_local_rp_callback(encrypted, decrypt_key, allowed)
