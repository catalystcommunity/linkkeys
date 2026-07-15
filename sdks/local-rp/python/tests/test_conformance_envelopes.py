"""envelopes.json: the four signature contexts, positive and negative
(tampered payload, wrong key, three wrong-context) cases -- 4 positive + 20
negative."""

from conftest import hex_decode

from linkkeys_local_rp import crypto
from linkkeys_local_rp.local_rp import envelope_signature_input


def _check_case(case: dict) -> None:
    context = case["context"]
    payload = hex_decode(case["payload_cbor_hex"])
    expected_sig_input = hex_decode(case["signature_input_cbor_hex"])
    signature = hex_decode(case["signature_hex"])
    verify_key = hex_decode(case["verify_key_hex"])
    expected_valid = case["expected_valid"]

    computed_sig_input = envelope_signature_input(context, payload)
    assert computed_sig_input == expected_sig_input, case.get("structure")

    try:
        crypto.verify_with_algorithm(crypto.SigningAlgorithm.ED25519, computed_sig_input, signature, verify_key)
        valid = True
    except crypto.CryptoError:
        valid = False

    assert valid == expected_valid, case.get("structure")


def test_envelopes_positive_cases_verify(envelopes):
    cases = envelopes["cases"]
    assert len(cases) == 4
    for case in cases:
        assert case["expected_valid"] is True
        _check_case(case)


def test_envelopes_negative_cases_fail(envelopes):
    cases = envelopes["negative_cases"]
    assert len(cases) == 20
    for case in cases:
        assert case["expected_valid"] is False
        _check_case(case)
