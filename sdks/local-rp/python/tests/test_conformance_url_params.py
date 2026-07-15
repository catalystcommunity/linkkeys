"""url_params.json: base64url-unpadded round trips for the begin route's
`signed_request=` and the callback's `encrypted_token=` parameters, plus
negative cases (padded base64, standard alphabet)."""

import pytest
from conftest import hex_decode

from linkkeys_local_rp import encoding
from linkkeys_local_rp.generated.types import LocalRpEncryptedCallback, SignedLocalRpLoginRequest


def test_url_params_cases_round_trip_both_directions(url_params):
    for case in url_params["cases"]:
        cbor = hex_decode(case["cbor_hex"])
        b64 = case["base64url_unpadded"]

        assert encoding.b64url_encode(cbor) == b64
        assert encoding.b64url_decode(b64) == cbor

        if case["name"] == "signed_local_rp_login_request":
            typed = SignedLocalRpLoginRequest.from_cbor(cbor)
            assert encoding.signed_local_rp_login_request_to_url_param(typed) == b64
            round_tripped = encoding.signed_local_rp_login_request_from_url_param(b64)
            assert round_tripped.request == typed.request
            assert round_tripped.signature == typed.signature
        elif case["name"] == "local_rp_encrypted_callback":
            typed = LocalRpEncryptedCallback.from_cbor(cbor)
            assert encoding.local_rp_encrypted_callback_to_url_param(typed) == b64
            round_tripped = encoding.local_rp_encrypted_callback_from_url_param(b64)
            assert round_tripped.header == typed.header
            assert round_tripped.ciphertext == typed.ciphertext
        else:
            raise AssertionError(f"unrecognized url_params.json case name: {case['name']}")


def test_url_params_negative_cases_rejected(url_params):
    cases = url_params["negative_cases"]
    assert len(cases) == 2
    for case in cases:
        input_str = case["input"]
        assert case["expected_valid"] is False
        with pytest.raises(Exception):
            encoding.b64url_decode(input_str)
        with pytest.raises(Exception):
            encoding.local_rp_encrypted_callback_from_url_param(input_str)
