"""keys.json: fingerprint calculation matches the fixed test vectors, and
the SDK's own fingerprint string helpers round-trip through it."""

from conftest import hex_decode

from linkkeys_local_rp import crypto, fingerprint_from_string, fingerprint_to_string


def test_fingerprints_match_and_round_trip_through_sdk_helpers(keys):
    for path in [
        keys["local_rp"]["signing"],
        keys["domain_signing_key"],
    ]:
        public = hex_decode(path["public_key_hex"])
        expected_fp = path["fingerprint_hex"]

        computed = crypto.fingerprint(public)
        assert computed == expected_fp

        s = fingerprint_to_string(computed)
        assert fingerprint_from_string(s) == expected_fp


def test_fingerprint_from_string_rejects_non_fingerprint():
    import pytest

    with pytest.raises(Exception):
        fingerprint_from_string("deadbeef")
