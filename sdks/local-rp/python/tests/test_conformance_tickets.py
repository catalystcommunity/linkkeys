"""tickets.json: a claim ticket is 32 opaque bytes; the server stores only
its SHA-256 hex (the SDK never touches server storage, but the fingerprint
routine must match exactly since it's the same `crypto.fingerprint` used
throughout the protocol)."""

from conftest import hex_decode

from linkkeys_local_rp import crypto


def test_ticket_hashes_match_fingerprint_routine(tickets):
    cases = tickets["cases"]
    assert len(cases) > 0
    for case in cases:
        ticket = hex_decode(case["ticket_hex"])
        assert len(ticket) == 32
        assert crypto.fingerprint(ticket) == case["sha256_hex"]
