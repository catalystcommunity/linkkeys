"""Act-as grantee tests: the `local_rp_grantee` case of
`sdks/regular-rp/conformance/act_as_grantee_signing.json` byte for byte,
begin act-as browser discovery with fake DNS, and the callback nonce check.
The refresh call is tested against the fake IDP in test_flow.py. No test
here touches the network."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from linkkeys_local_rp import crypto
from linkkeys_local_rp.act_as import (
    ACT_AS_GRANT_REQUEST_TAG,
    ActAsError,
    BeginActAsConfig,
    act_as_grant_hash,
    begin_act_as,
    complete_act_as_callback,
    format_act_as_time,
    present_act_as,
    sign_act_as_grant_request,
    sign_act_as_refresh_request,
    signed_act_as_grant_request_to_url_param,
)
from linkkeys_local_rp.generated.types import (
    ActAsGrantRequest,
    ActAsRefreshRequest,
    ApplicationRef,
    GranteeRef,
    LocalRpDescriptor,
    SignedActAsGrant,
    SignedActAsGrantRequest,
    SignedActAsScopeSet,
    SignedLocalRpDescriptor,
)
from linkkeys_local_rp.local_rp import DecodeFailed, NonceMismatch, envelope_signature_input

VECTOR_PATH = Path(__file__).resolve().parents[3] / "regular-rp" / "conformance" / "act_as_grantee_signing.json"
VECTORS = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
CASE = next(c for c in VECTORS["cases"] if c["name"] == "local_rp_grantee")
GRANTEE = VECTORS["local_rp_grantee"]

KEY_MATERIAL = SimpleNamespace(
    descriptor=SignedLocalRpDescriptor.from_cbor(bytes.fromhex(GRANTEE["signed_descriptor_cbor_hex"])),
    fingerprint=GRANTEE["fingerprint"],
    signing_private_key=bytes.fromhex(GRANTEE["signing_private_key_hex"]),
)


def _descriptor_public_key() -> bytes:
    return LocalRpDescriptor.from_cbor(KEY_MATERIAL.descriptor.descriptor).signing_public_key


def _parse_time(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def test_vector_descriptor_round_trips():
    assert KEY_MATERIAL.descriptor.to_cbor().hex() == GRANTEE["signed_descriptor_cbor_hex"]
    assert CASE["grantee"]["local_rp_descriptor_fingerprint"] == KEY_MATERIAL.fingerprint


def test_vector_grant_request():
    inputs = CASE["grant_request"]["inputs"]
    signed = sign_act_as_grant_request(
        ActAsGrantRequest(
            grantee=GranteeRef(local_rp_descriptor_fingerprint=KEY_MATERIAL.fingerprint),
            scope_set=SignedActAsScopeSet.from_cbor(bytes.fromhex(inputs["scope_set_signed_cbor_hex"])),
            requested_lifetime_seconds=inputs["requested_lifetime_seconds"],
            requested_renewal_window_seconds=inputs["requested_renewal_window_seconds"],
            callback_url=inputs["callback_url"],
            nonce=inputs["nonce"],
            requested_at=inputs["requested_at"],
            expires_at=inputs["expires_at"],
        ),
        KEY_MATERIAL,
    )
    assert signed.request.hex() == CASE["grant_request"]["request_cbor_hex"]
    assert (
        envelope_signature_input(ACT_AS_GRANT_REQUEST_TAG, signed.request).hex()
        == CASE["grant_request"]["signature_input_cbor_hex"]
    )
    assert signed.to_cbor().hex() == CASE["grant_request"]["signed_cbor_hex"]
    assert signed_act_as_grant_request_to_url_param(signed) == CASE["grant_request"]["url_param"]


def test_vector_refresh_request():
    inputs = CASE["refresh_request"]["inputs"]
    signed = sign_act_as_refresh_request(
        ActAsRefreshRequest(
            grant_id=inputs["grant_id"],
            grantee=GranteeRef(local_rp_descriptor_fingerprint=KEY_MATERIAL.fingerprint),
            requested_at=inputs["requested_at"],
            expires_at=inputs["expires_at"],
            nonce=inputs["nonce"],
        ),
        KEY_MATERIAL,
    )
    assert signed.request.hex() == CASE["refresh_request"]["request_cbor_hex"]
    assert signed.to_cbor().hex() == CASE["refresh_request"]["signed_cbor_hex"]


def test_vector_presentation_and_credential():
    inputs = CASE["presentation"]["inputs"]
    grant = SignedActAsGrant.from_cbor(bytes.fromhex(inputs["grant_signed_cbor_hex"]))
    assert act_as_grant_hash(grant.grant).hex() == CASE["presentation"]["grant_hash_hex"]
    result = present_act_as(
        grant,
        ApplicationRef(**inputs["audience"]),
        bytes.fromhex(inputs["request_digest_hex"]),
        _parse_time(inputs["presented_at"]),
        bytes.fromhex(inputs["nonce_hex"]),
        KEY_MATERIAL,
    )
    assert result.credential.presentation.presentation.hex() == CASE["presentation"]["presentation_cbor_hex"]
    assert result.credential_cbor.hex() == CASE["presentation"]["credential_cbor_hex"]


def test_format_act_as_time_drops_fraction():
    t = datetime(2026, 10, 6, 12, 5, 0, 987000, tzinfo=timezone.utc)
    assert format_act_as_time(t) == "2026-10-06T12:05:00Z"


# ---------------------------------------------------------------------
# begin_act_as
# ---------------------------------------------------------------------

IDENTITY_DOMAIN = "ident.example.test"
CALLBACK = "http://app.lan:8080/act-as/callback"
SCOPE_SET_BYTES = bytes.fromhex(CASE["grant_request"]["inputs"]["scope_set_signed_cbor_hex"])


class MapDns:
    def __init__(self, records):
        self.records = records

    def txt_lookup(self, name):
        if name not in self.records:
            raise RuntimeError(f"no fake record for {name}")
        return self.records[name]


def _begin(dns, **overrides):
    fields = dict(
        key_material=KEY_MATERIAL,
        user_domain=f"alice@{IDENTITY_DOMAIN}",
        scope_set=SCOPE_SET_BYTES,
        callback_url=CALLBACK,
        now=_parse_time(CASE["grant_request"]["inputs"]["requested_at"]),
        requested_lifetime_seconds=1800,
        dns=dns,
    )
    fields.update(overrides)
    return begin_act_as(BeginActAsConfig(**fields))


def test_begin_uses_discovered_host_and_signs_verifiable_request():
    redirect, pending = _begin(MapDns({f"_linkkeys_apis.{IDENTITY_DOMAIN}": ["v=lk1 https=login.example.test/linkkeys"]}))
    parts = urlsplit(redirect.redirect_url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://login.example.test/linkkeys/auth/act-as"
    query = parse_qs(parts.query)
    assert list(query) == ["signed_request"]
    assert pending.user_domain == IDENTITY_DOMAIN
    assert pending.callback_url == CALLBACK
    assert len(pending.nonce) == 43

    param = query["signed_request"][0]
    signed = SignedActAsGrantRequest.from_cbor(base64.urlsafe_b64decode(param + "=" * (-len(param) % 4)))
    request = ActAsGrantRequest.from_cbor(signed.request)
    inputs = CASE["grant_request"]["inputs"]
    assert request.nonce == pending.nonce
    assert request.grantee.local_rp_descriptor_fingerprint == KEY_MATERIAL.fingerprint
    assert request.grantee.application is None
    assert request.requested_at == inputs["requested_at"]
    assert request.expires_at == inputs["expires_at"]
    assert request.requested_lifetime_seconds == 1800
    assert request.requested_renewal_window_seconds is None
    assert request.callback_url == CALLBACK
    assert request.scope_set.to_cbor() == SCOPE_SET_BYTES
    assert signed.proof.signature.signed_by_key_id == KEY_MATERIAL.fingerprint
    assert signed.proof.local_rp_descriptor.to_cbor().hex() == GRANTEE["signed_descriptor_cbor_hex"]
    crypto.verify_with_algorithm(
        crypto.SigningAlgorithm.ED25519,
        envelope_signature_input(ACT_AS_GRANT_REQUEST_TAG, signed.request),
        signed.proof.signature.signature,
        _descriptor_public_key(),
    )


def test_begin_falls_back_to_identity_domain():
    redirect, _ = _begin(MapDns({}))
    assert redirect.redirect_url.startswith(f"https://{IDENTITY_DOMAIN}/auth/act-as?signed_request=")


def test_begin_makes_fresh_nonce():
    _, a = _begin(MapDns({}))
    _, b = _begin(MapDns({}))
    assert a.nonce != b.nonce


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_window_seconds": 901},
        {"request_window_seconds": 0},
        {"callback_url": "javascript:alert(1)"},
        {"user_domain": "not a domain"},
        {"requested_renewal_window_seconds": -1},
        {"requested_lifetime_seconds": 0},
    ],
)
def test_begin_rejects_bad_input(overrides):
    with pytest.raises(ActAsError):
        _begin(MapDns({}), **overrides)


def test_begin_rejects_undecodable_scope_set():
    with pytest.raises(DecodeFailed):
        _begin(MapDns({}), scope_set=b"\xff")


# ---------------------------------------------------------------------
# complete_act_as_callback
# ---------------------------------------------------------------------


def test_callback_returns_grant_id_on_nonce_match():
    _, pending = _begin(MapDns({}))
    arrived = f"{CALLBACK}?act_as_grant_id=grant-42&nonce={pending.nonce}"
    assert complete_act_as_callback(pending, arrived) == "grant-42"
    assert complete_act_as_callback(pending, "?" + urlsplit(arrived).query) == "grant-42"
    assert complete_act_as_callback(pending, {"act_as_grant_id": "grant-42", "nonce": pending.nonce}) == "grant-42"


def test_callback_rejects_nonce_mismatch_and_missing_parameters():
    _, pending = _begin(MapDns({}))
    wrong = pending.nonce[:-1] + ("B" if pending.nonce.endswith("A") else "A")
    with pytest.raises(NonceMismatch):
        complete_act_as_callback(pending, f"{CALLBACK}?act_as_grant_id=grant-42&nonce={wrong}")
    with pytest.raises(NonceMismatch):
        complete_act_as_callback(pending, f"{CALLBACK}?act_as_grant_id=grant-42&nonce=short")
    with pytest.raises(ActAsError):
        complete_act_as_callback(pending, f"{CALLBACK}?nonce={pending.nonce}")
    with pytest.raises(ActAsError):
        complete_act_as_callback(pending, f"{CALLBACK}?act_as_grant_id=grant-42")
    # A repeated parameter is refused, even when one value is correct.
    with pytest.raises(ActAsError):
        complete_act_as_callback(
            pending, f"{CALLBACK}?act_as_grant_id=evil&act_as_grant_id=grant-42&nonce={pending.nonce}"
        )
    with pytest.raises(ActAsError):
        complete_act_as_callback(pending, f"{CALLBACK}?act_as_grant_id=grant-42&nonce={pending.nonce}&nonce=x")
    with pytest.raises(ActAsError):
        complete_act_as_callback(pending, {"act_as_grant_id": ["evil", "grant-42"], "nonce": pending.nonce})
