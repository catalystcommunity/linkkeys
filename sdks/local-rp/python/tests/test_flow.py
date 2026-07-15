"""Flow tests: `complete_local_login`'s full verification chain, end to end,
against a real (but locally spun up, fake-identity) LinkKeys IDP -- DNS-pinned
TLS, CSIL-RPC framing, and all. Only two things are faked: the DNS TXT
answers (`FakeDnsResolver`, so no real network/DNS is touched) and the IDP's
identity itself (a throwaway domain signing key generated for this test, not
a real LinkKeys deployment). Mirrors
`sdks/local-rp/rust/tests/flow.rs` (happy path + one test per
verification-chain failure).

Canned callback/ticket-redemption/domain-keys responses are built with
`linkkeys_local_rp.local_rp`/`.claims` directly (the same pure protocol
layer `complete_local_login` itself calls), using the same fixed,
publicly-known test key seeds as `sdks/local-rp/conformance/keys.json`
(`local_rp.signing` = 0x01 repeated, `local_rp.encryption` = 0x02 repeated,
`domain_signing_key` = 0x03 repeated) so this test suite and the
conformance vectors describe the same identities.
"""

from __future__ import annotations

import datetime
import os
import socket
import ssl
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Callable, List, Optional

import pytest

from linkkeys_local_rp import claims as claims_mod
from linkkeys_local_rp import local_rp
from linkkeys_local_rp.begin import BeginLocalLoginConfig, begin_local_login
from linkkeys_local_rp.complete import IdentityMismatch, RequiredClaimsNotSatisfied, complete_local_login
from linkkeys_local_rp.crypto import AeadSuite, SigningAlgorithm
from linkkeys_local_rp.encoding import local_rp_encrypted_callback_to_url_param
from linkkeys_local_rp.generated.codec import CborTag, cbor_decode, cbor_encode
from linkkeys_local_rp.generated.types import (
    Claim,
    ClaimSignature,
    DomainPublicKey,
    GetDomainKeysResponse,
    GetRevocationsResponse,
    LocalRpCallbackPayload,
    LocalRpTicketRedemptionResponse,
    RevocationCertificate,
)
from linkkeys_local_rp.identity import LocalRpKeyMaterial
from linkkeys_local_rp.rpc import RpcError
from linkkeys_local_rp.transport import StdTransport


class DropConnection(Exception):
    """Test-only signal a hostile-IDP `dispatch` callable can raise to make
    `spawn_fake_idp`'s server thread close the connection without sending
    any response at all -- simulating a dropped/errored RPC call at the
    transport level (as opposed to `_encode_error_response`, which simulates
    a well-formed CSIL-RPC error reply)."""

# Same fixed seeds as sdks/local-rp/conformance/keys.json.
LOCAL_RP_SIGNING_SEED = bytes([1] * 32)
LOCAL_RP_ENCRYPTION_PRIVATE = bytes([2] * 32)
DOMAIN_SIGNING_SEED = bytes([3] * 32)
DOMAIN_KEY_ID = "test-domain-key-1"
USER_DOMAIN = "example.test"
CALLBACK_URL = "http://localhost/callback"


# ---------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------


class FakeDnsResolver:
    """Canned DNS answers for exactly one domain."""

    def __init__(self, linkkeys_txt: str, apis_txt: str):
        self.linkkeys_txt = linkkeys_txt
        self.apis_txt = apis_txt

    def txt_lookup(self, name: str) -> List[str]:
        if name == f"_linkkeys.{USER_DOMAIN}":
            return [self.linkkeys_txt]
        if name == f"_linkkeys_apis.{USER_DOMAIN}":
            return [self.apis_txt]
        raise RuntimeError(f"no fake record for {name}")


def _generate_domain_tls_cert(domain_name: str, ed25519_seed: bytes):
    """Self-signed Ed25519 TLS cert derived from a domain signing key --
    test-support only, mirroring what a real LinkKeys IDP's TLS listener
    does (`crates/linkkeys-rpc-client/src/tls.rs::generate_domain_tls_cert`).
    Returns (cert_pem, key_pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    from cryptography.x509.oid import NameOID

    key = Ed25519PrivateKey.from_private_bytes(ed25519_seed)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain_name)]), critical=False)
        .sign(key, None)
    )
    cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return cert_pem, key_pem


def _decode_request_envelope(data: bytes):
    value = cbor_decode(data)
    payload_tag = value["payload"]
    payload = payload_tag.value if isinstance(payload_tag, CborTag) else b""
    return value["service"], value["op"], payload


def _encode_ok_response(payload: bytes) -> bytes:
    return cbor_encode({"v": 1, "status": 0, "payload": CborTag(24, payload)})


def _encode_error_response(status: int, message: str) -> bytes:
    return cbor_encode({"v": 1, "status": status, "error": message, "payload": CborTag(24, b"")})


def spawn_fake_idp(domain_seed: bytes, expected_requests: int, dispatch: Callable[[str, str, bytes], bytes]):
    """Spawns a background thread that accepts up to `expected_requests` TLS
    connections on a fresh loopback port, presenting a certificate derived
    from `domain_seed` (so its SPKI fingerprint is whatever the test's DNS
    answer pins to), and answers each with `dispatch(service, op, payload)`.
    Returns `(host, port)`. The thread is not joined by the caller in the
    "bad pin" scenario (the client never sends a request after a failed
    pin check), so this loop tolerates a connection that closes without
    sending any bytes."""
    cert_pem, key_pem = _generate_domain_tls_cert(USER_DOMAIN, domain_seed)
    certfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    keyfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    try:
        certfile.write(cert_pem)
        certfile.close()
        keyfile.write(key_pem)
        keyfile.close()

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(certfile.name, keyfile.name)
    finally:
        os.unlink(certfile.name)
        os.unlink(keyfile.name)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(expected_requests + 1)
    listener.settimeout(10)
    host, port = listener.getsockname()

    def serve():
        for _ in range(expected_requests):
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            try:
                tls = server_ctx.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                continue
            try:
                len_bytes = tls.recv(4)
                if len(len_bytes) < 4:
                    continue
                length = int.from_bytes(len_bytes, "big")
                buf = b""
                while len(buf) < length:
                    chunk = tls.recv(length - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                if len(buf) != length:
                    continue
                service, op, payload = _decode_request_envelope(buf)
                try:
                    resp = dispatch(service, op, payload)
                except DropConnection:
                    continue
                tls.sendall(len(resp).to_bytes(4, "big"))
                tls.sendall(resp)
            except (ssl.SSLError, OSError):
                continue
            finally:
                tls.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return f"{host}:{port}"


# ---------------------------------------------------------------------
# Scenario construction
# ---------------------------------------------------------------------


def _fixed_key_material(now: datetime.datetime) -> LocalRpKeyMaterial:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    signing_key = Ed25519PrivateKey.from_private_bytes(LOCAL_RP_SIGNING_SEED)
    signing_public_key = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    from linkkeys_local_rp.crypto import x25519_public_from_private

    encryption_public_key = x25519_public_from_private(LOCAL_RP_ENCRYPTION_PRIVATE)

    created_at = (now - datetime.timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expires_at = (now + datetime.timedelta(days=3650)).isoformat().replace("+00:00", "Z")
    descriptor = local_rp.build_local_rp_descriptor(
        "Flow Test App",
        None,
        signing_public_key,
        encryption_public_key,
        ["aes-256-gcm", "chacha20-poly1305"],
        created_at,
        expires_at,
    )
    fingerprint = descriptor.fingerprint
    signed_descriptor = local_rp.sign_local_rp_descriptor(descriptor, LOCAL_RP_SIGNING_SEED)

    return LocalRpKeyMaterial(
        signing_private_key=LOCAL_RP_SIGNING_SEED,
        signing_public_key=signing_public_key,
        encryption_private_key=LOCAL_RP_ENCRYPTION_PRIVATE,
        encryption_public_key=encryption_public_key,
        descriptor=signed_descriptor,
        fingerprint=fingerprint,
    )


def _domain_public_key(now: datetime.datetime) -> DomainPublicKey:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from linkkeys_local_rp import crypto

    sk = Ed25519PrivateKey.from_private_bytes(DOMAIN_SIGNING_SEED)
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return DomainPublicKey(
        key_id=DOMAIN_KEY_ID,
        public_key=pk,
        fingerprint=crypto.fingerprint(pk),
        algorithm="ed25519",
        key_usage="sign",
        signed_by_key_id=None,
        key_signature=None,
        created_at=(now - datetime.timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        expires_at=(now + datetime.timedelta(days=365)).isoformat().replace("+00:00", "Z"),
        revoked_at=None,
    )


@dataclass
class Scenario:
    mutate_payload: Callable[[LocalRpCallbackPayload], None] = field(default=lambda p: None)
    mutate_domain_key: Callable[[DomainPublicKey], None] = field(default=lambda k: None)
    mutate_claim: Callable[[Claim], None] = field(default=lambda c: None)
    # Applied to the LocalRpTicketRedemptionResponse the fake IDP will
    # return from LocalRp/redeem-claim-ticket, after it's built but before
    # the fake IDP starts serving -- lets a hostile-IDP test claim a
    # different user_id/user_domain, or empty out the claim list, without
    # otherwise disturbing the signed callback payload it must be
    # cross-checked against.
    mutate_redemption: Callable[[LocalRpTicketRedemptionResponse], None] = field(default=lambda r: None)
    dns_fingerprint_override: Optional[str] = None
    # Additional signing keys the fake IDP serves (and the DNS answer pins)
    # alongside the callback-signing key -- e.g. revocation siblings.
    extra_domain_keys: List[DomainPublicKey] = field(default_factory=list)
    # Served from DomainKeys/get-revocations on every scenario now (FIX B:
    # the client fetches revocations unconditionally, not gated on
    # recent_revocations_available).
    revocation_certs: List[RevocationCertificate] = field(default_factory=list)
    # "ok" (default): answer get-revocations normally. "error": answer with
    # a well-formed CSIL-RPC error reply. "drop": close the connection
    # without responding at all. Both non-"ok" values must make
    # `fetch_domain_keys` fail closed (FIX B).
    revocations_behavior: str = "ok"
    # Overrides begin_local_login's required_claims (defaults to
    # DEFAULT_REQUIRED_CLAIMS, i.e. ["handle"]) so tests can exercise
    # required-claims enforcement independently of the default claim set.
    required_claims: Optional[List[str]] = None
    # Overrides the user_id the "handle" claim is SIGNED for (default
    # "user-1", matching the callback payload's user_id). Setting this to a
    # different value produces a claim with a cryptographically VALID
    # signature that nonetheless names the wrong subject -- i.e. it isolates
    # the claim.user_id == payload.user_id cross-check from claim signature
    # verification, which a mismatch introduced by tampering post-signing
    # would not do (that would just fail signature verification instead).
    claim_user_id: Optional[str] = None
    expected_requests: int = 3


def run_scenario(scenario: Scenario):
    now = datetime.datetime.now(datetime.timezone.utc)
    key_material = _fixed_key_material(now)

    _redirect, pending = begin_local_login(
        BeginLocalLoginConfig(
            key_material=key_material,
            callback_url=CALLBACK_URL,
            user_domain=USER_DOMAIN,
            now=now,
            required_claims=scenario.required_claims,
        )
    )

    domain_key = _domain_public_key(now)
    scenario.mutate_domain_key(domain_key)

    claim_ticket = bytes([7] * 32)
    payload = local_rp.build_local_rp_callback_payload(
        "user-1",
        USER_DOMAIN,
        claim_ticket,
        key_material.fingerprint,
        CALLBACK_URL,
        pending.nonce,
        pending.state,
        now.isoformat().replace("+00:00", "Z"),
        (now + datetime.timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
    )
    scenario.mutate_payload(payload)

    signed_payload = local_rp.sign_local_rp_callback_payload(
        payload, DOMAIN_KEY_ID, SigningAlgorithm.ED25519, DOMAIN_SIGNING_SEED
    )

    encrypted = local_rp.seal_local_rp_callback(
        signed_payload,
        AeadSuite.AES_256_GCM,
        key_material.encryption_public_key,
        payload.audience_fingerprint,
        payload.nonce,
        payload.state,
        payload.issued_at,
        payload.expires_at,
    )
    encrypted_token = local_rp_encrypted_callback_to_url_param(encrypted)
    arrived_url = f"{CALLBACK_URL}?encrypted_token={encrypted_token}"

    claim = claims_mod.sign_claim(
        claims_mod.ClaimSpec(
            claim_id="claim-1",
            claim_type="handle",
            claim_value=b"flowtestuser",
            user_id=scenario.claim_user_id or "user-1",
            subject_domain=USER_DOMAIN,
            attested_at=now.isoformat().replace("+00:00", "Z"),
        ),
        [
            claims_mod.ClaimSigner(
                domain=USER_DOMAIN,
                key_id=DOMAIN_KEY_ID,
                algorithm=SigningAlgorithm.ED25519,
                private_key_bytes=DOMAIN_SIGNING_SEED,
            )
        ],
    )
    scenario.mutate_claim(claim)

    ticket_expires_at = (now + datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    redemption_response = LocalRpTicketRedemptionResponse(
        user_id="user-1", user_domain=USER_DOMAIN, claims=[claim], ticket_expires_at=ticket_expires_at
    )
    scenario.mutate_redemption(redemption_response)

    served_keys = [domain_key] + scenario.extra_domain_keys
    revocations_available = True if scenario.revocation_certs else None

    def dispatch(service: str, op: str, _payload: bytes) -> bytes:
        if (service, op) == ("DomainKeys", "get-domain-keys"):
            resp = GetDomainKeysResponse(
                domain=USER_DOMAIN, keys=served_keys, recent_revocations_available=revocations_available
            )
            return _encode_ok_response(resp.to_cbor())
        if (service, op) == ("DomainKeys", "get-revocations"):
            if scenario.revocations_behavior == "error":
                return _encode_error_response(2, "fake IDP simulated a get-revocations failure")
            if scenario.revocations_behavior == "drop":
                raise DropConnection()
            resp = GetRevocationsResponse(revocations=scenario.revocation_certs)
            return _encode_ok_response(resp.to_cbor())
        if (service, op) == ("LocalRp", "redeem-claim-ticket"):
            return _encode_ok_response(redemption_response.to_cbor())
        return _encode_error_response(2, f"fake IDP has no handler for {service}/{op}")

    tcp_addr = spawn_fake_idp(DOMAIN_SIGNING_SEED, scenario.expected_requests, dispatch)

    from linkkeys_local_rp import crypto

    real_fingerprint = crypto.fingerprint(domain_key.public_key)
    pinned_fingerprint = scenario.dns_fingerprint_override or real_fingerprint
    pinned = [pinned_fingerprint] + [crypto.fingerprint(k.public_key) for k in scenario.extra_domain_keys]
    dns = FakeDnsResolver(
        linkkeys_txt="v=lk1 " + " ".join(f"fp={fp}" for fp in pinned),
        apis_txt=f"v=lk1 tcp={tcp_addr}",
    )
    transport = StdTransport()

    return complete_local_login(key_material, pending, encrypted_token, arrived_url, now, transport=transport, dns=dns)


# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------


def test_happy_path_returns_verified_login():
    verified = run_scenario(Scenario())
    assert verified.user_id == "user-1"
    assert verified.user_domain == USER_DOMAIN
    assert len(verified.claims) == 1
    assert verified.claims[0].claim_type == "handle"
    assert len(verified.local_rp_fingerprint) == 64
    assert len(verified.domain_public_keys) == 1


def test_wrong_audience_fingerprint_is_rejected():
    def mutate(p: LocalRpCallbackPayload) -> None:
        p.audience_fingerprint = "b" * 64

    # get-domain-keys + get-revocations both happen (FIX B: unconditional)
    # before envelope verification -- which is where this fails -- ever
    # runs, so ticket redemption is never attempted.
    with pytest.raises(local_rp.LocalRpError):
        run_scenario(Scenario(mutate_payload=mutate, expected_requests=2))


def test_wrong_issuer_domain_is_rejected():
    def mutate(p: LocalRpCallbackPayload) -> None:
        p.user_domain = "attacker.test"

    with pytest.raises(local_rp.LocalRpError):
        run_scenario(Scenario(mutate_payload=mutate, expected_requests=2))


def test_nonce_mismatch_is_rejected():
    def mutate(p: LocalRpCallbackPayload) -> None:
        p.nonce = bytes([0xEE] * 32)

    with pytest.raises(local_rp.LocalRpError):
        run_scenario(Scenario(mutate_payload=mutate, expected_requests=2))


def test_expired_callback_payload_is_rejected():
    def mutate(p: LocalRpCallbackPayload) -> None:
        n = datetime.datetime.now(datetime.timezone.utc)
        p.issued_at = (n - datetime.timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        p.expires_at = (n - datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z")

    with pytest.raises(local_rp.LocalRpError):
        run_scenario(Scenario(mutate_payload=mutate, expected_requests=2))


def test_dns_fingerprint_pin_mismatch_is_rejected():
    # Fails during the TLS pin check (the fake IDP's real cert fingerprint
    # no longer matches the pinned set) or, if it somehow got past that,
    # during key trust establishment -- either way it must never reach a
    # verified result.
    with pytest.raises(Exception):
        run_scenario(Scenario(dns_fingerprint_override="c" * 64, expected_requests=1))


def test_revoked_signing_key_is_rejected():
    def mutate(k: DomainPublicKey) -> None:
        k.revoked_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    with pytest.raises(local_rp.LocalRpError):
        run_scenario(Scenario(mutate_domain_key=mutate, expected_requests=2))


def test_tampered_claim_signature_is_rejected():
    def mutate(c: Claim) -> None:
        if c.signatures:
            sig = bytearray(c.signatures[0].signature)
            sig[0] ^= 0xFF
            c.signatures[0].signature = bytes(sig)

    with pytest.raises(claims_mod.ClaimError):
        run_scenario(Scenario(mutate_claim=mutate))


def _sibling_key(seed: bytes, key_id: str, now: datetime.datetime) -> DomainPublicKey:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from linkkeys_local_rp import crypto

    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return DomainPublicKey(
        key_id=key_id,
        public_key=pk,
        fingerprint=crypto.fingerprint(pk),
        algorithm="ed25519",
        key_usage="sign",
        signed_by_key_id=None,
        key_signature=None,
        created_at=(now - datetime.timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        expires_at=(now + datetime.timedelta(days=365)).isoformat().replace("+00:00", "Z"),
        revoked_at=None,
    )


def test_certificate_revoked_signing_key_fails_completion():
    """The fetched key entry for the callback-signing key carries NO
    revoked_at of its own -- only the sibling-signed revocation certificate
    (fetched via DomainKeys/get-revocations and APPLIED to the trusted set)
    reveals it is dead. An SDK that skips the fetch, or verifies the
    certificate without applying it, would incorrectly complete this
    login."""
    from linkkeys_local_rp import crypto
    from linkkeys_local_rp.revocation import revocation_payload

    now = datetime.datetime.now(datetime.timezone.utc)
    sibling_seeds = [bytes([0x0E] * 32), bytes([0x0F] * 32)]
    siblings = [_sibling_key(seed, f"sibling-key-{i+1}", now) for i, seed in enumerate(sibling_seeds)]

    # Build a quorum certificate targeting the callback-signing key, signed
    # by both siblings over the five-element revocation tuple.
    target = _domain_public_key(now)
    revoked_at = now.isoformat().replace("+00:00", "Z")
    signatures = []
    for seed, key in zip(sibling_seeds, siblings):
        payload = revocation_payload(target.key_id, target.fingerprint, revoked_at, USER_DOMAIN)
        sig = crypto.sign_with_algorithm(SigningAlgorithm.ED25519, payload, seed)
        signatures.append(ClaimSignature(domain=USER_DOMAIN, signed_by_key_id=key.key_id, signature=sig))
    cert = RevocationCertificate(
        target_key_id=target.key_id,
        target_fingerprint=target.fingerprint,
        revoked_at=revoked_at,
        signatures=signatures,
    )

    scenario = Scenario(
        extra_domain_keys=siblings,
        revocation_certs=[cert],
        # get-domain-keys + get-revocations, then envelope verification
        # fails (the callback-signing key has been dropped from the trusted
        # set) before ticket redemption is ever attempted.
        expected_requests=2,
    )
    with pytest.raises(local_rp.LocalRpError):
        run_scenario(scenario)


# ---------------------------------------------------------------------
# Hostile-IDP tests (security review: FIX A/B) -- a fake IDP that has
# already passed every prior check (valid domain keys, valid envelope
# signature, valid claim signatures) but then lies at exactly one more
# point in the flow. Each of these must fail closed.
# ---------------------------------------------------------------------


def test_redemption_identity_mismatch_is_rejected():
    """(1) The ticket-redemption response claims a different user than the
    signed callback payload named. A malicious/compromised IDP -- or a
    compromise of only the unauthenticated ticket-redemption RPC leg --
    must not be able to swap the completed identity this way."""

    def mutate(r: LocalRpTicketRedemptionResponse) -> None:
        r.user_id = "attacker-user"

    with pytest.raises(IdentityMismatch):
        run_scenario(Scenario(mutate_redemption=mutate))


def test_redemption_domain_mismatch_is_rejected():
    """(1, domain variant) Same as above but for user_domain instead of
    user_id."""

    def mutate(r: LocalRpTicketRedemptionResponse) -> None:
        r.user_domain = "attacker.test"

    with pytest.raises(IdentityMismatch):
        run_scenario(Scenario(mutate_redemption=mutate))


def test_claim_user_id_mismatch_is_rejected():
    """(2) A claim with a cryptographically VALID signature (it was signed
    for a different user_id from the start, not tampered with after
    signing) that nonetheless doesn't match the signed callback payload's
    user_id. Signature validity alone is not sufficient -- the subject
    binding must also match, or a claim about one user could be replayed as
    if it were another user's claim on the same domain."""
    with pytest.raises(IdentityMismatch):
        run_scenario(Scenario(claim_user_id="someone-else"))


def test_required_claims_empty_is_rejected():
    """(3) The login demanded a required claim (the default required set is
    ["handle"]), but the IDP's redemption response comes back with no
    claims at all. Must fail closed rather than silently completing an
    under-claimed login."""

    def mutate(r: LocalRpTicketRedemptionResponse) -> None:
        r.claims = []

    with pytest.raises(RequiredClaimsNotSatisfied):
        run_scenario(Scenario(mutate_redemption=mutate))


def test_required_claims_insufficient_is_rejected():
    """(3, insufficient variant) The login required both "handle" and
    "email", but the IDP only ever returns a "handle" claim. A partial
    claim set must not be silently accepted as satisfying the requirement."""
    with pytest.raises(RequiredClaimsNotSatisfied):
        run_scenario(Scenario(required_claims=["handle", "email"]))


def test_get_revocations_error_fails_closed():
    """(4) The domain's get-revocations RPC returns a well-formed CSIL-RPC
    error. Before the fix this was swallowed ("best-effort") and treated as
    an empty revocation list; it must now be fatal -- we would rather abort
    the login than proceed on a key set we couldn't confirm isn't missing a
    revocation."""
    with pytest.raises(RpcError):
        run_scenario(Scenario(revocations_behavior="error", expected_requests=2))


def test_get_revocations_dropped_connection_fails_closed():
    """(4, drop variant) The domain's get-revocations call is dropped at the
    transport level (connection closed with no response) rather than
    answered with an explicit error. Must fail closed identically to an
    explicit error reply."""
    with pytest.raises(RpcError):
        run_scenario(Scenario(revocations_behavior="drop", expected_requests=2))
