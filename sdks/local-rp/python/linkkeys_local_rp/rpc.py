"""CSIL-RPC over the injected `Transport`, TLS-pinned to a domain's DNS
`fp=` records — this SDK's only network surface (design doc, "Required
Network Access"): domain public keys, revocations, and claim-ticket
redemption, all unauthenticated-TLS TCP CSIL-RPC calls pinned the same way
`crates/linkkeys/src/tcp/tls.rs` pins the S2S path.

Why this module hand-builds the CSIL-RPC envelope instead of driving it
through `generated/client.py`'s `DomainKeysClient`/`LocalRpClient` wrapper
classes: when this SDK was written, those wrappers passed a lowercased
service name to their `Transport.call()` seam, unusable for the real wire
(a csilgen defect since fixed — the regenerated client now passes verbatim
CSIL names, `service="DomainKeys"`, `op="get-domain-keys"`). This SDK only
ever calls two operations, so the direct `CsilRpcRequest` construction —
which reuses `generated/codec.py`'s `to_cbor()`/`from_cbor()` for the typed
payloads and mirrors the Rust reference SDK's `rpc.rs` — remains in place;
switching to the generated wrappers is now possible but purely optional.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List

from . import claims as claims_mod
from . import dns as dns_mod
from . import revocation as revocation_mod
from . import tls as tls_mod
from .generated import codec as _codec  # noqa: F401  (side effect: attaches to_cbor/from_cbor)
from .generated.codec import CborTag, cbor_decode, cbor_encode
from .generated.types import (
    DomainPublicKey,
    EmptyRequest,
    GetDomainKeysResponse,
    GetRevocationsRequest,
    GetRevocationsResponse,
    LocalRpTicketRedemptionResponse,
    SignedLocalRpTicketRedemptionRequest,
)
from .transport import Transport

# Mirrors the server's own cap (`crates/linkkeys-rpc-client/src/lib.rs`) so a
# malicious/compromised peer cannot drive this client to an unbounded
# allocation via a forged length prefix.
MAX_FRAME_SIZE = 1024 * 1024

_CSIL_RPC_VERSION = 1
_TAG_ENCODED_CBOR = 24


class RpcError(Exception):
    pass


class ProtocolError(RpcError):
    pass


class ServerError(RpcError):
    def __init__(self, status: int, message: str):
        super().__init__(f"server error ({status}): {message}")
        self.status = status
        self.message = message


class NoTrustedDomainKeys(RpcError):
    def __init__(self, domain: str):
        super().__init__(f"no trusted public keys could be established for domain: {domain}")
        self.domain = domain


def _recv_exact(sock, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("connection closed before expected bytes were received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_frame(sock, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(4, "big"))
    sock.sendall(data)


def _recv_frame(sock) -> bytes:
    length = int.from_bytes(_recv_exact(sock, 4), "big")
    if length > MAX_FRAME_SIZE:
        raise ProtocolError(f"peer frame too large ({length} bytes, max {MAX_FRAME_SIZE})")
    return _recv_exact(sock, length)


def _encode_request(service: str, op: str, payload: bytes) -> bytes:
    envelope = {
        "v": _CSIL_RPC_VERSION,
        "service": service,
        "op": op,
        "payload": CborTag(_TAG_ENCODED_CBOR, payload),
    }
    return cbor_encode(envelope)


def _decode_response(data: bytes) -> tuple:
    """Returns (status: int, error: Optional[str], payload: bytes)."""
    value = cbor_decode(data)
    if not isinstance(value, dict):
        raise ProtocolError("RPC response envelope is not a CBOR map")
    status = value.get("status")
    if not isinstance(status, int):
        raise ProtocolError("RPC response missing integer 'status'")
    error = value.get("error")
    payload_tag = value.get("payload")
    if isinstance(payload_tag, CborTag) and payload_tag.tag == _TAG_ENCODED_CBOR:
        payload = payload_tag.value
    else:
        payload = b""
    return status, error, payload


@dataclass
class DomainEndpoint:
    fingerprints: List[str]
    tcp_addr: str


def discover_domain_endpoint(dns: dns_mod.DnsResolver, domain: str) -> DomainEndpoint:
    """Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails
    closed: a missing/unparseable record, or a `_linkkeys` record with no
    `fp=` entries, or a `_linkkeys_apis` record with no `tcp=` entry, is an
    error — this SDK never proceeds without a fingerprint set to pin to."""
    anchor_name = dns_mod.linkkeys_dns_name(domain)
    anchor_txts = dns.txt_lookup(anchor_name)
    fingerprints: List[str] = []
    for txt in anchor_txts:
        try:
            record = dns_mod.parse_linkkeys_txt(txt)
        except dns_mod.DnsParseError:
            continue
        if record.fingerprints:
            fingerprints = record.fingerprints
            break
    if not fingerprints:
        raise dns_mod.DnsParseError(f"no usable {anchor_name} TXT record with fp= entries")

    apis_name = dns_mod.linkkeys_apis_dns_name(domain)
    apis_txts = dns.txt_lookup(apis_name)
    tcp_addr = None
    for txt in apis_txts:
        try:
            apis = dns_mod.parse_linkkeys_apis_txt(txt)
        except dns_mod.DnsParseError:
            continue
        if apis.tcp:
            tcp_addr = apis.tcp
            break
    if not tcp_addr:
        raise dns_mod.DnsParseError(f"no usable {apis_name} TXT record with tcp= entry")

    return DomainEndpoint(fingerprints=fingerprints, tcp_addr=tcp_addr)


def _call(transport: Transport, endpoint: DomainEndpoint, service: str, op: str, payload: bytes) -> bytes:
    """Open a fresh TLS connection to `endpoint`, pinned to its
    fingerprints, send one CSIL-RPC request, and return the decoded success
    payload."""
    raw_sock = transport.dial(endpoint.tcp_addr)
    hostname = tls_mod.extract_hostname(endpoint.tcp_addr)
    tls_sock = tls_mod.dial_tls_pinned(raw_sock, hostname, endpoint.fingerprints)
    try:
        request_bytes = _encode_request(service, op, payload)
        _send_frame(tls_sock, request_bytes)
        response_bytes = _recv_frame(tls_sock)
        status, error, resp_payload = _decode_response(response_bytes)
        if status != 0:
            raise ServerError(status, error or "unknown error")
        return resp_payload
    finally:
        tls_sock.close()


def fetch_domain_keys(transport: Transport, dns: dns_mod.DnsResolver, domain: str) -> List[DomainPublicKey]:
    """Fetch `domain`'s currently-trusted public keys:
    `DomainKeys/get-domain-keys` over TCP CSIL-RPC, pinned to the domain's
    DNS `fp=` set, with signing keys pinned directly and encryption keys
    trusted only via a pinned signing key's vouch. `DomainKeys/get-revocations`
    is ALWAYS fetched afterward too — regardless of the response's
    `recent_revocations_available` hint, which is server-asserted and not
    itself authenticated, so a compromised/lying IDP could otherwise set it
    to false to hide a sibling-signed revocation certificate for one of its
    own keys. A failed/errored/dropped `get-revocations` call is fatal (fail
    closed): we would rather abort the login than silently proceed on a key
    set that might include a key the domain's own siblings have revoked. Any
    certificate that DOES arrive and quorum-verify is applied: its target
    key is dropped from the trusted set no matter what the fetched key entry
    itself says (its own `revoked_at` may well be unset — that is the whole
    point of the sibling-certificate channel; see
    `revocation.apply_revocations`). An empty trusted result — whether from
    the start or after revocations are applied — is `NoTrustedDomainKeys`,
    fail closed."""
    endpoint = discover_domain_endpoint(dns, domain)

    payload = EmptyRequest().to_cbor()
    resp_bytes = _call(transport, endpoint, "DomainKeys", "get-domain-keys", payload)
    resp = GetDomainKeysResponse.from_cbor(resp_bytes)

    now = datetime.now(timezone.utc)
    trusted = dns_mod.trust_keys(resp.keys, endpoint.fingerprints, now)
    if not trusted:
        raise NoTrustedDomainKeys(domain)

    since = (now - timedelta(days=30)).isoformat().replace("+00:00", "Z")
    req_payload = GetRevocationsRequest(since=since).to_cbor()
    # No try/except here: a get-revocations error/timeout/protocol failure
    # must propagate and abort the login, not be swallowed into "assume no
    # revocations" (see docstring above).
    resp_bytes = _call(transport, endpoint, "DomainKeys", "get-revocations", req_payload)
    revocations = GetRevocationsResponse.from_cbor(resp_bytes).revocations
    trusted = revocation_mod.apply_revocations(trusted, revocations, domain, now)

    if not trusted:
        raise NoTrustedDomainKeys(domain)
    return trusted


def redeem_claim_ticket(
    transport: Transport,
    dns: dns_mod.DnsResolver,
    domain: str,
    signed_request: SignedLocalRpTicketRedemptionRequest,
) -> LocalRpTicketRedemptionResponse:
    """Redeem a claim ticket with `domain`'s IDP:
    `LocalRp/redeem-claim-ticket` over TCP CSIL-RPC, pinned via the domain's
    DNS `fp=` set. Unauthenticated at the transport layer (no client cert)
    — the redemption request itself is signed with the local RP's signing
    key, which is the possession proof the server checks."""
    endpoint = discover_domain_endpoint(dns, domain)
    payload = signed_request.to_cbor()
    resp_bytes = _call(transport, endpoint, "LocalRp", "redeem-claim-ticket", payload)
    # Use claims.py's decode wrapper, not LocalRpTicketRedemptionResponse.from_cbor
    # directly -- it additionally enforces that every embedded Claim's
    # claim_value decoded as CBOR bytes (bstr), never text (tstr). See
    # claims.decode_ticket_redemption_response.
    return claims_mod.decode_ticket_redemption_response(resp_bytes)
