"""The TCP dial seam.

Mirrors `sdks/local-rp/rust/src/transport.rs`. Deliberately narrow: this
seam only *connects a byte stream* to `host:port`. TLS (certificate-pin
verification against DNS `fp=` records) is layered on top in `tls.py`, not
here, so a test double can swap out "how do I open a socket" without also
faking a TLS handshake.

Per the design doc's Wire Precision ("SDK endpoint discovery and pinning"):
the Rust `linkkeys-rpc-client` refuses non-public peer addresses as a
*server-side* SSRF guard. SDKs must not inherit that refusal as a default —
"connecting from a LAN box to wherever `_linkkeys_apis` points is the entire
point of this mode." The default policy here is `AddressPolicy.PERMISSIVE`.
`AddressPolicy.PUBLIC_ONLY` is an opt-in for integrators who specifically
want that stricter posture; nothing in this package selects it
automatically.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class TransportError(Exception):
    pass


class ConnectFailed(TransportError):
    pass


class AddressDenied(TransportError):
    pass


class AddressPolicy(str, Enum):
    """Which destination addresses `StdTransport` is willing to dial.
    Default is `PERMISSIVE` — see module docs for why."""

    PERMISSIVE = "permissive"
    PUBLIC_ONLY = "public_only"


def _is_non_public(ip_str: str) -> bool:
    """True for loopback/private/link-local/CGNAT/documentation/unspecified
    addresses. Only consulted under `AddressPolicy.PUBLIC_ONLY`, never by
    default."""
    ip = ipaddress.ip_address(ip_str)
    if isinstance(ip, ipaddress.IPv4Address):
        octets = ip.packed
        cgnat = octets[0] == 100 and (octets[1] & 0xC0) == 0x40
        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_reserved
            or ip_str == "255.255.255.255"
            or cgnat
        )
    # IPv6
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return _is_non_public(str(mapped))
    segments0 = ip.packed[0:2]
    link_local = (segments0[0] == 0xFE) and (segments0[1] & 0xC0) == 0x80
    ula = (segments0[0] & 0xFE) == 0xFC
    return bool(ip.is_loopback or ip.is_unspecified or ip.is_multicast or link_local or ula)


@dataclass
class StdTransport:
    """Default `Transport`: a plain blocking TCP socket, gated only by
    `policy` (permissive unless the caller opts into `AddressPolicy.PUBLIC_ONLY`)."""

    policy: AddressPolicy = AddressPolicy.PERMISSIVE
    connect_timeout: float = 10.0
    io_timeout: float = 30.0

    def dial(self, host_port: str) -> socket.socket:
        host, _, port_str = host_port.rpartition(":")
        if not host:
            raise ConnectFailed(f"{host_port}: missing host")
        try:
            port = int(port_str)
        except ValueError as e:
            raise ConnectFailed(f"{host_port}: invalid port") from e

        last_err: Exception | None = None
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as e:
            raise ConnectFailed(f"{host_port}: resolve failed: {e}") from e

        for family, socktype, proto, _canonname, sockaddr in infos:
            ip_str = sockaddr[0]
            if self.policy == AddressPolicy.PUBLIC_ONLY and _is_non_public(ip_str):
                last_err = AddressDenied(
                    f"{ip_str}: refusing non-public address under AddressPolicy.PUBLIC_ONLY"
                )
                continue
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(self.connect_timeout)
                sock.connect(sockaddr)
                sock.settimeout(self.io_timeout)
                return sock
            except OSError as e:
                last_err = ConnectFailed(f"{host_port}: {e}")
                continue

        if last_err is not None:
            raise last_err
        raise ConnectFailed(f"{host_port}: no address resolved")


class Transport(Protocol):
    """Dials `host_port` and returns a connected, blocking socket-like
    object. Injectable so tests can hand the RPC layer an in-memory pipe
    instead of a real socket."""

    def dial(self, host_port: str) -> socket.socket:
        ...
