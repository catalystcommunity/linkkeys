"""Timestamp helpers shared by every module that checks freshness or signs.

On the wire every timestamp is a CSIL `timestamp` (CBOR tag 0 over RFC 3339
text in UTC); the generated codec reads and writes it as a tz-aware
`datetime`. A signed tuple payload carries whole Unix seconds as a CBOR
integer instead (`signed_time`).

Every "current time" in this SDK is an explicit `datetime` parameter, never
`datetime.now()`/`datetime.utcnow()` read internally — mirroring
`liblinkkeys`'s discipline of taking `now` as an argument so verification
stays deterministic and testable.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def to_utc(dt: datetime) -> datetime:
    """Return `dt` in UTC. A naive `datetime` is read as UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def whole_seconds(dt: datetime) -> datetime:
    """`dt` in UTC without its fraction of a second (rounded down). Use this
    for a time that goes into a signed tuple payload."""
    return to_utc(dt).replace(microsecond=0)


def signed_time(dt: datetime) -> int:
    """The signed-payload form of a timestamp: whole Unix seconds, encoded as
    a CBOR integer (`liblinkkeys::timestamp::SignedTime`). Raises
    `ValueError` when `dt` has a fraction of a second: such a time was never
    signed, so a verifier must fail, not round. A naive `datetime` names no
    instant, so it also raises `ValueError`."""
    if dt.tzinfo is None:
        raise ValueError("a signed timestamp must have a timezone offset")
    utc = dt.astimezone(timezone.utc)
    if utc.microsecond != 0:
        raise ValueError("a signed timestamp must be a whole number of seconds")
    return (utc - _EPOCH) // timedelta(seconds=1)
