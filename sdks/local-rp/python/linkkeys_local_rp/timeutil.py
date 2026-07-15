"""RFC3339 timestamp parsing shared by every module that checks freshness.

Every "current time" in this SDK is an explicit `datetime` parameter, never
`datetime.now()`/`datetime.utcnow()` read internally — mirroring
`liblinkkeys`'s discipline of taking `now` as an argument so verification
stays deterministic and testable.
"""

from __future__ import annotations

from datetime import datetime, timezone


def parse_rfc3339(s: str) -> datetime:
    """Parse an RFC3339 timestamp into a timezone-aware UTC `datetime`.
    Raises `ValueError` on anything that isn't parseable — callers convert
    that into their own typed error.

    `datetime.fromisoformat` (Python 3.11+) accepts the `Z` UTC designator
    natively; for older 3.x we normalize `Z`/`z` to `+00:00` ourselves so
    behavior is identical across the supported interpreter range.
    """
    text = s.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"timestamp has no timezone offset: {s!r}")
    return dt.astimezone(timezone.utc)


def to_rfc3339(dt: datetime) -> str:
    """Render a `datetime` as RFC3339 UTC with a `Z` suffix, matching
    `chrono::DateTime<Utc>::to_rfc3339()`'s style closely enough for this
    protocol's purposes (exact separators are not wire-normative; only the
    parsed instant is compared)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
