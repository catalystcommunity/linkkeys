"""expirations.json: `check_expirations` threshold boundaries (exact, both
sides of each boundary) and `check_timestamps`'s bounded clock-skew
boundaries."""

from datetime import datetime, timezone

from linkkeys_local_rp import GenerateLocalRpIdentityConfig, check_expirations, generate_local_rp_identity
from linkkeys_local_rp.local_rp import check_timestamps


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def test_check_expirations_thresholds_via_sdk_wrapper(expirations):
    section = expirations["check_expirations"]
    expires_at = section["expires_at"]
    cases = section["cases"]
    assert len(cases) == 11

    # Build an identity whose descriptor expires at exactly `expires_at`, so
    # this exercises `check_expirations` end to end (identity -> descriptor
    # -> threshold logic) rather than calling the underlying function
    # directly.
    expires_dt = _parse(expires_at)
    created_dt = expires_dt.replace(year=expires_dt.year - 10)
    identity = generate_local_rp_identity(
        GenerateLocalRpIdentityConfig(
            app_name="Conformance Test App",
            now=created_dt,
            lifetime=expires_dt - created_dt,
        )
    )

    for case in cases:
        now = _parse(case["now"])
        status = check_expirations(identity, now)
        assert status.level.as_str() == case["expected_level"], f"now={now}"


def test_check_timestamps_skew_boundaries_are_exact(expirations):
    section = expirations["check_timestamps"]
    issued_at = section["issued_at"]
    expires_at = section["expires_at"]
    skew = section["skew_seconds"]
    cases = section["cases"]
    assert len(cases) == 4

    for case in cases:
        now = _parse(case["now"])
        expected_valid = case["expected_valid"]
        try:
            check_timestamps(issued_at, expires_at, now, skew)
            valid = True
        except Exception:
            valid = False
        assert valid == expected_valid, f"now={now}"
