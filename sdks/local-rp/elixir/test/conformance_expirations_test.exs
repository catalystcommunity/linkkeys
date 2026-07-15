defmodule LinkkeysLocalRp.ConformanceExpirationsTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Identity
  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Test.Vectors
  alias LinkkeysLocalRp.Timeutil

  @expirations Vectors.load("expirations.json")

  test "check_expirations thresholds via SDK wrapper" do
    section = @expirations["check_expirations"]
    expires_at = section["expires_at"]
    cases = section["cases"]
    assert length(cases) == 11

    # Build an identity whose descriptor expires at exactly `expires_at`,
    # so this exercises check_expirations end to end (identity ->
    # descriptor -> threshold logic) rather than calling the underlying
    # function directly.
    expires_dt = Timeutil.parse_rfc3339(expires_at)
    lifetime_days = 3650
    created_dt = DateTime.add(expires_dt, -lifetime_days * 86_400, :second)

    identity =
      Identity.generate_local_rp_identity(
        app_name: "Conformance Test App",
        now: created_dt,
        lifetime_days: lifetime_days
      )

    for case_ <- cases do
      now = Timeutil.parse_rfc3339(case_["now"])
      status = Identity.check_expirations(identity, now)
      assert Atom.to_string(status.level) == case_["expected_level"], "now=#{inspect(now)}"
    end
  end

  test "check_timestamps skew boundaries are exact" do
    section = @expirations["check_timestamps"]
    issued_at = section["issued_at"]
    expires_at = section["expires_at"]
    skew = section["skew_seconds"]
    cases = section["cases"]
    assert length(cases) == 4

    for case_ <- cases do
      now = Timeutil.parse_rfc3339(case_["now"])
      expected_valid = case_["expected_valid"]
      valid = match?(:ok, LocalRp.check_timestamps(issued_at, expires_at, now, skew))
      assert valid == expected_valid, "now=#{inspect(now)}"
    end
  end
end
