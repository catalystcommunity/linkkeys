defmodule LinkkeysLocalRp.BeginTest do
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Begin

  setup do
    now = ~U[2026-01-01 00:00:00Z]
    material = LinkkeysLocalRp.generate_local_rp_identity(app_name: "Test App", now: now)
    %{now: now, material: material}
  end

  test "identity input controls the destination and username hint", %{now: now, material: material} do
    {redirect, pending} =
      Begin.begin_local_login(
        key_material: material,
        callback_url: "http://localhost/callback",
        user_domain: "Alice+work@ID.Example.TEST",
        now: now
      )

    assert String.ends_with?(redirect.redirect_url, "&username=Alice%2Bwork")
    assert pending.user_domain == "id.example.test"

    {bare, _} =
      Begin.begin_local_login(
        key_material: material,
        callback_url: "http://localhost/callback",
        user_domain: "example.test",
        now: now
      )

    refute String.contains?(bare.redirect_url, "username=")
  end

  test "malformed identity input is rejected", %{now: now, material: material} do
    for identity <- ["alice", "alice@@example.test", "https://example.test"] do
      assert_raise Begin.BeginLoginError, fn ->
        Begin.begin_local_login(
          key_material: material,
          callback_url: "http://localhost/callback",
          user_domain: identity,
          now: now
        )
      end
    end
  end
end
