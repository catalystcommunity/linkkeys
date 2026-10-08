defmodule LinkkeysLocalRp.BrowserTest do
  @moduledoc """
  Browser endpoint discovery in `begin_local_login/1` (mirrors
  `sdks/local-rp/go/browser_test.go`). Every resolver here is a hermetic
  fake with canned TXT answers; no test performs a live DNS request.
  """
  use ExUnit.Case, async: true

  alias LinkkeysLocalRp.Begin
  alias LinkkeysLocalRp.Browser
  alias LinkkeysLocalRp.Encoding
  alias LinkkeysLocalRp.Types

  @domain "ident.example.test"
  @callback_url "http://app.lan:8080/cb"

  # A hermetic resolver with canned `_linkkeys_apis.<@domain>` answers.
  defp apis_resolver(txts) do
    fn name ->
      if name == "_linkkeys_apis.#{@domain}", do: {:ok, txts}, else: {:error, {:no_fake_record, name}}
    end
  end

  defp failing_resolver, do: fn _name -> {:error, :servfail} end

  setup do
    now = ~U[2026-08-17 12:00:00Z]
    material = LinkkeysLocalRp.generate_local_rp_identity(app_name: "browser-test", now: now)
    %{now: now, material: material}
  end

  defp begin_with(ctx, dns, user_domain \\ @domain) do
    Begin.begin_local_login(
      key_material: ctx.material,
      callback_url: @callback_url,
      user_domain: user_domain,
      now: ctx.now,
      dns: dns
    )
  end

  # Case 1: a valid https= host is used for the redirect instead of the
  # identity domain. Case 8: PendingLogin.user_domain stays the identity
  # domain — verification stays bound to it, not to the service host.
  test "uses the discovered https host, pending domain stays the identity domain", ctx do
    {redirect, pending} =
      begin_with(ctx, apis_resolver(["v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test"]))

    assert String.starts_with?(
             redirect.redirect_url,
             "https://linkkeys.ident.example.test/auth/local-rp?signed_request="
           )

    refute String.starts_with?(redirect.redirect_url, "https://#{@domain}/")
    assert pending.user_domain == @domain
  end

  # Case 2: an https= value with a path prefix preserves that prefix.
  test "preserves an https= path prefix", ctx do
    {redirect, _} = begin_with(ctx, apis_resolver(["v=lk1 https=login.example.test/linkkeys"]))

    assert String.starts_with?(
             redirect.redirect_url,
             "https://login.example.test/linkkeys/auth/local-rp?signed_request="
           )
  end

  # Case 3: a record with only tcp= falls back to the identity domain.
  test "tcp-only record falls back to the identity domain", ctx do
    {redirect, _} = begin_with(ctx, apis_resolver(["v=lk1 tcp=linkkeys.ident.example.test"]))
    assert String.starts_with?(redirect.redirect_url, "https://#{@domain}/auth/local-rp?signed_request=")
  end

  # Case 4: a DNS lookup error falls back to the identity domain.
  test "DNS error falls back to the identity domain", ctx do
    {redirect, _} = begin_with(ctx, failing_resolver())
    assert String.starts_with?(redirect.redirect_url, "https://#{@domain}/auth/local-rp?signed_request=")
  end

  # Cases 5 + 6: invalid TXT records are ignored, and across several records
  # the FIRST valid record with https= is selected.
  test "ignores invalid records and selects the first valid https= record", ctx do
    {redirect, _} =
      begin_with(
        ctx,
        apis_resolver([
          "not a linkkeys record",
          "v=lk2 https=wrong-version.example.test",
          "v=lk1 tcp=tcp-only.example.test",
          "v=lk1 https=first.example.test",
          "v=lk1 https=second.example.test"
        ])
      )

    assert String.starts_with?(redirect.redirect_url, "https://first.example.test/auth/local-rp?signed_request=")
  end

  # Case 7: signed_request rides the discovered URL unchanged — it decodes to
  # the signed login request whose fields match this login.
  test "signed_request survives the discovered URL and decodes", ctx do
    {redirect, pending} = begin_with(ctx, apis_resolver(["v=lk1 https=login.example.test/linkkeys"]))
    %URI{query: query} = URI.new!(redirect.redirect_url)
    param = URI.decode_query(query)["signed_request"]
    assert is_binary(param) and param != ""

    signed = Encoding.signed_local_rp_login_request_from_url_param(param)
    request = Types.local_rp_login_request_from_cbor(signed.request)
    assert request.callback_url == @callback_url
    assert request.nonce == pending.nonce
  end

  # The username hint still rides the discovered URL, after signed_request.
  test "username hint is appended to the discovered URL", ctx do
    {redirect, pending} = begin_with(ctx, apis_resolver(["v=lk1 https=login.example.test"]), "Alice+work@#{@domain}")
    assert String.starts_with?(redirect.redirect_url, "https://login.example.test/auth/local-rp?signed_request=")
    assert String.ends_with?(redirect.redirect_url, "&username=Alice%2Bwork")
    assert pending.user_domain == @domain
  end

  # Case 9: a config without :dns is accepted unchanged and the default is
  # the system resolver. The default path is not executed here — that would
  # be a live DNS request.
  test "config without :dns keeps its shape and the default resolver exists" do
    config = [key_material: nil, callback_url: @callback_url, user_domain: @domain]
    refute Keyword.has_key?(config, :dns)
    assert function_exported?(LinkkeysLocalRp.Dns, :system_resolver, 1)
  end

  # ---------------------------------------------------------------------
  # Direct tests for the exported helpers
  # ---------------------------------------------------------------------

  test "resolve_browser_base selects the first valid https= base" do
    assert {:ok, "https://login.example.test:8443/linkkeys"} =
             Browser.resolve_browser_base(
               apis_resolver(["v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys"]),
               @domain
             )

    # A record whose https= value smuggles URL structure is skipped; with no
    # other candidate, resolution errors so the caller can fall back.
    for hostile <- [
          "v=lk1 https=user@evil.example.test",
          "v=lk1 https=evil.example.test/x?y=1",
          "v=lk1 https=evil.example.test/x#frag"
        ] do
      assert {:error, _} = Browser.resolve_browser_base(apis_resolver([hostile]), @domain), hostile
    end

    assert {:error, _} = Browser.resolve_browser_base(apis_resolver(["v=lk1 tcp=only.example.test"]), @domain)
    assert {:error, :servfail} = Browser.resolve_browser_base(failing_resolver(), @domain)
  end

  test "build_browser_endpoint joins base, route, and signed_request" do
    assert {:ok, "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc"} =
             Browser.build_browser_endpoint(
               "https://h.example.test",
               Browser.browser_route_local_rp(),
               "PAYLOAD-123_abc"
             )

    # Path prefix, with and without a trailing slash, and the regular-RP
    # route — the same helper serves /auth/authorize glue.
    for {base, want} <- %{
          "https://h.example.test/pfx" => "https://h.example.test/pfx/auth/authorize?signed_request=s",
          "https://h.example.test/pfx/" => "https://h.example.test/pfx/auth/authorize?signed_request=s"
        } do
      assert {:ok, ^want} = Browser.build_browser_endpoint(base, Browser.browser_route_authorize(), "s"), base
    end

    # A non-HTTPS scheme must never be selectable.
    for bad <- ["http://h.example.test", "ftp://h.example.test", "https://", "https://u:p@h.example.test"] do
      assert {:error, _} = Browser.build_browser_endpoint(bad, Browser.browser_route_local_rp(), "s"), bad
    end

    assert {:error, _} = Browser.build_browser_endpoint("https://h.example.test", "auth/no-leading-slash", "s")
  end

  test "route constants match the wire routes" do
    assert Browser.browser_route_local_rp() == "/auth/local-rp"
    assert Browser.browser_route_authorize() == "/auth/authorize"
  end
end
