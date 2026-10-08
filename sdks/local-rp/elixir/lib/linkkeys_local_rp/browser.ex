defmodule LinkkeysLocalRp.Browser do
  @moduledoc """
  Browser endpoint discovery: resolve an identity domain's browser-facing
  HTTPS base from its `_linkkeys_apis` TXT record, and build browser route
  URLs against it. Mirrors `sdks/local-rp/go/browser.go`.

  The identity domain (the domain the user selected, e.g. `todandlorna.com`)
  is a trust and discovery domain. It is not necessarily the host that
  serves the browser login routes — the `https=` endpoint of
  `_linkkeys_apis.<identity-domain>` is (`docs/spec/trust-and-anchors.md`:
  "`https=` is the browser-facing endpoint"). These helpers are shared by
  `LinkkeysLocalRp.Begin.begin_local_login/1` (route
  `browser_route_local_rp/0`) and by regular-RP application glue (route
  `browser_route_authorize/0`), so discovery is implemented once.

  The resolved base is a service location only. Identity verification stays
  bound to the identity domain — never bind trust decisions to the host
  these helpers return.
  """

  alias LinkkeysLocalRp.Dns

  @browser_route_local_rp "/auth/local-rp"
  @browser_route_authorize "/auth/authorize"

  @doc "The browser route for the DNS-less local-RP login flow."
  def browser_route_local_rp, do: @browser_route_local_rp

  @doc "The browser route for the regular (domain-keyed) RP login flow."
  def browser_route_authorize, do: @browser_route_authorize

  @doc """
  Resolve `identity_domain`'s browser-facing HTTPS base URL (e.g.
  `https://linkkeys.todandlorna.com` or `https://login.example.com/linkkeys`)
  from its `_linkkeys_apis.<identity_domain>` TXT record, via the injected
  `dns` resolver (`t:LinkkeysLocalRp.Dns.resolver/0`).

  Selects the first LinkKeys v1 record whose `https=` endpoint is a valid
  browser base (see `validate_browser_base/1`); invalid TXT records and
  records without `https=` are skipped. Returns `{:error, reason}` when the
  lookup fails or no record yields a valid base — the caller decides the
  fallback (`begin_local_login/1` falls back to `https://<identity_domain>`).
  """
  @spec resolve_browser_base(Dns.resolver(), String.t()) :: {:ok, String.t()} | {:error, term}
  def resolve_browser_base(dns, identity_domain) when is_function(dns, 1) do
    name = Dns.linkkeys_apis_dns_name(identity_domain)

    case dns.(name) do
      {:ok, txts} when is_list(txts) ->
        case Enum.find_value(txts, &usable_https_base/1) do
          nil -> {:error, {:no_browser_base, "no usable #{name} TXT record with an https= endpoint"}}
          base -> {:ok, base}
        end

      {:error, reason} ->
        {:error, reason}

      other ->
        {:error, {:bad_resolver_result, other}}
    end
  end

  defp usable_https_base(txt) do
    case safe_parse_apis(txt) do
      %Dns.LinkKeysApis{https_base: base} when is_binary(base) ->
        case validate_browser_base(base) do
          {:ok, _uri} -> base
          {:error, _} -> nil
        end

      _ ->
        nil
    end
  end

  defp safe_parse_apis(txt) do
    Dns.parse_linkkeys_apis_txt(txt)
  rescue
    _ -> nil
  end

  @doc """
  Check that `base` is a usable https browser base URL: parseable, `https`
  scheme, a host, an optional path prefix, and nothing else. A TXT record
  value must never smuggle in userinfo, a query, a fragment, or (via
  `Dns.parse_linkkeys_apis_txt/1`'s unconditional `https://` prefix plus this
  check) a non-HTTPS scheme. Returns the parsed `URI` on success.
  """
  @spec validate_browser_base(String.t()) :: {:ok, URI.t()} | {:error, term}
  def validate_browser_base(base) when is_binary(base) do
    case URI.new(base) do
      {:ok, %URI{scheme: "https", host: host} = uri} when is_binary(host) and host != "" ->
        cond do
          uri.userinfo != nil or uri.query != nil or uri.fragment != nil ->
            {:error, {:invalid_browser_base, "browser base must be host[:port][/path] only"}}

          uri.port != nil and uri.port not in 1..65_535 ->
            {:error, {:invalid_browser_base, "browser base has an invalid port"}}

          true ->
            {:ok, uri}
        end

      {:ok, %URI{scheme: "https"}} ->
        {:error, {:invalid_browser_base, "browser base has no host"}}

      {:ok, %URI{}} ->
        {:error, {:invalid_browser_base, "browser base must use https"}}

      {:error, _} ->
        {:error, {:invalid_browser_base, "browser base is not a valid URL"}}
    end
  end

  @doc """
  Build the full browser URL for `route` (e.g. `browser_route_local_rp/0`)
  under `browser_base`, carrying `signed_request` as the `signed_request`
  query parameter. A path prefix in the base is preserved: base
  `https://login.example.com/linkkeys` and route `/auth/local-rp` produce
  `https://login.example.com/linkkeys/auth/local-rp?...`.

  The URL is assembled with `URI` (`URI.append_path/2`, `URI.append_query/2`).
  `signed_request` values are URL-param-encoded (unpadded base64url) by
  construction, so query encoding passes them through byte-identically.
  """
  @spec build_browser_endpoint(String.t(), String.t(), String.t()) :: {:ok, String.t()} | {:error, term}
  def build_browser_endpoint(browser_base, route, signed_request)
      when is_binary(browser_base) and is_binary(route) and is_binary(signed_request) do
    with {:ok, uri} <- validate_browser_base(browser_base),
         :ok <- validate_route(route) do
      url =
        uri
        |> URI.append_path(route)
        |> URI.append_query(URI.encode_query(%{"signed_request" => signed_request}))
        |> URI.to_string()

      {:ok, url}
    end
  end

  defp validate_route(route) do
    if String.starts_with?(route, "/") and not String.contains?(route, ["?", "#"]) do
      :ok
    else
      {:error, {:invalid_route, "route must start with / and carry no query or fragment"}}
    end
  end

  @doc """
  The begin-flow composition: discover the identity domain's browser base and
  build the route URL, falling back to `https://<identity_domain>` when DNS
  lookup fails, no valid record carries `https=`, or the discovered base is
  invalid. The fallback preserves the pre-discovery behavior, so a domain
  that serves its browser routes at the apex keeps working without a
  `_linkkeys_apis` record.
  """
  @spec resolve_browser_endpoint(Dns.resolver(), String.t(), String.t(), String.t()) ::
          {:ok, String.t()} | {:error, term}
  def resolve_browser_endpoint(dns, identity_domain, route, signed_request) do
    base =
      case resolve_browser_base(dns, identity_domain) do
        {:ok, base} -> base
        {:error, _} -> "https://" <> identity_domain
      end

    build_browser_endpoint(base, route, signed_request)
  end
end
