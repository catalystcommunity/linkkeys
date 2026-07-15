defmodule LinkkeysLocalRp.Begin do
  @moduledoc """
  `begin_local_login` (design doc: "SDK API Shape", "Flow" steps 4-6).

  Pure/offline: no network access happens here. It generates a fresh
  nonce/state, builds and signs a `LocalRpLoginRequest` around the
  identity's already-signed descriptor, and returns a redirect URL plus
  the pending-login state the app must persist and treat as single-use.
  """

  alias LinkkeysLocalRp.Encoding
  alias LinkkeysLocalRp.Identity.LocalRpKeyMaterial
  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Timeutil

  # Default requested claims when the caller doesn't specify any (design
  # doc, "Default Claim Set"): a usable "identity" out of the box with
  # zero claim configuration.
  @default_requested_claims ["display_name", "email", "handle"]
  def default_requested_claims, do: @default_requested_claims

  # Default required claims (design doc, "Default Claim Set").
  @default_required_claims ["handle"]
  def default_required_claims, do: @default_required_claims

  # Default login-request lifetime: short-lived, matching the callback's
  # own short default lifetime (design doc: "callback lifetime is short,
  # default 5 minutes").
  @default_login_request_lifetime_seconds 300
  def default_login_request_lifetime_seconds, do: @default_login_request_lifetime_seconds

  defmodule BeginLoginError do
    defexception [:message]
  end

  defmodule LocalLoginRedirect do
    @moduledoc "The redirect URL the app should send the user's browser to. The SDK never performs the redirect itself (design doc: 'Browser-only Flow')."
    defstruct [:redirect_url]
  end

  defmodule PendingLogin do
    @moduledoc """
    The state `begin_local_login/1` returns for the app to persist (e.g.
    in a server-side session tied to the browser) and pass unchanged to
    `complete_local_login/1`. **Single-use**: the app must discard it
    after one completion attempt — this package owns no storage and
    cannot enforce that itself.
    """
    defstruct [:nonce, :state, :user_domain, :callback_url, :required_claims]

    @doc """
    JSON/map-safe serialization helper (bytes -> hex) so apps can persist
    this in an ordinary session store without inventing their own encoding.
    Round-trips `required_claims` too (SEC checklist: "the app-declared
    required claims are actually enforced") — `complete_local_login/1`
    re-checks this set against the redemption's verified claims, so it must
    survive whatever storage the app persists `PendingLogin` in, exactly
    like `nonce`/`state`.
    """
    def to_map(%__MODULE__{} = p) do
      %{
        "nonce" => Base.encode16(p.nonce, case: :lower),
        "state" => Base.encode16(p.state, case: :lower),
        "user_domain" => p.user_domain,
        "callback_url" => p.callback_url,
        "required_claims" => p.required_claims
      }
    end

    def from_map(%{} = m) do
      %__MODULE__{
        nonce: Base.decode16!(Map.fetch!(m, "nonce"), case: :mixed),
        state: Base.decode16!(Map.fetch!(m, "state"), case: :mixed),
        user_domain: Map.fetch!(m, "user_domain"),
        callback_url: Map.fetch!(m, "callback_url"),
        required_claims: Map.fetch!(m, "required_claims")
      }
    end
  end

  defp validate_callback_scheme!(url) do
    if not (String.starts_with?(url, "http://") or String.starts_with?(url, "https://")) do
      raise BeginLoginError, message: "callback_url must be http:// or https://, got: #{inspect(url)}"
    end
  end

  @doc """
  `begin_local_login(config) -> {LocalLoginRedirect, PendingLogin}` (design
  doc, "SDK API Shape"). Generates a fresh nonce/state, builds and signs a
  `LocalRpLoginRequest` (envelope + `linkkeys-local-rp-login-request`
  context) around the identity's descriptor, and returns the full
  redirect URL for the user's LinkKeys domain plus the pending-login
  state.

  `config` (keyword list or map):
  - `:key_material` (required, `LocalRpKeyMaterial`)
  - `:callback_url` (required)
  - `:user_domain` (required)
  - `:now` (required, `DateTime.t()`)
  - `:requested_claims` (optional, defaults to #{inspect(@default_requested_claims)})
  - `:required_claims` (optional, defaults to #{inspect(@default_required_claims)})
  - `:request_lifetime_seconds` (optional, defaults to #{@default_login_request_lifetime_seconds})
  """
  def begin_local_login(config) do
    config = Map.new(config)
    key_material = Map.fetch!(config, :key_material)
    callback_url = Map.fetch!(config, :callback_url)
    user_domain = Map.fetch!(config, :user_domain)
    now = Map.fetch!(config, :now)

    validate_callback_scheme!(callback_url)

    if String.trim(user_domain) == "" do
      raise BeginLoginError, message: "user_domain must not be empty"
    end

    nonce = :crypto.strong_rand_bytes(32)
    state = :crypto.strong_rand_bytes(32)

    requested_claims = Map.get(config, :requested_claims) || @default_requested_claims
    required_claims = Map.get(config, :required_claims) || @default_required_claims
    lifetime = Map.get(config, :request_lifetime_seconds) || @default_login_request_lifetime_seconds

    issued_at = Timeutil.to_rfc3339(now)
    expires_at = Timeutil.to_rfc3339(DateTime.add(now, lifetime, :second))

    %LocalRpKeyMaterial{} = key_material

    request =
      LocalRp.build_local_rp_login_request(
        key_material.descriptor,
        callback_url,
        nonce,
        state,
        requested_claims,
        required_claims,
        issued_at,
        expires_at
      )

    signed = LocalRp.sign_local_rp_login_request(request, key_material.signing_private_key)
    encoded = Encoding.signed_local_rp_login_request_to_url_param(signed)

    # Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>"
    # — mirrors the existing GET /auth/authorize?signed_request=... shape.
    redirect_url = "https://#{user_domain}/auth/local-rp?signed_request=#{encoded}"

    {
      %LocalLoginRedirect{redirect_url: redirect_url},
      %PendingLogin{
        nonce: nonce,
        state: state,
        user_domain: user_domain,
        callback_url: callback_url,
        required_claims: required_claims
      }
    }
  end
end
