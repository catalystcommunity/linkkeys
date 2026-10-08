defmodule LinkkeysLocalRp.ActAs do
  @moduledoc """
  Act-as grants, grantee side (`docs/spec/reserved/act-as-grants.md`).

  A user lets this local RP (the grantee) act as the user at an enrolled
  application (the audience). A local RP is identified by its descriptor
  signing-key fingerprint. It signs every request with its descriptor signing
  key and carries its signed descriptor in each `GranteeProof`.

  A local RP can never be an audience: a peer cannot resolve its keys through
  DNS. This module therefore implements the grantee side only:

  1. `begin_act_as/1` builds and signs an `ActAsGrantRequest` and returns the
     browser redirect to the user's home domain (`GET /auth/act-as`).
  2. `complete_act_as/2` reads `act_as_grant_id` from the callback and checks
     the echoed nonce.
  3. `refresh_act_as_grant/1` fetches (or renews) the grant with
     `ActAs/refresh-grant` over the pinned TCP CSIL-RPC path.
  4. `present/1` signs one presentation for one call to the audience.

  Every signature covers `CBOR([tag, payload_bytes])`, the same construction
  as the descriptor and redemption signatures (`LocalRp.envelope_signature_input/2`).
  """

  alias LinkkeysLocalRp.Begin
  alias LinkkeysLocalRp.Browser
  alias LinkkeysLocalRp.Cbor
  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Dns
  alias LinkkeysLocalRp.Encoding
  alias LinkkeysLocalRp.Identity.LocalRpKeyMaterial
  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Rpc
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Transport
  alias LinkkeysLocalRp.Types

  alias LinkkeysLocalRp.Types.{
    ActAsCredential,
    ActAsGrantRequest,
    ActAsPresentation,
    ActAsRefreshRequest,
    ApplicationKeySignature,
    ApplicationRef,
    GranteeProof,
    GranteeRef,
    SignedActAsGrant,
    SignedActAsGrantRequest,
    SignedActAsPresentation,
    SignedActAsRefreshRequest
  }

  @grant_request_tag "linkkeys-act-as-grant-request-v1alpha"
  @refresh_request_tag "linkkeys-act-as-refresh-request-v1alpha"
  @presentation_tag "linkkeys-act-as-presentation-v1alpha"

  def grant_request_tag, do: @grant_request_tag
  def refresh_request_tag, do: @refresh_request_tag
  def presentation_tag, do: @presentation_tag

  @browser_route_act_as "/auth/act-as"
  def browser_route_act_as, do: @browser_route_act_as

  # Grant-request window: default 5 minutes. The reference home domain refuses
  # windows longer than 900 seconds (it keeps request nonces that long).
  @default_request_window_seconds 300
  @max_request_window_seconds 900
  @refresh_request_window_seconds 300

  def default_request_window_seconds, do: @default_request_window_seconds
  def max_request_window_seconds, do: @max_request_window_seconds

  defmodule ActAsError do
    defexception [:message]
  end

  defmodule ActAsRedirect do
    @moduledoc "The URL the app sends the user's browser to. The SDK never performs the redirect itself."
    defstruct [:redirect_url]
  end

  defmodule PendingActAs do
    @moduledoc """
    The state `begin_act_as/1` returns. The app persists it and passes it
    unchanged to `complete_act_as/2`. **Single-use**: discard it after one
    completion attempt. `nonce` is the base64url text the request carries.
    """
    defstruct [:nonce, :user_domain, :callback_url]

    def to_map(%__MODULE__{} = p),
      do: %{"nonce" => p.nonce, "user_domain" => p.user_domain, "callback_url" => p.callback_url}

    def from_map(%{} = m) do
      %__MODULE__{
        nonce: Map.fetch!(m, "nonce"),
        user_domain: Map.fetch!(m, "user_domain"),
        callback_url: Map.fetch!(m, "callback_url")
      }
    end
  end

  # -------------------------------------------------------------------------
  # Pure building blocks (deterministic; the conformance vectors drive these)
  # -------------------------------------------------------------------------

  @doc "The local-RP form of `GranteeRef` for `key_material`."
  def grantee_ref(%LocalRpKeyMaterial{fingerprint: fp}), do: %GranteeRef{local_rp_descriptor_fingerprint: fp}

  @doc """
  Sign `message` (already the `CBOR([tag, payload])` signature input) with the
  descriptor signing key, and wrap it in a local-RP `GranteeProof`.
  """
  def prove(%LocalRpKeyMaterial{} = km, message) when is_binary(message) do
    %GranteeProof{
      local_rp_descriptor: km.descriptor,
      signature: %ApplicationKeySignature{
        signed_by_key_id: km.fingerprint,
        signature: Crypto.ed25519_sign(message, km.signing_private_key)
      }
    }
  end

  @doc "Encode and sign an `ActAsGrantRequest` under `#{@grant_request_tag}`."
  def sign_grant_request(%ActAsGrantRequest{} = request, %LocalRpKeyMaterial{} = km) do
    bytes = Types.act_as_grant_request_to_cbor(request)

    %SignedActAsGrantRequest{
      request: bytes,
      proof: prove(km, LocalRp.envelope_signature_input(@grant_request_tag, bytes))
    }
  end

  @doc "Encode and sign an `ActAsRefreshRequest` under `#{@refresh_request_tag}`."
  def sign_refresh_request(%ActAsRefreshRequest{} = request, %LocalRpKeyMaterial{} = km) do
    bytes = Types.act_as_refresh_request_to_cbor(request)

    %SignedActAsRefreshRequest{
      request: bytes,
      proof: prove(km, LocalRp.envelope_signature_input(@refresh_request_tag, bytes))
    }
  end

  @doc "`base64url-no-pad(CBOR(SignedActAsGrantRequest))`, the `signed_request` query value."
  def signed_grant_request_to_url_param(%SignedActAsGrantRequest{} = signed),
    do: Encoding.b64url_encode(Types.signed_act_as_grant_request_to_cbor(signed))

  @doc "SHA-256 of a grant's signed bytes (`SignedActAsGrant.grant`). A presentation binds this value."
  def grant_hash(grant_bytes) when is_binary(grant_bytes), do: :crypto.hash(:sha256, grant_bytes)

  # -------------------------------------------------------------------------
  # 1. Begin
  # -------------------------------------------------------------------------

  @doc """
  `begin_act_as(config) -> {ActAsRedirect, PendingActAs}`. Raises `ActAsError`
  on bad input.

  `config` (keyword list or map):
  - `:key_material` (required, `LocalRpKeyMaterial`)
  - `:user_domain` (required, `user@domain` or `domain`; parsed like
    `begin_local_login/1`. Only the domain is used.)
  - `:scope_set` (required, the audience's `SignedActAsScopeSet` CBOR bytes,
    exactly as received. It is embedded unchanged.)
  - `:callback_url` (required, `http://` or `https://`)
  - `:now` (required, `DateTime.t()`)
  - `:requested_lifetime_seconds` (optional, positive)
  - `:requested_renewal_window_seconds` (optional, not negative)
  - `:request_window_seconds` (optional, default #{@default_request_window_seconds},
    max #{@max_request_window_seconds})
  - `:dns` (optional, defaults to the system resolver). Used for browser
    endpoint discovery, with the same fallback as `begin_local_login/1`.
  """
  def begin_act_as(config) do
    config = Map.new(config)
    km = Map.fetch!(config, :key_material)
    %LocalRpKeyMaterial{} = km
    scope_set_bytes = Map.fetch!(config, :scope_set)
    callback_url = Map.fetch!(config, :callback_url)
    now = Map.fetch!(config, :now)
    dns = Map.get(config, :dns) || (&Dns.system_resolver/1)
    lifetime = Map.get(config, :requested_lifetime_seconds)
    renewal = Map.get(config, :requested_renewal_window_seconds)
    window = Map.get(config, :request_window_seconds) || @default_request_window_seconds

    {_username, domain} =
      try do
        Begin.validate_callback_scheme!(callback_url)
        Begin.parse_identity_input!(Map.fetch!(config, :user_domain))
      rescue
        e in Begin.BeginLoginError -> raise ActAsError, message: e.message
      end

    if not (is_integer(window) and window in 1..@max_request_window_seconds),
      do: raise(ActAsError, message: "request window must be 1..#{@max_request_window_seconds} seconds")

    if lifetime != nil and not (is_integer(lifetime) and lifetime > 0),
      do: raise(ActAsError, message: "requested lifetime must be a positive integer")

    if renewal != nil and not (is_integer(renewal) and renewal >= 0),
      do: raise(ActAsError, message: "requested renewal window must be a non-negative integer")

    scope_set = decode_scope_set!(scope_set_bytes)
    nonce = Encoding.b64url_encode(:crypto.strong_rand_bytes(32))

    request = %ActAsGrantRequest{
      grantee: grantee_ref(km),
      scope_set: scope_set,
      requested_lifetime_seconds: lifetime,
      requested_renewal_window_seconds: renewal,
      callback_url: callback_url,
      nonce: nonce,
      requested_at: Timeutil.to_rfc3339(now),
      expires_at: Timeutil.to_rfc3339(DateTime.add(now, window, :second))
    }

    param = request |> sign_grant_request(km) |> signed_grant_request_to_url_param()

    redirect_url =
      case Browser.resolve_browser_endpoint(dns, domain, @browser_route_act_as, param) do
        {:ok, url} -> url
        {:error, reason} -> raise ActAsError, message: "browser endpoint could not be built: #{inspect(reason)}"
      end

    {%ActAsRedirect{redirect_url: redirect_url},
     %PendingActAs{nonce: nonce, user_domain: domain, callback_url: callback_url}}
  end

  defp decode_scope_set!(bytes) when is_binary(bytes) do
    Types.signed_act_as_scope_set_from_cbor(bytes)
  rescue
    _ -> raise ActAsError, message: "scope_set is not a SignedActAsScopeSet"
  end

  defp decode_scope_set!(_), do: raise(ActAsError, message: "scope_set must be CBOR bytes")

  # -------------------------------------------------------------------------
  # 2. Complete (callback)
  # -------------------------------------------------------------------------

  @doc """
  `complete_act_as(pending, callback) -> {:ok, grant_id} | {:error, reason}`.

  `callback` is the full URL the callback arrived at, its query string, or a
  map of its query parameters. The `nonce` parameter must equal
  `pending.nonce` (constant-time compare). Fetch the grant itself with
  `refresh_act_as_grant/1`.
  """
  def complete_act_as(%PendingActAs{} = pending, callback) do
    with {:ok, params} <- callback_params(callback),
         {:ok, grant_id} <- fetch_param(params, "act_as_grant_id"),
         {:ok, nonce} <- fetch_param(params, "nonce") do
      if Crypto.constant_time_equal?(nonce, pending.nonce) do
        {:ok, grant_id}
      else
        {:error, :nonce_mismatch}
      end
    end
  end

  defp callback_params(params) when is_map(params), do: {:ok, params}

  defp callback_params(url) when is_binary(url) do
    query =
      case String.split(url, "?", parts: 2) do
        [_base, q] -> q
        [q] -> if String.contains?(q, "="), do: q, else: ""
      end

    pairs = query |> String.split("#", parts: 2) |> hd() |> URI.query_decoder() |> Enum.to_list()

    # A repeated parameter is ambiguous: refuse it rather than pick one.
    if Enum.any?(["act_as_grant_id", "nonce"], fn key -> Enum.count(pairs, &(elem(&1, 0) == key)) > 1 end) do
      {:error, :repeated_param}
    else
      {:ok, Map.new(pairs)}
    end
  rescue
    _ -> {:error, :bad_callback}
  end

  defp callback_params(_), do: {:error, :bad_callback}

  defp fetch_param(params, key) do
    case Map.get(params, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> {:error, {:missing_param, key}}
    end
  end

  # -------------------------------------------------------------------------
  # 3. Refresh
  # -------------------------------------------------------------------------

  @doc """
  `refresh_act_as_grant(config) -> {:ok, {SignedActAsGrant, signed?}} | {:error, reason}`.

  Signs an `ActAsRefreshRequest` (window #{@refresh_request_window_seconds} s,
  fresh nonce) and calls `ActAs/refresh-grant` on the user's home domain over
  the same DNS-pinned TCP CSIL-RPC path as the claim-ticket redemption. The
  same call fetches a new grant and renews a current one. `signed?` is true
  when the home domain signed a new grant for this call.

  `config`: `:key_material`, `:user_domain` (the identity domain from
  `PendingActAs`), `:grant_id`, `:now`, and optional `:transport` / `:dns`.
  """
  def refresh_act_as_grant(config) do
    config = Map.new(config)
    km = Map.fetch!(config, :key_material)
    %LocalRpKeyMaterial{} = km
    domain = Map.fetch!(config, :user_domain)
    grant_id = Map.fetch!(config, :grant_id)
    now = Map.fetch!(config, :now)
    transport = Map.get(config, :transport) || (&Transport.dial/1)
    dns = Map.get(config, :dns) || (&Dns.system_resolver/1)

    signed =
      sign_refresh_request(
        %ActAsRefreshRequest{
          grant_id: grant_id,
          grantee: grantee_ref(km),
          requested_at: Timeutil.to_rfc3339(now),
          expires_at: Timeutil.to_rfc3339(DateTime.add(now, @refresh_request_window_seconds, :second)),
          nonce: Encoding.b64url_encode(:crypto.strong_rand_bytes(32))
        },
        km
      )

    with {:ok, resp} <- Rpc.refresh_act_as_grant(transport, dns, domain, signed),
         :ok <- check_returned_grant(resp.grant.grant, grant_id, domain, km) do
      {:ok, {resp.grant, resp.signed}}
    end
  end

  # The audience checks the grant signature. This only checks that the home
  # domain returned the grant the call asked for, so a confused or hostile
  # server cannot hand this grantee another grant.
  defp check_returned_grant(grant_bytes, grant_id, domain, %LocalRpKeyMaterial{} = km) do
    tree =
      try do
        Cbor.decode(grant_bytes)
      rescue
        _ -> nil
      end

    cond do
      not is_map(tree) -> {:error, {:grant_mismatch, :decode}}
      tree["grant_id"] != grant_id -> {:error, {:grant_mismatch, :grant_id}}
      not local_rp_grantee?(tree["grantee"], km.fingerprint) -> {:error, {:grant_mismatch, :grantee}}
      not same_domain?(tree["subject_domain"], domain) -> {:error, {:grant_mismatch, :subject_domain}}
      true -> :ok
    end
  end

  defp local_rp_grantee?(grantee, fingerprint) when is_map(grantee),
    do: not Map.has_key?(grantee, "application") and grantee["local_rp_descriptor_fingerprint"] == fingerprint

  defp local_rp_grantee?(_, _), do: false

  defp same_domain?(a, b) when is_binary(a) and is_binary(b),
    do: String.downcase(a, :ascii) == String.downcase(b, :ascii)

  defp same_domain?(_, _), do: false

  # -------------------------------------------------------------------------
  # 4. Present
  # -------------------------------------------------------------------------

  @doc """
  `present(config) -> {ActAsCredential, credential_cbor}`.

  Signs one `ActAsPresentation` under `#{@presentation_tag}` for one call to the
  audience. `config`: `:grant` (`SignedActAsGrant`), `:audience`
  (`ApplicationRef`, the audience's own identity), `:request_digest` (bytes,
  defined by the audience's protocol), `:now`, `:nonce` (bytes), and
  `:key_material`. Send the returned bytes with the call; the signed
  descriptor travels inside the proof.
  """
  def present(config) do
    config = Map.new(config)
    %SignedActAsGrant{} = grant = Map.fetch!(config, :grant)
    %ApplicationRef{} = audience = Map.fetch!(config, :audience)
    %LocalRpKeyMaterial{} = km = Map.fetch!(config, :key_material)
    request_digest = Map.fetch!(config, :request_digest)
    nonce = Map.fetch!(config, :nonce)
    now = Map.fetch!(config, :now)

    bytes =
      Types.act_as_presentation_to_cbor(%ActAsPresentation{
        grant_hash: grant_hash(grant.grant),
        audience: audience,
        request_digest: request_digest,
        presented_at: Timeutil.to_rfc3339(now),
        nonce: nonce
      })

    credential = %ActAsCredential{
      grant: grant,
      presentation: %SignedActAsPresentation{
        presentation: bytes,
        proof: prove(km, LocalRp.envelope_signature_input(@presentation_tag, bytes))
      }
    }

    {credential, Types.act_as_credential_to_cbor(credential)}
  end
end
