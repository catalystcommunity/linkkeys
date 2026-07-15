defmodule LinkkeysLocalRp.Complete do
  @moduledoc """
  `complete_local_login` (design doc: "SDK API Shape", "Flow" steps 12-13).

  This is the SDK's full verification chain, run in the exact order the
  pure `LinkkeysLocalRp.LocalRp` helpers require:

  1. decode the callback ciphertext from its URL-param encoding
  2. open it (decrypt) — only with a suite this identity's own descriptor
     advertises
  3. fetch the pending domain's public keys, DNS-`fp=`-pinned, over TCP
     CSIL-RPC
  4. verify the domain-signed envelope (key lookup, revocation/expiry,
     signature, payload timestamp bounds) — only now is anything inside
     the payload trusted
  5. cross-check the cleartext header's routing fields against the
     now-verified payload
  6. audience / issuer / callback-URL / nonce-state checks
  7. redeem the claim ticket over TCP CSIL-RPC (signed with the local RP's
     own key — the possession proof), then assert the (unauthenticated)
     redemption response's `user_id`/`user_domain` match the
     already-verified payload's — fatal on mismatch
  8. verify every returned claim's signatures against ITS signer domain's
     keys (fetched the same pinned way), which also checks the claim's own
     revocation/expiry, AND assert each claim's `user_id` matches the
     verified payload's (fatal on mismatch), then enforce that every
     `required_claims` entry from the pending login is covered by a claim
     that passed all of the above (fatal if missing/insufficient, including
     an empty claim set)

  The identity `complete_local_login/1` ultimately returns is always
  sourced from the domain-SIGNED, signature-verified callback payload
  (`payload.user_id` / `payload.user_domain`) — never from the ticket
  redemption response, which carries no signature of its own and is
  trusted only because it was fetched over the DNS-pinned TLS channel for
  the domain the signed payload named. Steps 7 and 8's identity checks
  exist precisely to catch a compromised/malicious IDP handing back claims
  for a different user than the one it cryptographically vouched for.
  """

  alias LinkkeysLocalRp.Begin.PendingLogin
  alias LinkkeysLocalRp.Claims
  alias LinkkeysLocalRp.Claims.DomainKeySet
  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Dns
  alias LinkkeysLocalRp.Encoding
  alias LinkkeysLocalRp.Identity.LocalRpKeyMaterial
  alias LinkkeysLocalRp.LocalRp
  alias LinkkeysLocalRp.Rpc
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Transport
  alias LinkkeysLocalRp.Types

  # Bound on the number of distinct claim-signer domains a single
  # completion will fetch keys for — see the comment at its use site for
  # why this exists (SSRF/DoS amplification guard against a malicious/
  # compromised home IDP).
  @max_claim_signer_domains 8

  defmodule CompleteLoginError do
    defexception [:message, :reason]

    @impl true
    def exception(reason) do
      %__MODULE__{reason: reason, message: "complete_local_login failed: #{inspect(reason)}"}
    end
  end

  defmodule VerifiedLocalLogin do
    @moduledoc "What `complete_local_login/1` returns to app code — verified protocol facts. This package returns rather than calling back."
    defstruct [
      :user_id,
      :user_domain,
      :claims,
      :domain_public_keys,
      :local_rp_fingerprint,
      :issued_at,
      :expires_at,
      :ticket_expires_at
    ]
  end

  defp strip_encrypted_token_param(arrived_url) do
    Enum.find_value(["?", "&"], arrived_url, fn sep ->
      marker = "#{sep}encrypted_token="

      case :binary.matches(arrived_url, marker) do
        [] ->
          nil

        matches ->
          {idx, _len} = List.last(matches)
          binary_part(arrived_url, 0, idx)
      end
    end)
  end

  @doc """
  `complete_local_login(config) -> {:ok, VerifiedLocalLogin} | {:error, term}`
  (design doc, "SDK API Shape"). Every entry in `config` is load-bearing
  (design doc: "`complete_local_login` inputs, spelled out because every
  one is load-bearing"):

  - `:key_material` — the same identity `begin_local_login/1` used.
  - `:pending` — the `PendingLogin` `begin_local_login/1` returned, exactly
    as the app persisted it. Treat as single-use.
  - `:encrypted_token` — the `encrypted_token` query-parameter's raw value.
  - `:arrived_url` — the full URL the callback actually arrived at.
  - `:now` — the current time (never read from the system clock internally).
  - `:clock_skew_seconds` (optional, defaults to `LocalRp.default_clock_skew_seconds/0`)
  - `:transport` (optional, defaults to `&LinkkeysLocalRp.Transport.dial/1`)
  - `:dns` (optional, defaults to `&LinkkeysLocalRp.Dns.system_resolver/1`)
  """
  def complete_local_login(config) do
    # Config-shape extraction is OUTSIDE the rescue below on purpose: a
    # missing/wrong-shaped config key is an integration bug (raise), not a
    # protocol-verification failure. Everything from here on touches
    # attacker-controlled bytes (the callback token, the network
    # responses) and must never leak a raw exception to app code — see
    # the module's return-value convention doc.
    config = Map.new(config)
    key_material = Map.fetch!(config, :key_material)
    %LocalRpKeyMaterial{} = key_material
    pending = Map.fetch!(config, :pending)
    %PendingLogin{} = pending
    encrypted_token = Map.fetch!(config, :encrypted_token)
    arrived_url = Map.fetch!(config, :arrived_url)
    now = Map.fetch!(config, :now)

    skew_seconds = Map.get(config, :clock_skew_seconds) || LocalRp.default_clock_skew_seconds()
    transport = Map.get(config, :transport) || (&Transport.dial/1)
    dns = Map.get(config, :dns) || (&Dns.system_resolver/1)

    try do
      run_chain(key_material, pending, encrypted_token, arrived_url, now, skew_seconds, transport, dns)
    rescue
      e -> {:error, e}
    end
  end

  defp run_chain(key_material, pending, encrypted_token, arrived_url, now, skew_seconds, transport, dns) do
    with {:ok, encrypted} <- decode_step(encrypted_token),
         {:ok, allowed_suites} <- allowed_suites_step(key_material),
         {:ok, header, signed_payload} <- open_step(encrypted, key_material, allowed_suites),
         {:ok, user_domain_keys} <- fetch_keys_step(transport, dns, pending.user_domain),
         {:ok, payload} <- verify_envelope_step(signed_payload, user_domain_keys, now, skew_seconds),
         :ok <- LocalRp.check_callback_header_matches_payload(header, payload),
         :ok <- LocalRp.verify_audience(payload.audience_fingerprint, key_material.fingerprint),
         :ok <- LocalRp.verify_issuer(payload.user_domain, pending.user_domain),
         arrived_base_url = strip_encrypted_token_param(arrived_url),
         :ok <- LocalRp.verify_callback_url(payload.callback_url, arrived_base_url),
         :ok <- LocalRp.verify_nonce_state(pending.nonce, pending.state, payload.nonce, payload.state),
         {:ok, redemption} <-
           redeem_ticket_step(transport, dns, pending.user_domain, payload, key_material, now),
         :ok <- verify_redemption_identity_step(redemption, payload),
         {:ok, domain_key_sets} <-
           gather_signer_keys_step(transport, dns, pending.user_domain, user_domain_keys, redemption.claims),
         {:ok, verified_claim_types} <-
           verify_claims_step(redemption.claims, payload.user_id, payload.user_domain, domain_key_sets, now),
         :ok <- verify_required_claims_step(pending.required_claims, verified_claim_types) do
      {:ok,
       %VerifiedLocalLogin{
         # Sourced from the VERIFIED, SIGNED payload — not the redemption
         # response — even though the two are now known to agree (checked
         # by verify_redemption_identity_step/2 above). The payload is the
         # thing that was actually cryptographically attested by the
         # domain; the redemption response is merely corroborating data
         # fetched over a channel that is pinned but otherwise unsigned.
         user_id: payload.user_id,
         user_domain: payload.user_domain,
         claims: redemption.claims,
         domain_public_keys: user_domain_keys,
         local_rp_fingerprint: key_material.fingerprint,
         issued_at: Timeutil.parse_rfc3339(payload.issued_at),
         expires_at: Timeutil.parse_rfc3339(payload.expires_at),
         ticket_expires_at: Timeutil.parse_rfc3339(redemption.ticket_expires_at)
       }}
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_step(encrypted_token) do
    {:ok, Encoding.local_rp_encrypted_callback_from_url_param(encrypted_token)}
  rescue
    e -> {:error, e}
  end

  defp allowed_suites_step(key_material) do
    own_descriptor = Types.local_rp_descriptor_from_cbor(key_material.descriptor.descriptor)
    allowed = own_descriptor.supported_suites |> Enum.map(&Crypto.parse_suite/1) |> Enum.filter(& &1)
    {:ok, allowed}
  rescue
    e -> {:error, e}
  end

  defp open_step(encrypted, key_material, allowed_suites) do
    case LocalRp.open_local_rp_callback(encrypted, key_material.encryption_private_key, allowed_suites) do
      {:ok, header, signed_payload} -> {:ok, header, signed_payload}
      {:error, reason} -> {:error, reason}
    end
  end

  defp fetch_keys_step(transport, dns, domain) do
    Rpc.fetch_domain_keys(transport, dns, domain)
  end

  defp verify_envelope_step(signed_payload, user_domain_keys, now, skew_seconds) do
    LocalRp.verify_local_rp_callback_payload(signed_payload, user_domain_keys, now, skew_seconds)
  end

  defp redeem_ticket_step(transport, dns, user_domain, payload, key_material, now) do
    redemption_request =
      LocalRp.build_local_rp_ticket_redemption_request(
        payload.claim_ticket,
        key_material.fingerprint,
        Timeutil.to_rfc3339(now)
      )

    signed_redemption =
      LocalRp.sign_local_rp_ticket_redemption_request(redemption_request, key_material.signing_private_key)

    Rpc.redeem_claim_ticket(transport, dns, user_domain, signed_redemption)
  end

  # The redemption response's claim signatures name their signing domains
  # as plain, not-yet-verified strings — a malicious/compromised home IDP
  # could otherwise list an unbounded number of distinct "signer domains"
  # purely to make this SDK perform many outbound DNS/TCP calls to
  # attacker-chosen targets before any signature is actually checked (an
  # SSRF/DoS amplification vector against the app's own process). Cap the
  # number of distinct signer domains this SDK will fetch keys for per
  # completion; a legitimate claim set names very few (typically one: the
  # home domain). Reuse the home domain's already-fetched keys.
  defp gather_signer_keys_step(transport, dns, user_domain, user_domain_keys, claims) do
    initial = [%DomainKeySet{domain: user_domain, keys: user_domain_keys}]

    signer_domains =
      claims
      |> Enum.flat_map(fn claim -> Enum.map(claim.signatures, & &1.domain) end)
      |> Enum.uniq()
      |> Enum.reject(fn d -> d == user_domain end)

    if length(signer_domains) > @max_claim_signer_domains - 1 do
      {:error,
       %CompleteLoginError{
         reason: :too_many_signer_domains,
         message:
           "claim set names more than #{@max_claim_signer_domains} distinct signer domains; refusing to fetch further keys"
       }}
    else
      fetch_additional_domains(transport, dns, signer_domains, initial)
    end
  end

  defp fetch_additional_domains(_transport, _dns, [], acc), do: {:ok, acc}

  defp fetch_additional_domains(transport, dns, [domain | rest], acc) do
    case Rpc.fetch_domain_keys(transport, dns, domain) do
      {:ok, keys} -> fetch_additional_domains(transport, dns, rest, acc ++ [%DomainKeySet{domain: domain, keys: keys}])
      {:error, reason} -> {:error, reason}
    end
  end

  # SEC fix: the ticket redemption response carries no signature of its
  # own — it is trusted only because it was fetched over the DNS-pinned TLS
  # channel for the domain the SIGNED callback payload named. That is not
  # the same as the redemption response actually agreeing with the
  # payload: a compromised/malicious IDP could hand back claims for a
  # different user than the one it cryptographically vouched for in the
  # signed callback (e.g. to launder an approval given to user A onto user
  # B's claims). Cross-check unconditionally, and treat any mismatch as
  # fatal — never fall back to either identity alone.
  defp verify_redemption_identity_step(redemption, payload) do
    if redemption.user_id == payload.user_id and redemption.user_domain == payload.user_domain do
      :ok
    else
      {:error,
       %CompleteLoginError{
         reason: :redemption_identity_mismatch,
         message:
           "ticket redemption identity (#{inspect(redemption.user_id)}, #{inspect(redemption.user_domain)}) " <>
             "does not match the signed callback payload's identity (#{inspect(payload.user_id)}, #{inspect(payload.user_domain)})"
       }}
    end
  end

  # Verifies every claim's signatures against its signer domain's keys
  # (revocation/expiry included), AND that each claim's user_id matches the
  # signature-VERIFIED payload's user_id — checked BEFORE signature
  # verification, so a claim naming a different user is rejected as an
  # identity violation rather than merely an "unverified claim". A claim
  # about a different user must never be attributed to this login,
  # regardless of whether its own signature checks out.
  #
  # Returns `{:ok, verified_claim_types}` — the set of claim TYPES that
  # survived every check above — so `verify_required_claims_step/2` can
  # enforce `required_claims` only against claims that actually verified,
  # never against whatever merely arrived in the response.
  defp verify_claims_step(claims, expected_user_id, subject_domain, domain_key_sets, now) do
    Enum.reduce_while(claims, {:ok, MapSet.new()}, fn claim, {:ok, verified_types} ->
      cond do
        claim.user_id != expected_user_id ->
          {:halt,
           {:error,
            %CompleteLoginError{
              reason: :claim_user_id_mismatch,
              message:
                "claim #{inspect(claim.claim_id)} names user_id #{inspect(claim.user_id)}, expected " <>
                  "#{inspect(expected_user_id)} (the signed callback payload's subject)"
            }}}

        true ->
          case Claims.verify_claim(claim, subject_domain, domain_key_sets, now) do
            :ok -> {:cont, {:ok, MapSet.put(verified_types, claim.claim_type)}}
            {:error, _} = err -> {:halt, err}
          end
      end
    end)
  end

  # Enforces the required_claims the login was BEGUN with (SEC checklist:
  # "the app-declared required claims are actually enforced"). Only claim
  # types that survived subject-binding AND signature verification in
  # verify_claims_step/5 count — an unsigned/unverifiable/wrong-subject
  # claim can never satisfy a requirement. An empty or insufficient claim
  # set against a non-empty requirement is fatal (this is the exact case
  # the security review flagged: the previous claim-verification loop
  # returned `:ok` trivially for an empty claim list, with nothing
  # downstream ever checking `required_claims` against it).
  defp verify_required_claims_step(required_claims, verified_claim_types) do
    missing =
      (required_claims || [])
      |> Enum.reject(fn rc -> MapSet.member?(verified_claim_types, rc) end)

    if missing == [] do
      :ok
    else
      {:error,
       %CompleteLoginError{
         reason: {:required_claims_missing, missing},
         message: "required claim types not satisfied by any verified claim: #{inspect(missing)}"
       }}
    end
  end
end
