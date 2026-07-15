defmodule LinkkeysLocalRp.LocalRp do
  @moduledoc """
  DNS-less local RP identity: pure protocol helpers.

  Mirrors `crates/liblinkkeys/src/local_rp.rs` and `dns-less-local-rp-design.md`'s
  "Wire Precision (Normative)" section — this module implements it
  byte-for-byte:

  - Every signed structure uses the envelope pattern: the payload is
    CBOR-encoded once, and the signature covers
    `CBOR([context: tstr, payload: bstr])` — a two-element CBOR array,
    never a bare `context || payload` concatenation (see
    `envelope_signature_input/2`).
  - Four mandatory, structure-specific context strings stop a signature
    over one structure from ever verifying as another.
  - The descriptor, login request, and ticket-redemption envelopes are
    self-asserted (verified against the local RP's own embedded signing
    key, SSH-host style). The callback payload envelope is domain-signed
    (verified against fetched domain public keys, keyed by
    `signing_key_id`).
  - The callback ciphertext is a variant of the sealed-box construction,
    extended with negotiated-suite selection and cleartext-header AAD
    binding — see `seal_local_rp_callback/8` / `open_local_rp_callback/3`.

  This module performs no I/O and never reads the system clock — every
  "current time" is an explicit `now` parameter, so verification stays
  deterministic and testable against fixed conformance vectors.
  """

  alias LinkkeysLocalRp.Cbor
  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Types

  alias LinkkeysLocalRp.Types.{
    LocalRpCallbackHeader,
    LocalRpCallbackPayload,
    LocalRpDescriptor,
    LocalRpEncryptedCallback,
    LocalRpLoginRequest,
    LocalRpTicketRedemptionRequest,
    SignedLocalRpCallbackPayload,
    SignedLocalRpDescriptor,
    SignedLocalRpLoginRequest,
    SignedLocalRpTicketRedemptionRequest
  }

  @ctx_descriptor "linkkeys-local-rp-descriptor"
  @ctx_login_request "linkkeys-local-rp-login-request"
  @ctx_callback "linkkeys-local-rp-callback"
  @ctx_ticket_redemption "linkkeys-local-rp-ticket-redemption"

  def ctx_descriptor, do: @ctx_descriptor
  def ctx_login_request, do: @ctx_login_request
  def ctx_callback, do: @ctx_callback
  def ctx_ticket_redemption, do: @ctx_ticket_redemption

  @default_clock_skew_seconds 300
  def default_clock_skew_seconds, do: @default_clock_skew_seconds

  @callback_box_tag "linkkeys-local-rp-callback-box"

  # ---------------------------------------------------------------------
  # Errors — every case wraps `{:error, {tag, detail}}` from the pure
  # helpers below; per the conformance suite's own contract only pass/fail
  # is portable, so callers that only need that can pattern-match `:ok`
  # vs `{:error, _}`. The tags exist for apps that want richer diagnostics
  # without ever including key material, nonces, tokens, tickets, or claim
  # values (AGENTS.md's error-handling rule).
  # ---------------------------------------------------------------------

  # ---------------------------------------------------------------------
  # Envelope signature input (Wire Precision: "Signature input bytes")
  # ---------------------------------------------------------------------

  @doc """
  `CBOR([context, payload_bytes])` — a two-element CBOR array, context
  string first (CBOR text string), then the exact payload bytes (CBOR byte
  string). Deliberately NOT a bare `context || payload` concatenation.
  """
  @spec envelope_signature_input(String.t(), binary) :: binary
  def envelope_signature_input(context, payload_bytes) do
    Cbor.encode([context, Cbor.bytes(payload_bytes)])
  end

  # ---------------------------------------------------------------------
  # Timestamps / expirations
  # ---------------------------------------------------------------------

  @doc """
  Check an `(issued_at, expires_at)` RFC3339 pair against `now`, tolerant
  of `skew_seconds` of clock skew in either direction. Boundaries are
  inclusive: exactly `now - skew == expires_at` still passes, one second
  past either boundary fails.
  """
  @spec check_timestamps(String.t(), String.t(), DateTime.t(), integer) ::
          :ok | {:error, :not_yet_valid | :expired | :bad_timestamp}
  def check_timestamps(issued_at, expires_at, %DateTime{} = now, skew_seconds) do
    with {:ok, issued} <- safe_parse(issued_at),
         {:ok, expires} <- safe_parse(expires_at) do
      skew = skew_seconds

      cond do
        DateTime.compare(DateTime.add(now, skew, :second), issued) == :lt ->
          {:error, :not_yet_valid}

        DateTime.compare(DateTime.add(now, -skew, :second), expires) == :gt ->
          {:error, :expired}

        true ->
          :ok
      end
    end
  end

  defp safe_parse(s) do
    {:ok, Timeutil.parse_rfc3339(s)}
  rescue
    _ -> {:error, :bad_timestamp}
  end

  @doc """
  `check_expirations(expires_at, now) -> {level, expires_at, now}` (design
  doc, "Expiration Helper"): `:notice` at 180 days remaining, `:warning`
  at 90, `:critical` at 30, `:expired` once `now >= expires_at`. No
  clock-skew tolerance (unlike `check_timestamps/4`) — expiry warnings are
  advisory, day-granularity facts, not a replay/freshness security
  boundary.
  """
  @spec check_expirations(String.t(), DateTime.t()) ::
          {:ok, %{level: atom, expires_at: DateTime.t(), now: DateTime.t()}}
          | {:error, :bad_timestamp}
  def check_expirations(expires_at, %DateTime{} = now) do
    case safe_parse(expires_at) do
      {:ok, expires} ->
        remaining_days = DateTime.diff(expires, now, :second) / 86_400

        level =
          cond do
            DateTime.compare(now, expires) != :lt -> :expired
            remaining_days <= 30 -> :critical
            remaining_days <= 90 -> :warning
            remaining_days <= 180 -> :notice
            true -> :ok
          end

        {:ok, %{level: level, expires_at: expires, now: now}}

      error ->
        error
    end
  end

  # ---------------------------------------------------------------------
  # Nonce/state/audience/issuer/callback-url checks
  # ---------------------------------------------------------------------

  @doc """
  Constant-time nonce/state comparison (`Crypto.constant_time_equal?/2`) —
  these values gate a security-relevant decision (is this callback the one
  THIS login began), so comparing them must not leak timing information
  about how much of a guessed value matched, even though both are also
  bound inside a signed/encrypted envelope elsewhere in the chain; defense
  in depth costs nothing here. Replay protection at the app boundary
  (treating `PendingLogin` as single-use) is the caller's job.
  """
  def verify_nonce_state(expected_nonce, expected_state, actual_nonce, actual_state) do
    cond do
      not Crypto.constant_time_equal?(expected_nonce, actual_nonce) -> {:error, :nonce_mismatch}
      not Crypto.constant_time_equal?(expected_state, actual_state) -> {:error, :state_mismatch}
      true -> :ok
    end
  end

  def verify_audience(payload_audience_fingerprint, local_rp_fingerprint) do
    if payload_audience_fingerprint == local_rp_fingerprint,
      do: :ok,
      else: {:error, :audience_mismatch}
  end

  def verify_issuer(payload_user_domain, expected_domain) do
    if payload_user_domain == expected_domain, do: :ok, else: {:error, :issuer_mismatch}
  end

  def verify_callback_url(payload_callback_url, arrived_url) do
    if payload_callback_url == arrived_url, do: :ok, else: {:error, :callback_url_mismatch}
  end

  # ---------------------------------------------------------------------
  # Descriptor (build + sign only — verification is the IDP's job)
  # ---------------------------------------------------------------------

  @doc "`fingerprint` is always derived from `signing_public_key` — callers cannot set it directly, so it can never drift from the key it names."
  def build_local_rp_descriptor(
        app_name,
        local_domain_hint,
        signing_public_key,
        encryption_public_key,
        supported_suites,
        created_at,
        expires_at
      ) do
    %LocalRpDescriptor{
      app_name: app_name,
      local_domain_hint: local_domain_hint,
      signing_public_key: signing_public_key,
      encryption_public_key: encryption_public_key,
      fingerprint: Crypto.fingerprint(signing_public_key),
      supported_suites: supported_suites,
      created_at: created_at,
      expires_at: expires_at
    }
  end

  def sign_local_rp_descriptor(%LocalRpDescriptor{} = descriptor, private_key) do
    descriptor_bytes = Types.local_rp_descriptor_to_cbor(descriptor)
    signature_input = envelope_signature_input(@ctx_descriptor, descriptor_bytes)
    signature = Crypto.ed25519_sign(signature_input, private_key)
    %SignedLocalRpDescriptor{descriptor: descriptor_bytes, signature: signature}
  end

  # ---------------------------------------------------------------------
  # Login request (build + sign only)
  # ---------------------------------------------------------------------

  def build_local_rp_login_request(
        %SignedLocalRpDescriptor{} = descriptor,
        callback_url,
        nonce,
        state,
        requested_claims,
        required_claims,
        issued_at,
        expires_at
      ) do
    %LocalRpLoginRequest{
      descriptor: descriptor,
      callback_url: callback_url,
      nonce: nonce,
      state: state,
      requested_claims: requested_claims,
      required_claims: required_claims,
      issued_at: issued_at,
      expires_at: expires_at
    }
  end

  def sign_local_rp_login_request(%LocalRpLoginRequest{} = request, private_key) do
    request_bytes = Types.local_rp_login_request_to_cbor(request)
    signature_input = envelope_signature_input(@ctx_login_request, request_bytes)
    signature = Crypto.ed25519_sign(signature_input, private_key)
    %SignedLocalRpLoginRequest{request: request_bytes, signature: signature}
  end

  # ---------------------------------------------------------------------
  # Ticket redemption (build + sign — the RP's possession proof)
  # ---------------------------------------------------------------------

  def build_local_rp_ticket_redemption_request(claim_ticket, fingerprint, issued_at) do
    %LocalRpTicketRedemptionRequest{
      claim_ticket: claim_ticket,
      fingerprint: fingerprint,
      issued_at: issued_at
    }
  end

  def sign_local_rp_ticket_redemption_request(
        %LocalRpTicketRedemptionRequest{} = request,
        private_key
      ) do
    request_bytes = Types.local_rp_ticket_redemption_request_to_cbor(request)
    signature_input = envelope_signature_input(@ctx_ticket_redemption, request_bytes)
    signature = Crypto.ed25519_sign(signature_input, private_key)
    %SignedLocalRpTicketRedemptionRequest{request: request_bytes, signature: signature}
  end

  # ---------------------------------------------------------------------
  # Callback payload (build + sign — IDP-side, used only by this package's
  # own fake-IDP flow tests) / verify (RP-side, used by complete_local_login)
  # ---------------------------------------------------------------------

  def build_local_rp_callback_payload(
        user_id,
        user_domain,
        claim_ticket,
        audience_fingerprint,
        callback_url,
        nonce,
        state,
        issued_at,
        expires_at
      ) do
    %LocalRpCallbackPayload{
      user_id: user_id,
      user_domain: user_domain,
      claim_ticket: claim_ticket,
      audience_fingerprint: audience_fingerprint,
      callback_url: callback_url,
      nonce: nonce,
      state: state,
      issued_at: issued_at,
      expires_at: expires_at
    }
  end

  def sign_local_rp_callback_payload(%LocalRpCallbackPayload{} = payload, key_id, private_key) do
    payload_bytes = Types.local_rp_callback_payload_to_cbor(payload)
    signature_input = envelope_signature_input(@ctx_callback, payload_bytes)
    signature = Crypto.ed25519_sign(signature_input, private_key)

    %SignedLocalRpCallbackPayload{
      payload: payload_bytes,
      signing_key_id: key_id,
      signature: signature
    }
  end

  defp check_signing_key_valid(key, now) do
    cond do
      key.key_usage != "sign" ->
        {:error, :signature_invalid}

      key.revoked_at != nil ->
        {:error, {:key_revoked, key.key_id}}

      true ->
        case safe_parse(key.expires_at) do
          {:ok, expires} ->
            if DateTime.compare(now, expires) == :gt,
              do: {:error, {:key_expired, key.key_id}},
              else: :ok

          {:error, _} ->
            {:error, {:key_expired, key.key_id}}
        end
    end
  end

  @doc """
  Verify a domain-signed callback payload envelope against a set of
  domain public keys: resolve `signing_key_id`, reject a
  revoked/expired/non-signing key, verify the envelope signature, decode,
  then check `issued_at`/`expires_at` bounds. Nothing inside the payload is
  trusted before this succeeds.
  """
  @spec verify_local_rp_callback_payload(
          SignedLocalRpCallbackPayload.t(),
          list,
          DateTime.t(),
          integer
        ) :: {:ok, LocalRpCallbackPayload.t()} | {:error, term}
  def verify_local_rp_callback_payload(
        %SignedLocalRpCallbackPayload{} = signed,
        domain_public_keys,
        %DateTime{} = now,
        skew_seconds
      ) do
    with {:ok, key} <- find_key(domain_public_keys, signed.signing_key_id),
         :ok <- check_signing_key_valid(key, now),
         signature_input = envelope_signature_input(@ctx_callback, signed.payload),
         :ok <- verify_sig(signature_input, signed.signature, key.public_key) do
      payload = Types.local_rp_callback_payload_from_cbor(signed.payload)

      case check_timestamps(payload.issued_at, payload.expires_at, now, skew_seconds) do
        :ok -> {:ok, payload}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp find_key(keys, key_id) do
    case Enum.find(keys, fn k -> k.key_id == key_id end) do
      nil -> {:error, {:key_not_found, key_id}}
      key -> {:ok, key}
    end
  end

  defp verify_sig(message, signature, public_key) do
    if Crypto.ed25519_verify(message, signature, public_key),
      do: :ok,
      else: {:error, :signature_invalid}
  end

  @doc """
  Cross-check the cleartext callback header's routing fields against the
  authoritative copies inside the decrypted, signature-verified payload.
  The header is already bound as AEAD associated data, but a verifier must
  still consult the signed copies rather than trusting the header alone.
  """
  def check_callback_header_matches_payload(%LocalRpCallbackHeader{} = header, %LocalRpCallbackPayload{} = payload) do
    cond do
      header.fingerprint != payload.audience_fingerprint -> {:error, {:header_payload_mismatch, :fingerprint}}
      header.nonce != payload.nonce -> {:error, {:header_payload_mismatch, :nonce}}
      header.state != payload.state -> {:error, {:header_payload_mismatch, :state}}
      header.issued_at != payload.issued_at -> {:error, {:header_payload_mismatch, :issued_at}}
      header.expires_at != payload.expires_at -> {:error, {:header_payload_mismatch, :expires_at}}
      true -> :ok
    end
  end

  # ---------------------------------------------------------------------
  # Callback sealed box (Wire Precision: "Callback sealed box")
  # ---------------------------------------------------------------------

  defp local_rp_callback_kdf(suite, ephemeral_public, recipient_public, shared_secret) do
    context = @callback_box_tag <> suite <> ephemeral_public <> recipient_public
    key = Crypto.hkdf_sha256_expand(shared_secret, context, 32)
    {key, context}
  end

  @doc """
  Seal a `SignedLocalRpCallbackPayload` into a `LocalRpEncryptedCallback`
  for `recipient_encryption_public_key`, under `suite`. IDP-side operation —
  included here purely so this package's own tests can build a
  self-contained fake IDP.

  `opts[:ephemeral_private_key]` / `opts[:aead_nonce]` are
  deterministic-testing hooks: production callers must leave both unset so
  real OS randomness (`:crypto.strong_rand_bytes/1`) is used.
  """
  def seal_local_rp_callback(
        %SignedLocalRpCallbackPayload{} = signed_payload,
        suite,
        recipient_encryption_public_key,
        fingerprint,
        nonce,
        state,
        issued_at,
        expires_at,
        opts \\ []
      ) do
    ephemeral_private = Keyword.get(opts, :ephemeral_private_key) || :crypto.strong_rand_bytes(32)
    aead_nonce = Keyword.get(opts, :aead_nonce) || :crypto.strong_rand_bytes(12)

    ephemeral_public = Crypto.x25519_public_from_private(ephemeral_private)

    case Crypto.x25519_dh(ephemeral_private, recipient_encryption_public_key) do
      {:error, :low_order_key} ->
        {:error, :low_order_key}

      {:ok, shared_secret} ->
        plaintext = Types.signed_local_rp_callback_payload_to_cbor(signed_payload)

        header = %LocalRpCallbackHeader{
          fingerprint: fingerprint,
          nonce: nonce,
          state: state,
          suite: suite,
          ephemeral_public_key: ephemeral_public,
          aead_nonce: aead_nonce,
          issued_at: issued_at,
          expires_at: expires_at
        }

        header_bytes = Types.local_rp_callback_header_to_cbor(header)

        {aead_key, kdf_context} =
          local_rp_callback_kdf(suite, ephemeral_public, recipient_encryption_public_key, shared_secret)

        aad = kdf_context <> header_bytes
        ciphertext = Crypto.aead_encrypt(suite, aead_key, aead_nonce, aad, plaintext)

        {:ok, %LocalRpEncryptedCallback{header: header_bytes, ciphertext: ciphertext}}
    end
  end

  @doc """
  Open a `LocalRpEncryptedCallback` with the local RP's encryption private
  key. `allowed_suites` is the local RP's own supported-suite list (from
  its descriptor): a header advertising a suite NOT in that list is
  rejected even if it is otherwise a valid registry id.

  Returns `{:ok, header, signed_payload}` where `signed_payload` is still
  domain-signature-unverified — callers must still call
  `verify_local_rp_callback_payload/4` against fetched domain keys, and
  then `check_callback_header_matches_payload/2`, before trusting the
  result.
  """
  def open_local_rp_callback(%LocalRpEncryptedCallback{} = encrypted, recipient_encryption_private_key, allowed_suites) do
    with {:ok, header} <- safe_decode_header(encrypted.header),
         {:ok, suite} <- validate_suite(header.suite, allowed_suites),
         :ok <- validate_lengths(header),
         recipient_public = Crypto.x25519_public_from_private(recipient_encryption_private_key),
         {:ok, shared_secret} <-
           Crypto.x25519_dh(recipient_encryption_private_key, header.ephemeral_public_key) do
      {aead_key, kdf_context} =
        local_rp_callback_kdf(suite, header.ephemeral_public_key, recipient_public, shared_secret)

      aad = kdf_context <> encrypted.header

      case Crypto.aead_decrypt(suite, aead_key, header.aead_nonce, aad, encrypted.ciphertext) do
        {:ok, plaintext} ->
          case safe_decode_signed_payload(plaintext) do
            {:ok, signed_payload} -> {:ok, header, signed_payload}
            error -> error
          end

        {:error, reason} ->
          {:error, reason}
      end
    else
      {:error, :low_order_key} -> {:error, :low_order_key}
      {:error, reason} -> {:error, reason}
    end
  end

  defp safe_decode_header(bytes) do
    {:ok, Types.local_rp_callback_header_from_cbor(bytes)}
  rescue
    _ -> {:error, :decode_failed}
  end

  defp safe_decode_signed_payload(bytes) do
    {:ok, Types.signed_local_rp_callback_payload_from_cbor(bytes)}
  rescue
    _ -> {:error, :decode_failed}
  end

  defp validate_suite(suite_id, allowed_suites) do
    case Crypto.parse_suite(suite_id) do
      nil -> {:error, {:unsupported_suite, suite_id}}
      suite -> if suite in allowed_suites, do: {:ok, suite}, else: {:error, {:suite_not_advertised, suite_id}}
    end
  end

  defp validate_lengths(%LocalRpCallbackHeader{} = header) do
    cond do
      byte_size(header.ephemeral_public_key) != 32 -> {:error, :invalid_key_length}
      byte_size(header.aead_nonce) != 12 -> {:error, :invalid_key_length}
      true -> :ok
    end
  end
end
