defmodule LinkkeysLocalRp.Claims do
  @moduledoc """
  Claim signature/revocation/expiry verification.

  Mirrors `crates/liblinkkeys/src/claims.rs` for exactly the pieces
  `complete_local_login` needs: per-signer-domain signature quorum,
  revocation, and expiry. `sign_claim/2` is included only so this
  package's own flow tests can build fake claims exactly like
  `sdks/local-rp/rust/tests/flow.rs` does (IDP-side operation; the SDK
  itself only ever verifies claims returned from a ticket redemption,
  never signs them).
  """

  alias LinkkeysLocalRp.Cbor
  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Types.{Claim, ClaimSignature}

  @claim_payload_tag "linkkeys-claim-v2"

  defmodule DomainKeySet do
    @moduledoc "A signer domain and the (already DNS-pinned) public keys fetched for it."
    defstruct [:domain, :keys]
  end

  defmodule ClaimSpec do
    @moduledoc "Test-support input to `sign_claim/2` (IDP-side operation)."
    defstruct [
      :claim_id,
      :claim_type,
      :claim_value,
      :user_id,
      :subject_domain,
      :attested_at,
      expires_at: nil
    ]
  end

  defmodule ClaimSigner do
    @moduledoc "Test-support signer input to `sign_claim/2`."
    defstruct [:domain, :key_id, :private_key]
  end

  defp claim_sign_payload(
         claim_id,
         claim_type,
         claim_value,
         user_id,
         subject_domain,
         signing_domain,
         expires_at,
         attested_at
       ) do
    # The subject is bound as the single full identity `user_id@subject_domain`
    # (not the bare user_id), so a claim about a user_id at one domain can't
    # be replayed as the same user_id at another. `signing_domain` — the
    # attestor for THIS signature — is bound per-signature.
    subject = "#{user_id}@#{subject_domain}"

    Cbor.encode([
      @claim_payload_tag,
      claim_id,
      claim_type,
      Cbor.bytes(claim_value),
      subject,
      signing_domain,
      expires_at,
      attested_at
    ])
  end

  @doc "Sign a claim with one or more keys, producing a `Claim` carrying one `ClaimSignature` per signer. IDP-side operation; see module docs."
  def sign_claim(%ClaimSpec{} = spec, signers) when is_list(signers) do
    signatures =
      Enum.map(signers, fn %ClaimSigner{} = signer ->
        payload =
          claim_sign_payload(
            spec.claim_id,
            spec.claim_type,
            spec.claim_value,
            spec.user_id,
            spec.subject_domain,
            signer.domain,
            spec.expires_at,
            spec.attested_at
          )

        signature = Crypto.ed25519_sign(payload, signer.private_key)
        %ClaimSignature{domain: signer.domain, signed_by_key_id: signer.key_id, signature: signature}
      end)

    %Claim{
      claim_id: spec.claim_id,
      user_id: spec.user_id,
      claim_type: spec.claim_type,
      claim_value: spec.claim_value,
      signatures: signatures,
      attested_at: spec.attested_at,
      created_at: spec.attested_at,
      expires_at: spec.expires_at,
      revoked_at: nil
    }
  end

  defp verify_one_signature(%ClaimSignature{} = sig, payload, keys, now) do
    case Enum.find(keys, fn k -> k.key_id == sig.signed_by_key_id end) do
      nil ->
        {:error, {:key_not_found, sig.signed_by_key_id}}

      key ->
        cond do
          key.key_usage != "sign" ->
            {:error, :signature_invalid}

          # Gates the SIGNING KEY's own revocation/expiry (not the claim's,
          # which verify_claim/4 checks separately). `now` is threaded
          # through explicitly (this SDK never reads the system clock
          # internally), which is strictly more testable/deterministic
          # than liblinkkeys' own key-validity check (which reads
          # Utc::now() directly at this exact point, a documented
          # exception to its "explicit now" discipline).
          key.revoked_at != nil ->
            {:error, {:key_revoked, key.key_id}}

          true ->
            case key_valid_at(key, now) do
              :ok ->
                if Crypto.ed25519_verify(payload, sig.signature, key.public_key),
                  do: :ok,
                  else: {:error, :signature_invalid}

              error ->
                error
            end
        end
    end
  end

  defp key_valid_at(key, now) do
    case safe_parse(key.expires_at) do
      {:ok, expires} ->
        if DateTime.compare(now, expires) == :gt,
          do: {:error, {:key_expired, key.key_id}},
          else: :ok

      {:error, _} ->
        {:error, {:key_expired, key.key_id}}
    end
  end

  defp safe_parse(s) do
    {:ok, Timeutil.parse_rfc3339(s)}
  rescue
    _ -> {:error, :bad_timestamp}
  end

  @doc "Every distinct domain that signed must contribute at least one signature from a currently-valid key of that domain."
  def verify_claim_signatures(%Claim{} = claim, subject_domain, domain_keys, now) do
    if claim.signatures == [] do
      {:error, :unsigned}
    else
      domains = claim.signatures |> Enum.map(& &1.domain) |> Enum.uniq() |> Enum.sort()
      do_verify_domains(domains, claim, subject_domain, domain_keys, now)
    end
  end

  defp do_verify_domains([], _claim, _subject_domain, _domain_keys, _now), do: :ok

  defp do_verify_domains([signing_domain | rest], claim, subject_domain, domain_keys, now) do
    case Enum.find(domain_keys, fn s -> s.domain == signing_domain end) do
      nil ->
        {:error, {:domain_keys_unavailable, signing_domain}}

      %DomainKeySet{keys: keys} ->
        payload =
          claim_sign_payload(
            claim.claim_id,
            claim.claim_type,
            claim.claim_value,
            claim.user_id,
            subject_domain,
            signing_domain,
            claim.expires_at,
            claim.attested_at
          )

        sigs_for_domain = Enum.filter(claim.signatures, fn s -> s.domain == signing_domain end)

        case verify_any(sigs_for_domain, payload, keys, now) do
          :ok -> do_verify_domains(rest, claim, subject_domain, domain_keys, now)
          error -> error
        end
    end
  end

  defp verify_any([], _payload, _keys, _now), do: {:error, {:domain_unverified, nil}}

  defp verify_any([sig | rest], payload, keys, now) do
    case verify_one_signature(sig, payload, keys, now) do
      :ok -> :ok
      {:error, _} = err -> if rest == [], do: err, else: verify_any(rest, payload, keys, now)
    end
  end

  @doc "Full claim verification: the cryptographic per-domain quorum plus the claim's own revocation and expiry. All must pass."
  def verify_claim(%Claim{} = claim, subject_domain, domain_keys, now) do
    with :ok <- verify_claim_signatures(claim, subject_domain, domain_keys, now) do
      cond do
        claim.revoked_at != nil ->
          {:error, :revoked}

        claim.expires_at != nil ->
          case safe_parse(claim.expires_at) do
            {:ok, expires} ->
              if DateTime.compare(now, expires) == :gt, do: {:error, :expired}, else: :ok

            {:error, _} ->
              {:error, :bad_expiry}
          end

        true ->
          :ok
      end
    end
  end
end
