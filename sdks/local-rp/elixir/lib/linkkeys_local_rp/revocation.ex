defmodule LinkkeysLocalRp.Revocation do
  @moduledoc """
  Sibling-signed key revocation certificate verification.

  Mirrors `crates/liblinkkeys/src/revocation.rs`. Only verification is
  ported here — building/signing a revocation certificate is a
  domain-admin/server-side operation, out of scope for a local-RP SDK.
  This SDK verifies revocation certificates fetched alongside domain keys
  (`LinkkeysLocalRp.Rpc.fetch_domain_keys/3`) so it can drop a key a
  quorum-verified sibling revocation targets *before* any envelope or
  claim verification consults the key set.

  Wire-precision gotchas, per `sdks/local-rp/conformance/README.md`'s
  `revocations.json` section (these are exactly what the vectors punish):

  - The signed payload is `CBOR([tag, target_key_id, target_fingerprint,
    revoked_at, signing_domain])` — a **five-element** CBOR array with the
    domain-separation tag `linkkeys-key-revocation-v1` first. This is the
    older house tuple pattern, NOT the local-RP envelopes' two-element
    `CBOR([context, payload])` framing.
  - The verifier recomputes each signature's payload from that signature's
    **wire** `domain` field; the `domain` parameter only *filters* which
    signatures are eligible. (This is what defeats cross-domain signature
    reuse: a signature whose wire `domain` lies about its binding
    recomputes to different bytes and fails.)
  - Sibling-key validity (expiry/revocation) is a **wall-clock** check in
    the Rust implementation (`check_signing_key_valid` takes no `now`);
    this port defaults `now` to the wall clock and only accepts an
    override for tests.
  - Invalid signatures are silently skipped; distinctness is by signer key
    id; the only failure mode is an insufficient count of valid signers.
  """

  alias LinkkeysLocalRp.Cbor
  alias LinkkeysLocalRp.Crypto
  alias LinkkeysLocalRp.Timeutil
  alias LinkkeysLocalRp.Types.RevocationCertificate

  @revocation_quorum 2
  def revocation_quorum, do: @revocation_quorum

  @revocation_tag "linkkeys-key-revocation-v1"

  @doc "The canonical signed bytes: `CBOR([tag, target_key_id, target_fingerprint, revoked_at, signing_domain])` — the signing sibling's domain is bound per-signature to stop cross-domain reuse."
  def revocation_payload(target_key_id, target_fingerprint, revoked_at, signing_domain) do
    Cbor.encode([@revocation_tag, target_key_id, target_fingerprint, revoked_at, signing_domain])
  end

  @doc """
  Count the DISTINCT signer key ids whose signature survives every
  filtering rule (not the target, wire domain equals `domain`, signer key
  present + currently-valid signing key) and cryptographically verifies
  over the recomputed payload. `now` defaults to the wall clock — the
  override exists for deterministic tests only.
  """
  def count_valid_signers(%RevocationCertificate{} = cert, domain_keys, domain, now \\ nil) do
    now = now || DateTime.utc_now()

    cert.signatures
    |> Enum.reduce(MapSet.new(), fn sig, acc ->
      if signer_counts?(sig, cert, domain_keys, domain, now),
        do: MapSet.put(acc, sig.signed_by_key_id),
        else: acc
    end)
    |> MapSet.size()
  end

  defp signer_counts?(sig, cert, domain_keys, domain, now) do
    cond do
      # A key can never authorize its own revocation.
      sig.signed_by_key_id == cert.target_key_id ->
        false

      # The signature must be bound to this domain (filter only; the
      # payload is recomputed below from the signature's own wire field).
      sig.domain != domain ->
        false

      true ->
        case Enum.find(domain_keys, fn k -> k.key_id == sig.signed_by_key_id end) do
          nil ->
            false

          key ->
            key.key_usage == "sign" and key_currently_valid?(key, now) and
              verifies_revocation_signature?(sig, cert, key)
        end
    end
  end

  defp verifies_revocation_signature?(sig, cert, key) do
    payload = revocation_payload(cert.target_key_id, cert.target_fingerprint, cert.revoked_at, sig.domain)
    Crypto.ed25519_verify(payload, sig.signature, key.public_key)
  end

  defp key_currently_valid?(key, now) do
    if key.revoked_at != nil do
      false
    else
      case safe_parse(key.expires_at) do
        {:ok, expires} -> DateTime.compare(now, expires) != :gt
        {:error, _} -> false
      end
    end
  end

  defp safe_parse(s) do
    {:ok, Timeutil.parse_rfc3339(s)}
  rescue
    _ -> {:error, :bad_timestamp}
  end

  @doc "Verify a revocation certificate against a domain's public key set. Requires at least `revocation_quorum/0` DISTINCT signing keys of `domain`, each currently valid and NOT the target key, to have signed the canonical payload."
  def verify_revocation_certificate(%RevocationCertificate{} = cert, domain_keys, domain, now \\ nil) do
    got = count_valid_signers(cert, domain_keys, domain, now)
    if got >= @revocation_quorum, do: :ok, else: {:error, {:insufficient_quorum, got, @revocation_quorum}}
  end

  @doc """
  Apply quorum-verified revocation certificates to a trusted key set: any
  key a valid certificate targets is dropped, no matter what the fetched
  key entry itself says (its own `revoked_at` may well be unset — that is
  the whole point of the sibling-certificate channel). Certificates that
  fail verification are ignored. Returns the filtered list.
  """
  def apply_revocations(trusted, revocations, domain, now \\ nil) do
    Enum.reduce(revocations, trusted, fn cert, keys ->
      case verify_revocation_certificate(cert, keys, domain, now) do
        :ok -> Enum.reject(keys, fn k -> k.key_id == cert.target_key_id end)
        {:error, _} -> keys
      end
    end)
  end
end
