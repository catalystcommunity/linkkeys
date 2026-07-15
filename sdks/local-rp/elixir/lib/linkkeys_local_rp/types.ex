defmodule LinkkeysLocalRp.Types do
  @moduledoc """
  Hand-written CSIL wire types for exactly the records this SDK needs, with
  `to_cbor/1` / `from_cbor/1` for each (mirroring the shape csilgen's
  generated `types.py` + `codec.py` produce for the sibling SDKs — see
  `sdks/local-rp/python/linkkeys_local_rp/generated/`). There is no csilgen
  Elixir target yet (request filed; see `LinkkeysLocalRp.Cbor` docs), so
  these are hand-maintained. Field shapes come from `dns-less-local-rp-design.md`'s
  "CSIL Work" section and from the conformance vectors' exact byte layouts.

  Every struct's `to_cbor/1` builds a plain Elixir map (text-string keys,
  `LinkkeysLocalRp.Cbor.Bytes` wrappers around byte fields, optional fields
  omitted entirely when `nil`) and hands it to `Cbor.encode/1`, which sorts
  map keys canonically — so encode order here never has to match any
  particular field declaration order to be wire-correct.
  """

  alias LinkkeysLocalRp.Cbor

  defmodule DomainPublicKey do
    @moduledoc "A domain's published signing or encryption key (CSIL `DomainPublicKey`)."
    defstruct [
      :key_id,
      :public_key,
      :fingerprint,
      :algorithm,
      :key_usage,
      :created_at,
      :expires_at,
      revoked_at: nil,
      signed_by_key_id: nil,
      key_signature: nil
    ]
  end

  defmodule ClaimSignature do
    @moduledoc "One domain's signature over a claim or revocation payload (CSIL `ClaimSignature`)."
    defstruct [:domain, :signed_by_key_id, :signature]
  end

  defmodule Claim do
    @moduledoc "A signed claim value (CSIL `Claim`)."
    defstruct [
      :claim_id,
      :user_id,
      :claim_type,
      :claim_value,
      :signatures,
      :attested_at,
      :created_at,
      expires_at: nil,
      revoked_at: nil
    ]
  end

  defmodule RevocationCertificate do
    @moduledoc "A sibling-signed key revocation certificate (CSIL `RevocationCertificate`)."
    defstruct [:target_key_id, :target_fingerprint, :revoked_at, :signatures]
  end

  defmodule LocalRpDescriptor do
    @moduledoc "CSIL `LocalRpDescriptor` — the unsigned local-RP descriptor payload."
    defstruct [
      :app_name,
      :signing_public_key,
      :encryption_public_key,
      :fingerprint,
      :supported_suites,
      :created_at,
      :expires_at,
      local_domain_hint: nil
    ]
  end

  defmodule SignedLocalRpDescriptor do
    @moduledoc "CSIL `SignedLocalRpDescriptor` — envelope around the exact `LocalRpDescriptor` CBOR bytes."
    defstruct [:descriptor, :signature]
  end

  defmodule LocalRpLoginRequest do
    @moduledoc "CSIL `LocalRpLoginRequest` — the unsigned login-request payload."
    defstruct [
      :descriptor,
      :callback_url,
      :nonce,
      :state,
      :requested_claims,
      :required_claims,
      :issued_at,
      :expires_at
    ]
  end

  defmodule SignedLocalRpLoginRequest do
    @moduledoc "CSIL `SignedLocalRpLoginRequest` — envelope around the exact `LocalRpLoginRequest` CBOR bytes."
    defstruct [:request, :signature]
  end

  defmodule LocalRpCallbackHeader do
    @moduledoc "CSIL `LocalRpCallbackHeader` — cleartext routing/decryption metadata, bound as AEAD AAD."
    defstruct [
      :fingerprint,
      :nonce,
      :state,
      :suite,
      :ephemeral_public_key,
      :aead_nonce,
      :issued_at,
      :expires_at
    ]
  end

  defmodule LocalRpEncryptedCallback do
    @moduledoc "CSIL `LocalRpEncryptedCallback` — the header + sealed-box ciphertext delivered via the callback URL."
    defstruct [:header, :ciphertext]
  end

  defmodule LocalRpCallbackPayload do
    @moduledoc "CSIL `LocalRpCallbackPayload` — the authoritative, domain-signed, encrypted payload."
    defstruct [
      :user_id,
      :user_domain,
      :claim_ticket,
      :audience_fingerprint,
      :callback_url,
      :nonce,
      :state,
      :issued_at,
      :expires_at
    ]
  end

  defmodule SignedLocalRpCallbackPayload do
    @moduledoc "CSIL `SignedLocalRpCallbackPayload` — domain-signed envelope (carries `signing_key_id`, unlike the RP-signed envelopes)."
    defstruct [:payload, :signing_key_id, :signature]
  end

  defmodule LocalRpTicketRedemptionRequest do
    @moduledoc "CSIL `LocalRpTicketRedemptionRequest` — the unsigned ticket-redemption payload."
    defstruct [:claim_ticket, :fingerprint, :issued_at]
  end

  defmodule SignedLocalRpTicketRedemptionRequest do
    @moduledoc "CSIL `SignedLocalRpTicketRedemptionRequest` — envelope, local-RP-signed (the possession proof)."
    defstruct [:request, :signature]
  end

  defmodule LocalRpTicketRedemptionResponse do
    @moduledoc "CSIL `LocalRpTicketRedemptionResponse` — claims returned by a ticket redemption."
    defstruct [:user_id, :user_domain, :claims, :ticket_expires_at]
  end

  defmodule EmptyRequest do
    @moduledoc "CSIL `EmptyRequest` — no fields."
    defstruct []
  end

  defmodule GetDomainKeysResponse do
    @moduledoc "CSIL `GetDomainKeysResponse`."
    defstruct [:domain, :keys, recent_revocations_available: nil]
  end

  defmodule GetRevocationsRequest do
    @moduledoc "CSIL `GetRevocationsRequest`."
    defstruct since: nil
  end

  defmodule GetRevocationsResponse do
    @moduledoc "CSIL `GetRevocationsResponse`."
    defstruct [:revocations]
  end

  # -- helpers -----------------------------------------------------------

  defp put_opt(map, _key, nil), do: map
  defp put_opt(map, key, value), do: Map.put(map, key, value)

  defp opt_bytes!(nil), do: nil
  defp opt_bytes!(v), do: Cbor.bytes!(v)

  defp get(tree, key), do: Map.fetch!(tree, key)
  defp get_opt(tree, key), do: Map.get(tree, key)

  defp map_list(list, f), do: Enum.map(list, f)

  # -- DomainPublicKey -----------------------------------------------------

  def domain_public_key_to_tree(%DomainPublicKey{} = v) do
    %{
      "key_id" => v.key_id,
      "public_key" => Cbor.bytes(v.public_key),
      "fingerprint" => v.fingerprint,
      "algorithm" => v.algorithm,
      "key_usage" => v.key_usage,
      "created_at" => v.created_at,
      "expires_at" => v.expires_at
    }
    |> put_opt("revoked_at", v.revoked_at)
    |> put_opt("signed_by_key_id", v.signed_by_key_id)
    |> put_opt("key_signature", if(v.key_signature, do: Cbor.bytes(v.key_signature)))
  end

  def domain_public_key_to_cbor(%DomainPublicKey{} = v), do: Cbor.encode(domain_public_key_to_tree(v))

  def domain_public_key_from_tree(tree) do
    %DomainPublicKey{
      key_id: get(tree, "key_id"),
      public_key: Cbor.bytes!(get(tree, "public_key")),
      fingerprint: get(tree, "fingerprint"),
      algorithm: get(tree, "algorithm"),
      key_usage: get(tree, "key_usage"),
      created_at: get(tree, "created_at"),
      expires_at: get(tree, "expires_at"),
      revoked_at: get_opt(tree, "revoked_at"),
      signed_by_key_id: get_opt(tree, "signed_by_key_id"),
      key_signature: opt_bytes!(get_opt(tree, "key_signature"))
    }
  end

  def domain_public_key_from_cbor(data), do: domain_public_key_from_tree(Cbor.decode(data))

  # -- ClaimSignature --------------------------------------------------

  def claim_signature_to_tree(%ClaimSignature{} = v) do
    %{
      "domain" => v.domain,
      "signed_by_key_id" => v.signed_by_key_id,
      "signature" => Cbor.bytes(v.signature)
    }
  end

  def claim_signature_to_cbor(%ClaimSignature{} = v), do: Cbor.encode(claim_signature_to_tree(v))

  def claim_signature_from_tree(tree) do
    %ClaimSignature{
      domain: get(tree, "domain"),
      signed_by_key_id: get(tree, "signed_by_key_id"),
      signature: Cbor.bytes!(get(tree, "signature"))
    }
  end

  def claim_signature_from_cbor(data), do: claim_signature_from_tree(Cbor.decode(data))

  # -- Claim -------------------------------------------------------------

  def claim_to_tree(%Claim{} = v) do
    %{
      "claim_id" => v.claim_id,
      "user_id" => v.user_id,
      "claim_type" => v.claim_type,
      "claim_value" => Cbor.bytes(v.claim_value),
      "signatures" => Enum.map(v.signatures, &claim_signature_to_tree/1),
      "attested_at" => v.attested_at,
      "created_at" => v.created_at
    }
    |> put_opt("expires_at", v.expires_at)
    |> put_opt("revoked_at", v.revoked_at)
  end

  def claim_to_cbor(%Claim{} = v), do: Cbor.encode(claim_to_tree(v))

  def claim_from_tree(tree) do
    %Claim{
      claim_id: get(tree, "claim_id"),
      user_id: get(tree, "user_id"),
      claim_type: get(tree, "claim_type"),
      claim_value: Cbor.bytes!(get(tree, "claim_value")),
      signatures: map_list(get(tree, "signatures"), &claim_signature_from_tree/1),
      attested_at: get(tree, "attested_at"),
      created_at: get(tree, "created_at"),
      expires_at: get_opt(tree, "expires_at"),
      revoked_at: get_opt(tree, "revoked_at")
    }
  end

  def claim_from_cbor(data), do: claim_from_tree(Cbor.decode(data))

  # -- RevocationCertificate --------------------------------------------

  def revocation_certificate_to_tree(%RevocationCertificate{} = v) do
    %{
      "target_key_id" => v.target_key_id,
      "target_fingerprint" => v.target_fingerprint,
      "revoked_at" => v.revoked_at,
      "signatures" => Enum.map(v.signatures, &claim_signature_to_tree/1)
    }
  end

  def revocation_certificate_to_cbor(%RevocationCertificate{} = v),
    do: Cbor.encode(revocation_certificate_to_tree(v))

  def revocation_certificate_from_tree(tree) do
    %RevocationCertificate{
      target_key_id: get(tree, "target_key_id"),
      target_fingerprint: get(tree, "target_fingerprint"),
      revoked_at: get(tree, "revoked_at"),
      signatures: map_list(get(tree, "signatures"), &claim_signature_from_tree/1)
    }
  end

  def revocation_certificate_from_cbor(data),
    do: revocation_certificate_from_tree(Cbor.decode(data))

  # -- LocalRpDescriptor --------------------------------------------------

  def local_rp_descriptor_to_tree(%LocalRpDescriptor{} = v) do
    if byte_size(v.signing_public_key) != 32,
      do: raise(ArgumentError, "signing_public_key must be 32 bytes")

    if byte_size(v.encryption_public_key) != 32,
      do: raise(ArgumentError, "encryption_public_key must be 32 bytes")

    %{
      "app_name" => v.app_name,
      "signing_public_key" => Cbor.bytes(v.signing_public_key),
      "encryption_public_key" => Cbor.bytes(v.encryption_public_key),
      "fingerprint" => v.fingerprint,
      "supported_suites" => v.supported_suites,
      "created_at" => v.created_at,
      "expires_at" => v.expires_at
    }
    |> put_opt("local_domain_hint", v.local_domain_hint)
  end

  def local_rp_descriptor_to_cbor(%LocalRpDescriptor{} = v),
    do: Cbor.encode(local_rp_descriptor_to_tree(v))

  def local_rp_descriptor_from_tree(tree) do
    %LocalRpDescriptor{
      app_name: get(tree, "app_name"),
      signing_public_key: Cbor.bytes!(get(tree, "signing_public_key")),
      encryption_public_key: Cbor.bytes!(get(tree, "encryption_public_key")),
      fingerprint: get(tree, "fingerprint"),
      supported_suites: get(tree, "supported_suites"),
      created_at: get(tree, "created_at"),
      expires_at: get(tree, "expires_at"),
      local_domain_hint: get_opt(tree, "local_domain_hint")
    }
  end

  def local_rp_descriptor_from_cbor(data), do: local_rp_descriptor_from_tree(Cbor.decode(data))

  # -- SignedLocalRpDescriptor --------------------------------------------

  def signed_local_rp_descriptor_to_tree(%SignedLocalRpDescriptor{} = v) do
    %{"descriptor" => Cbor.bytes(v.descriptor), "signature" => Cbor.bytes(v.signature)}
  end

  def signed_local_rp_descriptor_to_cbor(%SignedLocalRpDescriptor{} = v),
    do: Cbor.encode(signed_local_rp_descriptor_to_tree(v))

  def signed_local_rp_descriptor_from_tree(tree) do
    %SignedLocalRpDescriptor{
      descriptor: Cbor.bytes!(get(tree, "descriptor")),
      signature: Cbor.bytes!(get(tree, "signature"))
    }
  end

  def signed_local_rp_descriptor_from_cbor(data),
    do: signed_local_rp_descriptor_from_tree(Cbor.decode(data))

  # -- LocalRpLoginRequest ------------------------------------------------

  def local_rp_login_request_to_tree(%LocalRpLoginRequest{} = v) do
    %{
      "descriptor" => signed_local_rp_descriptor_to_tree(v.descriptor),
      "callback_url" => v.callback_url,
      "nonce" => Cbor.bytes(v.nonce),
      "state" => Cbor.bytes(v.state),
      "requested_claims" => v.requested_claims,
      "required_claims" => v.required_claims,
      "issued_at" => v.issued_at,
      "expires_at" => v.expires_at
    }
  end

  def local_rp_login_request_to_cbor(%LocalRpLoginRequest{} = v),
    do: Cbor.encode(local_rp_login_request_to_tree(v))

  def local_rp_login_request_from_tree(tree) do
    %LocalRpLoginRequest{
      descriptor: signed_local_rp_descriptor_from_tree(get(tree, "descriptor")),
      callback_url: get(tree, "callback_url"),
      nonce: Cbor.bytes!(get(tree, "nonce")),
      state: Cbor.bytes!(get(tree, "state")),
      requested_claims: get(tree, "requested_claims"),
      required_claims: get(tree, "required_claims"),
      issued_at: get(tree, "issued_at"),
      expires_at: get(tree, "expires_at")
    }
  end

  def local_rp_login_request_from_cbor(data),
    do: local_rp_login_request_from_tree(Cbor.decode(data))

  # -- SignedLocalRpLoginRequest -------------------------------------------

  def signed_local_rp_login_request_to_tree(%SignedLocalRpLoginRequest{} = v) do
    %{"request" => Cbor.bytes(v.request), "signature" => Cbor.bytes(v.signature)}
  end

  def signed_local_rp_login_request_to_cbor(%SignedLocalRpLoginRequest{} = v),
    do: Cbor.encode(signed_local_rp_login_request_to_tree(v))

  def signed_local_rp_login_request_from_tree(tree) do
    %SignedLocalRpLoginRequest{
      request: Cbor.bytes!(get(tree, "request")),
      signature: Cbor.bytes!(get(tree, "signature"))
    }
  end

  def signed_local_rp_login_request_from_cbor(data),
    do: signed_local_rp_login_request_from_tree(Cbor.decode(data))

  # -- LocalRpCallbackHeader ------------------------------------------------

  def local_rp_callback_header_to_tree(%LocalRpCallbackHeader{} = v) do
    if byte_size(v.ephemeral_public_key) != 32,
      do: raise(ArgumentError, "ephemeral_public_key must be 32 bytes")

    if byte_size(v.aead_nonce) != 12, do: raise(ArgumentError, "aead_nonce must be 12 bytes")

    %{
      "fingerprint" => v.fingerprint,
      "nonce" => Cbor.bytes(v.nonce),
      "state" => Cbor.bytes(v.state),
      "suite" => v.suite,
      "ephemeral_public_key" => Cbor.bytes(v.ephemeral_public_key),
      "aead_nonce" => Cbor.bytes(v.aead_nonce),
      "issued_at" => v.issued_at,
      "expires_at" => v.expires_at
    }
  end

  def local_rp_callback_header_to_cbor(%LocalRpCallbackHeader{} = v),
    do: Cbor.encode(local_rp_callback_header_to_tree(v))

  def local_rp_callback_header_from_tree(tree) do
    %LocalRpCallbackHeader{
      fingerprint: get(tree, "fingerprint"),
      nonce: Cbor.bytes!(get(tree, "nonce")),
      state: Cbor.bytes!(get(tree, "state")),
      suite: get(tree, "suite"),
      ephemeral_public_key: Cbor.bytes!(get(tree, "ephemeral_public_key")),
      aead_nonce: Cbor.bytes!(get(tree, "aead_nonce")),
      issued_at: get(tree, "issued_at"),
      expires_at: get(tree, "expires_at")
    }
  end

  def local_rp_callback_header_from_cbor(data),
    do: local_rp_callback_header_from_tree(Cbor.decode(data))

  # -- LocalRpEncryptedCallback ---------------------------------------------

  def local_rp_encrypted_callback_to_tree(%LocalRpEncryptedCallback{} = v) do
    %{"header" => Cbor.bytes(v.header), "ciphertext" => Cbor.bytes(v.ciphertext)}
  end

  def local_rp_encrypted_callback_to_cbor(%LocalRpEncryptedCallback{} = v),
    do: Cbor.encode(local_rp_encrypted_callback_to_tree(v))

  def local_rp_encrypted_callback_from_tree(tree) do
    %LocalRpEncryptedCallback{
      header: Cbor.bytes!(get(tree, "header")),
      ciphertext: Cbor.bytes!(get(tree, "ciphertext"))
    }
  end

  def local_rp_encrypted_callback_from_cbor(data),
    do: local_rp_encrypted_callback_from_tree(Cbor.decode(data))

  # -- LocalRpCallbackPayload -----------------------------------------------

  def local_rp_callback_payload_to_tree(%LocalRpCallbackPayload{} = v) do
    %{
      "user_id" => v.user_id,
      "user_domain" => v.user_domain,
      "claim_ticket" => Cbor.bytes(v.claim_ticket),
      "audience_fingerprint" => v.audience_fingerprint,
      "callback_url" => v.callback_url,
      "nonce" => Cbor.bytes(v.nonce),
      "state" => Cbor.bytes(v.state),
      "issued_at" => v.issued_at,
      "expires_at" => v.expires_at
    }
  end

  def local_rp_callback_payload_to_cbor(%LocalRpCallbackPayload{} = v),
    do: Cbor.encode(local_rp_callback_payload_to_tree(v))

  def local_rp_callback_payload_from_tree(tree) do
    %LocalRpCallbackPayload{
      user_id: get(tree, "user_id"),
      user_domain: get(tree, "user_domain"),
      claim_ticket: Cbor.bytes!(get(tree, "claim_ticket")),
      audience_fingerprint: get(tree, "audience_fingerprint"),
      callback_url: get(tree, "callback_url"),
      nonce: Cbor.bytes!(get(tree, "nonce")),
      state: Cbor.bytes!(get(tree, "state")),
      issued_at: get(tree, "issued_at"),
      expires_at: get(tree, "expires_at")
    }
  end

  def local_rp_callback_payload_from_cbor(data),
    do: local_rp_callback_payload_from_tree(Cbor.decode(data))

  # -- SignedLocalRpCallbackPayload -----------------------------------------

  def signed_local_rp_callback_payload_to_tree(%SignedLocalRpCallbackPayload{} = v) do
    %{
      "payload" => Cbor.bytes(v.payload),
      "signing_key_id" => v.signing_key_id,
      "signature" => Cbor.bytes(v.signature)
    }
  end

  def signed_local_rp_callback_payload_to_cbor(%SignedLocalRpCallbackPayload{} = v),
    do: Cbor.encode(signed_local_rp_callback_payload_to_tree(v))

  def signed_local_rp_callback_payload_from_tree(tree) do
    %SignedLocalRpCallbackPayload{
      payload: Cbor.bytes!(get(tree, "payload")),
      signing_key_id: get(tree, "signing_key_id"),
      signature: Cbor.bytes!(get(tree, "signature"))
    }
  end

  def signed_local_rp_callback_payload_from_cbor(data),
    do: signed_local_rp_callback_payload_from_tree(Cbor.decode(data))

  # -- LocalRpTicketRedemptionRequest ---------------------------------------

  def local_rp_ticket_redemption_request_to_tree(%LocalRpTicketRedemptionRequest{} = v) do
    %{
      "claim_ticket" => Cbor.bytes(v.claim_ticket),
      "fingerprint" => v.fingerprint,
      "issued_at" => v.issued_at
    }
  end

  def local_rp_ticket_redemption_request_to_cbor(%LocalRpTicketRedemptionRequest{} = v),
    do: Cbor.encode(local_rp_ticket_redemption_request_to_tree(v))

  def local_rp_ticket_redemption_request_from_tree(tree) do
    %LocalRpTicketRedemptionRequest{
      claim_ticket: Cbor.bytes!(get(tree, "claim_ticket")),
      fingerprint: get(tree, "fingerprint"),
      issued_at: get(tree, "issued_at")
    }
  end

  def local_rp_ticket_redemption_request_from_cbor(data),
    do: local_rp_ticket_redemption_request_from_tree(Cbor.decode(data))

  # -- SignedLocalRpTicketRedemptionRequest ----------------------------------

  def signed_local_rp_ticket_redemption_request_to_tree(%SignedLocalRpTicketRedemptionRequest{} = v) do
    %{"request" => Cbor.bytes(v.request), "signature" => Cbor.bytes(v.signature)}
  end

  def signed_local_rp_ticket_redemption_request_to_cbor(%SignedLocalRpTicketRedemptionRequest{} = v),
    do: Cbor.encode(signed_local_rp_ticket_redemption_request_to_tree(v))

  def signed_local_rp_ticket_redemption_request_from_tree(tree) do
    %SignedLocalRpTicketRedemptionRequest{
      request: Cbor.bytes!(get(tree, "request")),
      signature: Cbor.bytes!(get(tree, "signature"))
    }
  end

  def signed_local_rp_ticket_redemption_request_from_cbor(data),
    do: signed_local_rp_ticket_redemption_request_from_tree(Cbor.decode(data))

  # -- LocalRpTicketRedemptionResponse ---------------------------------------

  def local_rp_ticket_redemption_response_to_tree(%LocalRpTicketRedemptionResponse{} = v) do
    %{
      "user_id" => v.user_id,
      "user_domain" => v.user_domain,
      "claims" => Enum.map(v.claims, &claim_to_tree/1),
      "ticket_expires_at" => v.ticket_expires_at
    }
  end

  def local_rp_ticket_redemption_response_to_cbor(%LocalRpTicketRedemptionResponse{} = v),
    do: Cbor.encode(local_rp_ticket_redemption_response_to_tree(v))

  def local_rp_ticket_redemption_response_from_tree(tree) do
    %LocalRpTicketRedemptionResponse{
      user_id: get(tree, "user_id"),
      user_domain: get(tree, "user_domain"),
      claims: map_list(get(tree, "claims"), &claim_from_tree/1),
      ticket_expires_at: get(tree, "ticket_expires_at")
    }
  end

  def local_rp_ticket_redemption_response_from_cbor(data),
    do: local_rp_ticket_redemption_response_from_tree(Cbor.decode(data))

  # -- EmptyRequest ---------------------------------------------------------

  def empty_request_to_cbor(%EmptyRequest{}), do: Cbor.encode(%{})
  def empty_request_from_cbor(_data), do: %EmptyRequest{}

  # -- GetDomainKeysResponse --------------------------------------------------

  def get_domain_keys_response_to_tree(%GetDomainKeysResponse{} = v) do
    %{"domain" => v.domain, "keys" => Enum.map(v.keys, &domain_public_key_to_tree/1)}
    |> put_opt("recent_revocations_available", v.recent_revocations_available)
  end

  def get_domain_keys_response_to_cbor(%GetDomainKeysResponse{} = v),
    do: Cbor.encode(get_domain_keys_response_to_tree(v))

  def get_domain_keys_response_from_tree(tree) do
    %GetDomainKeysResponse{
      domain: get(tree, "domain"),
      keys: map_list(get(tree, "keys"), &domain_public_key_from_tree/1),
      recent_revocations_available: get_opt(tree, "recent_revocations_available")
    }
  end

  def get_domain_keys_response_from_cbor(data),
    do: get_domain_keys_response_from_tree(Cbor.decode(data))

  # -- GetRevocationsRequest --------------------------------------------------

  def get_revocations_request_to_tree(%GetRevocationsRequest{} = v) do
    %{} |> put_opt("since", v.since)
  end

  def get_revocations_request_to_cbor(%GetRevocationsRequest{} = v),
    do: Cbor.encode(get_revocations_request_to_tree(v))

  # -- GetRevocationsResponse --------------------------------------------------

  def get_revocations_response_to_tree(%GetRevocationsResponse{} = v) do
    %{"revocations" => Enum.map(v.revocations, &revocation_certificate_to_tree/1)}
  end

  def get_revocations_response_to_cbor(%GetRevocationsResponse{} = v),
    do: Cbor.encode(get_revocations_response_to_tree(v))

  def get_revocations_response_from_tree(tree) do
    %GetRevocationsResponse{
      revocations: map_list(get(tree, "revocations"), &revocation_certificate_from_tree/1)
    }
  end

  def get_revocations_response_from_cbor(data),
    do: get_revocations_response_from_tree(Cbor.decode(data))
end
