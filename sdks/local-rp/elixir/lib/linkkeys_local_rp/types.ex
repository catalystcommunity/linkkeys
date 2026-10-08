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

  # -- Act-as grants (docs/spec/reserved/act-as-grants.md) ----------------

  defmodule ApplicationRef do
    @moduledoc "CSIL `ApplicationRef` — an enrolled application. An act-as audience is always one of these."
    defstruct [:subject_user_id, :subject_domain, :application_id]
  end

  defmodule GranteeRef do
    @moduledoc "CSIL `GranteeRef` — exactly one of `application` or `local_rp_descriptor_fingerprint`."
    defstruct application: nil, local_rp_descriptor_fingerprint: nil
  end

  defmodule ApplicationKeySignature do
    @moduledoc "CSIL `ApplicationKeySignature`."
    defstruct [:signed_by_key_id, :signature]
  end

  defmodule GranteeProof do
    @moduledoc "CSIL `GranteeProof` — a local RP sets `local_rp_descriptor`, never `application_instance_id`."
    defstruct [:signature, application_instance_id: nil, local_rp_descriptor: nil]
  end

  defmodule SignedActAsScopeSet do
    @moduledoc """
    CSIL `SignedActAsScopeSet` — the audience's signed scope set. `scope_set` is kept as the
    exact signed bytes. `signatures` is a non-empty list of `ApplicationKeySignature`.
    """
    defstruct [:scope_set, :signer_instance_id, :signatures]
  end

  defmodule ActAsGrantRequest do
    @moduledoc """
    CSIL `ActAsGrantRequest`. A local RP never sends the optional `grantee_handle_claim` (it
    has no enrolling account), so this struct does not carry it and the encoder always omits it.
    """
    defstruct [
      :grantee,
      :scope_set,
      :callback_url,
      :nonce,
      :requested_at,
      :expires_at,
      requested_lifetime_seconds: nil,
      requested_renewal_window_seconds: nil
    ]
  end

  defmodule SignedActAsGrantRequest do
    @moduledoc "CSIL `SignedActAsGrantRequest` — the exact `ActAsGrantRequest` bytes plus the grantee proof."
    defstruct [:request, :proof]
  end

  defmodule ActAsRefreshRequest do
    @moduledoc "CSIL `ActAsRefreshRequest`."
    defstruct [:grant_id, :grantee, :requested_at, :expires_at, :nonce]
  end

  defmodule SignedActAsRefreshRequest do
    @moduledoc "CSIL `SignedActAsRefreshRequest`."
    defstruct [:request, :proof]
  end

  defmodule SignedActAsGrant do
    @moduledoc "CSIL `SignedActAsGrant` — `grant` is the exact home-domain-signed `ActAsGrant` bytes."
    defstruct [:grant, :signatures]
  end

  defmodule RefreshActAsGrantResponse do
    @moduledoc "CSIL `RefreshActAsGrantResponse` — `signed` is true when the home domain signed a new grant for this call."
    defstruct [:grant, :signed]
  end

  defmodule ActAsPresentation do
    @moduledoc "CSIL `ActAsPresentation`."
    defstruct [:grant_hash, :audience, :request_digest, :presented_at, :nonce]
  end

  defmodule SignedActAsPresentation do
    @moduledoc "CSIL `SignedActAsPresentation`."
    defstruct [:presentation, :proof]
  end

  defmodule ActAsCredential do
    @moduledoc "CSIL `ActAsCredential` — what a grantee sends the audience with each call."
    defstruct [:grant, :presentation]
  end

  # -- helpers -----------------------------------------------------------

  defp put_opt(map, _key, nil), do: map
  defp put_opt(map, key, value), do: Map.put(map, key, value)

  defp opt_bytes!(nil), do: nil
  defp opt_bytes!(v), do: Cbor.bytes!(v)

  defp get(tree, key), do: Map.fetch!(tree, key)
  defp get_opt(tree, key), do: Map.get(tree, key)

  defp map_list(list, f), do: Enum.map(list, f)

  defp non_empty_list!([_ | _] = list, f), do: Enum.map(list, f)
  defp non_empty_list!(_, _), do: raise(ArgumentError, "expected a non-empty CBOR array")

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

  # -- ApplicationRef -----------------------------------------------------------

  def application_ref_to_tree(%ApplicationRef{} = v) do
    %{
      "subject_user_id" => v.subject_user_id,
      "subject_domain" => v.subject_domain,
      "application_id" => v.application_id
    }
  end

  def application_ref_from_tree(tree) do
    %ApplicationRef{
      subject_user_id: get(tree, "subject_user_id"),
      subject_domain: get(tree, "subject_domain"),
      application_id: get(tree, "application_id")
    }
  end

  # -- GranteeRef ----------------------------------------------------------------

  def grantee_ref_to_tree(%GranteeRef{} = v) do
    %{}
    |> put_opt("application", if(v.application, do: application_ref_to_tree(v.application)))
    |> put_opt("local_rp_descriptor_fingerprint", v.local_rp_descriptor_fingerprint)
  end

  def grantee_ref_from_tree(tree) do
    %GranteeRef{
      application: if(app = get_opt(tree, "application"), do: application_ref_from_tree(app)),
      local_rp_descriptor_fingerprint: get_opt(tree, "local_rp_descriptor_fingerprint")
    }
  end

  # -- ApplicationKeySignature ---------------------------------------------------

  def application_key_signature_to_tree(%ApplicationKeySignature{} = v) do
    %{"signed_by_key_id" => v.signed_by_key_id, "signature" => Cbor.bytes(v.signature)}
  end

  def application_key_signature_from_tree(tree) do
    %ApplicationKeySignature{
      signed_by_key_id: get(tree, "signed_by_key_id"),
      signature: Cbor.bytes!(get(tree, "signature"))
    }
  end

  # -- GranteeProof --------------------------------------------------------------

  def grantee_proof_to_tree(%GranteeProof{} = v) do
    %{"signature" => application_key_signature_to_tree(v.signature)}
    |> put_opt("application_instance_id", v.application_instance_id)
    |> put_opt(
      "local_rp_descriptor",
      if(v.local_rp_descriptor, do: signed_local_rp_descriptor_to_tree(v.local_rp_descriptor))
    )
  end

  def grantee_proof_from_tree(tree) do
    %GranteeProof{
      signature: application_key_signature_from_tree(get(tree, "signature")),
      application_instance_id: get_opt(tree, "application_instance_id"),
      local_rp_descriptor: if(d = get_opt(tree, "local_rp_descriptor"), do: signed_local_rp_descriptor_from_tree(d))
    }
  end

  # -- SignedActAsScopeSet -------------------------------------------------------

  def signed_act_as_scope_set_to_tree(%SignedActAsScopeSet{} = v) do
    %{
      "scope_set" => Cbor.bytes(v.scope_set),
      "signer_instance_id" => v.signer_instance_id,
      "signatures" => Enum.map(v.signatures, &application_key_signature_to_tree/1)
    }
  end

  def signed_act_as_scope_set_to_cbor(%SignedActAsScopeSet{} = v),
    do: Cbor.encode(signed_act_as_scope_set_to_tree(v))

  def signed_act_as_scope_set_from_tree(tree) do
    %SignedActAsScopeSet{
      scope_set: Cbor.bytes!(get(tree, "scope_set")),
      signer_instance_id: get(tree, "signer_instance_id"),
      signatures: non_empty_list!(get(tree, "signatures"), &application_key_signature_from_tree/1)
    }
  end

  def signed_act_as_scope_set_from_cbor(data),
    do: signed_act_as_scope_set_from_tree(Cbor.decode(data))

  # -- ActAsGrantRequest -----------------------------------------------------------

  def act_as_grant_request_to_tree(%ActAsGrantRequest{} = v) do
    %{
      "grantee" => grantee_ref_to_tree(v.grantee),
      "scope_set" => signed_act_as_scope_set_to_tree(v.scope_set),
      "callback_url" => v.callback_url,
      "nonce" => v.nonce,
      "requested_at" => v.requested_at,
      "expires_at" => v.expires_at
    }
    |> put_opt("requested_lifetime_seconds", v.requested_lifetime_seconds)
    |> put_opt("requested_renewal_window_seconds", v.requested_renewal_window_seconds)
  end

  def act_as_grant_request_to_cbor(%ActAsGrantRequest{} = v), do: Cbor.encode(act_as_grant_request_to_tree(v))

  def act_as_grant_request_from_tree(tree) do
    %ActAsGrantRequest{
      grantee: grantee_ref_from_tree(get(tree, "grantee")),
      scope_set: signed_act_as_scope_set_from_tree(get(tree, "scope_set")),
      callback_url: get(tree, "callback_url"),
      nonce: get(tree, "nonce"),
      requested_at: get(tree, "requested_at"),
      expires_at: get(tree, "expires_at"),
      requested_lifetime_seconds: get_opt(tree, "requested_lifetime_seconds"),
      requested_renewal_window_seconds: get_opt(tree, "requested_renewal_window_seconds")
    }
  end

  def act_as_grant_request_from_cbor(data), do: act_as_grant_request_from_tree(Cbor.decode(data))

  # -- SignedActAsGrantRequest / SignedActAsRefreshRequest --------------------------

  def signed_act_as_grant_request_to_tree(%SignedActAsGrantRequest{} = v) do
    %{"request" => Cbor.bytes(v.request), "proof" => grantee_proof_to_tree(v.proof)}
  end

  def signed_act_as_grant_request_to_cbor(%SignedActAsGrantRequest{} = v),
    do: Cbor.encode(signed_act_as_grant_request_to_tree(v))

  def signed_act_as_grant_request_from_cbor(data) do
    tree = Cbor.decode(data)

    %SignedActAsGrantRequest{
      request: Cbor.bytes!(get(tree, "request")),
      proof: grantee_proof_from_tree(get(tree, "proof"))
    }
  end

  def signed_act_as_refresh_request_to_tree(%SignedActAsRefreshRequest{} = v) do
    %{"request" => Cbor.bytes(v.request), "proof" => grantee_proof_to_tree(v.proof)}
  end

  def signed_act_as_refresh_request_to_cbor(%SignedActAsRefreshRequest{} = v),
    do: Cbor.encode(signed_act_as_refresh_request_to_tree(v))

  def signed_act_as_refresh_request_from_tree(tree) do
    %SignedActAsRefreshRequest{
      request: Cbor.bytes!(get(tree, "request")),
      proof: grantee_proof_from_tree(get(tree, "proof"))
    }
  end

  def signed_act_as_refresh_request_from_cbor(data),
    do: signed_act_as_refresh_request_from_tree(Cbor.decode(data))

  # -- ActAsRefreshRequest ------------------------------------------------------------

  def act_as_refresh_request_to_tree(%ActAsRefreshRequest{} = v) do
    %{
      "grant_id" => v.grant_id,
      "grantee" => grantee_ref_to_tree(v.grantee),
      "requested_at" => v.requested_at,
      "expires_at" => v.expires_at,
      "nonce" => v.nonce
    }
  end

  def act_as_refresh_request_to_cbor(%ActAsRefreshRequest{} = v), do: Cbor.encode(act_as_refresh_request_to_tree(v))

  def act_as_refresh_request_from_cbor(data) do
    tree = Cbor.decode(data)

    %ActAsRefreshRequest{
      grant_id: get(tree, "grant_id"),
      grantee: grantee_ref_from_tree(get(tree, "grantee")),
      requested_at: get(tree, "requested_at"),
      expires_at: get(tree, "expires_at"),
      nonce: get(tree, "nonce")
    }
  end

  # -- RefreshActAsGrantRequest (CSIL `{request: SignedActAsRefreshRequest}`) ----------

  def refresh_act_as_grant_request_to_cbor(%SignedActAsRefreshRequest{} = request),
    do: Cbor.encode(%{"request" => signed_act_as_refresh_request_to_tree(request)})

  def refresh_act_as_grant_request_from_cbor(data),
    do: signed_act_as_refresh_request_from_tree(get(Cbor.decode(data), "request"))

  # -- SignedActAsGrant / RefreshActAsGrantResponse -------------------------------------

  def signed_act_as_grant_to_tree(%SignedActAsGrant{} = v) do
    %{"grant" => Cbor.bytes(v.grant), "signatures" => Enum.map(v.signatures, &claim_signature_to_tree/1)}
  end

  def signed_act_as_grant_to_cbor(%SignedActAsGrant{} = v), do: Cbor.encode(signed_act_as_grant_to_tree(v))

  def signed_act_as_grant_from_tree(tree) do
    %SignedActAsGrant{
      grant: Cbor.bytes!(get(tree, "grant")),
      signatures: map_list(get(tree, "signatures"), &claim_signature_from_tree/1)
    }
  end

  def signed_act_as_grant_from_cbor(data), do: signed_act_as_grant_from_tree(Cbor.decode(data))

  def refresh_act_as_grant_response_to_cbor(%RefreshActAsGrantResponse{} = v),
    do: Cbor.encode(%{"grant" => signed_act_as_grant_to_tree(v.grant), "signed" => v.signed})

  def refresh_act_as_grant_response_from_cbor(data) do
    tree = Cbor.decode(data)
    signed = get(tree, "signed")
    if not is_boolean(signed), do: raise(ArgumentError, "csil cbor: 'signed' must be a bool")
    %RefreshActAsGrantResponse{grant: signed_act_as_grant_from_tree(get(tree, "grant")), signed: signed}
  end

  # -- ActAsPresentation / SignedActAsPresentation / ActAsCredential ----------------------

  def act_as_presentation_to_tree(%ActAsPresentation{} = v) do
    %{
      "grant_hash" => Cbor.bytes(v.grant_hash),
      "audience" => application_ref_to_tree(v.audience),
      "request_digest" => Cbor.bytes(v.request_digest),
      "presented_at" => v.presented_at,
      "nonce" => Cbor.bytes(v.nonce)
    }
  end

  def act_as_presentation_to_cbor(%ActAsPresentation{} = v), do: Cbor.encode(act_as_presentation_to_tree(v))

  def signed_act_as_presentation_to_tree(%SignedActAsPresentation{} = v) do
    %{"presentation" => Cbor.bytes(v.presentation), "proof" => grantee_proof_to_tree(v.proof)}
  end

  def act_as_credential_to_tree(%ActAsCredential{} = v) do
    %{
      "grant" => signed_act_as_grant_to_tree(v.grant),
      "presentation" => signed_act_as_presentation_to_tree(v.presentation)
    }
  end

  def act_as_credential_to_cbor(%ActAsCredential{} = v), do: Cbor.encode(act_as_credential_to_tree(v))
end
