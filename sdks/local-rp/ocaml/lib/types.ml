(* Hand-written CBOR struct codecs for exactly the CSIL types this SDK
   touches. No csilgen OCaml target exists yet (see the filed csilgen
   request), so -- mirroring every other hand-rolled-codec SDK in this
   project (Ruby, Python's hand-written fallback, etc.) -- these are direct
   ports of the generated Python SDK's [generated/codec.py] per-struct
   encode/decode function pairs. Field encode ORDER below is load-bearing:
   it was read directly off the Ruby port's [types.rb] (itself read off the
   generated Python codec's field-append order) and is verified
   byte-for-byte against every [*_cbor_hex] fixture in
   sdks/local-rp/conformance/ by this package's own conformance tests.
   Decode order does not matter (map lookup by key), only encode order
   does. *)

open Cbor

let opt_field name = function
  | None -> []
  | Some v -> [ (Text name, v) ]

(* ------------------------------------------------------------------ *)
(* Local RP descriptor / login request                                 *)
(* ------------------------------------------------------------------ *)

module Local_rp_descriptor = struct
  type t = {
    app_name : string;
    local_domain_hint : string option;
    signing_public_key : string;
    encryption_public_key : string;
    fingerprint : string;
    supported_suites : string list;
    created_at : string;
    expires_at : string;
  }

  let to_value (v : t) : Cbor.value =
    Map
      ([
         (Text "app_name", Text v.app_name);
         (Text "created_at", Text v.created_at);
         (Text "expires_at", Text v.expires_at);
         (Text "fingerprint", Text v.fingerprint);
         (Text "supported_suites", Array (List.map (fun s -> Text s) v.supported_suites));
       ]
      @ opt_field "local_domain_hint" (Option.map (fun s -> Text s) v.local_domain_hint)
      @ [
          (Text "signing_public_key", Bytes v.signing_public_key);
          (Text "encryption_public_key", Bytes v.encryption_public_key);
        ])

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    {
      app_name = field_text m "app_name";
      local_domain_hint = field_text_opt m "local_domain_hint";
      signing_public_key = field_bytes m "signing_public_key";
      encryption_public_key = field_bytes m "encryption_public_key";
      fingerprint = field_text m "fingerprint";
      supported_suites = List.map as_text (field_array m "supported_suites");
      created_at = field_text m "created_at";
      expires_at = field_text m "expires_at";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Signed_local_rp_descriptor = struct
  type t = { descriptor : string; signature : string }

  let to_value (v : t) : Cbor.value = Map [ (Text "descriptor", Bytes v.descriptor); (Text "signature", Bytes v.signature) ]
  let of_map m = { descriptor = field_bytes m "descriptor"; signature = field_bytes m "signature" }
  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Local_rp_login_request = struct
  type t = {
    descriptor : Signed_local_rp_descriptor.t;
    callback_url : string;
    nonce : string;
    state : string;
    requested_claims : string list;
    required_claims : string list;
    issued_at : string;
    expires_at : string;
  }

  let to_value (v : t) : Cbor.value =
    Map
      [
        (Text "nonce", Bytes v.nonce);
        (Text "state", Bytes v.state);
        (Text "issued_at", Text v.issued_at);
        (Text "descriptor", Signed_local_rp_descriptor.to_value v.descriptor);
        (Text "expires_at", Text v.expires_at);
        (Text "callback_url", Text v.callback_url);
        (Text "required_claims", Array (List.map (fun s -> Text s) v.required_claims));
        (Text "requested_claims", Array (List.map (fun s -> Text s) v.requested_claims));
      ]

  let of_map m =
    {
      descriptor = Signed_local_rp_descriptor.of_map (as_map (field_exn m "descriptor"));
      callback_url = field_text m "callback_url";
      nonce = field_bytes m "nonce";
      state = field_bytes m "state";
      requested_claims = List.map as_text (field_array m "requested_claims");
      required_claims = List.map as_text (field_array m "required_claims");
      issued_at = field_text m "issued_at";
      expires_at = field_text m "expires_at";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Signed_local_rp_login_request = struct
  type t = { request : string; signature : string }

  let to_value (v : t) : Cbor.value = Map [ (Text "request", Bytes v.request); (Text "signature", Bytes v.signature) ]
  let of_map m = { request = field_bytes m "request"; signature = field_bytes m "signature" }
  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

(* ------------------------------------------------------------------ *)
(* Callback header / envelope / payload                                *)
(* ------------------------------------------------------------------ *)

module Local_rp_callback_header = struct
  type t = {
    fingerprint : string;
    nonce : string;
    state : string;
    suite : string;
    ephemeral_public_key : string;
    aead_nonce : string;
    issued_at : string;
    expires_at : string;
  }

  let to_value (v : t) : Cbor.value =
    Map
      [
        (Text "nonce", Bytes v.nonce);
        (Text "state", Bytes v.state);
        (Text "suite", Text v.suite);
        (Text "issued_at", Text v.issued_at);
        (Text "aead_nonce", Bytes v.aead_nonce);
        (Text "expires_at", Text v.expires_at);
        (Text "fingerprint", Text v.fingerprint);
        (Text "ephemeral_public_key", Bytes v.ephemeral_public_key);
      ]

  let of_map m =
    {
      fingerprint = field_text m "fingerprint";
      nonce = field_bytes m "nonce";
      state = field_bytes m "state";
      suite = field_text m "suite";
      ephemeral_public_key = field_bytes m "ephemeral_public_key";
      aead_nonce = field_bytes m "aead_nonce";
      issued_at = field_text m "issued_at";
      expires_at = field_text m "expires_at";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Local_rp_encrypted_callback = struct
  type t = { header : string; ciphertext : string }

  let to_value (v : t) : Cbor.value = Map [ (Text "header", Bytes v.header); (Text "ciphertext", Bytes v.ciphertext) ]
  let of_map m = { header = field_bytes m "header"; ciphertext = field_bytes m "ciphertext" }
  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Local_rp_callback_payload = struct
  type t = {
    user_id : string;
    user_domain : string;
    claim_ticket : string;
    audience_fingerprint : string;
    callback_url : string;
    nonce : string;
    state : string;
    issued_at : string;
    expires_at : string;
  }

  let to_value (v : t) : Cbor.value =
    Map
      [
        (Text "nonce", Bytes v.nonce);
        (Text "state", Bytes v.state);
        (Text "user_id", Text v.user_id);
        (Text "issued_at", Text v.issued_at);
        (Text "expires_at", Text v.expires_at);
        (Text "user_domain", Text v.user_domain);
        (Text "callback_url", Text v.callback_url);
        (Text "claim_ticket", Bytes v.claim_ticket);
        (Text "audience_fingerprint", Text v.audience_fingerprint);
      ]

  let of_map m =
    {
      user_id = field_text m "user_id";
      user_domain = field_text m "user_domain";
      claim_ticket = field_bytes m "claim_ticket";
      audience_fingerprint = field_text m "audience_fingerprint";
      callback_url = field_text m "callback_url";
      nonce = field_bytes m "nonce";
      state = field_bytes m "state";
      issued_at = field_text m "issued_at";
      expires_at = field_text m "expires_at";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Signed_local_rp_callback_payload = struct
  type t = { payload : string; signing_key_id : string; signature : string }

  let to_value (v : t) : Cbor.value =
    Map [ (Text "payload", Bytes v.payload); (Text "signature", Bytes v.signature); (Text "signing_key_id", Text v.signing_key_id) ]

  let of_map m =
    { payload = field_bytes m "payload"; signing_key_id = field_text m "signing_key_id"; signature = field_bytes m "signature" }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

(* ------------------------------------------------------------------ *)
(* Ticket redemption                                                    *)
(* ------------------------------------------------------------------ *)

module Local_rp_ticket_redemption_request = struct
  type t = { claim_ticket : string; fingerprint : string; issued_at : string }

  let to_value (v : t) : Cbor.value =
    Map [ (Text "issued_at", Text v.issued_at); (Text "fingerprint", Text v.fingerprint); (Text "claim_ticket", Bytes v.claim_ticket) ]

  let of_map m =
    { claim_ticket = field_bytes m "claim_ticket"; fingerprint = field_text m "fingerprint"; issued_at = field_text m "issued_at" }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Signed_local_rp_ticket_redemption_request = struct
  type t = { request : string; signature : string }

  let to_value (v : t) : Cbor.value = Map [ (Text "request", Bytes v.request); (Text "signature", Bytes v.signature) ]
  let of_map m = { request = field_bytes m "request"; signature = field_bytes m "signature" }
  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

(* ------------------------------------------------------------------ *)
(* Domain keys, claims, revocation                                     *)
(* ------------------------------------------------------------------ *)

module Domain_public_key = struct
  type t = {
    key_id : string;
    public_key : string;
    fingerprint : string;
    algorithm : string;
    key_usage : string;
    created_at : string;
    expires_at : string;
    revoked_at : string option;
    signed_by_key_id : string option;
    key_signature : string option;
  }

  let to_value (v : t) : Cbor.value =
    Map
      ([
         (Text "key_id", Text v.key_id);
         (Text "algorithm", Text v.algorithm);
         (Text "key_usage", Text v.key_usage);
         (Text "created_at", Text v.created_at);
         (Text "expires_at", Text v.expires_at);
         (Text "public_key", Bytes v.public_key);
       ]
      @ opt_field "revoked_at" (Option.map (fun s -> Text s) v.revoked_at)
      @ [ (Text "fingerprint", Text v.fingerprint) ]
      @ opt_field "key_signature" (Option.map (fun s -> Bytes s) v.key_signature)
      @ opt_field "signed_by_key_id" (Option.map (fun s -> Text s) v.signed_by_key_id))

  let of_map m =
    {
      key_id = field_text m "key_id";
      public_key = field_bytes m "public_key";
      fingerprint = field_text m "fingerprint";
      algorithm = field_text m "algorithm";
      key_usage = field_text m "key_usage";
      created_at = field_text m "created_at";
      expires_at = field_text m "expires_at";
      revoked_at = field_text_opt m "revoked_at";
      signed_by_key_id = field_text_opt m "signed_by_key_id";
      key_signature = Option.map as_bytes (field m "key_signature");
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Claim_signature = struct
  type t = { domain : string; signed_by_key_id : string; signature : string }

  let to_value (v : t) : Cbor.value =
    Map [ (Text "domain", Text v.domain); (Text "signature", Bytes v.signature); (Text "signed_by_key_id", Text v.signed_by_key_id) ]

  let of_map m =
    { domain = field_text m "domain"; signed_by_key_id = field_text m "signed_by_key_id"; signature = field_bytes m "signature" }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Claim = struct
  type t = {
    claim_id : string;
    user_id : string;
    claim_type : string;
    claim_value : string;
    signatures : Claim_signature.t list;
    attested_at : string;
    created_at : string;
    expires_at : string option;
    revoked_at : string option;
  }

  let to_value (v : t) : Cbor.value =
    Map
      ([
         (Text "user_id", Text v.user_id);
         (Text "claim_id", Text v.claim_id);
         (Text "claim_type", Text v.claim_type);
         (Text "created_at", Text v.created_at);
       ]
      @ opt_field "expires_at" (Option.map (fun s -> Text s) v.expires_at)
      @ opt_field "revoked_at" (Option.map (fun s -> Text s) v.revoked_at)
      @ [
          (Text "signatures", Array (List.map Claim_signature.to_value v.signatures));
          (Text "attested_at", Text v.attested_at);
          (* claim_value is a CBOR BYTE string on the wire (CSIL:
             `claim_value: bytes`; Rust codec:
             `cbor_bytes(&csil_v.claim_value)`) -- a claim value may carry
             arbitrary bytes, not only UTF-8 text. Decoding is strict
             ([field_bytes] rejects a text string here), matching the
             generated Rust codec's own `cbor_as_bytes` behavior. *)
          (Text "claim_value", Bytes v.claim_value);
        ])

  let of_map m =
    {
      claim_id = field_text m "claim_id";
      user_id = field_text m "user_id";
      claim_type = field_text m "claim_type";
      claim_value = field_bytes m "claim_value";
      signatures = List.map (fun v -> Claim_signature.of_map (as_map v)) (field_array m "signatures");
      attested_at = field_text m "attested_at";
      created_at = field_text m "created_at";
      expires_at = field_text_opt m "expires_at";
      revoked_at = field_text_opt m "revoked_at";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Revocation_certificate = struct
  type t = { target_key_id : string; target_fingerprint : string; revoked_at : string; signatures : Claim_signature.t list }

  let to_value (v : t) : Cbor.value =
    Map
      [
        (Text "revoked_at", Text v.revoked_at);
        (Text "signatures", Array (List.map Claim_signature.to_value v.signatures));
        (Text "target_key_id", Text v.target_key_id);
        (Text "target_fingerprint", Text v.target_fingerprint);
      ]

  let of_map m =
    {
      target_key_id = field_text m "target_key_id";
      target_fingerprint = field_text m "target_fingerprint";
      revoked_at = field_text m "revoked_at";
      signatures = List.map (fun v -> Claim_signature.of_map (as_map v)) (field_array m "signatures");
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

(* ------------------------------------------------------------------ *)
(* RPC request/response payload types                                  *)
(* ------------------------------------------------------------------ *)

module Empty_request = struct
  type t = unit

  let to_value (_v : t) : Cbor.value = Map []
  let to_cbor (v : t) = encode (to_value v)
end

module Get_domain_keys_response = struct
  type t = { domain : string; keys : Domain_public_key.t list; recent_revocations_available : bool option }

  let of_map m =
    {
      domain = field_text m "domain";
      keys = List.map (fun v -> Domain_public_key.of_map (as_map v)) (field_array m "keys");
      recent_revocations_available = field_bool_opt m "recent_revocations_available";
    }

  let of_cbor data = of_map (as_map (decode data))
end

module Get_revocations_request = struct
  type t = { since : string option }

  let to_value (v : t) : Cbor.value = Map (opt_field "since" (Option.map (fun s -> Text s) v.since))
  let to_cbor v = encode (to_value v)
end

module Get_revocations_response = struct
  type t = { revocations : Revocation_certificate.t list }

  let of_map m = { revocations = List.map (fun v -> Revocation_certificate.of_map (as_map v)) (field_array m "revocations") }
  let of_cbor data = of_map (as_map (decode data))
end

module Local_rp_ticket_redemption_response = struct
  type t = { user_id : string; user_domain : string; claims : Claim.t list; ticket_expires_at : string }

  let to_value (v : t) : Cbor.value =
    Map
      [
        (Text "claims", Array (List.map Claim.to_value v.claims));
        (Text "user_id", Text v.user_id);
        (Text "user_domain", Text v.user_domain);
        (Text "ticket_expires_at", Text v.ticket_expires_at);
      ]

  let of_map m =
    {
      user_id = field_text m "user_id";
      user_domain = field_text m "user_domain";
      claims = List.map (fun v -> Claim.of_map (as_map v)) (field_array m "claims");
      ticket_expires_at = field_text m "ticket_expires_at";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

(* ------------------------------------------------------------------ *)
(* Act-as grants (grantee side only; docs/spec/reserved/act-as-grants.md) *)
(*                                                                      *)
(* A local RP can be a grantee, never an audience, so this SDK carries   *)
(* only the types a grantee builds, signs, or forwards. [encode] sorts   *)
(* map keys canonically, and every optional field is omitted when it is  *)
(* [None] -- the same shape the generated Rust codec emits.              *)
(* ------------------------------------------------------------------ *)

let opt_map (f : (Cbor.value * Cbor.value) list -> 'a) (m : (Cbor.value * Cbor.value) list) (name : string) : 'a option =
  Option.map (fun v -> f (as_map v)) (field m name)

module Application_ref = struct
  type t = { subject_user_id : string; subject_domain : string; application_id : string }

  let to_value (v : t) : Cbor.value =
    Map
      [
        (Text "subject_user_id", Text v.subject_user_id);
        (Text "subject_domain", Text v.subject_domain);
        (Text "application_id", Text v.application_id);
      ]

  let of_map m =
    {
      subject_user_id = field_text m "subject_user_id";
      subject_domain = field_text m "subject_domain";
      application_id = field_text m "application_id";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Grantee_ref = struct
  type t = { application : Application_ref.t option; local_rp_descriptor_fingerprint : string option }

  let to_value (v : t) : Cbor.value =
    Map
      (opt_field "application" (Option.map Application_ref.to_value v.application)
      @ opt_field "local_rp_descriptor_fingerprint" (Option.map (fun s -> Text s) v.local_rp_descriptor_fingerprint))

  let of_map m =
    {
      application = opt_map Application_ref.of_map m "application";
      local_rp_descriptor_fingerprint = field_text_opt m "local_rp_descriptor_fingerprint";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Application_key_signature = struct
  type t = { signed_by_key_id : string; signature : string }

  let to_value (v : t) : Cbor.value =
    Map [ (Text "signed_by_key_id", Text v.signed_by_key_id); (Text "signature", Bytes v.signature) ]

  let of_map m = { signed_by_key_id = field_text m "signed_by_key_id"; signature = field_bytes m "signature" }
end

module Grantee_proof = struct
  type t = {
    application_instance_id : string option;
    local_rp_descriptor : Signed_local_rp_descriptor.t option;
    signature : Application_key_signature.t;
  }

  let to_value (v : t) : Cbor.value =
    Map
      (opt_field "application_instance_id" (Option.map (fun s -> Text s) v.application_instance_id)
      @ opt_field "local_rp_descriptor" (Option.map Signed_local_rp_descriptor.to_value v.local_rp_descriptor)
      @ [ (Text "signature", Application_key_signature.to_value v.signature) ])

  let of_map m =
    {
      application_instance_id = field_text_opt m "application_instance_id";
      local_rp_descriptor = opt_map Signed_local_rp_descriptor.of_map m "local_rp_descriptor";
      signature = Application_key_signature.of_map (as_map (field_exn m "signature"));
    }
end

(* The audience's signed scope set. A grantee embeds it unchanged.
   [signatures] has at least one entry (CSIL [[+ ApplicationKeySignature]]). *)
module Signed_act_as_scope_set = struct
  type t = { scope_set : string; signer_instance_id : string; signatures : Application_key_signature.t list }

  let to_value (v : t) : Cbor.value =
    Map
      [
        (Text "scope_set", Bytes v.scope_set);
        (Text "signer_instance_id", Text v.signer_instance_id);
        (Text "signatures", Array (List.map Application_key_signature.to_value v.signatures));
      ]

  let of_map m =
    let signatures = List.map (fun v -> Application_key_signature.of_map (as_map v)) (field_array m "signatures") in
    if signatures = [] then raise (Decode_error "SignedActAsScopeSet.signatures must not be empty");
    { scope_set = field_bytes m "scope_set"; signer_instance_id = field_text m "signer_instance_id"; signatures }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Act_as_grant_request = struct
  type t = {
    grantee : Grantee_ref.t;
    scope_set : Signed_act_as_scope_set.t;
    requested_lifetime_seconds : int option;
    requested_renewal_window_seconds : int option;
    callback_url : string;
    nonce : string;
    requested_at : string;
    expires_at : string;
  }

  (* [grantee_handle_claim] is never written: it is a signed claim about the
     account that enrolled an application grantee. A local RP has no enrolling
     account, so it has no such claim. *)
  let to_value (v : t) : Cbor.value =
    Map
      ([ (Text "grantee", Grantee_ref.to_value v.grantee); (Text "scope_set", Signed_act_as_scope_set.to_value v.scope_set) ]
      @ opt_field "requested_lifetime_seconds" (Option.map (fun n -> Int n) v.requested_lifetime_seconds)
      @ opt_field "requested_renewal_window_seconds" (Option.map (fun n -> Int n) v.requested_renewal_window_seconds)
      @ [
          (Text "callback_url", Text v.callback_url);
          (Text "nonce", Text v.nonce);
          (Text "requested_at", Text v.requested_at);
          (Text "expires_at", Text v.expires_at);
        ])

  let of_map m =
    {
      grantee = Grantee_ref.of_map (as_map (field_exn m "grantee"));
      scope_set = Signed_act_as_scope_set.of_map (as_map (field_exn m "scope_set"));
      requested_lifetime_seconds = Option.map as_int (field m "requested_lifetime_seconds");
      requested_renewal_window_seconds = Option.map as_int (field m "requested_renewal_window_seconds");
      callback_url = field_text m "callback_url";
      nonce = field_text m "nonce";
      requested_at = field_text m "requested_at";
      expires_at = field_text m "expires_at";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Signed_act_as_grant_request = struct
  type t = { request : string; proof : Grantee_proof.t }

  let to_value (v : t) : Cbor.value = Map [ (Text "request", Bytes v.request); (Text "proof", Grantee_proof.to_value v.proof) ]
  let of_map m = { request = field_bytes m "request"; proof = Grantee_proof.of_map (as_map (field_exn m "proof")) }
  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Act_as_refresh_request = struct
  type t = { grant_id : string; grantee : Grantee_ref.t; requested_at : string; expires_at : string; nonce : string }

  let to_value (v : t) : Cbor.value =
    Map
      [
        (Text "grant_id", Text v.grant_id);
        (Text "grantee", Grantee_ref.to_value v.grantee);
        (Text "requested_at", Text v.requested_at);
        (Text "expires_at", Text v.expires_at);
        (Text "nonce", Text v.nonce);
      ]

  let of_map m =
    {
      grant_id = field_text m "grant_id";
      grantee = Grantee_ref.of_map (as_map (field_exn m "grantee"));
      requested_at = field_text m "requested_at";
      expires_at = field_text m "expires_at";
      nonce = field_text m "nonce";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Signed_act_as_refresh_request = struct
  type t = { request : string; proof : Grantee_proof.t }

  let to_value (v : t) : Cbor.value = Map [ (Text "request", Bytes v.request); (Text "proof", Grantee_proof.to_value v.proof) ]
  let of_map m = { request = field_bytes m "request"; proof = Grantee_proof.of_map (as_map (field_exn m "proof")) }
  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Refresh_act_as_grant_request = struct
  type t = { request : Signed_act_as_refresh_request.t }

  let to_value (v : t) : Cbor.value = Map [ (Text "request", Signed_act_as_refresh_request.to_value v.request) ]
  let of_map m = { request = Signed_act_as_refresh_request.of_map (as_map (field_exn m "request")) }
  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

(* A grant as the home domain signed it. [grant] is the exact CBOR of
   [ActAsGrant]; a grantee never needs to decode it, only hash it and carry
   it unchanged. *)
module Signed_act_as_grant = struct
  type t = { grant : string; signatures : Claim_signature.t list }

  let to_value (v : t) : Cbor.value =
    Map [ (Text "grant", Bytes v.grant); (Text "signatures", Array (List.map Claim_signature.to_value v.signatures)) ]

  let of_map m =
    {
      grant = field_bytes m "grant";
      signatures = List.map (fun v -> Claim_signature.of_map (as_map v)) (field_array m "signatures");
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Refresh_act_as_grant_response = struct
  type t = { grant : Signed_act_as_grant.t; signed : bool }

  let to_value (v : t) : Cbor.value = Map [ (Text "grant", Signed_act_as_grant.to_value v.grant); (Text "signed", Bool v.signed) ]
  let of_map m = { grant = Signed_act_as_grant.of_map (as_map (field_exn m "grant")); signed = as_bool (field_exn m "signed") }
  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Act_as_presentation = struct
  type t = { grant_hash : string; audience : Application_ref.t; request_digest : string; presented_at : string; nonce : string }

  let to_value (v : t) : Cbor.value =
    Map
      [
        (Text "grant_hash", Bytes v.grant_hash);
        (Text "audience", Application_ref.to_value v.audience);
        (Text "request_digest", Bytes v.request_digest);
        (Text "presented_at", Text v.presented_at);
        (Text "nonce", Bytes v.nonce);
      ]

  let of_map m =
    {
      grant_hash = field_bytes m "grant_hash";
      audience = Application_ref.of_map (as_map (field_exn m "audience"));
      request_digest = field_bytes m "request_digest";
      presented_at = field_text m "presented_at";
      nonce = field_bytes m "nonce";
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end

module Signed_act_as_presentation = struct
  type t = { presentation : string; proof : Grantee_proof.t }

  let to_value (v : t) : Cbor.value =
    Map [ (Text "presentation", Bytes v.presentation); (Text "proof", Grantee_proof.to_value v.proof) ]

  let of_map m = { presentation = field_bytes m "presentation"; proof = Grantee_proof.of_map (as_map (field_exn m "proof")) }
end

module Act_as_credential = struct
  type t = { grant : Signed_act_as_grant.t; presentation : Signed_act_as_presentation.t }

  let to_value (v : t) : Cbor.value =
    Map [ (Text "grant", Signed_act_as_grant.to_value v.grant); (Text "presentation", Signed_act_as_presentation.to_value v.presentation) ]

  let of_map m =
    {
      grant = Signed_act_as_grant.of_map (as_map (field_exn m "grant"));
      presentation = Signed_act_as_presentation.of_map (as_map (field_exn m "presentation"));
    }

  let to_cbor v = encode (to_value v)
  let of_cbor data = of_map (as_map (decode data))
end
