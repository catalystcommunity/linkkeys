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
