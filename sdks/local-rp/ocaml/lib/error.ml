(* Typed error variant for this SDK's public, result-returning entry points
   ([Identity.generate_local_rp_identity], [Begin_login.begin_local_login],
   [Complete_login.complete_local_login], [check_expirations], and the byte
   storage helpers). OCaml-idiomatic: rather than every internal module
   raising its own bespoke exception hierarchy (the Ruby reference's
   approach) and callers rescuing a common base class, this SDK collapses
   every failure mode from every module into ONE closed variant here, and
   every public function returns [('a, Error.t) result] rather than raising.

   Internal helper modules (Cbor, Crypto, Local_rp, Claims, Revocation, Dns,
   Rpc) still raise their own local exceptions for control flow -- that is
   the natural idiom for a verification *chain* where an early failure
   should short-circuit everything after it, and OCaml's exception
   mechanism is a fine way to express that internally. The public API
   boundary in begin_login.ml / complete_login.ml / identity.ml is where
   every one of those exceptions gets caught and mapped into this type, so
   application code calling this SDK never has to catch an open-ended set
   of exception constructors.

   Per the conformance suite's own README: "Exact error *types* are
   intentionally not part of the contract ... only pass/fail is portable"
   -- so this variant is for THIS SDK's own callers (richer diagnostics
   without ever including key material, nonces, tokens, tickets, or claim
   values in a message -- AGENTS.md's error-handling rule), not something
   any conformance vector checks by name. *)

type t =
  | Invalid_config of string
  | Decode_failed of string
  | Invalid_key_length of string
  | Fingerprint_mismatch
  | Not_yet_valid
  | Expired
  | Bad_timestamp of string
  | Nonce_mismatch
  | State_mismatch
  | Audience_mismatch
  | Issuer_mismatch
  | Callback_url_mismatch
  | Header_payload_mismatch of string
  | Unsupported_algorithm of string
  | Unsupported_suite of string
  | Suite_not_advertised of string
  | Signature_invalid of string
  | Key_not_found of string
  | Key_revoked of string
  | Key_expired of string
  | Domain_keys_unavailable of string
  | Domain_unverified of string
  | Claim_unsigned
  | Claim_revoked
  | Claim_expired
  | Encryption_failed of string
  | Decryption_failed of string
  | Dns_error of string
  | Transport_error of string
  | Tls_error of string
  | Protocol_error of string
  | Server_error of int * string
  | No_trusted_domain_keys of string
  | Too_many_claim_signer_domains of int
  | Revocation_insufficient of int * int
  | Identity_mismatch of string
  | Required_claims_not_satisfied of string list

let to_string = function
  | Invalid_config s -> Printf.sprintf "invalid configuration: %s" s
  | Decode_failed s -> Printf.sprintf "decode failed: %s" s
  | Invalid_key_length s -> Printf.sprintf "invalid key length: %s" s
  | Fingerprint_mismatch -> "fingerprint does not match signing public key"
  | Not_yet_valid -> "timestamp is not yet valid"
  | Expired -> "timestamp has expired"
  | Bad_timestamp s -> Printf.sprintf "bad timestamp: %s" s
  | Nonce_mismatch -> "nonce does not match"
  | State_mismatch -> "state does not match"
  | Audience_mismatch -> "audience fingerprint does not match"
  | Issuer_mismatch -> "issuing domain does not match"
  | Callback_url_mismatch -> "callback URL does not match"
  | Header_payload_mismatch field -> Printf.sprintf "callback header does not match signed payload field: %s" field
  | Unsupported_algorithm alg -> Printf.sprintf "unsupported signing algorithm: %s" alg
  | Unsupported_suite s -> Printf.sprintf "unsupported AEAD suite: %s" s
  | Suite_not_advertised s -> Printf.sprintf "AEAD suite was not advertised/allowed: %s" s
  | Signature_invalid s -> Printf.sprintf "signature invalid: %s" s
  | Key_not_found id -> Printf.sprintf "signing key not found: %s" id
  | Key_revoked id -> Printf.sprintf "signing key has been revoked: %s" id
  | Key_expired id -> Printf.sprintf "signing key has expired: %s" id
  | Domain_keys_unavailable d -> Printf.sprintf "no public keys available for signing domain: %s" d
  | Domain_unverified d -> Printf.sprintf "no valid signature for signing domain: %s" d
  | Claim_unsigned -> "claim has no signatures"
  | Claim_revoked -> "claim has been revoked"
  | Claim_expired -> "claim has expired"
  | Encryption_failed s -> Printf.sprintf "encryption failed: %s" s
  | Decryption_failed s -> Printf.sprintf "decryption failed: %s" s
  | Dns_error s -> Printf.sprintf "DNS error: %s" s
  | Transport_error s -> Printf.sprintf "transport error: %s" s
  | Tls_error s -> Printf.sprintf "TLS error: %s" s
  | Protocol_error s -> Printf.sprintf "protocol error: %s" s
  | Server_error (status, msg) -> Printf.sprintf "server error (%d): %s" status msg
  | No_trusted_domain_keys d -> Printf.sprintf "no trusted public keys could be established for domain: %s" d
  | Too_many_claim_signer_domains n ->
    Printf.sprintf "claim set names more than %d distinct signer domains; refusing to fetch further keys" n
  | Revocation_insufficient (got, need) ->
    Printf.sprintf "revocation certificate has %d valid sibling signature(s), need %d" got need
  | Identity_mismatch s -> Printf.sprintf "identity binding mismatch: %s" s
  | Required_claims_not_satisfied missing ->
    Printf.sprintf "required claims not satisfied: %s" (String.concat ", " missing)

exception Sdk_error of t

let raise_ (e : t) = raise (Sdk_error e)

(* Run [f] and turn any [Sdk_error] it raises into [Error]; any other
   exception is a programming error and is allowed to propagate rather than
   being silently swallowed into a generic variant. *)
let capture (f : unit -> 'a) : ('a, t) result =
  try Ok (f ()) with Sdk_error e -> Error e
