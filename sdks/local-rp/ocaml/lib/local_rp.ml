(* DNS-less local RP identity: pure protocol helpers.

   Mirrors [crates/liblinkkeys/src/local_rp.rs] and the Ruby port's
   [local_rp.rb] (read that file's module docs and
   dns-less-local-rp-design.md's "Wire Precision (Normative)" section first
   -- this module implements it byte-for-byte). Summary of the shape:

   - Every signed structure uses the envelope pattern: the payload is
     CBOR-encoded once, and the signature covers
     [CBOR([context: tstr, payload: bstr])] -- a two-element CBOR array,
     never a bare [context || payload] concatenation (see
     [envelope_signature_input]).
   - Four mandatory, structure-specific context strings stop a signature
     over one structure from ever verifying as another.
   - The descriptor, login request, and ticket-redemption envelopes are
     self-asserted (verified against the local RP's own embedded signing
     key, SSH-host style). The callback payload envelope is domain-signed
     (verified against fetched domain public keys, keyed by
     [signing_key_id]).
   - The callback ciphertext is a variant of the sealed-box construction,
     extended with negotiated-suite selection and cleartext-header AAD
     binding -- see [seal_local_rp_callback] / [open_local_rp_callback].

   This module performs no I/O and never reads the system clock -- every
   "current time" is an explicit [now] parameter, so verification stays
   deterministic and testable against fixed conformance vectors.

   Only the subset actually used by an RP (build+sign the
   descriptor/login-request/ticket-redemption; verify+open the callback) is
   exercised at runtime by this SDK. [build_local_rp_callback_payload] /
   [sign_local_rp_callback_payload] / [seal_local_rp_callback] are IDP-side
   operations -- included here (mirroring [liblinkkeys::local_rp], which
   serves both sides) purely so this package's own test suite can act as a
   self-contained fake IDP in the flow tests. *)

let ctx_local_rp_descriptor = "linkkeys-local-rp-descriptor"
let ctx_local_rp_login_request = "linkkeys-local-rp-login-request"
let ctx_local_rp_callback = "linkkeys-local-rp-callback"
let ctx_local_rp_ticket_redemption = "linkkeys-local-rp-ticket-redemption"
let default_clock_skew_seconds = 300.0
let local_rp_callback_box_tag = "linkkeys-local-rp-callback-box"

(* [CBOR([context, payload_bytes])] -- a two-element CBOR array, context
   string first (CBOR text string), then the exact payload bytes (CBOR byte
   string). Deliberately NOT a bare [context || payload] concatenation. *)
let envelope_signature_input (context : string) (payload_bytes : string) : string =
  Cbor.encode (Cbor.Array [ Cbor.Text context; Cbor.Bytes payload_bytes ])

(* ------------------------------------------------------------------ *)
(* Timestamps / expirations                                            *)
(* ------------------------------------------------------------------ *)

(* Check an (issued_at, expires_at) pair against [now], tolerant of
   [skew_seconds] of clock skew in either direction. Boundaries are
   inclusive: exactly [now - skew == expires_at] still passes, and exactly
   one second past either boundary fails. *)
let check_timestamps (issued_at : string) (expires_at : string) (now : float) (skew_seconds : float) : unit =
  let issued, expires =
    try (Timeutil.parse_rfc3339 issued_at, Timeutil.parse_rfc3339 expires_at)
    with Timeutil.Bad_timestamp msg -> Error.raise_ (Error.Bad_timestamp msg)
  in
  if now +. skew_seconds < issued then Error.raise_ Error.Not_yet_valid;
  if now -. skew_seconds > expires then Error.raise_ Error.Expired

(* Named [Level_*] throughout (rather than the shorter [Ok]/[Expired]) to
   avoid shadowing the stdlib [Result.Ok] constructor and this module's own
   [Error] exception helper inside this file's scope. *)
type expiration_level =
  | Level_ok
  | Level_notice
  | Level_warning
  | Level_critical
  | Level_expired

type expiration_status = { level : expiration_level; expires_at : float; now : float }

(* [check_expirations(expires_at, now) -> ExpirationStatus] (design doc,
   "Expiration Helper"): notice at 180 days remaining, warning at 90,
   critical at 30, expired once now >= expires_at. No clock-skew tolerance
   (unlike [check_timestamps]) -- expiry warnings are advisory,
   day-granularity facts, not a replay/freshness security boundary. *)
let check_expirations (expires_at : string) (now : float) : expiration_status =
  let expires = try Timeutil.parse_rfc3339 expires_at with Timeutil.Bad_timestamp msg -> Error.raise_ (Error.Bad_timestamp msg) in
  let remaining = expires -. now in
  let day = 86400.0 in
  let level =
    if now >= expires then Level_expired
    else if remaining <= 30.0 *. day then Level_critical
    else if remaining <= 90.0 *. day then Level_warning
    else if remaining <= 180.0 *. day then Level_notice
    else Level_ok
  in
  { level; expires_at = expires; now }

(* ------------------------------------------------------------------ *)
(* Nonce/state/audience/issuer/callback-url checks                     *)
(* ------------------------------------------------------------------ *)

(* Constant-time comparison ([Eqaf.equal], not [<>]) -- SEC fix: nonce and
   state are unpredictable-to-the-attacker secrets the app committed to at
   [begin_local_login] time, so a timing side channel on the comparison
   must not leak how many leading bytes an attacker-supplied value got
   right. Audience/issuer/callback-URL below are NOT comparably
   attacker-guessable secrets (they're public-ish routing facts, not
   unpredictable tokens the app is relying on as proof of possession), so
   they intentionally keep ordinary structural equality. *)
let verify_nonce_state (expected_nonce : string) (expected_state : string) (actual_nonce : string) (actual_state : string) : unit =
  if not (Eqaf.equal expected_nonce actual_nonce) then Error.raise_ Error.Nonce_mismatch;
  if not (Eqaf.equal expected_state actual_state) then Error.raise_ Error.State_mismatch

let verify_audience (payload_audience_fingerprint : string) (local_rp_fingerprint : string) : unit =
  if payload_audience_fingerprint <> local_rp_fingerprint then Error.raise_ Error.Audience_mismatch

let verify_issuer (payload_user_domain : string) (expected_domain : string) : unit =
  if payload_user_domain <> expected_domain then Error.raise_ Error.Issuer_mismatch

let verify_callback_url (payload_callback_url : string) (arrived_url : string) : unit =
  if payload_callback_url <> arrived_url then Error.raise_ Error.Callback_url_mismatch

(* ------------------------------------------------------------------ *)
(* Descriptor (build + sign only -- verification is the IDP's job)     *)
(* ------------------------------------------------------------------ *)

(* [fingerprint] is always derived from [signing_public_key] -- callers
   cannot set it directly, so it can never drift from the key it names. *)
let build_local_rp_descriptor ~app_name ~local_domain_hint ~signing_public_key ~encryption_public_key ~supported_suites
    ~created_at ~expires_at : Types.Local_rp_descriptor.t =
  {
    app_name;
    local_domain_hint;
    signing_public_key;
    encryption_public_key;
    fingerprint = Crypto.fingerprint signing_public_key;
    supported_suites;
    created_at;
    expires_at;
  }

let sign_local_rp_descriptor (descriptor : Types.Local_rp_descriptor.t) (private_key : string) :
    Types.Signed_local_rp_descriptor.t =
  let descriptor_bytes = Types.Local_rp_descriptor.to_cbor descriptor in
  let signature_input = envelope_signature_input ctx_local_rp_descriptor descriptor_bytes in
  let signature = Crypto.sign_ed25519 private_key signature_input in
  { descriptor = descriptor_bytes; signature }

(* ------------------------------------------------------------------ *)
(* Login request (build + sign only)                                   *)
(* ------------------------------------------------------------------ *)

let build_local_rp_login_request ~descriptor ~callback_url ~nonce ~state ~requested_claims ~required_claims ~issued_at
    ~expires_at : Types.Local_rp_login_request.t =
  { descriptor; callback_url; nonce; state; requested_claims; required_claims; issued_at; expires_at }

let sign_local_rp_login_request (request : Types.Local_rp_login_request.t) (private_key : string) :
    Types.Signed_local_rp_login_request.t =
  let request_bytes = Types.Local_rp_login_request.to_cbor request in
  let signature_input = envelope_signature_input ctx_local_rp_login_request request_bytes in
  let signature = Crypto.sign_ed25519 private_key signature_input in
  { request = request_bytes; signature }

(* ------------------------------------------------------------------ *)
(* Ticket redemption (build + sign -- the RP's possession proof)       *)
(* ------------------------------------------------------------------ *)

let build_local_rp_ticket_redemption_request ~claim_ticket ~fingerprint ~issued_at :
    Types.Local_rp_ticket_redemption_request.t =
  { claim_ticket; fingerprint; issued_at }

let sign_local_rp_ticket_redemption_request (request : Types.Local_rp_ticket_redemption_request.t) (private_key : string) :
    Types.Signed_local_rp_ticket_redemption_request.t =
  let request_bytes = Types.Local_rp_ticket_redemption_request.to_cbor request in
  let signature_input = envelope_signature_input ctx_local_rp_ticket_redemption request_bytes in
  let signature = Crypto.sign_ed25519 private_key signature_input in
  { request = request_bytes; signature }

(* ------------------------------------------------------------------ *)
(* Callback payload (build + sign -- IDP-side, used only by this       *)
(* package's own fake-IDP flow tests) / verify (RP-side, used by       *)
(* Complete_login.complete_local_login)                                *)
(* ------------------------------------------------------------------ *)

let build_local_rp_callback_payload ~user_id ~user_domain ~claim_ticket ~audience_fingerprint ~callback_url ~nonce
    ~state ~issued_at ~expires_at : Types.Local_rp_callback_payload.t =
  { user_id; user_domain; claim_ticket; audience_fingerprint; callback_url; nonce; state; issued_at; expires_at }

let sign_local_rp_callback_payload (payload : Types.Local_rp_callback_payload.t) ~(key_id : string) ~(algorithm : string)
    (private_key : string) : Types.Signed_local_rp_callback_payload.t =
  let payload_bytes = Types.Local_rp_callback_payload.to_cbor payload in
  let signature_input = envelope_signature_input ctx_local_rp_callback payload_bytes in
  let signature =
    try Crypto.sign_with_algorithm algorithm signature_input private_key
    with Crypto.Unsupported_algorithm a -> Error.raise_ (Error.Unsupported_algorithm a)
  in
  { payload = payload_bytes; signing_key_id = key_id; signature }

(* Reject a signing key that is not currently a signing key, or is
   revoked/expired -- shared by every verify path that resolves a key by
   id. *)
let check_signing_key_valid (key : Types.Domain_public_key.t) (now : float) : unit =
  if key.key_usage <> "sign" then Error.raise_ (Error.Signature_invalid "key is not a signing key");
  match Crypto.signing_key_validity key.expires_at key.revoked_at now with
  | Crypto.Revoked -> Error.raise_ (Error.Key_revoked key.key_id)
  | Crypto.Expired | Crypto.Bad_expiry -> Error.raise_ (Error.Key_expired key.key_id)
  | Crypto.Valid -> ()

(* Verify a domain-signed callback payload envelope against a set of domain
   public keys: resolve signing_key_id, reject a
   revoked/expired/non-signing key, verify the envelope signature, decode,
   then check issued_at/expires_at bounds. Nothing inside the payload is
   trusted before this succeeds. *)
let verify_local_rp_callback_payload (signed : Types.Signed_local_rp_callback_payload.t)
    (domain_public_keys : Types.Domain_public_key.t list) (now : float) (skew_seconds : float) :
    Types.Local_rp_callback_payload.t =
  let key =
    match List.find_opt (fun (k : Types.Domain_public_key.t) -> k.key_id = signed.signing_key_id) domain_public_keys with
    | Some k -> k
    | None -> Error.raise_ (Error.Key_not_found signed.signing_key_id)
  in
  check_signing_key_valid key now;
  let signature_input = envelope_signature_input ctx_local_rp_callback signed.payload in
  (try Crypto.resolve_and_verify key.algorithm signature_input signed.signature key.public_key with
  | Crypto.Unsupported_algorithm a -> Error.raise_ (Error.Unsupported_algorithm a)
  | Crypto.Verification_failed _ -> Error.raise_ (Error.Signature_invalid "callback payload signature verification failed"));
  let payload =
    try Types.Local_rp_callback_payload.of_cbor signed.payload
    with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed (Printf.sprintf "callback payload: %s" msg))
  in
  check_timestamps payload.issued_at payload.expires_at now skew_seconds;
  payload

(* Cross-check the cleartext callback header's routing fields against the
   authoritative copies inside the decrypted, signature-verified payload.
   The header is already bound as AEAD associated data, but a verifier must
   still consult the signed copies rather than trusting the header alone. *)
let check_callback_header_matches_payload (header : Types.Local_rp_callback_header.t)
    (payload : Types.Local_rp_callback_payload.t) : unit =
  if header.fingerprint <> payload.audience_fingerprint then Error.raise_ (Error.Header_payload_mismatch "fingerprint");
  if header.nonce <> payload.nonce then Error.raise_ (Error.Header_payload_mismatch "nonce");
  if header.state <> payload.state then Error.raise_ (Error.Header_payload_mismatch "state");
  if header.issued_at <> payload.issued_at then Error.raise_ (Error.Header_payload_mismatch "issued_at");
  if header.expires_at <> payload.expires_at then Error.raise_ (Error.Header_payload_mismatch "expires_at")

(* ------------------------------------------------------------------ *)
(* Callback sealed box (Wire Precision: "Callback sealed box")         *)
(* ------------------------------------------------------------------ *)

(* Derive the AEAD key and construct the KDF info/AAD-prefix context:
   [tag || suite_id_utf8 || ephemeral_public(32) || recipient_public(32)],
   raw concatenation. Returns (aead_key, context). *)
let local_rp_callback_kdf (suite : Crypto.AeadSuite.t) (ephemeral_public : string) (recipient_public : string)
    (shared_secret : string) : string * string =
  let suite_id = Crypto.AeadSuite.to_str suite in
  let context = local_rp_callback_box_tag ^ suite_id ^ ephemeral_public ^ recipient_public in
  let key = Crypto.hkdf_sha256_expand shared_secret context 32 in
  (key, context)

(* Seal a SignedLocalRpCallbackPayload into a LocalRpEncryptedCallback for
   [recipient_encryption_public_key], under [suite]. IDP-side operation --
   included here purely so this package's own tests can build a
   self-contained fake IDP (see module docs).

   [?ephemeral_private_key]/[?aead_nonce] are deterministic-testing hooks:
   production callers must leave both [None] so real OS randomness is
   used. *)
let seal_local_rp_callback ?ephemeral_private_key ?aead_nonce (signed_payload : Types.Signed_local_rp_callback_payload.t)
    (suite : Crypto.AeadSuite.t) (recipient_encryption_public_key : string) ~fingerprint ~nonce ~state ~issued_at
    ~expires_at : Types.Local_rp_encrypted_callback.t =
  let ephemeral_private = match ephemeral_private_key with Some k -> k | None -> Crypto.random_bytes 32 in
  let nonce_bytes = match aead_nonce with Some n -> n | None -> Crypto.random_bytes 12 in
  let ephemeral_public = Crypto.x25519_public_from_private ephemeral_private in
  let shared_secret = Crypto.x25519_diffie_hellman ephemeral_private recipient_encryption_public_key in
  Crypto.reject_low_order shared_secret;
  let plaintext = Types.Signed_local_rp_callback_payload.to_cbor signed_payload in
  let header : Types.Local_rp_callback_header.t =
    {
      fingerprint;
      nonce;
      state;
      suite = Crypto.AeadSuite.to_str suite;
      ephemeral_public_key = ephemeral_public;
      aead_nonce = nonce_bytes;
      issued_at;
      expires_at;
    }
  in
  let header_bytes = Types.Local_rp_callback_header.to_cbor header in
  let aead_key, kdf_context = local_rp_callback_kdf suite ephemeral_public recipient_encryption_public_key shared_secret in
  let aad = kdf_context ^ header_bytes in
  let ciphertext = Crypto.aead_encrypt suite aead_key nonce_bytes aad plaintext in
  { header = header_bytes; ciphertext }

(* Open a LocalRpEncryptedCallback with the local RP's encryption private
   key. [allowed_suites] is the local RP's own supported-suite list (from
   its descriptor): a header advertising a suite NOT in that list is
   rejected even if it is otherwise a valid registry id (Wire Precision:
   "The SDK must decrypt only with a suite listed in its own descriptor").

   Returns (header, signed_payload) -- the still-domain-signature-
   unverified payload envelope. Callers must still call
   [verify_local_rp_callback_payload] against fetched domain keys, and then
   [check_callback_header_matches_payload], before trusting the result. *)
let open_local_rp_callback (encrypted : Types.Local_rp_encrypted_callback.t) (recipient_encryption_private_key : string)
    (allowed_suites : Crypto.AeadSuite.t list) : Types.Local_rp_callback_header.t * Types.Signed_local_rp_callback_payload.t =
  let header =
    try Types.Local_rp_callback_header.of_cbor encrypted.header
    with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed (Printf.sprintf "callback header: %s" msg))
  in
  let suite =
    match Crypto.AeadSuite.parse_str header.suite with
    | None -> Error.raise_ (Error.Unsupported_suite header.suite)
    | Some s -> s
  in
  if not (List.mem suite allowed_suites) then Error.raise_ (Error.Suite_not_advertised header.suite);
  if String.length header.ephemeral_public_key <> 32 then
    Error.raise_ (Error.Invalid_key_length "ephemeral_public_key must be 32 bytes");
  if String.length header.aead_nonce <> 12 then Error.raise_ (Error.Invalid_key_length "aead_nonce must be 12 bytes");
  let recipient_public = Crypto.x25519_public_from_private recipient_encryption_private_key in
  let shared_secret =
    try Crypto.x25519_diffie_hellman recipient_encryption_private_key header.ephemeral_public_key
    with Crypto.Error msg -> Error.raise_ (Error.Decryption_failed (Printf.sprintf "callback decryption failed: %s" msg))
  in
  Crypto.reject_low_order shared_secret;
  let aead_key, kdf_context = local_rp_callback_kdf suite header.ephemeral_public_key recipient_public shared_secret in
  let aad = kdf_context ^ encrypted.header in
  let plaintext =
    try Crypto.aead_decrypt suite aead_key header.aead_nonce aad encrypted.ciphertext
    with Crypto.Error msg -> Error.raise_ (Error.Decryption_failed (Printf.sprintf "callback decryption failed: %s" msg))
  in
  let signed_payload =
    try Types.Signed_local_rp_callback_payload.of_cbor plaintext
    with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed (Printf.sprintf "callback payload: %s" msg))
  in
  (header, signed_payload)
