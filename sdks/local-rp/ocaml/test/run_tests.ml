open Linkkeys_local_rp
open Linkkeys_local_rp.Internal
open Test_helper

(* ==================================================================== *)
(* keys.json                                                             *)
(* ==================================================================== *)

let keys_json = lazy (read_json "keys.json")

module Key_fixture = struct
  type ed = { public_key : string; private_key : string; fingerprint : string }
  type x25519 = { public_key : string; private_key : string }

  let ed_of_json j = { public_key = hex "public_key_hex" j; private_key = hex "private_key_hex" j; fingerprint = text "fingerprint_hex" j }
  let x25519_of_json j = { public_key = hex "public_key_hex" j; private_key = hex "private_key_hex" j }

  let local_rp_signing () = ed_of_json (field "signing" (field "local_rp" (Lazy.force keys_json)))
  let local_rp_encryption () = x25519_of_json (field "encryption" (field "local_rp" (Lazy.force keys_json)))
  let domain_signing () = ed_of_json (field "domain_signing_key" (Lazy.force keys_json))
end

let test_keys_fixture () =
  let k = Key_fixture.local_rp_signing () in
  Alcotest.(check string) "local_rp.signing fingerprint" k.fingerprint (Crypto.fingerprint k.public_key);
  let sig_ = Crypto.sign_ed25519 k.private_key "probe message" in
  check_bool "sign/verify roundtrip with fixture key" true (Crypto.verify_ed25519 k.public_key "probe message" sig_);
  let enc = Key_fixture.local_rp_encryption () in
  Alcotest.(check string) "x25519 public derived from private matches fixture"
    (Hex.encode enc.public_key)
    (Hex.encode (Crypto.x25519_public_from_private enc.private_key));
  let dk = Key_fixture.domain_signing () in
  Alcotest.(check string) "domain_signing_key fingerprint" dk.fingerprint (Crypto.fingerprint dk.public_key)

(* ==================================================================== *)
(* envelopes.json                                                        *)
(* ==================================================================== *)

let check_envelope_case (name : string) (j : Yojson.Safe.t) : unit =
  let context = text "context" j in
  let payload = hex "payload_cbor_hex" j in
  let expected_input = hex "signature_input_cbor_hex" j in
  let signature = hex "signature_hex" j in
  let verify_key = hex "verify_key_hex" j in
  let expected_valid = bool_ (field "expected_valid" j) in
  let computed_input = Local_rp.envelope_signature_input context payload in
  Alcotest.(check string) (name ^ ": signature_input bytes") (Hex.encode expected_input) (Hex.encode computed_input);
  let actual_valid = Crypto.verify_ed25519 verify_key computed_input signature in
  check_bool (name ^ ": verify == expected_valid") expected_valid actual_valid

let test_envelopes () =
  let d = read_json "envelopes.json" in
  List.iteri (fun i j -> check_envelope_case (Printf.sprintf "cases[%d]/%s" i (text "structure" j)) j) (list_ (field "cases" d));
  List.iteri
    (fun i j -> check_envelope_case (Printf.sprintf "negative_cases[%d]/%s" i (text "name" j)) j)
    (list_ (field "negative_cases" d))

(* ==================================================================== *)
(* callback_box.json                                                     *)
(* ==================================================================== *)

let parse_allowed_suites (j : Yojson.Safe.t) : Crypto.AeadSuite.t list =
  strings "allowed_suites" j |> List.filter_map Crypto.AeadSuite.parse_str

let attempt_open (j : Yojson.Safe.t) : (Types.Local_rp_callback_header.t * Types.Signed_local_rp_callback_payload.t, exn) result =
  let encrypted : Types.Local_rp_encrypted_callback.t = { header = hex "header_cbor_hex" j; ciphertext = hex "ciphertext_hex" j } in
  let decrypt_key = hex "decrypt_private_key_hex" j in
  let allowed = parse_allowed_suites j in
  try Ok (Local_rp.open_local_rp_callback encrypted decrypt_key allowed) with e -> Error e

let test_callback_box_positive (name : string) (j : Yojson.Safe.t) : unit =
  (match attempt_open j with
  | Error e -> Alcotest.failf "%s: expected valid, got exception %s" name (Printexc.to_string e)
  | Ok (_header, signed_payload) ->
    let expected_plaintext = hex "plaintext_cbor_hex" j in
    Alcotest.(check string) (name ^ ": recovered plaintext") (Hex.encode expected_plaintext)
      (Hex.encode (Types.Signed_local_rp_callback_payload.to_cbor signed_payload)));
  (* Independently verify the KDF/AAD-prefix construction against the
     published [kdf_context_hex]/[aad_hex], per the README: "publish so you
     can unit-test your own HKDF derivation independent of a full decrypt". *)
  let suite = match Crypto.AeadSuite.parse_str (text "suite" j) with Some s -> s | None -> Alcotest.fail "bad suite in fixture" in
  let ephemeral_public = hex "ephemeral_public_key_hex" j in
  let recipient_public = hex "recipient_public_key_hex" j in
  let ephemeral_private = hex "ephemeral_private_key_hex" j in
  let shared_secret = Crypto.x25519_diffie_hellman ephemeral_private recipient_public in
  let _aead_key, kdf_context = Local_rp.local_rp_callback_kdf suite ephemeral_public recipient_public shared_secret in
  Alcotest.(check string) (name ^ ": kdf_context bytes") (Hex.encode (hex "kdf_context_hex" j)) (Hex.encode kdf_context);
  let header_bytes = hex "header_cbor_hex" j in
  Alcotest.(check string) (name ^ ": aad bytes") (Hex.encode (hex "aad_hex" j)) (Hex.encode (kdf_context ^ header_bytes))

let test_callback_box_negative (name : string) (j : Yojson.Safe.t) : unit =
  let ok = match attempt_open j with Ok _ -> true | Error _ -> false in
  check_bool name false ok

let test_callback_box () =
  let d = read_json "callback_box.json" in
  List.iteri (fun i j -> test_callback_box_positive (Printf.sprintf "positive_cases[%d]/%s" i (text "suite" j)) j) (list_ (field "positive_cases" d));
  List.iteri (fun i j -> test_callback_box_negative (Printf.sprintf "negative_cases[%d]/%s" i (text "name" j)) j) (list_ (field "negative_cases" d))

(* ==================================================================== *)
(* url_params.json                                                       *)
(* ==================================================================== *)

let test_url_params () =
  let d = read_json "url_params.json" in
  List.iter
    (fun j ->
      let name = text "name" j in
      let cbor = hex "cbor_hex" j in
      let expected_param = text "base64url_unpadded" j in
      match name with
      | "signed_local_rp_login_request" ->
        let signed = Types.Signed_local_rp_login_request.of_cbor cbor in
        Alcotest.(check string) (name ^ ": encode matches") expected_param (Url_params.signed_local_rp_login_request_to_url_param signed);
        let decoded = Url_params.signed_local_rp_login_request_from_url_param expected_param in
        Alcotest.(check string) (name ^ ": decode round-trips to same CBOR") (Hex.encode cbor) (Hex.encode (Types.Signed_local_rp_login_request.to_cbor decoded))
      | "local_rp_encrypted_callback" ->
        let cb = Types.Local_rp_encrypted_callback.of_cbor cbor in
        Alcotest.(check string) (name ^ ": encode matches") expected_param (Url_params.local_rp_encrypted_callback_to_url_param cb);
        let decoded = Url_params.local_rp_encrypted_callback_from_url_param expected_param in
        Alcotest.(check string) (name ^ ": decode round-trips to same CBOR") (Hex.encode cbor) (Hex.encode (Types.Local_rp_encrypted_callback.to_cbor decoded))
      | other -> Alcotest.failf "unknown url_params case name: %s" other)
    (list_ (field "cases" d));
  List.iteri
    (fun i j ->
      let input = text "input" j in
      let ok =
        (try
           ignore (Url_params.signed_local_rp_login_request_from_url_param input);
           true
         with _ -> false)
        || (try
              ignore (Url_params.local_rp_encrypted_callback_from_url_param input);
              true
            with _ -> false)
      in
      check_bool (Printf.sprintf "negative_cases[%d]" i) false ok)
    (list_ (field "negative_cases" d))

(* ==================================================================== *)
(* dns.json                                                               *)
(* ==================================================================== *)

let test_dns () =
  let d = read_json "dns.json" in
  let lk = field "linkkeys_txt" d in
  List.iter
    (fun j ->
      let txt = text "txt" j in
      let expected = strings "expected_fingerprints" j in
      let r = Dns.parse_linkkeys_txt txt in
      Alcotest.(check (list string)) "linkkeys_txt fingerprints" expected r.fingerprints)
    (list_ (field "valid_cases" lk));
  List.iteri
    (fun i j ->
      let txt = text "txt" j in
      let ok = try ignore (Dns.parse_linkkeys_txt txt); true with Dns.Dns_parse_error _ -> false in
      check_bool (Printf.sprintf "linkkeys_txt invalid_cases[%d]" i) false ok)
    (list_ (field "invalid_cases" lk));
  let apis = field "linkkeys_apis_txt" d in
  List.iter
    (fun j ->
      let txt = text "txt" j in
      let r = Dns.parse_linkkeys_apis_txt txt in
      Alcotest.(check (option string)) "expected_tcp" (text_opt "expected_tcp" j) r.tcp;
      Alcotest.(check (option string)) "expected_https_base" (text_opt "expected_https_base" j) r.https_base)
    (list_ (field "valid_cases" apis));
  List.iteri
    (fun i j ->
      let txt = text "txt" j in
      let ok = try ignore (Dns.parse_linkkeys_apis_txt txt); true with Dns.Dns_parse_error _ -> false in
      check_bool (Printf.sprintf "linkkeys_apis_txt invalid_cases[%d]" i) false ok)
    (list_ (field "invalid_cases" apis));
  Alcotest.(check int) "default_tcp_port" (int_of_string (Yojson.Safe.to_string (field "default_tcp_port" d))) Dns.default_tcp_port

(* ==================================================================== *)
(* tickets.json                                                          *)
(* ==================================================================== *)

let test_tickets () =
  let d = read_json "tickets.json" in
  List.iter
    (fun j ->
      let ticket = hex "ticket_hex" j in
      let expected_sha256 = text "sha256_hex" j in
      Alcotest.(check string) "ticket sha256" expected_sha256 (Crypto.fingerprint ticket))
    (list_ (field "cases" d))

(* ==================================================================== *)
(* claims.json                                                           *)
(*                                                                        *)
(* Consumer of Claim wire encoding + claim-signature verification        *)
(* (crates/liblinkkeys/src/claims.rs). This is the authoritative         *)
(* replacement for [test_claim_value_wire_type] below -- that test was   *)
(* written to pin the bstr-not-tstr fix BEFORE any cross-implementation  *)
(* vector existed for it; it is left in place (it still passes and adds  *)
(* an additional non-UTF-8 self-built case) but claims.json is now the   *)
(* real authority. *)
(* ==================================================================== *)

let claim_of_json (j : Yojson.Safe.t) : Types.Claim.t =
  {
    claim_id = text "claim_id" j;
    user_id = text "user_id" j;
    claim_type = text "claim_type" j;
    claim_value = hex "claim_value_hex" j;
    signatures = list_ (field "signatures" j) |> List.map claim_signature_of_json;
    attested_at = text "attested_at" j;
    created_at = text "created_at" j;
    expires_at = text_opt "expires_at" j;
    revoked_at = text_opt "revoked_at" j;
  }

(* Fixed "now" between the fixture's attested_at (2026-01-01) and every
   expires_at in play (claim: 2126-01-01 or absent; domain keys:
   2126-01-01), so every positive case's timestamp bounds are satisfied. *)
let claims_now = Timeutil.parse_rfc3339 "2026-06-01T00:00:00Z"

let test_claims_positive_cases () =
  let d = read_json "claims.json" in
  let default_domain_keys = list_ (field "domain_keys" d) |> List.map domain_public_key_of_json in
  let signing_domain = "conformance.example" in
  List.iter
    (fun j ->
      let name = text "name" j in
      let claim_j = field "claim" j in
      let subject_domain = text "subject_domain" j in
      let expected_cbor = hex "claim_cbor_hex" j in
      let expected_valid = bool_ (field "expected_valid" j) in
      (* Positive wire round-trip: decoding the exact wire bytes then
         re-encoding must reproduce them byte-identically (this is the
         check a tstr-wired claim_value would fail, since re-encoding a
         non-UTF-8 bstr as tstr is not even well-defined). *)
      let decoded = Types.Claim.of_cbor expected_cbor in
      Alcotest.(check string) (name ^ ": decode-then-reencode round-trips") (Hex.encode expected_cbor)
        (Hex.encode (Types.Claim.to_cbor decoded));
      (* The claim built directly from the vector's expanded fields must
         ALSO encode to the exact same wire bytes -- proves this SDK's own
         field encode order (and claim_value-as-bstr) matches the
         authoritative encoding, independent of round-trip symmetry. *)
      let claim = claim_of_json claim_j in
      Alcotest.(check string) (name ^ ": constructed-from-fields matches wire bytes") (Hex.encode expected_cbor)
        (Hex.encode (Types.Claim.to_cbor claim));
      (* Signed-payload byte recomputation, per signature, via claims.ml's
         own [claim_sign_payload] construction -- then Ed25519-verify that
         exact recomputed payload against the signer's public key. *)
      List.iter2
        (fun sig_j (claim_sig : Types.Claim_signature.t) ->
          let expected_payload = hex "signed_payload_cbor_hex" sig_j in
          let computed_payload =
            Claims.claim_sign_payload claim.claim_id claim.claim_type claim.claim_value claim.user_id subject_domain
              claim_sig.domain claim.expires_at claim.attested_at
          in
          Alcotest.(check string)
            (Printf.sprintf "%s: signed_payload bytes (%s)" name claim_sig.signed_by_key_id)
            (Hex.encode expected_payload) (Hex.encode computed_payload);
          let signer_key =
            match List.find_opt (fun (k : Types.Domain_public_key.t) -> k.key_id = claim_sig.signed_by_key_id) default_domain_keys with
            | Some k -> k
            | None -> Alcotest.failf "%s: no domain key fixture for signer %s" name claim_sig.signed_by_key_id
          in
          check_bool
            (Printf.sprintf "%s: Ed25519 verify over recomputed payload (%s)" name claim_sig.signed_by_key_id)
            true
            (Crypto.verify_ed25519 signer_key.public_key computed_payload claim_sig.signature))
        (list_ (field "signatures" claim_j))
        claim.signatures;
      (* Through the SDK's own claim-verification path, exactly as
         complete_local_login uses it. *)
      let domain_key_sets = [ ({ domain = signing_domain; keys = default_domain_keys } : Claims.domain_key_set) ] in
      let ok = try Claims.verify_claim claim subject_domain domain_key_sets claims_now; true with _ -> false in
      check_bool (name ^ ": verify_claim == expected_valid") expected_valid ok)
    (list_ (field "cases" d))

let test_claims_decode_negative_cases () =
  let d = read_json "claims.json" in
  List.iteri
    (fun i j ->
      let name = text "name" j in
      let cbor = hex "claim_cbor_hex" j in
      let expected_decode_ok = bool_ (field "expected_decode_ok" j) in
      (* [Types.Claim.of_cbor]'s [claim_value] field goes through
         [Cbor.field_bytes] -> [Cbor.as_bytes], which raises on anything
         that isn't a CBOR byte string (major type 2) -- this is the
         tstr-decode-rejection case: byte-identical to a valid claim except
         claim_value is encoded as CBOR text (major type 3). A codec that
         wired claim_value as tstr would accept this and would also have
         been computing wrong signature payloads all along. *)
      let ok = try ignore (Types.Claim.of_cbor cbor); true with _ -> false in
      check_bool (Printf.sprintf "decode_negative_cases[%d]/%s" i name) expected_decode_ok ok)
    (list_ (field "decode_negative_cases" d))

let test_claims_negative_cases () =
  let d = read_json "claims.json" in
  let default_domain_keys = list_ (field "domain_keys" d) |> List.map domain_public_key_of_json in
  let signing_domain = "conformance.example" in
  List.iteri
    (fun i j ->
      let name = text "name" j in
      let cbor = hex "claim_cbor_hex" j in
      let subject_domain = text "subject_domain" j in
      let expected_error = text "expected_error" j in
      let domain_keys =
        match field_opt "domain_keys" j with Some dk -> list_ dk |> List.map domain_public_key_of_json | None -> default_domain_keys
      in
      let claim = Types.Claim.of_cbor cbor in
      let domain_key_sets = [ ({ domain = signing_domain; keys = domain_keys } : Claims.domain_key_set) ] in
      (* NOTE on "expected error kinds": the vector's [expected_error] field
         (["signature_invalid"] / ["key_not_found"]) names liblinkkeys'
         (Rust) per-signature failure reason. This SDK's [verify_claim] --
         mirroring [crates/liblinkkeys/src/claims.rs]'s own quorum design,
         not a shortcut taken here -- checks *every* distinct signing
         domain has at least one satisfying signature and, if none does,
         raises ONE [Domain_unverified] regardless of which per-signature
         reason (bad signature vs. unresolvable key) caused each attempt to
         fail; the per-signature reason is deliberately not threaded
         through the domain-quorum loop (see [verify_claim_signatures]'s
         [with Error.Sdk_error _ -> false]). All four vector negatives
         (tampered value, wrong key, missing key, subject-domain replay)
         are therefore expected to surface as [Domain_unverified] here.
         This is consistent with the conformance README's own statement:
         "Exact error *types* are intentionally not part of the contract
         ... only pass/fail is portable" -- so what's asserted below is (a)
         verification fails, matching every [expected_error] value's
         common meaning of "this signature set does not verify", and (b)
         the failure is a well-typed [Domain_unverified] from this SDK's
         own quorum path, not a decode crash or a different, unrelated
         error path. *)
      match Claims.verify_claim claim subject_domain domain_key_sets claims_now with
      | () -> Alcotest.failf "negative_cases[%d]/%s: expected verification to fail, but it succeeded" i name
      | exception Error.Sdk_error (Error.Domain_unverified d) ->
        Alcotest.(check string)
          (Printf.sprintf "negative_cases[%d]/%s: unverified domain (vector's expected_error: %s)" i name expected_error)
          signing_domain d
      | exception e -> Alcotest.failf "negative_cases[%d]/%s: unexpected exception %s" i name (Printexc.to_string e))
    (list_ (field "negative_cases" d))

let test_claims_ticket_redemption_response () =
  let d = read_json "claims.json" in
  let default_domain_keys = list_ (field "domain_keys" d) |> List.map domain_public_key_of_json in
  let signing_domain = "conformance.example" in
  let trr = field "ticket_redemption_response" d in
  let expected_cbor = hex "response_cbor_hex" trr in
  (* Byte-exact round trip of the actual wire message
     complete_local_login's ticket-redemption RPC response decodes. *)
  let decoded = Types.Local_rp_ticket_redemption_response.of_cbor expected_cbor in
  Alcotest.(check string) "ticket_redemption_response: round-trips byte-exactly" (Hex.encode expected_cbor)
    (Hex.encode (Types.Local_rp_ticket_redemption_response.to_cbor decoded));
  Alcotest.(check string) "ticket_redemption_response: user_id" (text "user_id" trr) decoded.user_id;
  Alcotest.(check string) "ticket_redemption_response: user_domain" (text "user_domain" trr) decoded.user_domain;
  Alcotest.(check string) "ticket_redemption_response: ticket_expires_at" (text "ticket_expires_at" trr) decoded.ticket_expires_at;
  Alcotest.(check int) "ticket_redemption_response: claim count" 3 (List.length decoded.claims);
  (* Decoding without verifying fails the point (per the README): verify
     every embedded claim's signatures too, through the SDK's own path. *)
  let domain_key_sets = [ ({ domain = signing_domain; keys = default_domain_keys } : Claims.domain_key_set) ] in
  List.iter (fun c -> Claims.verify_claim c decoded.user_domain domain_key_sets claims_now) decoded.claims

(* ==================================================================== *)
(* expirations.json                                                      *)
(* ==================================================================== *)

let level_to_string = function
  | Local_rp.Level_ok -> "ok"
  | Local_rp.Level_notice -> "notice"
  | Local_rp.Level_warning -> "warning"
  | Local_rp.Level_critical -> "critical"
  | Local_rp.Level_expired -> "expired"

let test_expirations () =
  let d = read_json "expirations.json" in
  let ce = field "check_expirations" d in
  let expires_at = text "expires_at" ce in
  List.iter
    (fun j ->
      let now = Timeutil.parse_rfc3339 (text "now" j) in
      let expected_level = text "expected_level" j in
      let status = Local_rp.check_expirations expires_at now in
      Alcotest.(check string) (Printf.sprintf "check_expirations at %s" (text "now" j)) expected_level (level_to_string status.level))
    (list_ (field "cases" ce));
  let ct = field "check_timestamps" d in
  let issued_at = text "issued_at" ct in
  let expires_at2 = text "expires_at" ct in
  let skew = float_of_int (int_of_string (Yojson.Safe.to_string (field "skew_seconds" ct))) in
  List.iter
    (fun j ->
      let now = Timeutil.parse_rfc3339 (text "now" j) in
      let expected_valid = bool_ (field "expected_valid" j) in
      let ok = try Local_rp.check_timestamps issued_at expires_at2 now skew; true with _ -> false in
      check_bool (text "description" j) expected_valid ok)
    (list_ (field "cases" ct))

(* ==================================================================== *)
(* revocations.json                                                      *)
(* ==================================================================== *)

let revocation_certificate_of_json (j : Yojson.Safe.t) : Types.Revocation_certificate.t =
  let c = field "certificate" j in
  {
    target_key_id = text "target_key_id" c;
    target_fingerprint = text "target_fingerprint" c;
    revoked_at = text "revoked_at" c;
    signatures = list_ (field "signatures" c) |> List.map claim_signature_of_json;
  }

let test_revocations () =
  let d = read_json "revocations.json" in
  let domain = text "domain" d in
  let domain_keys = list_ (field "domain_keys" d) |> List.map domain_public_key_of_json in
  List.iter
    (fun j ->
      let name = text "name" j in
      let verify_domain = text "verify_domain" j in
      let cert = revocation_certificate_of_json j in
      let expected_valid = bool_ (field "expected_valid" j) in
      let expected_counted = int_of_string (Yojson.Safe.to_string (field "expected_counted_signers" j)) in
      let counted = Revocation.count_valid_signers ~now:(Timeutil.parse_rfc3339 "2126-01-01T00:00:00Z") cert domain_keys verify_domain in
      Alcotest.(check int) (name ^ ": counted signers") expected_counted counted;
      let valid = try Revocation.verify_revocation_certificate ~now:(Timeutil.parse_rfc3339 "2126-01-01T00:00:00Z") cert domain_keys verify_domain; true with _ -> false in
      check_bool (name ^ ": overall valid") expected_valid valid)
    (list_ (field "certificate_cases" d));
  (* application_case: the flow complete_local_login actually exercises. *)
  let app = field "application_case" d in
  let envelope_j = field "envelope" app in
  let envelope : Types.Signed_local_rp_callback_payload.t =
    { payload = hex "payload_cbor_hex" envelope_j; signing_key_id = text "signing_key_id" envelope_j; signature = hex "signature_hex" envelope_j }
  in
  let verify_now = Timeutil.parse_rfc3339 (text "verify_now" app) in
  let skew = float_of_int (int_of_string (Yojson.Safe.to_string (field "clock_skew_seconds" app))) in
  let before_ok = try ignore (Local_rp.verify_local_rp_callback_payload envelope domain_keys verify_now skew); true with _ -> false in
  check_bool "application_case: valid before revocation" (bool_ (field "expected_valid_before_revocation" app)) before_ok;
  let target_cert =
    list_ (field "certificate_cases" d) |> List.find (fun j -> text "name" j = "valid_quorum_two_siblings") |> revocation_certificate_of_json
  in
  let filtered = Revocation.apply_revocations ~now:(Timeutil.parse_rfc3339 "2126-01-01T00:00:00Z") domain_keys [ target_cert ] domain in
  let after_ok = try ignore (Local_rp.verify_local_rp_callback_payload envelope filtered verify_now skew); true with _ -> false in
  check_bool "application_case: valid after revocation" (bool_ (field "expected_valid_after_revocation" app)) after_ok

(* ==================================================================== *)
(* Tls_client pin extraction -- openssl-CLI-minted Ed25519 cert fixture  *)
(* ==================================================================== *)

let test_tls_pin_extraction () =
  let ic = open_in_bin "fixtures/ed25519_cert.der" in
  let n = in_channel_length ic in
  let der = really_input_string ic n in
  close_in ic;
  (* Expected value computed independently with the openssl CLI: sha256 of
     the raw 32-byte Ed25519 public key extracted from the certificate's
     SubjectPublicKeyInfo (see the shell transcript in the README's TLS
     evaluation section). *)
  let expected = "0edf01c28f9066cd4ea14875b3490ee5d48e497c26145215797f1666700eece8" in
  Alcotest.(check string) "leaf_fingerprint_of_der matches independently-computed sha256(raw pubkey)" expected
    (Tls_client.leaf_fingerprint_of_der der);
  (* The pin authenticator itself: accepts when the fingerprint is in the
     pinned set, rejects otherwise. *)
  let cert = match X509.Certificate.decode_der (Cstruct.of_string der) with Ok c -> c | Error (`Msg m) -> Alcotest.fail m in
  let now = Unix.gettimeofday () in
  let auth_ok = Tls_client.pin_authenticator [ expected ] now in
  (match auth_ok ~host:None [ cert ] with Ok _ -> () | Error _ -> Alcotest.fail "expected pin authenticator to accept the matching fingerprint");
  let auth_bad = Tls_client.pin_authenticator [ String.make 64 'f' ] now in
  (match auth_bad ~host:None [ cert ] with Ok _ -> Alcotest.fail "expected pin authenticator to reject a non-matching fingerprint" | Error _ -> ())

(* ==================================================================== *)
(* RPC framing (length-prefix + CSIL-RPC envelope) -- in-memory, no TLS  *)
(* ==================================================================== *)

let test_rpc_framing () =
  let buf = Buffer.create 64 in
  let write s = Buffer.add_string buf s in
  Rpc.send_frame write "hello csil-rpc";
  let contents = Buffer.contents buf in
  let pos = ref 0 in
  let read_exact n =
    let s = String.sub contents !pos n in
    pos := !pos + n;
    s
  in
  let framed = Rpc.read_frame read_exact in
  Alcotest.(check string) "frame round-trip" "hello csil-rpc" framed;
  (* CSIL-RPC envelope encode/decode round trip. *)
  let req = Rpc.encode_request "DomainKeys" "get-domain-keys" "PAYLOAD" in
  let m = Cbor.as_map (Cbor.decode req) in
  Alcotest.(check string) "service" "DomainKeys" (Cbor.field_text m "service");
  Alcotest.(check string) "op" "get-domain-keys" (Cbor.field_text m "op");
  (* A representative CsilRpcResponse: status 0, variant, tag-24 payload. *)
  let resp = Cbor.encode (Map [ (Text "v", Int 1); (Text "status", Int 0); (Text "payload", Tag (24, Bytes "RESP")) ]) in
  let status, error, payload = Rpc.decode_response resp in
  Alcotest.(check int) "status" 0 status;
  Alcotest.(check (option string)) "error" None error;
  Alcotest.(check string) "payload" "RESP" payload

(* ==================================================================== *)
(* Flow test: end-to-end protocol logic with a fake IDP, no network/TLS  *)
(*                                                                       *)
(* TLS evaluation outcome (see tls_client.ml's module docs and the       *)
(* README for the full writeup): x509 supports Ed25519 certs and tls's   *)
(* Config.client accepts a custom pin-checking authenticator, but the    *)
(* [tls] package ships no blocking I/O driver (only Lwt/Async/Eio/Miou    *)
(* ones), so this SDK hand-drives Tls.Engine over a raw Unix socket       *)
(* (real code, in tls_client.ml) rather than pulling in an async         *)
(* runtime. That handshake loop has no live LinkKeys server to talk to   *)
(* in this environment, so it is exercised here only at the honest       *)
(* sub-seams that don't require one: pin-extraction (above) and framing  *)
(* (above). This flow test exercises the OTHER 95% of the SDK -- the     *)
(* full cryptographic verification chain complete_local_login runs      *)
(* internally -- by calling the same Local_rp/Claims/Revocation/Dns      *)
(* functions complete_local_login calls, in the same order, with a       *)
(* directly-supplied "fetched" key set standing in for what Rpc.        *)
(* fetch_domain_keys would have returned over the (untestable-here) TLS  *)
(* transport. This is "whatever seam is honest" per the task brief.     *)
(* ==================================================================== *)

type fake_idp = {
  domain : string;
  domain_signing_public : string;
  domain_signing_private : string;
  domain_signing_key_id : string;
  domain_keys : Types.Domain_public_key.t list;
}

let make_fake_idp ~now ~domain : fake_idp =
  let pub, priv = Crypto.generate_ed25519_keypair () in
  let key_id = "idp-signing-1" in
  let key : Types.Domain_public_key.t =
    {
      key_id;
      public_key = pub;
      fingerprint = Crypto.fingerprint pub;
      algorithm = Crypto.SigningAlgorithm.ed25519;
      key_usage = "sign";
      created_at = Timeutil.to_rfc3339 now;
      expires_at = Timeutil.to_rfc3339 (now +. (365.0 *. 86400.0));
      revoked_at = None;
      signed_by_key_id = None;
      key_signature = None;
    }
  in
  { domain; domain_signing_public = pub; domain_signing_private = priv; domain_signing_key_id = key_id; domain_keys = [ key ] }

(* Run the begin -> (fake IDP issues callback) -> complete chain, with
   [complete]'s domain-key-fetch step replaced by directly supplying
   [idp.domain_keys] (this is the untestable-without-a-live-server part;
   everything else is the real SDK code). Returns the verified login. *)
let run_happy_path () : Complete_login.verified_local_login =
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let identity =
    Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"Flow Test App" ~now ())
  in
  let idp = make_fake_idp ~now ~domain:"idp.example" in
  let redirect, pending =
    Begin_login.begin_local_login_exn
      (Begin_login.make_config ~key_material:identity ~callback_url:"http://127.0.0.1:9000/callback" ~user_domain:idp.domain ~now ())
  in
  check_bool "redirect URL targets the user domain" true (String.length redirect.redirect_url > 0);
  let request = Url_params.signed_local_rp_login_request_from_url_param
      (match String.index_opt redirect.redirect_url '=' with
      | Some idx -> String.sub redirect.redirect_url (idx + 1) (String.length redirect.redirect_url - idx - 1)
      | None -> Alcotest.fail "redirect URL missing signed_request param")
  in
  let login_request = Types.Local_rp_login_request.of_cbor request.request in
  (* Fake IDP: build+sign+seal the callback payload. *)
  let claim_ticket = Crypto.random_bytes 32 in
  let payload =
    Local_rp.build_local_rp_callback_payload ~user_id:"user-1" ~user_domain:idp.domain ~claim_ticket
      ~audience_fingerprint:identity.fingerprint ~callback_url:login_request.callback_url ~nonce:login_request.nonce
      ~state:login_request.state ~issued_at:(Timeutil.to_rfc3339 now) ~expires_at:(Timeutil.to_rfc3339 (now +. 300.0))
  in
  let signed_payload =
    Local_rp.sign_local_rp_callback_payload payload ~key_id:idp.domain_signing_key_id ~algorithm:Crypto.SigningAlgorithm.ed25519
      idp.domain_signing_private
  in
  let suite = Crypto.AeadSuite.Aes256Gcm in
  let encrypted =
    Local_rp.seal_local_rp_callback signed_payload suite identity.encryption_public_key ~fingerprint:identity.fingerprint
      ~nonce:login_request.nonce ~state:login_request.state ~issued_at:(Timeutil.to_rfc3339 now)
      ~expires_at:(Timeutil.to_rfc3339 (now +. 300.0))
  in
  let encrypted_token = Url_params.local_rp_encrypted_callback_to_url_param encrypted in
  let arrived_url = Printf.sprintf "%s?encrypted_token=%s" login_request.callback_url encrypted_token in
  (* RP side: everything complete_local_login does, except the domain-key
     fetch is a direct value instead of an Rpc/Tls round-trip (see module
     docs above). *)
  let own_descriptor = Types.Local_rp_descriptor.of_cbor identity.descriptor.descriptor in
  let allowed_suites = List.filter_map Crypto.AeadSuite.parse_str own_descriptor.supported_suites in
  let header, sp = Local_rp.open_local_rp_callback encrypted identity.encryption_private_key allowed_suites in
  let verified_payload = Local_rp.verify_local_rp_callback_payload sp idp.domain_keys now Local_rp.default_clock_skew_seconds in
  Local_rp.check_callback_header_matches_payload header verified_payload;
  Local_rp.verify_audience verified_payload.audience_fingerprint identity.fingerprint;
  Local_rp.verify_issuer verified_payload.user_domain pending.user_domain;
  Local_rp.verify_callback_url verified_payload.callback_url (Complete_login.strip_encrypted_token_param arrived_url);
  Local_rp.verify_nonce_state pending.nonce pending.state verified_payload.nonce verified_payload.state;
  (* Ticket redemption: fake IDP signs a claim and hands it back directly
     (again standing in for the untestable-here TCP round trip); the
     redemption REQUEST itself (the RP's possession-proof signature) is
     real SDK code. *)
  let redemption_request =
    Local_rp.build_local_rp_ticket_redemption_request ~claim_ticket:verified_payload.claim_ticket ~fingerprint:identity.fingerprint
      ~issued_at:(Timeutil.to_rfc3339 now)
  in
  let signed_redemption = Local_rp.sign_local_rp_ticket_redemption_request redemption_request identity.signing_private_key in
  (* The fake IDP "verifies" the redemption signature the way the real
     server would, proving the request really is possession-proof shaped. *)
  Crypto.resolve_and_verify Crypto.SigningAlgorithm.ed25519
    (Local_rp.envelope_signature_input Local_rp.ctx_local_rp_ticket_redemption signed_redemption.request)
    signed_redemption.signature identity.signing_public_key;
  let claim : Types.Claim.t =
    Claims.sign_claim
      { claim_id = "claim-1"; claim_type = "handle"; claim_value = "flowtester"; user_id = "user-1"; subject_domain = idp.domain; attested_at = Timeutil.to_rfc3339 now; expires_at = None }
      [ { domain = idp.domain; key_id = idp.domain_signing_key_id; algorithm = Crypto.SigningAlgorithm.ed25519; private_key = idp.domain_signing_private } ]
  in
  let redemption_response : Types.Local_rp_ticket_redemption_response.t =
    { user_id = "user-1"; user_domain = idp.domain; claims = [ claim ]; ticket_expires_at = Timeutil.to_rfc3339 (now +. 3600.0) }
  in
  let domain_key_sets = [ ({ domain = idp.domain; keys = idp.domain_keys } : Claims.domain_key_set) ] in
  List.iter (fun c -> Claims.verify_claim c redemption_response.user_domain domain_key_sets now) redemption_response.claims;
  {
    user_id = redemption_response.user_id;
    user_domain = redemption_response.user_domain;
    claims = redemption_response.claims;
    domain_public_keys = idp.domain_keys;
    local_rp_fingerprint = identity.fingerprint;
    issued_at = Timeutil.parse_rfc3339 verified_payload.issued_at;
    expires_at = Timeutil.parse_rfc3339 verified_payload.expires_at;
    ticket_expires_at = Timeutil.parse_rfc3339 redemption_response.ticket_expires_at;
  }

let test_flow_happy_path () =
  let v = run_happy_path () in
  Alcotest.(check string) "user_id" "user-1" v.user_id;
  Alcotest.(check string) "user_domain" "idp.example" v.user_domain;
  Alcotest.(check int) "claim count" 1 (List.length v.claims)

let test_flow_wrong_domain_keys_fails () =
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let identity = Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"Flow Test App" ~now ()) in
  let idp = make_fake_idp ~now ~domain:"idp.example" in
  let attacker_idp = make_fake_idp ~now ~domain:"idp.example" in
  let _redirect, pending =
    Begin_login.begin_local_login_exn
      (Begin_login.make_config ~key_material:identity ~callback_url:"http://127.0.0.1:9000/callback" ~user_domain:idp.domain ~now ())
  in
  let payload =
    Local_rp.build_local_rp_callback_payload ~user_id:"user-1" ~user_domain:idp.domain ~claim_ticket:(Crypto.random_bytes 32)
      ~audience_fingerprint:identity.fingerprint ~callback_url:pending.callback_url ~nonce:pending.nonce ~state:pending.state
      ~issued_at:(Timeutil.to_rfc3339 now) ~expires_at:(Timeutil.to_rfc3339 (now +. 300.0))
  in
  (* Signed by the ATTACKER's key, but we verify against the real idp's
     fetched key set: must fail (Key_not_found -- the signing_key_id won't
     resolve in idp.domain_keys). *)
  let signed_payload =
    Local_rp.sign_local_rp_callback_payload payload ~key_id:attacker_idp.domain_signing_key_id ~algorithm:Crypto.SigningAlgorithm.ed25519
      attacker_idp.domain_signing_private
  in
  let ok = try ignore (Local_rp.verify_local_rp_callback_payload signed_payload idp.domain_keys now Local_rp.default_clock_skew_seconds); true with _ -> false in
  check_bool "callback signed by a non-matching key must fail verification" false ok

let test_flow_unadvertised_suite_rejected () =
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let identity =
    Identity.generate_local_rp_identity_exn
      (Identity.make_config ~app_name:"Flow Test App" ~now ~supported_suites:[ Crypto.AeadSuite.aes_256_gcm_str ] ())
  in
  let idp = make_fake_idp ~now ~domain:"idp.example" in
  let payload =
    Local_rp.build_local_rp_callback_payload ~user_id:"user-1" ~user_domain:idp.domain ~claim_ticket:(Crypto.random_bytes 32)
      ~audience_fingerprint:identity.fingerprint ~callback_url:"http://127.0.0.1:9000/callback" ~nonce:(Crypto.random_bytes 32)
      ~state:(Crypto.random_bytes 32) ~issued_at:(Timeutil.to_rfc3339 now) ~expires_at:(Timeutil.to_rfc3339 (now +. 300.0))
  in
  let signed_payload =
    Local_rp.sign_local_rp_callback_payload payload ~key_id:idp.domain_signing_key_id ~algorithm:Crypto.SigningAlgorithm.ed25519
      idp.domain_signing_private
  in
  let encrypted =
    Local_rp.seal_local_rp_callback signed_payload Crypto.AeadSuite.Chacha20Poly1305 identity.encryption_public_key
      ~fingerprint:identity.fingerprint ~nonce:(Crypto.random_bytes 32) ~state:(Crypto.random_bytes 32)
      ~issued_at:(Timeutil.to_rfc3339 now) ~expires_at:(Timeutil.to_rfc3339 (now +. 300.0))
  in
  let own_descriptor = Types.Local_rp_descriptor.of_cbor identity.descriptor.descriptor in
  let allowed_suites = List.filter_map Crypto.AeadSuite.parse_str own_descriptor.supported_suites in
  let ok = try ignore (Local_rp.open_local_rp_callback encrypted identity.encryption_private_key allowed_suites); true with _ -> false in
  check_bool "suite not advertised in own descriptor must be rejected" false ok

let test_flow_revoked_rp_style_ticket_rejected () =
  (* Mirrors "revoked local RP fails ticket redemption" at the layer this
     SDK owns: the redemption REQUEST signature itself. If the app's
     signing key is wrong (e.g. a stale/rotated identity), the possession
     proof fails -- this is the check the server relies on, exercised
     here without a server. *)
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let identity = Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"App" ~now ()) in
  let other_identity = Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"Other App" ~now ()) in
  let redemption_request =
    Local_rp.build_local_rp_ticket_redemption_request ~claim_ticket:(Crypto.random_bytes 32) ~fingerprint:identity.fingerprint
      ~issued_at:(Timeutil.to_rfc3339 now)
  in
  let signed_redemption = Local_rp.sign_local_rp_ticket_redemption_request redemption_request other_identity.signing_private_key in
  let ok =
    try
      Crypto.resolve_and_verify Crypto.SigningAlgorithm.ed25519
        (Local_rp.envelope_signature_input Local_rp.ctx_local_rp_ticket_redemption signed_redemption.request)
        signed_redemption.signature identity.signing_public_key;
      true
    with _ -> false
  in
  check_bool "redemption signed by the wrong identity must fail possession-proof verification" false ok

let test_check_expirations_facade () =
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let identity = Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"App" ~now ()) in
  match check_expirations identity now with
  | Ok status -> Alcotest.(check string) "fresh identity is ok" "ok" (level_to_string status.level)
  | Error e -> Alcotest.failf "check_expirations failed: %s" (Error.to_string e)

let test_identity_byte_roundtrip () =
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let identity = Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"App" ~now ()) in
  let bytes = local_rp_identity_to_bytes identity in
  match local_rp_identity_from_bytes bytes with
  | Error e -> Alcotest.failf "round-trip failed: %s" (Error.to_string e)
  | Ok identity2 ->
    Alcotest.(check string) "fingerprint round-trips" identity.fingerprint identity2.fingerprint;
    Alcotest.(check string) "signing private key round-trips" (Hex.encode identity.signing_private_key) (Hex.encode identity2.signing_private_key);
    Alcotest.(check string) "encryption private key round-trips" (Hex.encode identity.encryption_private_key) (Hex.encode identity2.encryption_private_key)

(* Regression test: Claim.claim_value is CBOR BYTES on the wire (CSIL:
   `claim_value: bytes`; Rust codec: `cbor_bytes(&csil_v.claim_value)`).
   An earlier revision of types.ml encoded it as CBOR text, which no
   conformance vector caught -- NO vector file contains a Claim struct at
   all (envelopes/callback_box cover the four local-RP envelopes,
   revocations covers RevocationCertificate/ClaimSignature; none carries a
   Claim or a LocalRpTicketRedemptionResponse). This test pins the wire
   type directly, including a non-UTF-8 value, until the shared vectors
   grow a Claim case. *)
let test_claim_value_wire_type () =
  let binary_value = "\x00\xff\x80binary\x01" in
  let claim : Types.Claim.t =
    {
      claim_id = "claim-wire";
      user_id = "user-1";
      claim_type = "avatar";
      claim_value = binary_value;
      signatures = [];
      attested_at = "2030-01-01T00:00:00Z";
      created_at = "2030-01-01T00:00:00Z";
      expires_at = None;
      revoked_at = None;
    }
  in
  let encoded = Types.Claim.to_cbor claim in
  (* The encoded map's claim_value entry must be a CBOR byte string (major
     type 2), not a text string. *)
  (match Cbor.field (Cbor.as_map (Cbor.decode encoded)) "claim_value" with
  | Some (Cbor.Bytes b) -> Alcotest.(check string) "claim_value bytes survive" (Hex.encode binary_value) (Hex.encode b)
  | Some (Cbor.Text _) -> Alcotest.fail "claim_value encoded as CBOR text; wire type is bytes"
  | _ -> Alcotest.fail "claim_value missing or wrong CBOR type");
  (* Full round trip, binary-safe. *)
  let decoded = Types.Claim.of_cbor encoded in
  Alcotest.(check string) "claim_value round-trips" (Hex.encode binary_value) (Hex.encode decoded.claim_value);
  (* Decode is strict: a Claim whose claim_value arrives as CBOR text (a
     buggy peer) is rejected, matching the generated Rust codec's own
     cbor_as_bytes behavior. *)
  let text_variant =
    Cbor.encode
      (Cbor.Map
         (List.map
            (fun (k, v) -> if k = Cbor.Text "claim_value" then (k, Cbor.Text "not-bytes") else (k, v))
            (Cbor.as_map (Cbor.decode encoded))))
  in
  let ok = try ignore (Types.Claim.of_cbor text_variant); true with _ -> false in
  check_bool "text claim_value rejected on decode" false ok;
  (* And the signature payload binds claim_value as bytes too (mirroring
     crates/liblinkkeys/src/claims.rs's serde_bytes::Bytes): a claim signed
     over a binary value must verify. *)
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let idp = make_fake_idp ~now ~domain:"idp.example" in
  let signed_claim =
    Claims.sign_claim
      { claim_id = "claim-wire"; claim_type = "avatar"; claim_value = binary_value; user_id = "user-1"; subject_domain = idp.domain; attested_at = Timeutil.to_rfc3339 now; expires_at = None }
      [ { domain = idp.domain; key_id = idp.domain_signing_key_id; algorithm = Crypto.SigningAlgorithm.ed25519; private_key = idp.domain_signing_private } ]
  in
  Claims.verify_claim signed_claim idp.domain [ { domain = idp.domain; keys = idp.domain_keys } ] now

(* ==================================================================== *)
(* Security-review fixes: identity binding (FIX A), revocation           *)
(* fail-open -> fail-closed (FIX B), and DNS response validation (SF-4). *)
(*                                                                        *)
(* The identity-binding and revocation checks below are exercised        *)
(* directly against the small, PURE functions [complete_login.ml]/       *)
(* [rpc.ml] extract them into ([Complete_login.check_*],                *)
(* [Rpc.establish_trusted_keys]) rather than by driving the full         *)
(* [complete_local_login]/[Rpc.fetch_domain_keys] end-to-end -- the rest *)
(* of that chain needs a real TLS+CSIL-RPC peer, which (per               *)
(* [tls_client.ml]'s module docs) is not available in this environment.  *)
(* This is the same "test the honest seam" philosophy the flow tests     *)
(* above already use, applied to the new fixes specifically: these ARE   *)
(* the real production functions [complete_local_login_exn]/             *)
(* [fetch_domain_keys] call, not reimplementations of their logic.       *)
(* ==================================================================== *)

let dummy_payload ~user_id ~user_domain : Types.Local_rp_callback_payload.t =
  {
    user_id;
    user_domain;
    claim_ticket = "ticket";
    audience_fingerprint = "fp";
    callback_url = "http://localhost/callback";
    nonce = "nonce";
    state = "state";
    issued_at = "2030-01-01T00:00:00Z";
    expires_at = "2030-01-01T00:05:00Z";
  }

let dummy_redemption ~user_id ~user_domain ~claims : Types.Local_rp_ticket_redemption_response.t =
  { user_id; user_domain; claims; ticket_expires_at = "2030-01-01T01:00:00Z" }

let dummy_claim ~user_id ~claim_type : Types.Claim.t =
  {
    claim_id = "claim-1";
    user_id;
    claim_type;
    claim_value = "value";
    signatures = [];
    attested_at = "2030-01-01T00:00:00Z";
    created_at = "2030-01-01T00:00:00Z";
    expires_at = None;
    revoked_at = None;
  }

(* Hostile-IDP fatal test (1): ticket redemption identity != signed
   callback payload identity. *)
let test_complete_login_redemption_identity_mismatch_is_fatal () =
  let payload = dummy_payload ~user_id:"user-1" ~user_domain:"idp.example" in
  (* Same domain, different user_id -- laundering an approval given to one
     user onto another's claims. *)
  let redemption_wrong_user = dummy_redemption ~user_id:"attacker-user" ~user_domain:"idp.example" ~claims:[] in
  (match Complete_login.check_redemption_identity_matches_payload redemption_wrong_user payload with
  | () -> Alcotest.fail "expected a mismatched redemption user_id to be rejected as fatal"
  | exception Error.Sdk_error (Error.Identity_mismatch _) -> ()
  | exception e -> Alcotest.failf "expected Error.Identity_mismatch, got %s" (Printexc.to_string e));
  (* Same user_id, different domain. *)
  let redemption_wrong_domain = dummy_redemption ~user_id:"user-1" ~user_domain:"attacker.example" ~claims:[] in
  (match Complete_login.check_redemption_identity_matches_payload redemption_wrong_domain payload with
  | () -> Alcotest.fail "expected a mismatched redemption user_domain to be rejected as fatal"
  | exception Error.Sdk_error (Error.Identity_mismatch _) -> ()
  | exception e -> Alcotest.failf "expected Error.Identity_mismatch, got %s" (Printexc.to_string e));
  (* Positive control: matching identity must not raise. *)
  let redemption_ok = dummy_redemption ~user_id:"user-1" ~user_domain:"idp.example" ~claims:[] in
  Complete_login.check_redemption_identity_matches_payload redemption_ok payload

(* Hostile-IDP fatal test (2): a claim naming a user_id other than the
   signed callback payload's. *)
let test_complete_login_claim_user_id_mismatch_is_fatal () =
  let claim = dummy_claim ~user_id:"attacker-user" ~claim_type:"handle" in
  (match Complete_login.check_claim_user_id_matches_payload claim "user-1" with
  | () -> Alcotest.fail "expected a claim naming a different user_id to be rejected as fatal"
  | exception Error.Sdk_error (Error.Identity_mismatch _) -> ()
  | exception e -> Alcotest.failf "expected Error.Identity_mismatch, got %s" (Printexc.to_string e));
  let ok_claim = dummy_claim ~user_id:"user-1" ~claim_type:"handle" in
  Complete_login.check_claim_user_id_matches_payload ok_claim "user-1"

(* Hostile-IDP fatal test (3): required_claims empty or insufficient
   against the claims that survived verification. *)
let test_complete_login_required_claims_missing_is_fatal () =
  let handle_claim = dummy_claim ~user_id:"user-1" ~claim_type:"handle" in
  (* Entirely empty verified-claims set against a non-empty requirement. *)
  (match Complete_login.check_required_claims_satisfied [ "handle" ] [] with
  | () -> Alcotest.fail "expected an empty verified-claim set to fail a non-empty requirement"
  | exception Error.Sdk_error (Error.Required_claims_not_satisfied missing) -> Alcotest.(check (list string)) "missing" [ "handle" ] missing
  | exception e -> Alcotest.failf "expected Error.Required_claims_not_satisfied, got %s" (Printexc.to_string e));
  (* Insufficient: required handle+email, only handle present. *)
  (match Complete_login.check_required_claims_satisfied [ "handle"; "email" ] [ handle_claim ] with
  | () -> Alcotest.fail "expected an insufficient verified-claim set to fail"
  | exception Error.Sdk_error (Error.Required_claims_not_satisfied missing) -> Alcotest.(check (list string)) "missing" [ "email" ] missing
  | exception e -> Alcotest.failf "expected Error.Required_claims_not_satisfied, got %s" (Printexc.to_string e));
  (* Positive controls: a satisfied requirement, and no requirement at all
     (even against zero claims), must not raise. *)
  Complete_login.check_required_claims_satisfied [ "handle" ] [ handle_claim ];
  Complete_login.check_required_claims_satisfied [] []

(* FIX A.1: [pending_login] must retain [required_claims], and it must
   round-trip through [pending_login_to_fields]/[pending_login_of_fields]
   (the serialization form apps persist between begin and complete). *)
let test_pending_login_required_claims_roundtrip () =
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let identity = Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"App" ~now ()) in
  let _redirect, pending =
    Begin_login.begin_local_login_exn
      (Begin_login.make_config ~key_material:identity ~callback_url:"http://127.0.0.1:9000/callback" ~user_domain:"idp.example" ~now
         ~required_claims:[ "handle"; "email" ] ())
  in
  Alcotest.(check (list string)) "pending_login retains the required_claims it was begun with" [ "handle"; "email" ] pending.required_claims;
  let fields = Begin_login.pending_login_to_fields pending in
  match Begin_login.pending_login_of_fields fields with
  | Error e -> Alcotest.failf "pending_login_of_fields failed: %s" (Error.to_string e)
  | Ok pending2 ->
    Alcotest.(check (list string)) "required_claims round-trips through pending_login_to_fields/of_fields" pending.required_claims
      pending2.required_claims

(* Hostile-IDP fatal test (4): a [get-revocations] fetch failure must fail
   closed (propagate), never be silently swallowed to "proceed
   unfiltered". *)
let test_rpc_establish_trusted_keys_revocation_fetch_error_fails_closed () =
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let idp = make_fake_idp ~now ~domain:"idp.example" in
  let resp : Types.Get_domain_keys_response.t = { domain = idp.domain; keys = idp.domain_keys; recent_revocations_available = None } in
  let endpoint_fingerprints = List.map (fun (k : Types.Domain_public_key.t) -> k.fingerprint) idp.domain_keys in
  let fetch_revocations () : Types.Get_revocations_response.t = failwith "simulated get-revocations RPC failure" in
  let ok =
    try
      ignore (Rpc.establish_trusted_keys ~now ~domain:idp.domain resp ~endpoint_fingerprints fetch_revocations);
      true
    with Failure _ -> false
  in
  check_bool "a get-revocations fetch failure must propagate (fail closed), not be silently swallowed" false ok

(* Hostile-IDP fatal test (5): a quorum-verified sibling revocation
   certificate targeting a domain's signing key must actually be applied
   -- the revoked key is excluded from the trusted result (so it can never
   again verify an envelope/claim signature), even though this SDK now
   fetches revocations on EVERY call (not just when a flag says to). The
   (non-revoked) sibling keys that supplied the quorum remain trusted. *)
let test_rpc_establish_trusted_keys_cert_revoked_signing_key_excluded () =
  let now = Timeutil.parse_rfc3339 "2030-01-01T00:00:00Z" in
  let domain = "idp.example" in
  let make_key key_id pub : Types.Domain_public_key.t =
    {
      key_id;
      public_key = pub;
      fingerprint = Crypto.fingerprint pub;
      algorithm = Crypto.SigningAlgorithm.ed25519;
      key_usage = "sign";
      created_at = Timeutil.to_rfc3339 now;
      expires_at = Timeutil.to_rfc3339 (now +. (365.0 *. 86400.0));
      revoked_at = None;
      signed_by_key_id = None;
      key_signature = None;
    }
  in
  let target_pub, _target_priv = Crypto.generate_ed25519_keypair () in
  let sib1_pub, sib1_priv = Crypto.generate_ed25519_keypair () in
  let sib2_pub, sib2_priv = Crypto.generate_ed25519_keypair () in
  let target_key = make_key "idp-target" target_pub in
  let sib1_key = make_key "idp-sibling-1" sib1_pub in
  let sib2_key = make_key "idp-sibling-2" sib2_pub in
  let all_keys = [ target_key; sib1_key; sib2_key ] in
  let revoked_at = Timeutil.to_rfc3339 now in
  let sign priv = Crypto.sign_ed25519 priv (Revocation.revocation_payload target_key.key_id target_key.fingerprint revoked_at domain) in
  let cert : Types.Revocation_certificate.t =
    {
      target_key_id = target_key.key_id;
      target_fingerprint = target_key.fingerprint;
      revoked_at;
      signatures =
        [
          ({ domain; signed_by_key_id = sib1_key.key_id; signature = sign sib1_priv } : Types.Claim_signature.t);
          { domain; signed_by_key_id = sib2_key.key_id; signature = sign sib2_priv };
        ];
    }
  in
  let resp : Types.Get_domain_keys_response.t = { domain; keys = all_keys; recent_revocations_available = None } in
  let endpoint_fingerprints = List.map (fun (k : Types.Domain_public_key.t) -> k.fingerprint) all_keys in
  let trusted =
    Rpc.establish_trusted_keys ~now ~domain resp ~endpoint_fingerprints (fun () -> ({ revocations = [ cert ] } : Types.Get_revocations_response.t))
  in
  check_bool "quorum-verified revocation certificate excludes the target signing key" false
    (List.exists (fun (k : Types.Domain_public_key.t) -> k.key_id = target_key.key_id) trusted);
  check_bool "the (non-revoked) sibling keys remain trusted" true
    (List.exists (fun (k : Types.Domain_public_key.t) -> k.key_id = sib1_key.key_id) trusted
    && List.exists (fun (k : Types.Domain_public_key.t) -> k.key_id = sib2_key.key_id) trusted)

(* SF-4 SEC fix: build a minimal DNS message (header + one question,
   optionally marked as a response) so [Dns.System_resolver.response_matches_query]
   can be tested directly against exact byte-level id/QR/question
   mismatches, without a real socket (loopback UDP port 53 requires root
   in this environment, so this is the honest seam here too). *)
let build_dns_msg ~id ~qr ~qname ~qtype ~qclass : string =
  let buf = Buffer.create 64 in
  let add_u16 n =
    Buffer.add_char buf (Char.chr ((n lsr 8) land 0xff));
    Buffer.add_char buf (Char.chr (n land 0xff))
  in
  add_u16 id;
  add_u16 (if qr then 0x8100 else 0x0100);
  add_u16 1 (* qdcount *);
  add_u16 0;
  add_u16 0;
  add_u16 0;
  Buffer.add_string buf (Dns.System_resolver.encode_qname qname);
  add_u16 qtype;
  add_u16 qclass;
  Buffer.contents buf

let test_dns_spoofed_response_rejected () =
  let name = "_linkkeys.example.com" in
  let genuine = build_dns_msg ~id:0x1234 ~qr:true ~qname:name ~qtype:16 ~qclass:1 in
  check_bool "matching id/QR/question is accepted" true (Dns.System_resolver.response_matches_query genuine ~query_id:0x1234 ~qname:name);
  let wrong_id = build_dns_msg ~id:0x9999 ~qr:true ~qname:name ~qtype:16 ~qclass:1 in
  check_bool "mismatched transaction id is rejected" false (Dns.System_resolver.response_matches_query wrong_id ~query_id:0x1234 ~qname:name);
  let still_a_query = build_dns_msg ~id:0x1234 ~qr:false ~qname:name ~qtype:16 ~qclass:1 in
  check_bool "QR bit unset (not actually a response) is rejected" false
    (Dns.System_resolver.response_matches_query still_a_query ~query_id:0x1234 ~qname:name);
  let wrong_question_name = build_dns_msg ~id:0x1234 ~qr:true ~qname:"attacker.example" ~qtype:16 ~qclass:1 in
  check_bool "echoed question naming a different domain is rejected" false
    (Dns.System_resolver.response_matches_query wrong_question_name ~query_id:0x1234 ~qname:name);
  let wrong_qtype = build_dns_msg ~id:0x1234 ~qr:true ~qname:name ~qtype:1 (* A, not TXT *) ~qclass:1 in
  check_bool "echoed qtype != TXT is rejected" false (Dns.System_resolver.response_matches_query wrong_qtype ~query_id:0x1234 ~qname:name);
  let case_insensitive = build_dns_msg ~id:0x1234 ~qr:true ~qname:(String.uppercase_ascii name) ~qtype:16 ~qclass:1 in
  check_bool "echoed question name comparison is case-insensitive" true
    (Dns.System_resolver.response_matches_query case_insensitive ~query_id:0x1234 ~qname:name);
  let truncated = String.sub genuine 0 8 in
  check_bool "a too-short/malformed datagram is rejected, not an uncaught exception" false
    (Dns.System_resolver.response_matches_query truncated ~query_id:0x1234 ~qname:name);
  (* Peer-address pinning: a datagram must also come from the exact
     nameserver the query was sent to. *)
  let real_ns = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 53) in
  let same_ns = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 53) in
  let spoofed_ip = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.2", 53) in
  let spoofed_port = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 9999) in
  check_bool "identical resolver address+port matches" true (Dns.System_resolver.same_peer real_ns same_ns);
  check_bool "a datagram from a different address is not the queried resolver" false (Dns.System_resolver.same_peer real_ns spoofed_ip);
  check_bool "a datagram from a different port is not the queried resolver" false (Dns.System_resolver.same_peer real_ns spoofed_port)

(* ==================================================================== *)

let () =
  Alcotest.run "linkkeys_local_rp"
    [
      ("keys.json", [ Alcotest.test_case "fixture sanity" `Quick test_keys_fixture ]);
      ("envelopes.json", [ Alcotest.test_case "cases + negative_cases" `Quick test_envelopes ]);
      ("callback_box.json", [ Alcotest.test_case "positive_cases + negative_cases" `Quick test_callback_box ]);
      ("url_params.json", [ Alcotest.test_case "cases + negative_cases" `Quick test_url_params ]);
      ("dns.json", [ Alcotest.test_case "linkkeys_txt + linkkeys_apis_txt" `Quick test_dns ]);
      ("tickets.json", [ Alcotest.test_case "sha256 hashing" `Quick test_tickets ]);
      ( "claims.json",
        [
          Alcotest.test_case "cases: round-trip + signed-payload recomputation + verify_claim" `Quick test_claims_positive_cases;
          Alcotest.test_case "decode_negative_cases: tstr claim_value rejected" `Quick test_claims_decode_negative_cases;
          Alcotest.test_case "negative_cases: verification failures with expected error kinds" `Quick test_claims_negative_cases;
          Alcotest.test_case "ticket_redemption_response: round-trip + embedded claim verification" `Quick
            test_claims_ticket_redemption_response;
        ] );
      ("expirations.json", [ Alcotest.test_case "check_expirations + check_timestamps" `Quick test_expirations ]);
      ("revocations.json", [ Alcotest.test_case "certificate_cases + application_case" `Quick test_revocations ]);
      ("tls pin extraction", [ Alcotest.test_case "openssl-minted Ed25519 cert fixture" `Quick test_tls_pin_extraction ]);
      ("rpc framing", [ Alcotest.test_case "length-prefix + envelope round-trip" `Quick test_rpc_framing ]);
      ( "flow",
        [
          Alcotest.test_case "happy path end-to-end" `Quick test_flow_happy_path;
          Alcotest.test_case "wrong signer key fails" `Quick test_flow_wrong_domain_keys_fails;
          Alcotest.test_case "unadvertised suite rejected" `Quick test_flow_unadvertised_suite_rejected;
          Alcotest.test_case "wrong-identity ticket redemption signature rejected" `Quick test_flow_revoked_rp_style_ticket_rejected;
          Alcotest.test_case "check_expirations facade" `Quick test_check_expirations_facade;
          Alcotest.test_case "identity byte round-trip" `Quick test_identity_byte_roundtrip;
          Alcotest.test_case "claim_value wire type is bytes" `Quick test_claim_value_wire_type;
        ] );
      ( "security fixes",
        [
          Alcotest.test_case "pending_login required_claims round-trips" `Quick test_pending_login_required_claims_roundtrip;
          Alcotest.test_case "hostile IDP (1): redemption identity != signed payload is fatal" `Quick
            test_complete_login_redemption_identity_mismatch_is_fatal;
          Alcotest.test_case "hostile IDP (2): claim.user_id != payload.user_id is fatal" `Quick
            test_complete_login_claim_user_id_mismatch_is_fatal;
          Alcotest.test_case "hostile IDP (3): required_claims empty/insufficient is fatal" `Quick
            test_complete_login_required_claims_missing_is_fatal;
          Alcotest.test_case "hostile IDP (4): get-revocations fetch error fails closed" `Quick
            test_rpc_establish_trusted_keys_revocation_fetch_error_fails_closed;
          Alcotest.test_case "hostile IDP (5): certificate-revoked signing key is excluded" `Quick
            test_rpc_establish_trusted_keys_cert_revoked_signing_key_excluded;
          Alcotest.test_case "SF-4: spoofed/mismatched DNS response is rejected" `Quick test_dns_spoofed_response_rejected;
        ] );
    ]
