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

let string_contains (haystack : string) (needle : string) : bool =
  let h = String.length haystack and n = String.length needle in
  let rec loop i = i + n <= h && (String.sub haystack i n = needle || loop (i + 1)) in
  loop 0

(* ------------------------------------------------------------------ *)
(* Browser endpoint discovery in [begin_local_login] (mirrors             *)
(* sdks/local-rp/go/browser_test.go). Every resolver here is a hermetic  *)
(* fake with canned TXT answers; no test performs a live DNS request.    *)
(* ------------------------------------------------------------------ *)

let browser_test_domain = "ident.example.test"

let apis_resolver (txts : string list) : Dns.resolver =
  {
    Dns.txt_lookup =
      (fun name ->
        if name = "_linkkeys_apis." ^ browser_test_domain then txts
        else raise (Dns.Dns_parse_error ("no fake record for " ^ name)));
  }

(* Every lookup fails: [begin_local_login] falls back to the identity domain. *)
let failing_resolver : Dns.resolver = { Dns.txt_lookup = (fun _ -> raise (Dns.Dns_parse_error "SERVFAIL")) }

let has_prefix ~prefix s = String.length s >= String.length prefix && String.sub s 0 (String.length prefix) = prefix

let has_suffix ~suffix s =
  let ls = String.length s and lx = String.length suffix in
  ls >= lx && String.sub s (ls - lx) lx = suffix

let check_prefix (msg : string) (prefix : string) (url : string) : unit =
  check_bool (Printf.sprintf "%s: %S has prefix %S" msg url prefix) true (has_prefix ~prefix url)

let browser_begin_with ?(user_domain = browser_test_domain) (dns : Dns.resolver) =
  let now = Timeutil.parse_rfc3339 "2026-08-17T12:00:00Z" in
  let identity = Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"browser-test" ~now ()) in
  Begin_login.begin_local_login_exn
    (Begin_login.make_config ~key_material:identity ~callback_url:"http://app.lan:8080/cb" ~user_domain ~now ~dns ())

(* Case 1: a valid https= host is used for the redirect instead of the
   identity domain. Case 8: [pending_login.user_domain] stays the identity
   domain -- verification stays bound to it, not to the service host. *)
let test_browser_discovered_host () =
  let redirect, pending =
    browser_begin_with (apis_resolver [ "v=lk1 tcp=linkkeys.ident.example.test https=linkkeys.ident.example.test" ])
  in
  check_prefix "discovered host" "https://linkkeys.ident.example.test/auth/local-rp?signed_request=" redirect.redirect_url;
  check_bool "identity domain is not the redirect host" false
    (has_prefix ~prefix:("https://" ^ browser_test_domain ^ "/") redirect.redirect_url);
  Alcotest.(check string) "pending user_domain stays the identity domain" browser_test_domain pending.user_domain

(* Case 2: an https= value with a path prefix preserves that prefix. *)
let test_browser_path_prefix () =
  let redirect, _ = browser_begin_with (apis_resolver [ "v=lk1 https=login.example.test/linkkeys" ]) in
  check_prefix "path prefix" "https://login.example.test/linkkeys/auth/local-rp?signed_request=" redirect.redirect_url

(* Case 3: a record with only tcp= falls back to the identity domain. *)
let test_browser_tcp_only_fallback () =
  let redirect, _ = browser_begin_with (apis_resolver [ "v=lk1 tcp=linkkeys.ident.example.test" ]) in
  check_prefix "tcp-only fallback" ("https://" ^ browser_test_domain ^ "/auth/local-rp?signed_request=") redirect.redirect_url

(* Case 4: a DNS lookup error falls back to the identity domain. *)
let test_browser_dns_error_fallback () =
  let redirect, _ = browser_begin_with failing_resolver in
  check_prefix "dns error fallback" ("https://" ^ browser_test_domain ^ "/auth/local-rp?signed_request=") redirect.redirect_url

(* Cases 5 + 6: invalid TXT records are ignored, and across several records
   the FIRST valid record with https= is selected. *)
let test_browser_first_valid_record () =
  let redirect, _ =
    browser_begin_with
      (apis_resolver
         [
           "not a linkkeys record";
           "v=lk2 https=wrong-version.example.test";
           "v=lk1 tcp=tcp-only.example.test";
           "v=lk1 https=first.example.test";
           "v=lk1 https=second.example.test";
         ])
  in
  check_prefix "first valid record" "https://first.example.test/auth/local-rp?signed_request=" redirect.redirect_url

(* Case 7: signed_request rides the discovered URL unchanged -- it decodes
   to the signed login request whose fields match this login. *)
let test_browser_signed_request_survives () =
  let redirect, pending = browser_begin_with (apis_resolver [ "v=lk1 https=login.example.test/linkkeys" ]) in
  let url = redirect.redirect_url in
  let marker = "?signed_request=" in
  let rec find i = if i + String.length marker > String.length url then None else if String.sub url i (String.length marker) = marker then Some i else find (i + 1) in
  let start = match find 0 with Some i -> i + String.length marker | None -> Alcotest.fail "redirect URL missing signed_request param" in
  let stop = match String.index_from_opt url start '&' with Some i -> i | None -> String.length url in
  let param = String.sub url start (stop - start) in
  let signed = Url_params.signed_local_rp_login_request_from_url_param param in
  let request = Types.Local_rp_login_request.of_cbor signed.request in
  Alcotest.(check string) "callback_url" "http://app.lan:8080/cb" request.callback_url;
  check_bool "nonce matches pending" true (request.nonce = pending.nonce)

(* The username hint still rides the discovered URL, after signed_request. *)
let test_browser_username_hint () =
  let redirect, pending =
    browser_begin_with ~user_domain:("Alice+work@" ^ browser_test_domain) (apis_resolver [ "v=lk1 https=login.example.test" ])
  in
  check_prefix "username on discovered host" "https://login.example.test/auth/local-rp?signed_request=" redirect.redirect_url;
  check_bool "username hint is last" true (has_suffix ~suffix:"&username=Alice%2Bwork" redirect.redirect_url);
  Alcotest.(check string) "pending user_domain stays the identity domain" browser_test_domain pending.user_domain

(* Case 9: a config built without [~dns] compiles unchanged (this test is
   that caller) and defaults to [Dns.default_resolver] at call time. The
   default path is not executed here -- that would be a live DNS request. *)
let test_browser_config_without_resolver () =
  let now = Timeutil.parse_rfc3339 "2026-08-17T12:00:00Z" in
  let identity = Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"browser-test" ~now ()) in
  let config =
    Begin_login.make_config ~key_material:identity ~callback_url:"http://app.lan:8080/cb" ~user_domain:browser_test_domain ~now ()
  in
  check_bool "dns defaults to None" true (match config.dns with None -> true | Some _ -> false)

(* Direct tests for the exported helpers. *)
let test_resolve_browser_base () =
  (match Browser.resolve_browser_base (apis_resolver [ "v=lk1 tcp=x.example.test https=login.example.test:8443/linkkeys" ]) browser_test_domain with
  | Ok base -> Alcotest.(check string) "base" "https://login.example.test:8443/linkkeys" base
  | Error e -> Alcotest.failf "resolve_browser_base: %s" (Error.to_string e));
  (* A record whose https= value smuggles URL structure is skipped; with no
     other candidate, resolution errors so the caller can fall back. *)
  List.iter
    (fun hostile ->
      match Browser.resolve_browser_base (apis_resolver [ hostile ]) browser_test_domain with
      | Ok base -> Alcotest.failf "accepted hostile record %S as %S" hostile base
      | Error _ -> ())
    [ "v=lk1 https=user@evil.example.test"; "v=lk1 https=evil.example.test/x?y=1"; "v=lk1 https=evil.example.test/x#frag" ];
  check_bool "tcp-only errors" true
    (Result.is_error (Browser.resolve_browser_base (apis_resolver [ "v=lk1 tcp=only.example.test" ]) browser_test_domain));
  check_bool "lookup failure errors" true (Result.is_error (Browser.resolve_browser_base failing_resolver browser_test_domain))

let test_build_browser_endpoint () =
  (match Browser.build_browser_endpoint "https://h.example.test" Browser.browser_route_local_rp "PAYLOAD-123_abc" with
  | Ok url -> Alcotest.(check string) "plain host" "https://h.example.test/auth/local-rp?signed_request=PAYLOAD-123_abc" url
  | Error e -> Alcotest.failf "build_browser_endpoint: %s" (Error.to_string e));
  (* Path prefix, with and without a trailing slash, and the regular-RP
     route -- the same helper serves /auth/authorize glue. *)
  List.iter
    (fun (base, want) ->
      match Browser.build_browser_endpoint base Browser.browser_route_authorize "s" with
      | Ok url -> Alcotest.(check string) base want url
      | Error e -> Alcotest.failf "build_browser_endpoint %S: %s" base (Error.to_string e))
    [
      ("https://h.example.test/pfx", "https://h.example.test/pfx/auth/authorize?signed_request=s");
      ("https://h.example.test/pfx/", "https://h.example.test/pfx/auth/authorize?signed_request=s");
      ("https://h.example.test:8443", "https://h.example.test:8443/auth/authorize?signed_request=s");
    ];
  (* A non-HTTPS scheme must never be selectable. *)
  List.iter
    (fun bad ->
      check_bool (Printf.sprintf "rejects %S" bad) true
        (Result.is_error (Browser.build_browser_endpoint bad Browser.browser_route_local_rp "s")))
    [ "http://h.example.test"; "ftp://h.example.test"; "https://"; "https://u:p@h.example.test"; "https://h.example.test:0"; "https://h.example.test:abc"; "https://h.example.test/x?y" ];
  check_bool "rejects route without leading slash" true
    (Result.is_error (Browser.build_browser_endpoint "https://h.example.test" "auth/no-leading-slash" "s"));
  Alcotest.(check string) "local-rp route" "/auth/local-rp" Browser.browser_route_local_rp;
  Alcotest.(check string) "authorize route" "/auth/authorize" Browser.browser_route_authorize

let test_begin_identity_input () =
  let now = Timeutil.parse_rfc3339 "2026-01-01T00:00:00Z" in
  let identity = Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"Test App" ~now ()) in
  let redirect, pending = Begin_login.begin_local_login_exn
      (Begin_login.make_config ~key_material:identity ~callback_url:"http://localhost/callback"
         ~user_domain:"Alice+work@ID.Example.TEST" ~now ~dns:failing_resolver ()) in
  check_bool "username is encoded in redirect" true (string_contains redirect.redirect_url "&username=Alice%2Bwork");
  Alcotest.(check string) "pending state contains destination only" "id.example.test" pending.user_domain;
  List.iter (fun input ->
    match Begin_login.begin_local_login
        (Begin_login.make_config ~key_material:identity ~callback_url:"http://localhost/callback" ~user_domain:input ~now ~dns:failing_resolver ()) with
    | Error _ -> ()
    | Ok _ -> Alcotest.failf "accepted malformed identity input %S" input)
    [ "alice"; "alice@@example.test"; "https://example.test"; "alice@example.test:+443" ]

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
      (Begin_login.make_config ~key_material:identity ~callback_url:"http://127.0.0.1:9000/callback" ~user_domain:idp.domain ~now ~dns:failing_resolver ())
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
      (Begin_login.make_config ~key_material:identity ~callback_url:"http://127.0.0.1:9000/callback" ~user_domain:idp.domain ~now ~dns:failing_resolver ())
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
         ~required_claims:[ "handle"; "email" ] ~dns:failing_resolver ())
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

(* ==================================================================== *)
(* Act-as grants, grantee side                                          *)
(* ==================================================================== *)

(* The act-as vectors live with the regular-RP conformance suite:
   sdks/regular-rp/conformance/act_as_grantee_signing.json. *)
let act_as_vectors = lazy (Yojson.Safe.from_file "../../../../../regular-rp/conformance/act_as_grantee_signing.json")

let act_as_local_rp_case () : Yojson.Safe.t =
  match
    List.find_opt (fun c -> text "name" c = "local_rp_grantee") (list_ (field "cases" (Lazy.force act_as_vectors)))
  with
  | Some c -> c
  | None -> Alcotest.fail "act_as_grantee_signing.json has no local_rp_grantee case"

(* Key material for the vector's published local-RP grantee. The encryption
   private key is not used by act-as signing. *)
let act_as_vector_key_material () : Identity.key_material =
  let g = field "local_rp_grantee" (Lazy.force act_as_vectors) in
  let descriptor = Types.Signed_local_rp_descriptor.of_cbor (hex "signed_descriptor_cbor_hex" g) in
  let inner = Types.Local_rp_descriptor.of_cbor descriptor.descriptor in
  Alcotest.(check string) "descriptor fingerprint" (text "fingerprint" g) inner.fingerprint;
  {
    signing_private_key = hex "signing_private_key_hex" g;
    signing_public_key = inner.signing_public_key;
    encryption_private_key = String.make 32 '\x00';
    encryption_public_key = inner.encryption_public_key;
    descriptor;
    fingerprint = inner.fingerprint;
  }

let check_hex (msg : string) (expected_hex : string) (actual : string) : unit =
  Alcotest.(check string) msg expected_hex (Hex.encode actual)

let test_act_as_vector_grant_request () =
  let km = act_as_vector_key_material () in
  let case = act_as_local_rp_case () in
  let gr = field "grant_request" case in
  let inputs = field "inputs" gr in
  let int_opt name = match field name inputs with `Null -> None | `Int n -> Some n | _ -> Alcotest.fail name in
  let request : Types.Act_as_grant_request.t =
    {
      grantee = Act_as.local_rp_grantee km;
      scope_set = Types.Signed_act_as_scope_set.of_cbor (hex "scope_set_signed_cbor_hex" inputs);
      requested_lifetime_seconds = int_opt "requested_lifetime_seconds";
      requested_renewal_window_seconds = int_opt "requested_renewal_window_seconds";
      callback_url = text "callback_url" inputs;
      nonce = text "nonce" inputs;
      requested_at = text "requested_at" inputs;
      expires_at = text "expires_at" inputs;
    }
  in
  check_hex "request cbor" (text "request_cbor_hex" gr) (Types.Act_as_grant_request.to_cbor request);
  check_hex "signature input" (text "signature_input_cbor_hex" gr)
    (Internal.Local_rp.envelope_signature_input Act_as.grant_request_tag (Types.Act_as_grant_request.to_cbor request));
  let signed = Act_as.sign_grant_request km request in
  check_hex "signed grant request" (text "signed_cbor_hex" gr) (Types.Signed_act_as_grant_request.to_cbor signed);
  Alcotest.(check string) "url_param" (text "url_param" gr) (Url_params.signed_act_as_grant_request_to_url_param signed)

let test_act_as_vector_refresh_request () =
  let km = act_as_vector_key_material () in
  let rr = field "refresh_request" (act_as_local_rp_case ()) in
  let inputs = field "inputs" rr in
  let now = Timeutil.parse_rfc3339 (text "requested_at" inputs) in
  let request = Act_as.build_refresh_request km ~grant_id:(text "grant_id" inputs) ~now ~nonce:(text "nonce" inputs) in
  Alcotest.(check string) "expires_at is now + 300 s" (text "expires_at" inputs) request.expires_at;
  check_hex "refresh request cbor" (text "request_cbor_hex" rr) (Types.Act_as_refresh_request.to_cbor request);
  check_hex "signed refresh request" (text "signed_cbor_hex" rr)
    (Types.Signed_act_as_refresh_request.to_cbor (Act_as.sign_refresh_request km request))

let test_act_as_vector_presentation () =
  let km = act_as_vector_key_material () in
  let pr = field "presentation" (act_as_local_rp_case ()) in
  let inputs = field "inputs" pr in
  let a = field "audience" inputs in
  let audience : Types.Application_ref.t =
    { subject_user_id = text "subject_user_id" a; subject_domain = text "subject_domain" a; application_id = text "application_id" a }
  in
  let grant_bytes = hex "grant_signed_cbor_hex" inputs in
  let grant = Types.Signed_act_as_grant.of_cbor grant_bytes in
  check_hex "grant re-encodes unchanged" (text "grant_signed_cbor_hex" inputs) (Types.Signed_act_as_grant.to_cbor grant);
  check_hex "grant hash" (text "grant_hash_hex" pr) (Act_as.grant_hash grant.grant);
  (* A fractional [now] still yields a whole-second presented_at. *)
  let now = Timeutil.parse_rfc3339 (text "presented_at" inputs) +. 0.75 in
  let credential, credential_bytes =
    Act_as.present_bytes ~grant ~audience ~request_digest:(hex "request_digest_hex" inputs) ~now
      ~nonce:(hex "nonce_hex" inputs) km
  in
  check_hex "presentation cbor" (text "presentation_cbor_hex" pr) credential.presentation.presentation;
  check_hex "credential cbor" (text "credential_cbor_hex" pr) credential_bytes;
  Alcotest.(check bool) "facade present matches" true
    (Types.Act_as_credential.to_cbor (present_act_as ~grant ~audience ~request_digest:(hex "request_digest_hex" inputs) ~now
        ~nonce:(hex "nonce_hex" inputs) km) = credential_bytes)

(* The audience's signed scope set decodes through the typed record with every
   signature kept, and encodes back to the same bytes. *)
let test_act_as_scope_set_vector_round_trip () =
  let bytes = hex "scope_set_signed_cbor_hex" (field "inputs" (field "grant_request" (act_as_local_rp_case ()))) in
  let decoded = Types.Signed_act_as_scope_set.of_cbor bytes in
  Alcotest.(check int) "two signatures" 2 (List.length decoded.signatures);
  Alcotest.(check (list string)) "signer key ids" [ "audience-key-1"; "audience-key-2" ]
    (List.map (fun (s : Types.Application_key_signature.t) -> s.signed_by_key_id) decoded.signatures);
  Alcotest.(check string) "signer instance" "audience-instance-1" decoded.signer_instance_id;
  check_hex "re-encodes byte-identically" (Hex.encode bytes) (Types.Signed_act_as_scope_set.to_cbor decoded)

let test_act_as_scope_set_empty_signatures_refused () =
  let bytes =
    Cbor.encode
      (Map [ (Text "scope_set", Bytes "\xa0"); (Text "signer_instance_id", Text "audience-instance-1"); (Text "signatures", Array []) ])
  in
  match Types.Signed_act_as_scope_set.of_cbor bytes with
  | _ -> Alcotest.fail "an empty signatures array decoded"
  | exception Cbor.Decode_error _ -> ()

(* A scope set and identity for the begin/refresh tests. Its bytes need not
   verify: the home domain checks the audience's signature, not the
   grantee. *)
let act_as_scope_set_bytes () : string = hex "scope_set_signed_cbor_hex" (field "inputs" (field "grant_request" (act_as_local_rp_case ())))

let act_as_identity () =
  Identity.generate_local_rp_identity_exn (Identity.make_config ~app_name:"act-as-test" ~now:(Timeutil.parse_rfc3339 "2026-10-01T00:00:00Z") ())

let act_as_begin ?(user_domain = browser_test_domain) ?request_window ?requested_lifetime_seconds km dns =
  Act_as.begin_act_as
    (Act_as.make_begin_config ~key_material:km ~user_domain ~scope_set:(act_as_scope_set_bytes ()) ?requested_lifetime_seconds
       ~callback_url:"http://app.lan:8080/act-as/callback" ~now:(Timeutil.parse_rfc3339 "2026-10-06T11:59:00Z") ~dns
       ?request_window ())

let signed_request_of_url (url : string) : string =
  match String.index_opt url '=' with
  | Some i -> String.sub url (i + 1) (String.length url - i - 1)
  | None -> Alcotest.fail "redirect URL has no signed_request"

let test_act_as_begin_discovered_host () =
  let km = act_as_identity () in
  let redirect, pending =
    match act_as_begin ~user_domain:("Alice@" ^ browser_test_domain) km (apis_resolver [ "v=lk1 https=login.example.test/lk" ]) with
    | Ok v -> v
    | Error e -> Alcotest.fail (Error.to_string e)
  in
  check_prefix "discovered host" "https://login.example.test/lk/auth/act-as?signed_request=" redirect.redirect_url;
  check_bool "no username hint" false (string_contains redirect.redirect_url "username=");
  Alcotest.(check string) "pending domain is the identity domain" browser_test_domain pending.user_domain;
  Alcotest.(check string) "pending callback" "http://app.lan:8080/act-as/callback" pending.callback_url;
  let signed = Url_params.signed_act_as_grant_request_from_url_param (signed_request_of_url redirect.redirect_url) in
  let request = Types.Act_as_grant_request.of_cbor signed.request in
  Alcotest.(check string) "nonce matches pending" pending.nonce request.nonce;
  Alcotest.(check int) "nonce is 32 bytes" 32 (String.length (Url_params.b64url_decode request.nonce));
  Alcotest.(check (option string)) "grantee fingerprint" (Some km.fingerprint) request.grantee.local_rp_descriptor_fingerprint;
  check_bool "no application grantee" true (request.grantee.application = None);
  Alcotest.(check string) "requested_at" "2026-10-06T11:59:00Z" request.requested_at;
  Alcotest.(check string) "default window 300 s" "2026-10-06T12:04:00Z" request.expires_at;
  check_hex "scope set embedded unchanged" (Hex.encode (act_as_scope_set_bytes ()))
    (Types.Signed_act_as_scope_set.to_cbor request.scope_set);
  check_bool "proof carries descriptor" true (signed.proof.local_rp_descriptor = Some km.descriptor);
  Alcotest.(check string) "signed_by_key_id" km.fingerprint signed.proof.signature.signed_by_key_id;
  check_bool "signature verifies with descriptor key" true
    (Crypto.verify_ed25519 km.signing_public_key
       (Internal.Local_rp.envelope_signature_input Act_as.grant_request_tag signed.request)
       signed.proof.signature.signature)

let test_act_as_begin_fallback_and_validation () =
  let km = act_as_identity () in
  (match act_as_begin km failing_resolver with
  | Ok (redirect, _) ->
    check_prefix "fallback" ("https://" ^ browser_test_domain ^ "/auth/act-as?signed_request=") redirect.redirect_url
  | Error e -> Alcotest.fail (Error.to_string e));
  (match act_as_begin ~request_window:900 km failing_resolver with
  | Ok (redirect, _) ->
    let signed = Url_params.signed_act_as_grant_request_from_url_param (signed_request_of_url redirect.redirect_url) in
    Alcotest.(check string) "900 s window" "2026-10-06T12:14:00Z" (Types.Act_as_grant_request.of_cbor signed.request).expires_at
  | Error e -> Alcotest.fail (Error.to_string e));
  let rejected msg = function Ok _ -> Alcotest.failf "accepted %s" msg | Error _ -> () in
  rejected "901 s window" (act_as_begin ~request_window:901 km failing_resolver);
  rejected "0 s window" (act_as_begin ~request_window:0 km failing_resolver);
  rejected "zero lifetime" (act_as_begin ~requested_lifetime_seconds:0 km failing_resolver);
  rejected "bad identity" (act_as_begin ~user_domain:"alice" km failing_resolver);
  rejected "bad scope set"
    (Act_as.begin_act_as
       (Act_as.make_begin_config ~key_material:km ~user_domain:browser_test_domain ~scope_set:"\x01"
          ~callback_url:"http://app.lan/cb" ~now:0.0 ~dns:failing_resolver ()))

let test_act_as_complete () =
  let pending : Act_as.pending_act_as =
    { nonce = "n0nce-AbC_123"; user_domain = "example.test"; callback_url = "http://app.lan/cb" }
  in
  (match complete_act_as pending "http://app.lan/cb?x=1&act_as_grant_id=grant%2D1&nonce=n0nce-AbC_123#frag" with
  | Ok id -> Alcotest.(check string) "grant id" "grant-1" id
  | Error e -> Alcotest.fail (Error.to_string e));
  (match complete_act_as pending "act_as_grant_id=g2&nonce=n0nce-AbC_123" with
  | Ok id -> Alcotest.(check string) "bare query" "g2" id
  | Error e -> Alcotest.fail (Error.to_string e));
  (match complete_act_as pending "http://app.lan/cb?act_as_grant_id=g&nonce=n0nce-AbC_124" with
  | Error Error.Nonce_mismatch -> ()
  | _ -> Alcotest.fail "expected Nonce_mismatch");
  List.iter
    (fun cb -> match complete_act_as pending cb with Ok _ -> Alcotest.failf "accepted %S" cb | Error _ -> ())
    [
      "http://app.lan/cb?nonce=n0nce-AbC_123";
      "http://app.lan/cb?act_as_grant_id=g";
      "http://app.lan/cb?act_as_grant_id=g&nonce=n0nce-AbC_123&nonce=n0nce-AbC_123";
      "http://app.lan/cb?act_as_grant_id=g&nonce=%zz";
    ]

(* A one-shot fake home domain: a real TLS server (Tls.Engine) in a forked
   child, over a socketpair. No listener and no network. The child sends the
   raw request frame back to the parent through a pipe. *)
let act_as_server_cert (now : float) =
  Crypto.ensure_rng ();
  let priv = X509.Private_key.generate `ED25519 in
  let dn = [ X509.Distinguished_name.(Relative_distinguished_name.singleton (CN "act-as.example.test")) ] in
  let csr = Result.get_ok (X509.Signing_request.create dn priv) in
  let ptime t = Option.get (Ptime.of_float_s t) in
  let cert =
    Result.get_ok (X509.Signing_request.sign csr ~valid_from:(ptime (now -. 86400.)) ~valid_until:(ptime (now +. 86400.)) priv dn)
  in
  (cert, priv)

let serve_one_tls (fd : Unix.file_descr) ~cert ~priv (response : string) : string =
  let state = ref (Tls.Engine.server (Tls.Config.server ~certificates:(`Single ([ cert ], priv)) ())) in
  let inbuf = ref "" in
  let rec read_exact n =
    if String.length !inbuf >= n then begin
      let r = String.sub !inbuf 0 n in
      inbuf := String.sub !inbuf n (String.length !inbuf - n);
      r
    end
    else
      match Tls.Engine.handle_tls !state (Tls_client.raw_read fd) with
      | Ok (st, _, `Response resp, `Data data) ->
        state := st;
        Option.iter (Tls_client.raw_write fd) resp;
        Option.iter (fun d -> inbuf := !inbuf ^ Cstruct.to_string d) data;
        read_exact n
      | Error (_, `Response resp) ->
        Tls_client.raw_write fd resp;
        failwith "fake server TLS failure"
  in
  let request = Rpc.read_frame read_exact in
  Rpc.send_frame
    (fun s ->
      match Tls.Engine.send_application_data !state [ Cstruct.of_string s ] with
      | Some (st, out) ->
        state := st;
        Tls_client.raw_write fd out
      | None -> failwith "fake server not ready")
    response;
  request

let read_all (fd : Unix.file_descr) : string =
  let buf = Buffer.create 1024 and chunk = Bytes.create 4096 in
  let rec go () =
    let n = Unix.read fd chunk 0 4096 in
    if n > 0 then begin
      Buffer.add_subbytes buf chunk 0 n;
      go ()
    end
  in
  go ();
  Buffer.contents buf

(* Run one refresh against the fake server. Returns the refresh result and
   the raw request frame the server received. *)
let run_act_as_refresh (km : Identity.key_material) ~(now : float) (response : string) =
  let cert, priv = act_as_server_cert now in
  let fp = Tls_client.leaf_fingerprint cert in
  let client_fd, server_fd = Unix.socketpair Unix.PF_UNIX Unix.SOCK_STREAM 0 in
  let pipe_r, pipe_w = Unix.pipe () in
  match Unix.fork () with
  | 0 ->
    Unix.close client_fd;
    Unix.close pipe_r;
    (try
       let request = serve_one_tls server_fd ~cert ~priv response in
       ignore (Unix.write_substring pipe_w request 0 (String.length request))
     with _ -> ());
    Unix._exit 0
  | pid ->
    Unix.close server_fd;
    Unix.close pipe_w;
    let dialed = ref "" in
    let transport : Transport.t = { dial = (fun addr -> dialed := addr; client_fd) } in
    let dns : Dns.resolver =
      {
        Dns.txt_lookup =
          (fun name ->
            if name = "_linkkeys.home.example.test" then [ "v=lk1 fp=" ^ fp ]
            else if name = "_linkkeys_apis.home.example.test" then [ "v=lk1 tcp=act-as.example.test:7443" ]
            else raise (Dns.Dns_parse_error ("no fake record for " ^ name)));
      }
    in
    let result =
      refresh_act_as_grant
        (Act_as.make_refresh_config ~key_material:km ~user_domain:"home.example.test" ~grant_id:"grant-1" ~now ~transport ~dns ())
    in
    let received = read_all pipe_r in
    Unix.close pipe_r;
    ignore (Unix.waitpid [] pid);
    Alcotest.(check string) "dialed the discovered tcp= address" "act-as.example.test:7443" !dialed;
    (result, received)

(* A grant as a home domain stores it. Only the identifying fields matter to
   the grantee; the audience checks the signature. *)
let served_act_as_grant ~grant_id ~fingerprint ~subject_domain : Types.Signed_act_as_grant.t =
  let grant =
    Cbor.encode
      (Map
         [
           (Text "grant_id", Text grant_id);
           (Text "user_id", Text "user-1");
           (Text "subject_domain", Text subject_domain);
           (Text "grantee", Map [ (Text "local_rp_descriptor_fingerprint", Text fingerprint) ]);
           ( Text "audience",
             Map
               [
                 (Text "subject_user_id", Text "audience-owner");
                 (Text "subject_domain", Text "audience.test");
                 (Text "application_id", Text "audience-app");
               ] );
           ( Text "scope_set",
             Map
               [
                 (Text "scope_set", Bytes "\xa0");
                 (Text "signer_instance_id", Text "audience-inst");
                 ( Text "signatures",
                   Array
                     [
                       Map
                         [ (Text "signed_by_key_id", Text "audience-key"); (Text "signature", Bytes (String.make 64 '\000')) ];
                     ] );
               ] );
           (Text "approved_scope", Array [ Text "read" ]);
           (Text "issued_at", Text "2026-10-06T12:00:00Z");
           (Text "expires_at", Text "2026-10-06T13:00:00Z");
           (Text "series_issued_at", Text "2026-10-06T12:00:00Z");
           (Text "renewable_until", Text "2026-10-06T13:00:00Z");
         ])
  in
  { grant; signatures = [ { domain = subject_domain; signed_by_key_id = "domain-key"; signature = String.make 64 '\009' } ] }

let refresh_ok_response (grant : Types.Signed_act_as_grant.t) ~(signed : bool) : string =
  Cbor.encode
    (Map
       [
         (Text "v", Int 1);
         (Text "status", Int 0);
         (Text "payload", Tag (24, Bytes (Types.Refresh_act_as_grant_response.to_cbor { grant; signed })));
       ])

let test_act_as_refresh_refuses_another_grant () =
  let km = act_as_identity () in
  let now = Float.floor (Unix.gettimeofday ()) in
  List.iter
    (fun served ->
      match run_act_as_refresh km ~now (refresh_ok_response served ~signed:false) with
      | Error (Error.Identity_mismatch _), _ -> ()
      | Ok _, _ -> Alcotest.fail "accepted a grant for another grant id, grantee, or domain"
      | Error e, _ -> Alcotest.fail (Error.to_string e))
    [
      served_act_as_grant ~grant_id:"grant-2" ~fingerprint:km.fingerprint ~subject_domain:"home.example.test";
      served_act_as_grant ~grant_id:"grant-1" ~fingerprint:"another-local-rp" ~subject_domain:"home.example.test";
      served_act_as_grant ~grant_id:"grant-1" ~fingerprint:km.fingerprint ~subject_domain:"other.test";
    ]

let test_act_as_refresh_via_fake_server () =
  let km = act_as_identity () in
  let now = Float.floor (Unix.gettimeofday ()) in
  let grant = served_act_as_grant ~grant_id:"grant-1" ~fingerprint:km.fingerprint ~subject_domain:"home.example.test" in
  let grant_bytes = Types.Signed_act_as_grant.to_cbor grant in
  let ok_response = refresh_ok_response grant ~signed:true in
  let result, received = run_act_as_refresh km ~now ok_response in
  (match result with
  | Ok (g, signed) ->
    check_hex "returned grant" (Hex.encode grant_bytes) (Types.Signed_act_as_grant.to_cbor g);
    check_bool "signed flag" true signed
  | Error e -> Alcotest.fail (Error.to_string e));
  let envelope = Cbor.as_map (Cbor.decode received) in
  Alcotest.(check string) "service" "ActAs" (Cbor.field_text envelope "service");
  Alcotest.(check string) "op" "refresh-grant" (Cbor.field_text envelope "op");
  let payload = match Cbor.field envelope "payload" with Some (Tag (24, Bytes b)) -> b | _ -> Alcotest.fail "payload" in
  let signed = (Types.Refresh_act_as_grant_request.of_cbor payload).request in
  let request = Types.Act_as_refresh_request.of_cbor signed.request in
  Alcotest.(check string) "grant id" "grant-1" request.grant_id;
  Alcotest.(check (option string)) "grantee" (Some km.fingerprint) request.grantee.local_rp_descriptor_fingerprint;
  Alcotest.(check string) "requested_at" (Timeutil.to_rfc3339 now) request.requested_at;
  Alcotest.(check string) "expires_at" (Timeutil.to_rfc3339 (now +. 300.)) request.expires_at;
  check_bool "fresh nonce" true (String.length request.nonce = 43);
  check_bool "proof descriptor" true (signed.proof.local_rp_descriptor = Some km.descriptor);
  Alcotest.(check string) "signed_by_key_id" km.fingerprint signed.proof.signature.signed_by_key_id;
  check_bool "signature verifies with descriptor key" true
    (Crypto.verify_ed25519 km.signing_public_key
       (Internal.Local_rp.envelope_signature_input Act_as.refresh_request_tag signed.request)
       signed.proof.signature.signature);
  (* A server status error surfaces as Server_error. *)
  let error_response =
    Cbor.encode (Map [ (Text "v", Int 1); (Text "status", Int 3); (Text "error", Text "grant not found"); (Text "payload", Tag (24, Bytes "")) ])
  in
  match run_act_as_refresh km ~now error_response with
  | Error (Error.Server_error (3, _)), _ -> ()
  | _ -> Alcotest.fail "expected Server_error"

let test_act_as_refresh_transport_error () =
  let km = act_as_identity () in
  let dns : Dns.resolver =
    {
      Dns.txt_lookup =
        (fun name ->
          if name = "_linkkeys.home.example.test" then [ "v=lk1 fp=" ^ String.make 64 'a' ]
          else [ "v=lk1 tcp=act-as.example.test:7443" ]);
    }
  in
  let transport : Transport.t = { dial = (fun _ -> raise (Transport.Connect_failed "refused")) } in
  match
    refresh_act_as_grant
      (Act_as.make_refresh_config ~key_material:km ~user_domain:"home.example.test" ~grant_id:"grant-1" ~now:0.0 ~transport ~dns ())
  with
  | Error (Error.Transport_error _) -> ()
  | _ -> Alcotest.fail "expected Transport_error"

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
      ("begin login", [ Alcotest.test_case "identity input" `Quick test_begin_identity_input ]);
      ( "browser endpoint discovery",
        [
          Alcotest.test_case "discovered https host used; pending domain stays identity" `Quick test_browser_discovered_host;
          Alcotest.test_case "https= path prefix preserved" `Quick test_browser_path_prefix;
          Alcotest.test_case "tcp-only record falls back" `Quick test_browser_tcp_only_fallback;
          Alcotest.test_case "DNS error falls back" `Quick test_browser_dns_error_fallback;
          Alcotest.test_case "invalid records ignored; first valid https= selected" `Quick test_browser_first_valid_record;
          Alcotest.test_case "signed_request survives and decodes" `Quick test_browser_signed_request_survives;
          Alcotest.test_case "username hint appended" `Quick test_browser_username_hint;
          Alcotest.test_case "config without resolver compiles" `Quick test_browser_config_without_resolver;
          Alcotest.test_case "resolve_browser_base" `Quick test_resolve_browser_base;
          Alcotest.test_case "build_browser_endpoint" `Quick test_build_browser_endpoint;
        ] );
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
      ( "act-as grantee",
        [
          Alcotest.test_case "vector: signed grant request + url_param" `Quick test_act_as_vector_grant_request;
          Alcotest.test_case "vector: signed refresh request" `Quick test_act_as_vector_refresh_request;
          Alcotest.test_case "vector: presentation + credential" `Quick test_act_as_vector_presentation;
          Alcotest.test_case "vector: signed scope set round trip" `Quick test_act_as_scope_set_vector_round_trip;
          Alcotest.test_case "scope set: empty signatures refused" `Quick test_act_as_scope_set_empty_signatures_refused;
          Alcotest.test_case "begin: discovered host, signed request" `Quick test_act_as_begin_discovered_host;
          Alcotest.test_case "begin: fallback + input validation" `Quick test_act_as_begin_fallback_and_validation;
          Alcotest.test_case "complete: nonce match + mismatch" `Quick test_act_as_complete;
          Alcotest.test_case "refresh: fake TLS home domain" `Quick test_act_as_refresh_via_fake_server;
          Alcotest.test_case "refresh: another grant is refused" `Quick test_act_as_refresh_refuses_another_grant;
          Alcotest.test_case "refresh: transport error surfaces" `Quick test_act_as_refresh_transport_error;
        ] );
    ]
