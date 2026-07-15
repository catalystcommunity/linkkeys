(* [complete_local_login] (design doc: "SDK API Shape", "Flow" steps
   12-13).

   This is the SDK's full verification chain, run in the exact order the
   pure [Local_rp] helpers require:

   1. decode the callback ciphertext from its URL-param encoding
   2. open it (decrypt) -- only with a suite this identity's own
      descriptor advertises
   3. fetch the pending domain's public keys, DNS-[fp=]-pinned, over TCP
      CSIL-RPC
   4. verify the domain-signed envelope (key lookup, revocation/expiry,
      signature, payload timestamp bounds) -- only now is anything inside
      the payload trusted
   5. cross-check the cleartext header's routing fields against the
      now-verified payload
   6. audience / issuer / callback-URL / nonce-state checks
   7. redeem the claim ticket over TCP CSIL-RPC (signed with the local
      RP's own key -- the possession proof)
   7a. identity binding (SEC fix): the redemption's user_id/user_domain
      must equal the SIGNED payload's -- fatal mismatch, never Ok
   8. verify every returned claim's signatures against ITS signer domain's
      keys (fetched the same pinned way, subject-domain bound to the
      VERIFIED payload's user_domain), which also checks the claim's own
      revocation/expiry; each claim's user_id is checked against the
      payload's before its signature is even verified; finally the
      pending login's required_claims are enforced against the claim
      types that survived verification -- missing/insufficient (including
      empty) is fatal *)

(* Bound on the number of distinct claim-signer domains
   [complete_local_login] will fetch keys for per completion -- a
   malicious/compromised home IDP could otherwise list an unbounded number
   of distinct "signer domains" purely to make this SDK perform many
   outbound DNS/TCP calls to attacker-chosen targets before any signature
   is actually checked (an SSRF/DoS amplification vector against the
   app's own process). A legitimate claim set names very few (typically
   one: the home domain). *)
let max_claim_signer_domains = 8

type config = {
  key_material : Identity.key_material;
  pending : Begin_login.pending_login;
  encrypted_token : string;
  arrived_url : string;
  now : float;
  clock_skew_seconds : float option;
  transport : Transport.t option;
  dns : Dns.resolver option;
}

let make_config ~key_material ~pending ~encrypted_token ~arrived_url ~now ?clock_skew_seconds ?transport ?dns () : config
    =
  { key_material; pending; encrypted_token; arrived_url; now; clock_skew_seconds; transport; dns }

(* What [complete_local_login] returns to app code (design doc: "SDKs ...
   should either return verified results or call registered callbacks
   with:" -- this package returns rather than calling back). *)
type verified_local_login = {
  user_id : string;
  user_domain : string;
  claims : Types.Claim.t list;
  domain_public_keys : Types.Domain_public_key.t list;
  local_rp_fingerprint : string;
  issued_at : float;
  expires_at : float;
  ticket_expires_at : float;
}

(* Undo the exact [?]/[&] + [encrypted_token=] suffix construction the IDP
   uses to deliver the callback, so the recovered value can be compared
   against the signed payload's [callback_url]. If the arrived URL doesn't
   end with that exact suffix, returns it unchanged -- the subsequent
   [verify_callback_url] equality check then correctly fails closed rather
   than this function guessing. *)
let strip_encrypted_token_param (arrived_url : string) : string =
  let find_last_index sep =
    let marker = sep ^ "encrypted_token=" in
    let mlen = String.length marker in
    let alen = String.length arrived_url in
    let rec go i = if i < 0 then None else if i + mlen <= alen && String.sub arrived_url i mlen = marker then Some i else go (i - 1) in
    go (alen - mlen)
  in
  match find_last_index "?" with
  | Some idx -> String.sub arrived_url 0 idx
  | None -> ( match find_last_index "&" with Some idx -> String.sub arrived_url 0 idx | None -> arrived_url)

(* ------------------------------------------------------------------ *)
(* Identity-binding / required-claims checks (SEC fix, FIX A)          *)
(*                                                                      *)
(* Extracted as standalone, pure functions -- not just inlined into    *)
(* [complete_local_login_exn] -- specifically so this package's own    *)
(* test suite can unit-test each FATAL check directly (exact inputs,   *)
(* exact expected [Error.t]) without needing a live TLS/CSIL-RPC       *)
(* server to drive the full chain end-to-end (see this SDK's README /  *)
(* [tls_client.ml]'s module docs for why that's currently untestable   *)
(* in this environment). *)
(* ------------------------------------------------------------------ *)

(* 7a. The ticket redemption response carries no signature of its own --
   it is trusted only because it was fetched over the DNS-pinned TLS
   channel for the domain the SIGNED callback payload named. That is not
   the same as the redemption response actually agreeing with the
   payload: a compromised/malicious IDP could hand back claims for a
   different user than the one it cryptographically vouched for in the
   signed callback (e.g. to launder an approval given to user A onto user
   B's claims). Cross-check unconditionally, and treat any mismatch as
   fatal -- never fall back to either identity alone. *)
let check_redemption_identity_matches_payload (redemption : Types.Local_rp_ticket_redemption_response.t)
    (payload : Types.Local_rp_callback_payload.t) : unit =
  if redemption.user_id <> payload.user_id || redemption.user_domain <> payload.user_domain then
    Error.raise_
      (Error.Identity_mismatch
         (Printf.sprintf "ticket redemption identity (%S, %S) does not match the signed callback payload's identity (%S, %S)"
            redemption.user_id redemption.user_domain payload.user_id payload.user_domain))

(* Each claim must also name the SAME user the signed payload vouched
   for -- without this, a malicious IDP could splice in a claim belonging
   to a different user_id inside an otherwise-valid, correctly-signed
   redemption response (the claim's own signature only proves the issuing
   domain signed *that* claim, not that it's the claim for *this* login).
   Checked BEFORE signature verification, against [payload_user_id] -- the
   SIGNED source of truth, never [redemption.user_id]. *)
let check_claim_user_id_matches_payload (claim : Types.Claim.t) (payload_user_id : string) : unit =
  if claim.user_id <> payload_user_id then
    Error.raise_
      (Error.Identity_mismatch
         (Printf.sprintf "claim %S names user_id %S, expected %S (the signed callback payload's subject)" claim.claim_id claim.user_id
            payload_user_id))

(* Enforce the required_claims the login was BEGUN with. Only claim types
   in [verified_claims] count -- by construction, every entry there has
   already survived [check_claim_user_id_matches_payload] and
   [Claims.verify_claim] by the time this runs (either of those raising
   would already have aborted the whole completion). Missing or
   insufficient -- including an entirely empty [verified_claims] -- is
   fatal. *)
let check_required_claims_satisfied (required_claims : string list) (verified_claims : Types.Claim.t list) : unit =
  let verified_claim_types = List.map (fun (c : Types.Claim.t) -> c.claim_type) verified_claims in
  let missing_required = List.filter (fun rc -> not (List.mem rc verified_claim_types)) required_claims in
  if missing_required <> [] then Error.raise_ (Error.Required_claims_not_satisfied missing_required)

(* [complete_local_login(config) -> VerifiedLocalLogin] (design doc, "SDK
   API Shape"). Every argument is load-bearing:

   - key_material: the same identity [begin_local_login] used.
   - pending: the pending-login state [begin_local_login] returned, exactly
     as the app persisted it. Treat as single-use.
   - encrypted_token: the [encrypted_token] query-parameter's raw value.
   - arrived_url: the full URL the callback actually arrived at.
   - now: the current time (never read from the system clock internally).
   - transport / dns: the network seams. Default to
     [Transport.default_transport] / [Dns.default_resolver] when omitted. *)
let complete_local_login_exn (config : config) : verified_local_login =
  let transport = match config.transport with Some t -> t | None -> Transport.default_transport in
  let dns = match config.dns with Some d -> d | None -> Dns.default_resolver in
  let clock_skew_seconds = match config.clock_skew_seconds with Some s -> s | None -> Local_rp.default_clock_skew_seconds in

  (* 1. Decode the callback's URL-param encoding. *)
  let encrypted =
    try Url_params.local_rp_encrypted_callback_from_url_param config.encrypted_token
    with Url_params.Decode_error msg -> Error.raise_ (Error.Decode_failed msg)
  in

  (* 2. Open it, restricted to suites THIS identity's own descriptor
     advertises (Wire Precision: "The SDK must decrypt only with a suite
     listed in its own descriptor"). *)
  let own_descriptor =
    try Types.Local_rp_descriptor.of_cbor config.key_material.descriptor.descriptor
    with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed msg)
  in
  let allowed_suites = List.filter_map Crypto.AeadSuite.parse_str own_descriptor.supported_suites in
  let header, signed_payload = Local_rp.open_local_rp_callback encrypted config.key_material.encryption_private_key allowed_suites in

  (* 3. Fetch the PENDING state's domain's keys, DNS-pinned, over TCP
     CSIL-RPC (design doc: "fetches domain public keys ... for the domain
     the login was begun with"). *)
  let user_domain_keys = Rpc.fetch_domain_keys transport dns ~now:config.now config.pending.user_domain in

  (* 4. Verify the domain-signed envelope against those keys (key lookup,
     revocation/expiry, signature, payload timestamp bounds). Nothing
     inside [payload] is trusted before this succeeds. *)
  let payload = Local_rp.verify_local_rp_callback_payload signed_payload user_domain_keys config.now clock_skew_seconds in

  (* 5. Cross-check the cleartext header's routing twins against the
     now-verified payload. *)
  Local_rp.check_callback_header_matches_payload header payload;

  (* 6a. Audience: the callback names THIS local RP. *)
  Local_rp.verify_audience payload.audience_fingerprint config.key_material.fingerprint;

  (* 6b. Issuer binding: the payload's user_domain must be the domain the
     login was BEGUN with, not merely whichever domain's keys happened to
     verify. *)
  Local_rp.verify_issuer payload.user_domain config.pending.user_domain;

  (* 6c. Callback URL binding against the URL the callback actually
     arrived at (not merely the URL originally requested). *)
  let arrived_base_url = strip_encrypted_token_param config.arrived_url in
  Local_rp.verify_callback_url payload.callback_url arrived_base_url;

  (* 6d. Nonce/state equality against the pending state. Single-use replay
     protection at the app boundary is the app's job. *)
  Local_rp.verify_nonce_state config.pending.nonce config.pending.state payload.nonce payload.state;

  (* 7. Redeem the claim ticket over TCP CSIL-RPC, signed with the local
     RP's own key (the possession proof a stolen ticket can't satisfy). *)
  let redemption_request =
    Local_rp.build_local_rp_ticket_redemption_request ~claim_ticket:payload.claim_ticket ~fingerprint:config.key_material.fingerprint
      ~issued_at:(Timeutil.to_rfc3339 config.now)
  in
  let signed_redemption = Local_rp.sign_local_rp_ticket_redemption_request redemption_request config.key_material.signing_private_key in
  let redemption = Rpc.redeem_claim_ticket transport dns ~now:config.now config.pending.user_domain signed_redemption in

  (* 7a. Identity binding (SEC fix). *)
  check_redemption_identity_matches_payload redemption payload;

  (* 8. Verify every returned claim's signatures against ITS signer
     domain's keys, fetched the same pinned way (a claim may be attested
     by a domain other than the user's home domain). Reuse the home
     domain's already-fetched keys; fetch any additional signer domains on
     demand, capped. *)
  let domain_key_sets = ref [ ({ domain = config.pending.user_domain; keys = user_domain_keys } : Claims.domain_key_set) ] in
  List.iter
    (fun (claim : Types.Claim.t) ->
      List.iter
        (fun (sig_ : Types.Claim_signature.t) ->
          if not (List.exists (fun (s : Claims.domain_key_set) -> s.domain = sig_.domain) !domain_key_sets) then begin
            if List.length !domain_key_sets >= max_claim_signer_domains then
              Error.raise_ (Error.Too_many_claim_signer_domains max_claim_signer_domains);
            let keys = Rpc.fetch_domain_keys transport dns ~now:config.now sig_.domain in
            domain_key_sets := !domain_key_sets @ [ { domain = sig_.domain; keys } ]
          end)
        claim.signatures)
    redemption.claims;

  (* Each claim must also name the SAME user the signed payload vouched
     for (SEC fix), checked BEFORE signature verification, against
     [payload.user_id] -- the SIGNED source of truth, not
     [redemption.user_id]. Subject-domain binding for the signature check
     itself also uses the verified [payload.user_domain], never
     [redemption.user_domain]. *)
  List.iter
    (fun (claim : Types.Claim.t) ->
      check_claim_user_id_matches_payload claim payload.user_id;
      Claims.verify_claim claim payload.user_domain !domain_key_sets config.now)
    redemption.claims;

  (* Enforce the required_claims the login was BEGUN with (SEC fix). Only
     claim types that survived the loop above count -- any claim failing
     its user_id check or signature verification would already have
     raised, so by construction every claim_type here PASSED
     verification. *)
  check_required_claims_satisfied config.pending.required_claims redemption.claims;

  {
    (* Sourced from the VERIFIED, SIGNED payload -- not the redemption
       response -- even though the two are now known to agree (checked
       above in 7a). The payload is the thing that was actually
       cryptographically attested by the domain; the redemption response
       is merely corroborating data fetched over a channel that is pinned
       but otherwise unsigned. *)
    user_id = payload.user_id;
    user_domain = payload.user_domain;
    claims = redemption.claims;
    domain_public_keys = user_domain_keys;
    local_rp_fingerprint = config.key_material.fingerprint;
    issued_at = (try Timeutil.parse_rfc3339 payload.issued_at with Timeutil.Bad_timestamp msg -> Error.raise_ (Error.Bad_timestamp msg));
    expires_at = (try Timeutil.parse_rfc3339 payload.expires_at with Timeutil.Bad_timestamp msg -> Error.raise_ (Error.Bad_timestamp msg));
    ticket_expires_at =
      (try Timeutil.parse_rfc3339 redemption.ticket_expires_at with Timeutil.Bad_timestamp msg -> Error.raise_ (Error.Bad_timestamp msg));
  }

let complete_local_login (config : config) : (verified_local_login, Error.t) result = Error.capture (fun () -> complete_local_login_exn config)
