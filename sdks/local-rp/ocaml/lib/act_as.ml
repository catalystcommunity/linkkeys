(* Act-as grants, grantee side (docs/spec/reserved/act-as-grants.md).

   A user lets this local RP (the grantee) act as the user at an enrolled
   application (the audience). The user's home domain signs that decision.
   A local RP is identified by its descriptor fingerprint, and its
   descriptor signing key is its grantee key. A local RP can never be an
   audience: a peer cannot resolve its keys through DNS.

   Flow:
   1. [begin_act_as] signs an [ActAsGrantRequest] and returns the browser
      redirect to the home domain's [/auth/act-as] route.
   2. The home domain sends the browser back to the callback URL with
      [act_as_grant_id] and [nonce]. [complete_act_as] checks the nonce and
      returns the grant id.
   3. [refresh_act_as_grant] fetches (and later renews) the signed grant over
      the same pinned TCP CSIL-RPC path [complete_local_login] uses.
   4. [present] signs one presentation for one call to the audience.

   Every signature covers CBOR([tag, payload_bytes]), the same construction
   as the descriptor and redemption signatures
   ([Local_rp.envelope_signature_input]). *)

let grant_request_tag = "linkkeys-act-as-grant-request-v1alpha"
let refresh_request_tag = "linkkeys-act-as-refresh-request-v1alpha"
let presentation_tag = "linkkeys-act-as-presentation-v1alpha"

(* Request windows. The reference home domain refuses a grant-request window
   longer than 900 seconds (it keeps nonces that long). *)
let default_request_window = 300
let max_request_window = 900
let refresh_request_window = 300

(* Whole-second RFC3339 UTC ending in [Z], like liblinkkeys' [format_time]. *)
let format_time (t : float) : string = Timeutil.to_rfc3339 (Float.floor t)

(* A fresh request nonce: 32 random bytes, unpadded base64url text. *)
let fresh_nonce () : string = Url_params.b64url_encode (Crypto.random_bytes 32)

(* ------------------------------------------------------------------ *)
(* Grantee identity and proofs                                         *)
(* ------------------------------------------------------------------ *)

(* This local RP as a [GranteeRef]: its descriptor fingerprint. *)
let local_rp_grantee (km : Identity.key_material) : Types.Grantee_ref.t =
  { application = None; local_rp_descriptor_fingerprint = Some km.fingerprint }

(* Sign [CBOR([tag, payload])] with the descriptor signing key and wrap the
   signature in a local-RP [GranteeProof] that carries the signed
   descriptor. *)
let prove (km : Identity.key_material) (tag : string) (payload : string) : Types.Grantee_proof.t =
  let signature = Crypto.sign_ed25519 km.signing_private_key (Local_rp.envelope_signature_input tag payload) in
  {
    application_instance_id = None;
    local_rp_descriptor = Some km.descriptor;
    signature = { signed_by_key_id = km.fingerprint; signature };
  }

let sign_grant_request (km : Identity.key_material) (request : Types.Act_as_grant_request.t) :
    Types.Signed_act_as_grant_request.t =
  let bytes = Types.Act_as_grant_request.to_cbor request in
  { request = bytes; proof = prove km grant_request_tag bytes }

let sign_refresh_request (km : Identity.key_material) (request : Types.Act_as_refresh_request.t) :
    Types.Signed_act_as_refresh_request.t =
  let bytes = Types.Act_as_refresh_request.to_cbor request in
  { request = bytes; proof = prove km refresh_request_tag bytes }

let decode_failed (what : string) (msg : string) : 'a = Error.raise_ (Error.Decode_failed (Printf.sprintf "%s: %s" what msg))

(* ------------------------------------------------------------------ *)
(* Begin                                                               *)
(* ------------------------------------------------------------------ *)

type begin_config = {
  key_material : Identity.key_material;
  user_domain : string; (* user@domain or domain, parsed like [begin_local_login]. *)
  scope_set : string; (* CBOR of the audience's SignedActAsScopeSet, as received. *)
  requested_lifetime_seconds : int option;
  requested_renewal_window_seconds : int option;
  callback_url : string;
  now : float;
  dns : Dns.resolver option; (* Browser endpoint discovery. Defaults to [Dns.default_resolver]. *)
  request_window : int option; (* Seconds. Defaults to 300; at most 900. *)
}

let make_begin_config ~key_material ~user_domain ~scope_set ?requested_lifetime_seconds ?requested_renewal_window_seconds
    ~callback_url ~now ?dns ?request_window () : begin_config =
  {
    key_material;
    user_domain;
    scope_set;
    requested_lifetime_seconds;
    requested_renewal_window_seconds;
    callback_url;
    now;
    dns;
    request_window;
  }

type act_as_redirect = { redirect_url : string }

(* What the app keeps between [begin_act_as] and [complete_act_as]. Single
   use: discard it after one completion attempt. [user_domain] is the
   identity (home) domain to refresh against, never the discovered browser
   host. *)
type pending_act_as = { nonce : string; user_domain : string; callback_url : string }

let begin_act_as_exn (config : begin_config) : act_as_redirect * pending_act_as =
  Begin_login.validate_callback_scheme config.callback_url;
  let _username, domain = Begin_login.parse_identity_input config.user_domain in
  let window = Option.value config.request_window ~default:default_request_window in
  if window <= 0 || window > max_request_window then
    Error.raise_ (Error.Invalid_config (Printf.sprintf "request_window must be 1..%d seconds" max_request_window));
  (match config.requested_lifetime_seconds with
  | Some n when n <= 0 -> Error.raise_ (Error.Invalid_config "requested_lifetime_seconds must be positive")
  | _ -> ());
  (match config.requested_renewal_window_seconds with
  | Some n when n < 0 -> Error.raise_ (Error.Invalid_config "requested_renewal_window_seconds must not be negative")
  | _ -> ());
  let scope_set =
    try Types.Signed_act_as_scope_set.of_cbor config.scope_set with Cbor.Decode_error msg -> decode_failed "scope set" msg
  in
  let nonce = fresh_nonce () in
  let request : Types.Act_as_grant_request.t =
    {
      grantee = local_rp_grantee config.key_material;
      scope_set;
      requested_lifetime_seconds = config.requested_lifetime_seconds;
      requested_renewal_window_seconds = config.requested_renewal_window_seconds;
      callback_url = config.callback_url;
      nonce;
      requested_at = format_time config.now;
      expires_at = format_time (config.now +. float_of_int window);
    }
  in
  let signed = sign_grant_request config.key_material request in
  let encoded = Url_params.signed_act_as_grant_request_to_url_param signed in
  let dns = match config.dns with Some d -> d | None -> Dns.default_resolver in
  (* Same discovery and fallback as [begin_local_login]. The act-as route
     takes no username hint. *)
  let redirect_url = Browser.resolve_browser_endpoint_exn dns domain Browser.browser_route_act_as encoded in
  ({ redirect_url }, { nonce; user_domain = domain; callback_url = config.callback_url })

let begin_act_as (config : begin_config) : (act_as_redirect * pending_act_as, Error.t) result =
  Error.capture (fun () -> begin_act_as_exn config)

(* ------------------------------------------------------------------ *)
(* Complete (callback)                                                 *)
(* ------------------------------------------------------------------ *)

let hex_value (c : char) : int option =
  match c with
  | '0' .. '9' -> Some (Char.code c - 48)
  | 'a' .. 'f' -> Some (Char.code c - 87)
  | 'A' .. 'F' -> Some (Char.code c - 55)
  | _ -> None

(* application/x-www-form-urlencoded value decoding: [+] is a space, [%XX]
   is one byte. A malformed escape is an error. *)
let percent_decode (s : string) : string =
  let n = String.length s in
  let buf = Buffer.create n in
  let rec go i =
    if i < n then
      match s.[i] with
      | '+' ->
        Buffer.add_char buf ' ';
        go (i + 1)
      | '%' -> (
        if i + 2 >= n then decode_failed "callback query" "malformed percent escape";
        match (hex_value s.[i + 1], hex_value s.[i + 2]) with
        | Some hi, Some lo ->
          Buffer.add_char buf (Char.chr ((hi * 16) + lo));
          go (i + 3)
        | _ -> decode_failed "callback query" "malformed percent escape")
      | c ->
        Buffer.add_char buf c;
        go (i + 1)
  in
  go 0;
  Buffer.contents buf

(* The query part of a full callback URL, or the input itself when it is
   already a bare query. A fragment is dropped. *)
let query_of (callback : string) : string =
  let without_fragment = match String.index_opt callback '#' with Some i -> String.sub callback 0 i | None -> callback in
  match String.index_opt without_fragment '?' with
  | Some i -> String.sub without_fragment (i + 1) (String.length without_fragment - i - 1)
  | None -> without_fragment

let query_params (query : string) : (string * string) list =
  String.split_on_char '&' query
  |> List.filter (fun p -> p <> "")
  |> List.map (fun p ->
         match String.index_opt p '=' with
         | Some i -> (percent_decode (String.sub p 0 i), percent_decode (String.sub p (i + 1) (String.length p - i - 1)))
         | None -> (percent_decode p, ""))

(* Exactly one non-empty value. A repeated parameter is ambiguous, so it is
   an error. *)
let single_param (params : (string * string) list) (name : string) : string =
  match List.filter (fun (k, _) -> k = name) params with
  | [ (_, v) ] when v <> "" -> v
  | [] | [ _ ] -> decode_failed "callback query" (Printf.sprintf "missing %s" name)
  | _ -> decode_failed "callback query" (Printf.sprintf "repeated %s" name)

(* Read [act_as_grant_id] and [nonce] from the callback (a full URL or its
   query). The nonce must equal [pending.nonce] (constant-time compare).
   Returns the grant id. *)
let complete_act_as_exn (pending : pending_act_as) (callback : string) : string =
  let params = query_params (query_of callback) in
  let grant_id = single_param params "act_as_grant_id" in
  let nonce = single_param params "nonce" in
  if not (Eqaf.equal pending.nonce nonce) then Error.raise_ Error.Nonce_mismatch;
  grant_id

let complete_act_as (pending : pending_act_as) (callback : string) : (string, Error.t) result =
  Error.capture (fun () -> complete_act_as_exn pending callback)

(* ------------------------------------------------------------------ *)
(* Refresh                                                             *)
(* ------------------------------------------------------------------ *)

type refresh_config = {
  key_material : Identity.key_material;
  user_domain : string; (* The identity (home) domain, e.g. [pending_act_as.user_domain]. *)
  grant_id : string;
  now : float;
  transport : Transport.t option; (* Defaults to [Transport.default_transport]. *)
  dns : Dns.resolver option; (* Defaults to [Dns.default_resolver]. *)
}

let make_refresh_config ~key_material ~user_domain ~grant_id ~now ?transport ?dns () : refresh_config =
  { key_material; user_domain; grant_id; now; transport; dns }

(* The refresh request this SDK signs, before signing. Exposed for tests and
   for apps that log what they send. *)
let build_refresh_request (km : Identity.key_material) ~(grant_id : string) ~(now : float) ~(nonce : string) :
    Types.Act_as_refresh_request.t =
  {
    grant_id;
    grantee = local_rp_grantee km;
    requested_at = format_time now;
    expires_at = format_time (now +. float_of_int refresh_request_window);
    nonce;
  }

(* Fetch the current grant, or a renewed one, from the user's home domain.
   Returns the signed grant and whether the home domain signed it for this
   call. *)
(* The audience checks the grant signature. This only checks that the home
   domain returned the grant the call asked for, so a confused or hostile
   server cannot hand this grantee another grant. *)
let check_returned_grant (grant_bytes : string) ~(grant_id : string) ~(domain : string) (km : Identity.key_material) :
    unit =
  let grant_id', grantee, subject_domain =
    try
      let m = Cbor.as_map (Cbor.decode grant_bytes) in
      ( Cbor.field_text m "grant_id",
        Types.Grantee_ref.of_map (Cbor.as_map (Cbor.field_exn m "grantee")),
        Cbor.field_text m "subject_domain" )
    with Cbor.Decode_error msg -> decode_failed "refresh-grant grant" msg
  in
  let mismatch what = Error.raise_ (Error.Identity_mismatch ("refresh-grant returned " ^ what)) in
  if grant_id' <> grant_id then mismatch "another grant id";
  if grantee.application <> None || grantee.local_rp_descriptor_fingerprint <> Some km.fingerprint then
    mismatch "a grant for another grantee";
  if String.lowercase_ascii subject_domain <> String.lowercase_ascii domain then
    mismatch "a grant from another subject domain"

let refresh_act_as_grant_exn (config : refresh_config) : Types.Signed_act_as_grant.t * bool =
  if config.grant_id = "" then Error.raise_ (Error.Invalid_config "grant_id must not be empty");
  let _username, domain = Begin_login.parse_identity_input config.user_domain in
  let request = build_refresh_request config.key_material ~grant_id:config.grant_id ~now:config.now ~nonce:(fresh_nonce ()) in
  let signed = sign_refresh_request config.key_material request in
  let transport = Option.value config.transport ~default:Transport.default_transport in
  let dns = Option.value config.dns ~default:Dns.default_resolver in
  let response = Rpc.refresh_act_as_grant transport dns ~now:config.now domain signed in
  check_returned_grant response.grant.grant ~grant_id:config.grant_id ~domain config.key_material;
  (response.grant, response.signed)

let refresh_act_as_grant (config : refresh_config) : (Types.Signed_act_as_grant.t * bool, Error.t) result =
  Error.capture (fun () -> refresh_act_as_grant_exn config)

(* ------------------------------------------------------------------ *)
(* Presentation                                                        *)
(* ------------------------------------------------------------------ *)

(* SHA-256 of the grant's signed bytes ([SignedActAsGrant.grant]). *)
let grant_hash (grant_bytes : string) : string = Digestif.SHA256.(to_raw_string (digest_string grant_bytes))

(* Sign one presentation for one call to [audience]. [request_digest] is
   defined by the audience's application protocol; [nonce] is the caller's
   per-call nonce. Returns the credential to send with the call. *)
let present ~(grant : Types.Signed_act_as_grant.t) ~(audience : Types.Application_ref.t) ~(request_digest : string)
    ~(now : float) ~(nonce : string) (km : Identity.key_material) : Types.Act_as_credential.t =
  let presentation : Types.Act_as_presentation.t =
    { grant_hash = grant_hash grant.grant; audience; request_digest; presented_at = format_time now; nonce }
  in
  let bytes = Types.Act_as_presentation.to_cbor presentation in
  { grant; presentation = { presentation = bytes; proof = prove km presentation_tag bytes } }

(* [present] plus the credential's CBOR bytes. *)
let present_bytes ~grant ~audience ~request_digest ~now ~nonce km : Types.Act_as_credential.t * string =
  let credential = present ~grant ~audience ~request_digest ~now ~nonce km in
  (credential, Types.Act_as_credential.to_cbor credential)
