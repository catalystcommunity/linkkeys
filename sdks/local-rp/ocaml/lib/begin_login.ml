(* [begin_local_login] (design doc: "SDK API Shape", "Flow" steps 4-6).

   Pure/offline: no network access happens here. It generates a fresh
   nonce/state, builds and signs a [LocalRpLoginRequest] around the
   identity's already-signed descriptor, and returns a redirect URL plus
   the pending-login state the app must persist and treat as single-use. *)

(* Default requested claims when the caller doesn't specify any (design
   doc, "Default Claim Set"): a usable "identity" out of the box with zero
   claim configuration. *)
let default_requested_claims = [ "display_name"; "email"; "handle" ]

(* Default required claims (design doc, "Default Claim Set"). *)
let default_required_claims = [ "handle" ]

(* Default login-request lifetime: short-lived, matching the callback's
   own short default lifetime (design doc: "callback lifetime is short,
   default 5 minutes"). *)
let default_login_request_lifetime = 5.0 *. 60.0

type config = {
  key_material : Identity.key_material;
  callback_url : string;
  user_domain : string;
  now : float;
  requested_claims : string list option;
  required_claims : string list option;
  request_lifetime : float option;
}

let make_config ~key_material ~callback_url ~user_domain ~now ?requested_claims ?required_claims ?request_lifetime () :
    config =
  { key_material; callback_url; user_domain; now; requested_claims; required_claims; request_lifetime }

(* The redirect URL the app should send the user's browser to. The SDK
   never performs the redirect itself (design doc: "Browser-only Flow"). *)
type local_login_redirect = { redirect_url : string }

(* The state [begin_local_login] returns for the app to persist (e.g. in a
   server-side session tied to the browser) and pass unchanged to
   [complete_local_login]. SINGLE-USE: the app must discard it after one
   completion attempt -- this package owns no storage and cannot enforce
   that itself.

   [required_claims] (SEC fix, identity-binding FIX A.1): the claim types
   this login REQUIRED at [begin_local_login] time. [complete_local_login]
   re-checks this exact set against the redemption's verified claims -- it
   must round-trip through whatever storage the app persists
   [pending_login] in (see [pending_login_to_fields]/[pending_login_of_fields]
   below), so a login that began requiring e.g. [handle] can't complete
   without it just because the requirement was forgotten between begin and
   complete. *)
type pending_login = { nonce : string; state : string; user_domain : string; callback_url : string; required_claims : string list }

(* CBOR-array-of-text, then hex-encoded, so an arbitrary claim-type string
   (not just identifier-shaped ones) round-trips losslessly through the
   same flat [(string * string) list] field format every other
   [pending_login] field already uses. This is an SDK-local storage
   convenience, not a protocol wire format. *)
let required_claims_to_field (claims : string list) : string =
  Hex.encode (Cbor.encode (Cbor.Array (List.map (fun s -> Cbor.Text s) claims)))

let required_claims_of_field (field : string) : string list =
  match Cbor.decode (Hex.decode field) with
  | Cbor.Array items -> List.map Cbor.as_text items
  | _ -> Error.raise_ (Error.Decode_failed "pending login required_claims field was not a CBOR array")
  | exception Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed (Printf.sprintf "pending login required_claims field: %s" msg))
  | exception Hex.Error msg -> Error.raise_ (Error.Decode_failed msg)

(* JSON-safe(-ish) serialization helpers (bytes -> hex) so apps can persist
   this in an ordinary session store without inventing their own encoding. *)
let pending_login_to_fields (p : pending_login) : (string * string) list =
  [
    ("nonce", Hex.encode p.nonce);
    ("state", Hex.encode p.state);
    ("user_domain", p.user_domain);
    ("callback_url", p.callback_url);
    ("required_claims", required_claims_to_field p.required_claims);
  ]

let pending_login_of_fields (fields : (string * string) list) : (pending_login, Error.t) result =
  Error.capture (fun () ->
      let get k = match List.assoc_opt k fields with Some v -> v | None -> Error.raise_ (Error.Decode_failed (Printf.sprintf "pending login missing field: %s" k)) in
      {
        nonce = (try Hex.decode (get "nonce") with Hex.Error msg -> Error.raise_ (Error.Decode_failed msg));
        state = (try Hex.decode (get "state") with Hex.Error msg -> Error.raise_ (Error.Decode_failed msg));
        user_domain = get "user_domain";
        callback_url = get "callback_url";
        required_claims = required_claims_of_field (get "required_claims");
      })

let validate_callback_scheme (url : string) : unit =
  let has_prefix p = String.length url >= String.length p && String.sub url 0 (String.length p) = p in
  if not (has_prefix "http://" || has_prefix "https://") then
    Error.raise_ (Error.Invalid_config (Printf.sprintf "callback_url must be http:// or https://, got: %S" url))

(* [begin_local_login(config) -> (LocalLoginRedirect, PendingLogin)] (design
   doc, "SDK API Shape"). Generates a fresh nonce/state, builds and signs a
   [LocalRpLoginRequest] (envelope + linkkeys-local-rp-login-request
   context) around the identity's descriptor, and returns the full
   redirect URL for the user's LinkKeys domain plus the pending-login
   state. *)
let begin_local_login_exn (config : config) : local_login_redirect * pending_login =
  validate_callback_scheme config.callback_url;
  if String.trim config.user_domain = "" then Error.raise_ (Error.Invalid_config "user_domain must not be empty");
  let nonce = Crypto.random_bytes 32 in
  let state = Crypto.random_bytes 32 in
  let requested_claims = match config.requested_claims with Some c -> c | None -> default_requested_claims in
  let required_claims = match config.required_claims with Some c -> c | None -> default_required_claims in
  let lifetime = match config.request_lifetime with Some l -> l | None -> default_login_request_lifetime in
  let issued_at = Timeutil.to_rfc3339 config.now in
  let expires_at = Timeutil.to_rfc3339 (config.now +. lifetime) in
  let request =
    Local_rp.build_local_rp_login_request ~descriptor:config.key_material.descriptor ~callback_url:config.callback_url ~nonce
      ~state ~requested_claims ~required_claims ~issued_at ~expires_at
  in
  let signed = Local_rp.sign_local_rp_login_request request config.key_material.signing_private_key in
  let encoded = Url_params.signed_local_rp_login_request_to_url_param signed in
  (* Wire Precision: "Begin route: GET /auth/local-rp?signed_request=<...>"
     -- mirrors the existing GET /auth/authorize?signed_request=... route
     shape. *)
  let redirect_url = Printf.sprintf "https://%s/auth/local-rp?signed_request=%s" config.user_domain encoded in
  ( { redirect_url },
    { nonce; state; user_domain = config.user_domain; callback_url = config.callback_url; required_claims } )

let begin_local_login (config : config) : (local_login_redirect * pending_login, Error.t) result =
  Error.capture (fun () -> begin_local_login_exn config)
