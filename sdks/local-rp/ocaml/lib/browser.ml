(* Browser endpoint discovery: resolve an identity domain's browser-facing
   HTTPS base from its [_linkkeys_apis] TXT record, and build browser route
   URLs against it. Mirrors [sdks/local-rp/go/browser.go].

   The identity domain (the domain the user selected, e.g. [todandlorna.com])
   is a trust and discovery domain. It is not necessarily the host that
   serves the browser login routes -- the [https=] endpoint of
   [_linkkeys_apis.<identity-domain>] is ([docs/spec/trust-and-anchors.md]:
   "[https=] is the browser-facing endpoint"). These helpers are shared by
   [Begin_login.begin_local_login] (route [browser_route_local_rp]) and by
   regular-RP application glue (route [browser_route_authorize]), so
   discovery is implemented once.

   The resolved base is a service location only. Identity verification stays
   bound to the identity domain -- never bind trust decisions to the host
   these helpers return.

   Dependency note: this SDK does not depend on the [uri] opam package, so
   URL validation and joining are hand-rolled here for exactly the shape a
   [_linkkeys_apis] [https=] value may take ([host[:port][/path]], scheme
   prefixed by [Dns.parse_linkkeys_apis_txt]). Everything else is rejected. *)

(* The browser route for the DNS-less local-RP login flow. *)
let browser_route_local_rp = "/auth/local-rp"

(* The browser route for the regular (domain-keyed) RP login flow. *)
let browser_route_authorize = "/auth/authorize"

(* The browser route where a grantee sends the user to approve an act-as
   grant ([Act_as.begin_act_as]). *)
let browser_route_act_as = "/auth/act-as"

(* A validated browser base: [origin] is [https://host[:port]] and
   [path_prefix] is either [""] or a [/]-prefixed path with no trailing
   slash, so [origin ^ path_prefix ^ route] is a clean join. *)
type browser_base = { origin : string; path_prefix : string }

let starts_with ~prefix s = String.length s >= String.length prefix && String.sub s 0 (String.length prefix) = prefix

let invalid_base (base : string) (detail : string) : 'a =
  Error.raise_ (Error.Invalid_config (Printf.sprintf "browser base %S %s" base detail))

let is_host_char = function 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '.' | '-' -> true | _ -> false

let valid_port (port : string) : bool =
  port <> ""
  && String.length port <= 5
  && String.for_all (function '0' .. '9' -> true | _ -> false) port
  &&
  let n = int_of_string port in
  n >= 1 && n <= 65535

(* Check that [base] is a usable https browser base URL: [https] scheme, a
   hostname, an optional port, an optional path prefix, and nothing else. A
   TXT record value must never smuggle in userinfo, a query, a fragment, or
   (via [Dns.parse_linkkeys_apis_txt]'s unconditional [https://] prefix plus
   this check) a non-HTTPS scheme. *)
let validate_browser_base_exn (base : string) : browser_base =
  let scheme = "https://" in
  if not (starts_with ~prefix:scheme base) then invalid_base base "must use https";
  let rest = String.sub base (String.length scheme) (String.length base - String.length scheme) in
  if String.contains rest '?' || String.contains rest '#' then invalid_base base "must be host[:port][/path] only";
  let authority, path =
    match String.index_opt rest '/' with
    | None -> (rest, "")
    | Some i -> (String.sub rest 0 i, String.sub rest i (String.length rest - i))
  in
  if String.contains authority '@' then invalid_base base "must be host[:port][/path] only";
  let host, port =
    match String.index_opt authority ':' with
    | None -> (authority, None)
    | Some i -> (String.sub authority 0 i, Some (String.sub authority (i + 1) (String.length authority - i - 1)))
  in
  if host = "" then invalid_base base "has no host";
  if not (String.for_all is_host_char host) then invalid_base base "has an invalid host";
  (match port with Some p when not (valid_port p) -> invalid_base base "has an invalid port" | _ -> ());
  let path_prefix =
    if path = "/" then ""
    else if path <> "" && path.[String.length path - 1] = '/' then String.sub path 0 (String.length path - 1)
    else path
  in
  { origin = scheme ^ authority; path_prefix }

let validate_browser_base (base : string) : (browser_base, Error.t) result =
  Error.capture (fun () -> validate_browser_base_exn base)

(* Resolve [identity_domain]'s browser-facing HTTPS base URL (e.g.
   [https://linkkeys.todandlorna.com] or [https://login.example.com/linkkeys])
   from its [_linkkeys_apis.<identity_domain>] TXT record, via the injected
   [dns] resolver.

   It selects the first LinkKeys v1 record whose [https=] endpoint is a
   valid browser base; invalid TXT records and records without [https=] are
   skipped. It returns [Error] when the lookup fails or no record yields a
   valid base -- the caller decides the fallback ([Begin_login] falls back to
   [https://<identity_domain>]).

   A lookup failure is the resolver raising [Dns.Dns_parse_error] (the
   default resolver's own failure signal), [Unix.Unix_error] (a socket
   error from the default resolver), [Failure] / [Invalid_argument] (a
   malformed nameserver address or a malformed datagram inside the default
   resolver), or [Error.Sdk_error] (a custom resolver's failure signal). *)
let resolve_browser_base (dns : Dns.resolver) (identity_domain : string) : (string, Error.t) result =
  let name = Dns.linkkeys_apis_dns_name identity_domain in
  match dns.txt_lookup name with
  | exception Dns.Dns_parse_error msg -> Error (Error.Dns_error msg)
  | exception Unix.Unix_error (e, fn, _) -> Error (Error.Dns_error (Printf.sprintf "%s: %s" fn (Unix.error_message e)))
  | exception Failure msg -> Error (Error.Dns_error msg)
  | exception Invalid_argument msg -> Error (Error.Dns_error msg)
  | exception Error.Sdk_error e -> Error e
  | txts -> (
    let candidate (txt : string) : string option =
      match Dns.parse_linkkeys_apis_txt txt with
      | { Dns.https_base = Some b; _ } -> ( match validate_browser_base b with Ok _ -> Some b | Error _ -> None)
      | { Dns.https_base = None; _ } -> None
      | exception Dns.Dns_parse_error _ -> None
    in
    match List.find_map candidate txts with
    | Some base -> Ok base
    | None -> Error (Error.Dns_error (Printf.sprintf "no usable %s TXT record with an https= endpoint" name)))

(* Percent-encode one query value (RFC 3986 unreserved characters pass
   through; everything else becomes [%XX]). [signed_request] values are
   unpadded base64url -- entirely unreserved -- so they pass through
   byte-identically. *)
let percent_encode_query_value (value : string) : string =
  let hex = "0123456789ABCDEF" in
  let output = Buffer.create (String.length value) in
  String.iter
    (fun c ->
      match c with
      | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '-' | '.' | '_' | '~' -> Buffer.add_char output c
      | _ ->
        let n = Char.code c in
        Buffer.add_char output '%';
        Buffer.add_char output hex.[n lsr 4];
        Buffer.add_char output hex.[n land 15])
    value;
  Buffer.contents output

(* Build the full browser URL for [route] (e.g. [browser_route_local_rp])
   under [browser_base], carrying [signed_request] as the [signed_request]
   query parameter. A path prefix in the base is preserved: base
   [https://login.example.com/linkkeys] and route [/auth/local-rp] produce
   [https://login.example.com/linkkeys/auth/local-rp?...]. *)
let build_browser_endpoint_exn (browser_base : string) (route : string) (signed_request : string) : string =
  let base = validate_browser_base_exn browser_base in
  if not (starts_with ~prefix:"/" route) || String.contains route '?' || String.contains route '#' then
    Error.raise_ (Error.Invalid_config (Printf.sprintf "route %S must start with / and carry no query or fragment" route));
  Printf.sprintf "%s%s%s?signed_request=%s" base.origin base.path_prefix route (percent_encode_query_value signed_request)

let build_browser_endpoint (browser_base : string) (route : string) (signed_request : string) : (string, Error.t) result =
  Error.capture (fun () -> build_browser_endpoint_exn browser_base route signed_request)

(* The begin-flow composition: discover the identity domain's browser base
   and build the route URL, falling back to [https://<identity_domain>] when
   DNS lookup fails, no valid record carries [https=], or the discovered base
   is invalid. The fallback preserves the pre-discovery behavior, so a domain
   that serves its browser routes at the apex keeps working without a
   [_linkkeys_apis] record. *)
let resolve_browser_endpoint_exn (dns : Dns.resolver) (identity_domain : string) (route : string) (signed_request : string) :
    string =
  let base = match resolve_browser_base dns identity_domain with Ok b -> b | Error _ -> "https://" ^ identity_domain in
  build_browser_endpoint_exn base route signed_request

let resolve_browser_endpoint (dns : Dns.resolver) (identity_domain : string) (route : string) (signed_request : string) :
    (string, Error.t) result =
  Error.capture (fun () -> resolve_browser_endpoint_exn dns identity_domain route signed_request)
