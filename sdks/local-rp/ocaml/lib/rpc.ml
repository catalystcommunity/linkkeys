(* CSIL-RPC over the injected [Transport.t], TLS-pinned to a domain's DNS
   [fp=] records -- this SDK's only network surface (design doc, "Required
   Network Access"): domain public keys, revocations, and claim-ticket
   redemption, all unauthenticated-TLS TCP CSIL-RPC calls pinned the same
   way [crates/linkkeys/src/tcp/tls.rs] pins the S2S path.

   There is no csilgen OCaml target yet (a request has been filed at
   ~/repos/catalystcommunity/csilgen/docs/csilgen-requests/), so this
   module hand-rolls the CSIL-RPC envelope + stream framing directly per
   [~/repos/catalystcommunity/csilgen/docs/csil-rpc-transport.md] section
   2.3 ("Byte stream (TCP, Unix socket, TLS stream)"): a 4-byte
   big-endian length prefix, then that many bytes of CBOR envelope. This
   SDK only ever calls two services (three operations), so hand-building
   the three real [CsilRpcRequest]s directly (verbatim CSIL names:
   [service="DomainKeys"], [op="get-domain-keys"], etc. -- NOT a
   transport-agnostic lowercased pair) and reusing [Types]' to_cbor/of_cbor
   for the typed payloads is both correct and small, exactly mirroring
   what the Rust and Ruby reference SDKs' own rpc.rs/rpc.rb do for the same
   reason. *)

(* Mirrors the server's own cap ([crates/linkkeys-rpc-client/src/lib.rs])
   so a malicious/compromised peer cannot drive this client to an
   unbounded allocation via a forged length prefix. *)
let max_frame_size = 1024 * 1024

let csil_rpc_version = 1
let tag_encoded_cbor = 24

(* ------------------------------------------------------------------ *)
(* Byte-stream I/O seam: send_frame/read_frame work over anything with  *)
(* a [write]/[read_exact] shape -- both [Unix.file_descr] (used only by *)
(* Dns's own socket code, not here) and [Tls_client.t] (used here) fit. *)
(* ------------------------------------------------------------------ *)

let send_frame (write : string -> unit) (data : string) : unit =
  let len = String.length data in
  let len_prefix = Bytes.create 4 in
  Bytes.set_uint8 len_prefix 0 ((len lsr 24) land 0xff);
  Bytes.set_uint8 len_prefix 1 ((len lsr 16) land 0xff);
  Bytes.set_uint8 len_prefix 2 ((len lsr 8) land 0xff);
  Bytes.set_uint8 len_prefix 3 (len land 0xff);
  write (Bytes.to_string len_prefix);
  write data

let read_frame (read_exact : int -> string) : string =
  let len_bytes = read_exact 4 in
  let len =
    (Char.code len_bytes.[0] lsl 24) lor (Char.code len_bytes.[1] lsl 16) lor (Char.code len_bytes.[2] lsl 8)
    lor Char.code len_bytes.[3]
  in
  if len > max_frame_size then
    Error.raise_ (Error.Protocol_error (Printf.sprintf "peer frame too large (%d bytes, max %d)" len max_frame_size));
  read_exact len

let encode_request (service : string) (op : string) (payload : string) : string =
  Cbor.encode
    (Map
       [
         (Text "v", Int csil_rpc_version);
         (Text "service", Text service);
         (Text "op", Text op);
         (Text "payload", Tag (tag_encoded_cbor, Bytes payload));
       ])

(* Returns (status, error, payload). *)
let decode_response (data : string) : int * string option * string =
  let m =
    try Cbor.as_map (Cbor.decode data)
    with Cbor.Decode_error msg -> Error.raise_ (Error.Protocol_error (Printf.sprintf "RPC response envelope is malformed: %s" msg))
  in
  let status = try Cbor.as_int (Cbor.field_exn m "status") with Cbor.Decode_error _ -> Error.raise_ (Error.Protocol_error "RPC response missing integer 'status'") in
  let error = Cbor.field_text_opt m "error" in
  let payload = match Cbor.field m "payload" with Some (Cbor.Tag (t, Cbor.Bytes b)) when t = tag_encoded_cbor -> b | _ -> "" in
  (status, error, payload)

(* ------------------------------------------------------------------ *)
(* Domain endpoint discovery                                           *)
(* ------------------------------------------------------------------ *)

type domain_endpoint = { fingerprints : string list; tcp_addr : string }

(* Look up a domain's trust anchor + TCP endpoint over DNS TXT. Fails
   closed: a missing/unparseable record, or a [_linkkeys] record with no
   [fp=] entries, or a [_linkkeys_apis] record with no [tcp=] entry, is an
   error -- this SDK never proceeds without a fingerprint set to pin to. *)
let discover_domain_endpoint (dns : Dns.resolver) (domain : string) : domain_endpoint =
  let anchor_name = Dns.linkkeys_dns_name domain in
  let anchor_txts = try dns.txt_lookup anchor_name with Dns.Dns_parse_error msg -> Error.raise_ (Error.Dns_error msg) in
  let fingerprints =
    List.find_map
      (fun txt -> match Dns.parse_linkkeys_txt txt with r -> if r.fingerprints = [] then None else Some r.fingerprints | exception Dns.Dns_parse_error _ -> None)
      anchor_txts
  in
  let fingerprints =
    match fingerprints with
    | Some fps -> fps
    | None -> Error.raise_ (Error.Dns_error (Printf.sprintf "no usable %s TXT record with fp= entries" anchor_name))
  in
  let apis_name = Dns.linkkeys_apis_dns_name domain in
  let apis_txts = try dns.txt_lookup apis_name with Dns.Dns_parse_error msg -> Error.raise_ (Error.Dns_error msg) in
  let tcp_addr =
    List.find_map
      (fun txt -> match Dns.parse_linkkeys_apis_txt txt with a -> a.tcp | exception Dns.Dns_parse_error _ -> None)
      apis_txts
  in
  let tcp_addr =
    match tcp_addr with
    | Some addr -> addr
    | None -> Error.raise_ (Error.Dns_error (Printf.sprintf "no usable %s TXT record with tcp= entry" apis_name))
  in
  { fingerprints; tcp_addr }

(* ------------------------------------------------------------------ *)
(* One request/response over a fresh TLS connection                    *)
(* ------------------------------------------------------------------ *)

let call (transport : Transport.t) (endpoint : domain_endpoint) ~(now : float) (service : string) (op : string)
    (payload : string) : string =
  let raw = try transport.dial endpoint.tcp_addr with Transport.Connect_failed msg -> Error.raise_ (Error.Transport_error msg) in
  let hostname = Tls_client.extract_hostname endpoint.tcp_addr in
  let tls =
    try Tls_client.connect ~server_hostname:hostname ~expected_fingerprints:endpoint.fingerprints ~now raw
    with
    | Tls_client.Error msg -> Error.raise_ (Error.Tls_error msg)
    | Tls_client.Pin_mismatch msg -> Error.raise_ (Error.Tls_error msg)
  in
  Fun.protect
    ~finally:(fun () -> try Tls_client.close tls with _ -> ())
    (fun () ->
      let request_bytes = encode_request service op payload in
      (try send_frame (Tls_client.write tls) request_bytes with Tls_client.Error msg -> Error.raise_ (Error.Transport_error msg));
      let response_bytes = try read_frame (Tls_client.read_exact tls) with Tls_client.Error msg -> Error.raise_ (Error.Transport_error msg) in
      let status, error, resp_payload = decode_response response_bytes in
      if status <> 0 then Error.raise_ (Error.Server_error (status, Option.value error ~default:"unknown error"));
      resp_payload)

(* ------------------------------------------------------------------ *)
(* The two operations this SDK needs                                   *)
(* ------------------------------------------------------------------ *)

(* Establish a domain's trusted key set from an already-fetched
   [get-domain-keys] response: DNS-[fp=] pin, then ALWAYS invoke
   [fetch_revocations] -- never gated on
   [resp.recent_revocations_available] (SEC fix: fail-open -> fail-closed)
   -- and apply any quorum-verified revocation certificates it returns.
   [recent_revocations_available] is an optional performance hint a
   well-behaved IDP may use to signal "you don't even need to ask"; a
   compromised/malicious or merely buggy IDP could otherwise use its
   ABSENCE to suppress this SDK from ever learning about a revocation,
   which is exactly the scenario revocation exists to guard against -- so
   this SDK never uses it to skip the check. [fetch_revocations] raising
   propagates completely unchanged (FATAL, fail closed): this SDK must
   fail closed rather than silently proceed with a possibly-stale key set
   an attacker could have engineered by making the endpoint fail. An
   empty revocation list is normal success (nothing to apply). An empty
   trusted result (before OR after applying revocations) is
   [Error.No_trusted_domain_keys] -- fail closed.

   This function performs no network I/O itself (that's [fetch_domain_keys]
   below, which supplies the real RPC call as [fetch_revocations]); that
   split is what makes the actual fix logic here directly unit-testable
   without a live TLS/CSIL-RPC server -- see test/run_tests.ml's
   [test_rpc_establish_trusted_keys_*]. *)
let establish_trusted_keys ~(now : float) ~(domain : string) (resp : Types.Get_domain_keys_response.t)
    ~(endpoint_fingerprints : string list) (fetch_revocations : unit -> Types.Get_revocations_response.t) :
    Types.Domain_public_key.t list =
  let trusted = Dns.trust_keys resp.keys endpoint_fingerprints now in
  if trusted = [] then Error.raise_ (Error.No_trusted_domain_keys domain);
  let revocations = (fetch_revocations ()).revocations in
  let trusted = Revocation.apply_revocations ~now trusted revocations domain in
  if trusted = [] then Error.raise_ (Error.No_trusted_domain_keys domain);
  trusted

(* Fetch [domain]'s currently-trusted public keys:
   [DomainKeys/get-domain-keys] over TCP CSIL-RPC, pinned to the domain's
   DNS [fp=] set, with signing keys pinned directly and encryption keys
   trusted only via a pinned signing key's vouch, then ALWAYS also fetches
   [DomainKeys/get-revocations] and applies it -- see
   [establish_trusted_keys]'s doc comment for the fail-closed rationale. *)
let fetch_domain_keys (transport : Transport.t) (dns : Dns.resolver) ~(now : float) (domain : string) :
    Types.Domain_public_key.t list =
  let endpoint = discover_domain_endpoint dns domain in
  let payload = Types.Empty_request.to_cbor () in
  let resp_bytes = call transport endpoint ~now "DomainKeys" "get-domain-keys" payload in
  let resp =
    try Types.Get_domain_keys_response.of_cbor resp_bytes
    with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed (Printf.sprintf "get-domain-keys response: %s" msg))
  in
  establish_trusted_keys ~now ~domain resp ~endpoint_fingerprints:endpoint.fingerprints (fun () ->
      (* Always fetch revocations -- never gated on
         recent_revocations_available (see [establish_trusted_keys]'s doc
         comment). Any failure here (transport/TLS/protocol/decode)
         propagates via [Error.raise_] / the exceptions [call] itself
         already raises, i.e. is FATAL: it must never be swallowed to
         "just proceed unfiltered". *)
      let since = Timeutil.to_rfc3339 (now -. (30.0 *. 86400.0)) in
      let req_payload = Types.Get_revocations_request.to_cbor { since = Some since } in
      let resp_bytes = call transport endpoint ~now "DomainKeys" "get-revocations" req_payload in
      try Types.Get_revocations_response.of_cbor resp_bytes
      with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed (Printf.sprintf "get-revocations response: %s" msg)))

(* Redeem a claim ticket with [domain]'s IDP: [LocalRp/redeem-claim-ticket]
   over TCP CSIL-RPC, pinned via the domain's DNS [fp=] set. Unauthenticated
   at the transport layer (no client cert) -- the redemption request itself
   is signed with the local RP's signing key, which is the possession
   proof the server checks. *)
let redeem_claim_ticket (transport : Transport.t) (dns : Dns.resolver) ~(now : float) (domain : string)
    (signed_request : Types.Signed_local_rp_ticket_redemption_request.t) : Types.Local_rp_ticket_redemption_response.t =
  let endpoint = discover_domain_endpoint dns domain in
  let payload = Types.Signed_local_rp_ticket_redemption_request.to_cbor signed_request in
  let resp_bytes = call transport endpoint ~now "LocalRp" "redeem-claim-ticket" payload in
  try Types.Local_rp_ticket_redemption_response.of_cbor resp_bytes
  with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed (Printf.sprintf "redeem-claim-ticket response: %s" msg))
