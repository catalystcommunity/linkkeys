(* DNS TXT lookup seam + [_linkkeys]/[_linkkeys_apis] record parsing and key
   pinning.

   Mirrors [crates/liblinkkeys/src/dns.rs] (record parsing, pinning, vouch
   verification, [trust_keys]) plus the DNS *lookup* seam itself. Per the
   design doc's "Required Network Access" / "SDK endpoint discovery and
   pinning": the resolver is configurable, defaulting to the system
   resolver -- LAN resolver spoofing is an accepted, documented tradeoff
   for this mode.

   Dependency note: rather than pull in the [ocaml-dns] package (a much
   larger surface: full record/zone/wire-format support this SDK does not
   need) this module hand-rolls a small, bounded UDP DNS TXT query
   directly over a Unix datagram socket, reading the resolver address from
   [/etc/resolv.conf] -- the same approach the sibling C#/Dart/Zig SDKs
   take for the same reason (design doc's SDK Layout: "hand-roll a bounded
   UDP DNS TXT query over Unix sockets reading /etc/resolv.conf ... OR use
   the ocaml-dns package if it installs cleanly and is justified"). A
   ~100-line hand-rolled query/response parser for exactly one record type
   is a smaller, more auditable dependency footprint than a general DNS
   stack, and this SDK only ever needs TXT lookups. *)

let default_tcp_port = 4987

exception Dns_parse_error of string

let linkkeys_dns_name (domain : string) = "_linkkeys." ^ domain
let linkkeys_apis_dns_name (domain : string) = "_linkkeys_apis." ^ domain

type linkkeys_record = { fingerprints : string list }
type linkkeys_apis = { tcp : string option; https_base : string option }

let split_ws (s : string) : string list =
  String.split_on_char ' ' s |> List.concat_map (String.split_on_char '\t') |> List.filter (fun s -> s <> "")

let starts_with ~prefix s = String.length s >= String.length prefix && String.sub s 0 (String.length prefix) = prefix

let strip_prefix ~prefix s = String.sub s (String.length prefix) (String.length s - String.length prefix)

let require_lk1_version (parts : string list) : unit =
  match List.find_opt (fun p -> starts_with ~prefix:"v=" p) parts with
  | None -> raise (Dns_parse_error "missing v= tag in TXT record")
  | Some vp ->
    let version = strip_prefix ~prefix:"v=" vp in
    if version <> "lk1" then raise (Dns_parse_error (Printf.sprintf "unsupported linkkeys version: %s" version))

let parse_linkkeys_txt (txt : string) : linkkeys_record =
  let parts = split_ws txt in
  require_lk1_version parts;
  let fingerprints = List.filter_map (fun p -> if starts_with ~prefix:"fp=" p then Some (strip_prefix ~prefix:"fp=" p) else None) parts in
  { fingerprints }

let normalize_tcp_endpoint (value : string) : string =
  if value = "" || String.contains value ':' then value else Printf.sprintf "%s:%d" value default_tcp_port

let parse_linkkeys_apis_txt (txt : string) : linkkeys_apis =
  let parts = split_ws txt in
  require_lk1_version parts;
  let tcp_raw = List.find_opt (fun p -> starts_with ~prefix:"tcp=" p) parts |> Option.map (strip_prefix ~prefix:"tcp=") in
  let tcp = match tcp_raw with Some v when v <> "" -> Some (normalize_tcp_endpoint v) | _ -> None in
  let https_raw = List.find_opt (fun p -> starts_with ~prefix:"https=" p) parts |> Option.map (strip_prefix ~prefix:"https=") in
  let https_base = match https_raw with Some v when v <> "" -> Some ("https://" ^ v) | _ -> None in
  if tcp = None && https_base = None then raise (Dns_parse_error "_linkkeys_apis record has neither tcp= nor https=");
  { tcp; https_base }

let valid_fingerprint (fp : string) : bool =
  String.length fp = 64
  && String.for_all (function '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true | _ -> false) fp

(* Recompute each candidate key's fingerprint (never trust the wire
   [fingerprint] field) and keep only keys whose recomputed fingerprint is
   a member of [pinned]. *)
let pin_keys_to_fingerprints (keys : Types.Domain_public_key.t list) (pinned : string list) : Types.Domain_public_key.t list =
  let module SS = Set.Make (String) in
  let pinned_lower = List.filter valid_fingerprint pinned |> List.map String.lowercase_ascii |> SS.of_list in
  List.filter (fun (k : Types.Domain_public_key.t) -> SS.mem (String.lowercase_ascii (Crypto.fingerprint k.public_key)) pinned_lower) keys

let key_vouch_tag = "linkkeys-key-vouch-v1"

let key_vouch_payload (enc_fingerprint : string) (enc_expires_at : string) : string =
  Cbor.encode (Array [ Text key_vouch_tag; Text enc_fingerprint; Text enc_expires_at ])

(* Verify that [signing_key] vouches for [enc_key] (encryption keys are not
   published in DNS; they are trusted only via a DNS-pinned signing key's
   vouch). *)
let verify_key_vouch (enc_key : Types.Domain_public_key.t) (signing_key : Types.Domain_public_key.t) (now : float) : bool =
  if enc_key.signed_by_key_id <> Some signing_key.key_id then false
  else if Crypto.signing_key_validity signing_key.expires_at signing_key.revoked_at now <> Crypto.Valid then false
  else
    match enc_key.key_signature with
    | None -> false
    | Some key_signature -> (
      let recomputed_fp = Crypto.fingerprint enc_key.public_key in
      let payload = key_vouch_payload recomputed_fp enc_key.expires_at in
      try
        Crypto.resolve_and_verify signing_key.algorithm payload key_signature signing_key.public_key;
        true
      with _ -> false)

(* Establish the trusted key set from a fetched key list and the DNS-pinned
   fingerprint set. Signing keys are pinned directly; encryption keys are
   trusted only when a pinned signing key vouches for them. Callers MUST
   treat an empty result as "no trustworthy keys" and fail closed. *)
let trust_keys (keys : Types.Domain_public_key.t list) (pinned : string list) (now : float) : Types.Domain_public_key.t list =
  let signing = List.filter (fun (k : Types.Domain_public_key.t) -> k.key_usage = "sign") keys in
  let pinned_signing = pin_keys_to_fingerprints signing pinned in
  let vouched =
    List.filter
      (fun (k : Types.Domain_public_key.t) ->
        k.key_usage = "encrypt" && List.exists (fun sk -> verify_key_vouch k sk now) pinned_signing)
      keys
  in
  pinned_signing @ vouched

(* ------------------------------------------------------------------ *)
(* DNS TXT lookup seam                                                  *)
(* ------------------------------------------------------------------ *)

(* An injectable resolver is just "how do I get the TXT record strings for
   this name" -- a one-function record (mirrors [Transport.t]'s shape),
   so a test fake is a one-line value. *)
type resolver = { txt_lookup : string -> string list }

(* Hand-rolled, bounded UDP DNS TXT query (RFC 1035): builds one query
   packet, sends it to the first nameserver in [/etc/resolv.conf] (falling
   back to 127.0.0.1 if that file is unreadable/empty, matching common
   resolver-shim behavior on minimal systems), and parses TXT records out
   of the answer section. No recursion-desired-off / EDNS0 / TCP fallback
   -- this SDK only ever needs a handful of small TXT lookups, and a
   truncated response is treated as "no usable record" (fail closed) rather
   than adding a TCP retry path.

   SEC fix (SF-4): earlier versions of this module sent a query but never
   validated that a received UDP datagram was actually a response TO that
   query -- no transaction-id check, no QR-bit check, no echoed-question
   check, and [Unix.recvfrom]'s peer address was discarded entirely. Since
   the [_linkkeys]/[_linkkeys_apis] TXT records parsed here are this SDK's
   pin root-of-trust (every downstream TLS-pinned RPC call trusts exactly
   the [fp=]/[tcp=] values resolved here), that meant ANY UDP datagram
   landing on this process's ephemeral source port -- from anywhere
   reachable, not necessarily even on-path -- was accepted as
   authoritative, letting a LAN/off-path spoofer forge the pin and defeat
   the entire TLS-pinning chain with no crypto break at all. [query_one_server]
   below now (a) generates the query id from this SDK's CSPRNG rather than
   the default non-cryptographic generator, (b) verifies each candidate
   response's sender address against the exact nameserver socket address
   the query was sent to ([same_peer]), and (c) validates the response's
   header id, QR bit, and echoed question section against the query
   ([response_matches_query]) before ever handing it to [parse_txt_answers]
   -- reading (bounded) datagrams until a genuine match is found or the
   bound is exhausted, rather than trusting the first thing that arrives. *)
module System_resolver = struct
  let read_resolv_conf () : string list =
    try
      let ic = open_in "/etc/resolv.conf" in
      let rec loop acc =
        match input_line ic with
        | line -> (
          let line = String.trim line in
          match String.split_on_char ' ' line with
          | "nameserver" :: addr :: _ -> loop (addr :: acc)
          | _ -> loop acc)
        | exception End_of_file ->
          close_in ic;
          List.rev acc
      in
      loop []
    with Sys_error _ -> []

  let encode_qname (name : string) : string =
    let labels = String.split_on_char '.' name |> List.filter (fun s -> s <> "") in
    let buf = Buffer.create 64 in
    List.iter
      (fun label ->
        if String.length label > 63 then raise (Dns_parse_error "DNS label too long");
        Buffer.add_char buf (Char.chr (String.length label));
        Buffer.add_string buf label)
      labels;
    Buffer.add_char buf '\000';
    Buffer.contents buf

  let build_query (id : int) (name : string) : string =
    let buf = Buffer.create 64 in
    let add_u16 n =
      Buffer.add_char buf (Char.chr ((n lsr 8) land 0xff));
      Buffer.add_char buf (Char.chr (n land 0xff))
    in
    add_u16 id;
    add_u16 0x0100 (* RD=1, standard query *);
    add_u16 1 (* qdcount *);
    add_u16 0;
    add_u16 0;
    add_u16 0;
    Buffer.add_string buf (encode_qname name);
    add_u16 16 (* TXT *);
    add_u16 1 (* IN *);
    Buffer.contents buf

  let u16_at (s : string) (pos : int) : int = (Char.code s.[pos] lsl 8) lor Char.code s.[pos + 1]

  (* Skip a (possibly compressed) DNS name starting at [pos]; returns the
     position immediately after it. Does not need to resolve compression
     pointers' *contents* (we never need the name text itself here), only
     to skip past them correctly. *)
  let rec skip_name (msg : string) (pos : int) : int =
    let len = Char.code msg.[pos] in
    if len = 0 then pos + 1
    else if len land 0xc0 = 0xc0 then pos + 2 (* compression pointer: 2 bytes total *)
    else skip_name msg (pos + 1 + len)

  (* Decode a (possibly compressed) DNS name at [pos] into a lowercase,
     dot-joined string for comparison purposes, and return the position
     immediately after it IN THE ORIGINAL MESSAGE (i.e. right after the
     first compression pointer followed, if any -- never after data
     reached by following that pointer). Used only to validate a
     response's echoed question section against the query we sent
     (SF-4 fix, below) -- the name itself is attacker-controlled input
     from an untrusted UDP datagram, so pointers are bounds- and
     direction-checked (must point strictly backward) and hop-limited to
     rule out a self-referential/forward loop hanging this parser. *)
  let read_name_for_compare (msg : string) (start_pos : int) : string * int =
    let msg_len = String.length msg in
    let buf = Buffer.create 64 in
    let after_pos = ref None in
    let rec go pos hops =
      if hops > 128 then raise (Dns_parse_error "DNS name has too many compression jumps");
      if pos < 0 || pos >= msg_len then raise (Dns_parse_error "DNS name out of bounds");
      let len = Char.code msg.[pos] in
      if len = 0 then begin
        if !after_pos = None then after_pos := Some (pos + 1)
      end
      else if len land 0xc0 = 0xc0 then begin
        if pos + 1 >= msg_len then raise (Dns_parse_error "truncated DNS compression pointer");
        let ptr = ((len land 0x3f) lsl 8) lor Char.code msg.[pos + 1] in
        if !after_pos = None then after_pos := Some (pos + 2);
        if ptr >= pos then raise (Dns_parse_error "DNS compression pointer does not point backward");
        go ptr (hops + 1)
      end
      else begin
        if pos + 1 + len > msg_len then raise (Dns_parse_error "truncated DNS name label");
        if Buffer.length buf > 0 then Buffer.add_char buf '.';
        Buffer.add_string buf (String.lowercase_ascii (String.sub msg (pos + 1) len));
        go (pos + 1 + len) hops
      end
    in
    go start_pos 0;
    match !after_pos with Some p -> (Buffer.contents buf, p) | None -> raise (Dns_parse_error "DNS name did not terminate")

  let normalize_dns_name (name : string) : string =
    let name = if String.length name > 0 && name.[String.length name - 1] = '.' then String.sub name 0 (String.length name - 1) else name in
    String.lowercase_ascii name

  (* SF-4 SEC fix: a response is only accepted as an answer to OUR query if
     its header id echoes [query_id], the QR bit marks it as a response
     (not another query), and its (single) echoed question section names
     [qname] with qtype=TXT/qclass=IN -- exactly what we sent. Without
     this, [parse_txt_answers] would happily parse ANY UDP datagram that
     happens to land on this ephemeral port as if it were the authoritative
     answer, which is exactly what a LAN off-path spoofer needs to forge
     the [fp=] pin root-of-trust this SDK's entire TLS pinning chain rests
     on. Returns [false] (never raises) on any malformed/short input --
     "not a valid match" is the only signal the caller needs; a malformed
     datagram is simply ignored, same as a well-formed but non-matching
     one. *)
  let response_matches_query (msg : string) ~(query_id : int) ~(qname : string) : bool =
    try
      String.length msg >= 12
      && u16_at msg 0 = query_id
      && (u16_at msg 2 lsr 15) land 1 = 1 (* QR: this is a response, not a query *)
      && u16_at msg 4 >= 1 (* qdcount *)
      &&
      let name, pos_after_name = read_name_for_compare msg 12 in
      pos_after_name + 4 <= String.length msg
      && name = normalize_dns_name qname
      && u16_at msg pos_after_name = 16 (* TXT *)
      && u16_at msg (pos_after_name + 2) = 1 (* IN *)
    with Dns_parse_error _ -> false

  (* Compare a UDP datagram's sender against the nameserver address we sent
     the query to (SF-4 SEC fix): without this, an off-path spoofer
     anywhere reachable to this host's ephemeral UDP port -- not
     necessarily even on the same LAN segment as the real resolver -- could
     race a forged response in. IPv4/IPv6 address AND port must both
     match; anything else (including a non-INET sockaddr, which cannot
     occur for an [SOCK_DGRAM]/[PF_INET] socket but is handled rather than
     assumed) is treated as "not our resolver". *)
  let same_peer (a : Unix.sockaddr) (b : Unix.sockaddr) : bool =
    match (a, b) with Unix.ADDR_INET (ip_a, port_a), Unix.ADDR_INET (ip_b, port_b) -> ip_a = ip_b && port_a = port_b | _ -> false

  (* Bound on the number of UDP datagrams read per query, per server:
     defense against a flood of spoofed/garbage datagrams being used to
     keep this SDK reading forever instead of ever reaching (or timing out
     waiting for) the real resolver's answer. Each individual read is still
     subject to the socket's own [SO_RCVTIMEO], so a genuinely silent
     resolver still fails via the existing timeout path, not this bound. *)
  let max_response_reads = 8

  let parse_txt_answers (msg : string) : string list =
    if String.length msg < 12 then raise (Dns_parse_error "DNS response too short");
    let qdcount = u16_at msg 4 in
    let ancount = u16_at msg 6 in
    let pos = ref 12 in
    for _ = 1 to qdcount do
      pos := skip_name msg !pos;
      pos := !pos + 4 (* qtype + qclass *)
    done;
    let results = ref [] in
    for _ = 1 to ancount do
      pos := skip_name msg !pos;
      let rtype = u16_at msg !pos in
      let rdlength = u16_at msg (!pos + 8) in
      let rdata_start = !pos + 10 in
      if rtype = 16 (* TXT *) then begin
        (* One TXT record's RDATA is a sequence of length-prefixed
           character-strings; RFC 1035 says concatenate them for the
           record's logical value. *)
        let buf = Buffer.create rdlength in
        let p = ref rdata_start in
        let rdata_end = rdata_start + rdlength in
        while !p < rdata_end do
          let clen = Char.code msg.[!p] in
          Buffer.add_string buf (String.sub msg (!p + 1) clen);
          p := !p + 1 + clen
        done;
        results := Buffer.contents buf :: !results
      end;
      pos := rdata_start + rdlength
    done;
    List.rev !results

  (* Cryptographically-unpredictable transaction id (SF-4 fix: cheap
     half-measure alongside the essential fix, which is
     [response_matches_query]'s validation below) -- [Random.int]'s default
     generator is not seeded for unpredictability against an adversary who
     might otherwise narrow down the id space, and [Crypto] (this SDK's
     already-initialized CSPRNG) is a sibling module, so this costs
     nothing extra to wire in. *)
  let random_query_id () : int =
    let b = Crypto.random_bytes 2 in
    (Char.code b.[0] lsl 8) lor Char.code b.[1]

  let query_one_server (server : string) (name : string) : string list =
    let addr = Unix.inet_addr_of_string server in
    let sockaddr = Unix.ADDR_INET (addr, 53) in
    let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
    Fun.protect
      ~finally:(fun () -> try Unix.close sock with _ -> ())
      (fun () ->
        Unix.setsockopt_float sock Unix.SO_RCVTIMEO 5.0;
        let id = random_query_id () in
        let query = build_query id name in
        let sent = Unix.sendto sock (Bytes.of_string query) 0 (String.length query) [] sockaddr in
        if sent <> String.length query then raise (Dns_parse_error "short DNS query write");
        let buf = Bytes.create 4096 in
        (* SF-4 SEC fix: read (bounded) until a datagram both (a) arrives
           from the exact nameserver address we queried and (b) validates
           as an actual response to THIS query (id/QR/question all match)
           -- anything else is silently discarded and the next datagram is
           read instead, exactly as if it had never arrived. Exhausting the
           bound without a match is a normal [Dns_parse_error], handled by
           [txt_lookup]'s existing try-next-server fallback below. *)
        let rec read_valid_response attempts_left =
          if attempts_left <= 0 then
            raise (Dns_parse_error (Printf.sprintf "no valid DNS response received for %s (id/question mismatch or spoofed source)" name))
          else
            let n, from_addr = Unix.recvfrom sock buf 0 (Bytes.length buf) [] in
            let msg = Bytes.sub_string buf 0 n in
            if (not (same_peer from_addr sockaddr)) || not (response_matches_query msg ~query_id:id ~qname:name) then
              read_valid_response (attempts_left - 1)
            else msg
        in
        let msg = read_valid_response max_response_reads in
        parse_txt_answers msg)

  let txt_lookup (name : string) : string list =
    let servers = read_resolv_conf () in
    let servers = if servers = [] then [ "127.0.0.1" ] else servers in
    let rec try_servers = function
      | [] -> raise (Dns_parse_error (Printf.sprintf "DNS TXT lookup failed for %s: no nameserver responded" name))
      | server :: rest -> (
        try query_one_server server name with
        | Dns_parse_error _ when rest <> [] -> try_servers rest
        | Unix.Unix_error _ when rest <> [] -> try_servers rest)
    in
    try_servers servers
end

let default_resolver : resolver = { txt_lookup = System_resolver.txt_lookup }
