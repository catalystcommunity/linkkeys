(* The TCP dial seam.

   Mirrors [sdks/local-rp/rust/src/transport.rs] / the Ruby port's
   [transport.rb]. Deliberately narrow: this seam only *connects a byte
   stream* to [host:port]. TLS (certificate-pin verification against DNS
   [fp=] records) is layered on top in [tls_client.ml], not here, so a test
   double can swap out "how do I open a socket" without also faking a TLS
   handshake.

   Per the design doc's Wire Precision ("SDK endpoint discovery and
   pinning"): the Rust [linkkeys-rpc-client]'s non-public-address refusal
   is a SERVER-SIDE SSRF guard and must NOT be inherited as this SDK's
   default -- "connecting from a LAN box to wherever [_linkkeys_apis]
   points is the entire point of this mode." The default policy here is
   [Permissive]. [Public_only] is an opt-in for integrators who
   specifically want that stricter posture; nothing in this package selects
   it automatically. *)

exception Connect_failed of string
exception Address_denied of string

type address_policy =
  | Permissive
  | Public_only

(* An injectable transport is just "how do I open a byte-stream socket to
   host:port" -- a one-function record rather than a module type, so a
   test fake is a one-line value rather than a first-class-module
   wrapper. *)
type t = { dial : string -> Unix.file_descr }

(* True for loopback/private/link-local/CGNAT/documentation/unspecified
   addresses. Only consulted under [Public_only], never by default. *)
let non_public (ip : Unix.inet_addr) : bool =
  let s = Unix.string_of_inet_addr ip in
  if String.contains s ':' then
    (* IPv6 *)
    let lower = String.lowercase_ascii s in
    lower = "::1" || lower = "::"
    || String.length lower >= 5 && String.sub lower 0 5 = "fe80:"
    || String.length lower >= 2 && String.sub lower 0 2 = "fc"
    || String.length lower >= 2 && String.sub lower 0 2 = "fd"
    || String.length lower >= 3 && String.sub lower 0 3 = "ff0"
  else begin
    let parts = String.split_on_char '.' s |> List.map int_of_string in
    match parts with
    | [ a; b; _c; _d ] ->
      let cgnat = a = 100 && b land 0xc0 = 0x40 in
      let loopback = a = 127 in
      let private_range = a = 10 || (a = 172 && b >= 16 && b <= 31) || (a = 192 && b = 168) in
      let link_local = a = 169 && b = 254 in
      let unspecified = s = "0.0.0.0" in
      let broadcast = s = "255.255.255.255" in
      let documentation =
        (a = 192 && b = 0 && (match parts with [ _; _; c; _ ] -> c = 2 | _ -> false))
        || (a = 198 && b = 51)
        || (a = 203 && b = 0)
      in
      cgnat || loopback || private_range || link_local || unspecified || broadcast || documentation
    | _ -> false
  end

(* Default Transport: a plain blocking TCP socket, gated only by [policy]
   (permissive unless the caller opts into [Public_only]). *)
module Std_transport = struct
  type config = { policy : address_policy; connect_timeout : float; io_timeout : float }

  let create ?(policy = Permissive) ?(connect_timeout = 10.0) ?(io_timeout = 30.0) () : config =
    { policy; connect_timeout; io_timeout }

  let split_host_port (host_port : string) : string * int =
    match String.rindex_opt host_port ':' with
    | None -> raise (Connect_failed (Printf.sprintf "%s: missing port" host_port))
    | Some idx ->
      let host = String.sub host_port 0 idx in
      let port_str = String.sub host_port (idx + 1) (String.length host_port - idx - 1) in
      if host = "" then raise (Connect_failed (Printf.sprintf "%s: missing host" host_port));
      (match int_of_string_opt port_str with
      | None -> raise (Connect_failed (Printf.sprintf "%s: invalid port" host_port))
      | Some port -> (host, port))

  let connect_with_timeout (sock : Unix.file_descr) (sockaddr : Unix.sockaddr) (timeout : float) : unit =
    Unix.set_nonblock sock;
    (try Unix.connect sock sockaddr with
    | Unix.Unix_error ((Unix.EINPROGRESS | Unix.EWOULDBLOCK), _, _) -> (
      match Unix.select [] [ sock ] [] timeout with
      | _, [ _ ], _ -> (
        match Unix.getsockopt_error sock with
        | None -> ()
        | Some err -> raise (Connect_failed (Unix.error_message err)))
      | _ ->
        (try Unix.close sock with _ -> ());
        raise (Connect_failed "connect timed out")));
    Unix.clear_nonblock sock

  let dial (cfg : config) (host_port : string) : Unix.file_descr =
    let host, port = split_host_port host_port in
    let addrs =
      try Unix.getaddrinfo host (string_of_int port) [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
      with _ -> raise (Connect_failed (Printf.sprintf "%s: resolve failed" host_port))
    in
    if addrs = [] then raise (Connect_failed (Printf.sprintf "%s: no address resolved" host_port));
    let rec try_addrs last_err = function
      | [] -> raise (match last_err with Some e -> e | None -> Connect_failed (Printf.sprintf "%s: no address resolved" host_port))
      | (ai : Unix.addr_info) :: rest -> (
        match ai.ai_addr with
        | Unix.ADDR_INET (ip, _) when cfg.policy = Public_only && non_public ip ->
          try_addrs
            (Some (Address_denied (Printf.sprintf "%s: refusing non-public address under Public_only" (Unix.string_of_inet_addr ip))))
            rest
        | _ -> (
          try
            let sock = Unix.socket ai.ai_family ai.ai_socktype ai.ai_protocol in
            connect_with_timeout sock ai.ai_addr cfg.connect_timeout;
            Unix.setsockopt_float sock Unix.SO_RCVTIMEO cfg.io_timeout;
            Unix.setsockopt_float sock Unix.SO_SNDTIMEO cfg.io_timeout;
            sock
          with
          | Connect_failed _ as e -> try_addrs (Some e) rest
          | Unix.Unix_error (err, _, _) -> try_addrs (Some (Connect_failed (Printf.sprintf "%s: %s" host_port (Unix.error_message err)))) rest))
    in
    try_addrs None addrs

  let to_transport (cfg : config) : t = { dial = dial cfg }
end

let default_transport : t = Std_transport.to_transport (Std_transport.create ())
