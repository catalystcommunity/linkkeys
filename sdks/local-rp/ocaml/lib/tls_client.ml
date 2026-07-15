(* Client-side TLS pinning: verify a peer's certificate by its SPKI public
   key fingerprint against a DNS-published [fp=] set -- no CA chain,
   matching the trust model [crates/linkkeys/src/tcp/tls.rs] uses for every
   LinkKeys TCP peer.

   TLS evaluation outcome (design doc/task instructions: "evaluate the
   [tls] (ocaml-tls) + tls-unix packages -- check whether ocaml-tls
   supports Ed25519 server certificates and exposes the peer certificate
   for the MANDATORY manual SPKI pin check"):

   - [x509] (0.16.5) DOES support Ed25519 certificates directly:
     [X509.Public_key.t] has an [`ED25519 of Mirage_crypto_ec.Ed25519.pub]
     constructor, and [X509.Certificate.public_key] exposes it. This is a
     real, first-class case, not a fallback path.
   - [tls] (0.17.5) exposes exactly the hook this needs:
     [Tls.Config.client ~authenticator ...] takes an
     [X509.Authenticator.t = ?ip:_ -> host:_ -> Certificate.t list ->
     Validation.r], which is invoked WITH the peer's certificate chain
     during the handshake itself. This is a cleaner fit than the Ruby
     reference's approach (which has to set
     [OpenSSL::SSL::VERIFY_NONE] and perform the pin check manually,
     post-handshake, because Ruby's OpenSSL binding cannot express
     "verify only by SPKI pin"): here, the pin check IS the authenticator,
     enforced natively as part of the standard verification flow, and a
     mismatch fails the handshake before a single application byte is
     exchanged.
   - IMPORTANT gotcha found during the evaluation: [X509.Public_key.fingerprint]
     (and the ready-made [X509.Authenticator.server_key_fingerprint]) hash
     the ASN.1-encoded SubjectPublicKeyInfo DER structure
     ([Mirage_crypto.Hash.digest hash (Asn.pub_info_to_cstruct pub)] --
     confirmed by reading [x509]'s own [public_key.ml]), which is NOT the
     LinkKeys fingerprint convention (sha256 of the raw 32-byte Ed25519
     public key only, matching DNS [fp=] records and
     [crates/linkkeys/src/tcp/tls.rs]). Using the ready-made fingerprint
     authenticator would silently pin against the wrong hash. This module
     therefore extracts the raw Ed25519 public key via
     [X509.Certificate.public_key] -> [`ED25519 pub] ->
     [Mirage_crypto_ec.Ed25519.pub_to_cstruct] and computes the SDK's own
     [Crypto.fingerprint] over exactly those 32 bytes, matching every other
     fingerprint computation in this SDK and in [liblinkkeys] itself.
   - Remaining gap: the standalone [tls] package is a PURE state machine
     ([Tls.Engine]) with no bundled blocking I/O driver -- only
     Lwt/Async/Eio/Miou driver packages exist ([tls-lwt], [tls-async],
     [tls-eio], [tls-miou-unix]). Pulling in an entire async runtime
     (e.g. Lwt) purely to get TLS I/O, when every other module in this SDK
     is deliberately synchronous/blocking (matching the Go/Ruby/C#
     siblings' style and this project's "every dependency is a liability"
     rule), was judged not worth it for one I/O driver. Instead, this
     module hand-drives [Tls.Engine] directly over a blocking
     [Unix.file_descr] (the handshake loop and application-data
     read/write below) -- roughly 90 lines, entirely on top of the pure
     engine, no additional dependency beyond [tls]/[x509] themselves. This
     is real, working TLS 1.2/1.3 client code (Ed25519 leaf certs and all),
     not a stub -- but it has never been exercised against a live LinkKeys
     server in this environment (none is reachable here), so treat the
     handshake loop as reviewed-but-field-untested. What IS tested
     directly, and included in [dune runtest]: the pin-extraction logic
     (this module's [leaf_fingerprint]/[pin_authenticator]) against a real
     openssl-CLI-minted Ed25519 certificate fixture's DER bytes -- see
     [test/test_tls_pin.ml]. Flow tests exercise the rest of the SDK
     (everything above the TLS byte-stream) through the injected
     [Transport]/[Dns] seams with a fake in-memory transport, per the
     conformance suite's own pattern of testing protocol logic
     independently of live network I/O. *)

exception Error of string
exception Pin_mismatch of string
exception Unsupported_certificate_key_type of string

let extract_hostname (host_port : string) : string =
  match String.rindex_opt host_port ':' with
  | None -> host_port
  | Some idx -> if idx = 0 then host_port else String.sub host_port 0 idx

(* Extract the SPKI raw Ed25519 public-key bytes from a certificate and
   return their SHA-256 hex fingerprint -- the same value
   [crates/linkkeys/src/tcp/tls.rs] computes from
   [spki.subject_public_key.data]. See the module docs above for why this
   does NOT use [X509.Public_key.fingerprint]. *)
let leaf_fingerprint (cert : X509.Certificate.t) : string =
  match X509.Certificate.public_key cert with
  | `ED25519 pub -> Crypto.fingerprint (Cstruct.to_string (Mirage_crypto_ec.Ed25519.pub_to_cstruct pub))
  | _ -> raise (Unsupported_certificate_key_type "expected an Ed25519 certificate public key")

let leaf_fingerprint_of_der (der_bytes : string) : string =
  match X509.Certificate.decode_der (Cstruct.of_string der_bytes) with
  | Error (`Msg msg) -> raise (Error (Printf.sprintf "peer certificate could not be parsed: %s" msg))
  | Ok cert -> leaf_fingerprint cert

(* Build an [X509.Authenticator.t] that accepts a certificate chain iff its
   leaf certificate's SPKI Ed25519 fingerprint is a member of
   [expected_fingerprints] (case-insensitive) and the certificate is
   currently within its validity period at [now]. No chain-of-trust /
   hostname check is performed -- the pin IS the trust anchor, exactly
   matching [crates/linkkeys/src/tcp/tls.rs]'s model (WebPKI validity of
   the cert is not the anchor; the pin is). *)
let pin_authenticator (expected_fingerprints : string list) (now : float) : X509.Authenticator.t =
  let expected_lower = List.map String.lowercase_ascii expected_fingerprints in
  fun ?ip:_ ~host:_ certs ->
    match certs with
    | [] -> Error `EmptyCertificateChain
    | leaf :: _ -> (
      let not_before, not_after = X509.Certificate.validity leaf in
      match Ptime.of_float_s now with
      | None -> Error `InvalidChain
      | Some t ->
        if Ptime.is_earlier t ~than:not_before || Ptime.is_later t ~than:not_after then
          Error (`LeafCertificateExpired (leaf, Some t))
        else begin
          match X509.Certificate.public_key leaf with
          | `ED25519 pub ->
            let fp = Crypto.fingerprint (Cstruct.to_string (Mirage_crypto_ec.Ed25519.pub_to_cstruct pub)) in
            if List.mem (String.lowercase_ascii fp) expected_lower then Ok (Some ([ leaf ], leaf)) else Error `InvalidChain
          | _ -> Error `InvalidChain
        end)

(* ------------------------------------------------------------------ *)
(* Blocking TLS byte-stream over a raw Unix socket                     *)
(* ------------------------------------------------------------------ *)

type t = { fd : Unix.file_descr; mutable state : Tls.Engine.state; mutable inbuf : string }

let raw_write (fd : Unix.file_descr) (data : Cstruct.t) : unit =
  if Cstruct.length data > 0 then begin
    let s = Cstruct.to_bytes data in
    let n = Bytes.length s in
    let off = ref 0 in
    while !off < n do
      let written = Unix.write fd s !off (n - !off) in
      off := !off + written
    done
  end

let raw_read (fd : Unix.file_descr) : Cstruct.t =
  let buf = Bytes.create 65536 in
  let n = Unix.read fd buf 0 (Bytes.length buf) in
  if n = 0 then raise (Error "connection closed by peer during TLS handshake")
  else Cstruct.of_bytes ~len:n buf

(* Drive the handshake to completion, feeding [state]'s initial ClientHello
   ([initial]) and then alternating read/[Tls.Engine.handle_tls] until the
   engine reports the handshake is no longer in progress. *)
let handshake (fd : Unix.file_descr) (config : Tls.Config.client) : Tls.Engine.state =
  let state, initial = Tls.Engine.client config in
  raw_write fd initial;
  let rec loop state =
    if not (Tls.Engine.handshake_in_progress state) then state
    else begin
      let incoming = raw_read fd in
      match Tls.Engine.handle_tls state incoming with
      | Ok (state', eof, `Response resp, `Data _) ->
        (match resp with Some r -> raw_write fd r | None -> ());
        (match eof with
        | Some `Eof -> raise (Error "peer closed the connection during the TLS handshake")
        | None -> ());
        loop state'
      | Error (failure, `Response resp) ->
        raw_write fd resp;
        raise (Error (Tls.Engine.string_of_failure failure))
    end
  in
  loop state

(* Connect a TLS client session over [fd] (already-connected raw TCP
   socket, per the injected [Transport]), pinned to [expected_fingerprints],
   presenting no client certificate (public domain-key/revocation fetch and
   ticket redemption must not require mutual TLS -- design doc, "Required
   Network Access"). Raises on any handshake or pin failure. *)
let connect ~(server_hostname : string) ~(expected_fingerprints : string list) ~(now : float) (fd : Unix.file_descr) : t =
  let peer_name : [ `host ] Domain_name.t option =
    match Domain_name.of_string server_hostname with
    | Error _ -> None
    | Ok raw -> ( match Domain_name.host raw with Ok h -> Some h | Error _ -> None)
  in
  let authenticator = pin_authenticator expected_fingerprints now in
  let config = Tls.Config.client ~authenticator ?peer_name () in
  let state = handshake fd config in
  { fd; state; inbuf = "" }

(* Write [data] as one or more TLS application-data records. *)
let write (t : t) (data : string) : unit =
  match Tls.Engine.send_application_data t.state [ Cstruct.of_string data ] with
  | None -> raise (Error "TLS session is not ready to send application data")
  | Some (state', out) ->
    t.state <- state';
    raw_write t.fd out

(* Read application data off the wire until at least [n] bytes are
   available in [t]'s internal buffer, then return and consume exactly [n]
   of them. *)
let read_exact (t : t) (n : int) : string =
  let rec fill () =
    if String.length t.inbuf >= n then ()
    else begin
      let incoming = raw_read t.fd in
      match Tls.Engine.handle_tls t.state incoming with
      | Ok (state', eof, `Response resp, `Data data) ->
        t.state <- state';
        (match resp with Some r -> raw_write t.fd r | None -> ());
        (match data with Some d -> t.inbuf <- t.inbuf ^ Cstruct.to_string d | None -> ());
        (match eof with
        | Some `Eof -> if String.length t.inbuf < n then raise (Error "connection closed before expected bytes were received")
        | None -> ());
        fill ()
      | Error (failure, `Response resp) ->
        raw_write t.fd resp;
        raise (Error (Tls.Engine.string_of_failure failure))
    end
  in
  fill ();
  let result = String.sub t.inbuf 0 n in
  t.inbuf <- String.sub t.inbuf n (String.length t.inbuf - n);
  result

let close (t : t) : unit =
  let state', out = Tls.Engine.send_close_notify t.state in
  t.state <- state';
  (try raw_write t.fd out with _ -> ());
  try Unix.close t.fd with _ -> ()
