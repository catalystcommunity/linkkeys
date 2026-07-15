(* Base64url (unpadded) URL-parameter helpers.

   Mirrors [crates/liblinkkeys/src/encoding.rs]'s [Base64UrlUnpadded]
   helpers, used for the begin route's [?signed_request=] parameter and the
   callback redirect's [&encrypted_token=] parameter (Wire Precision: "URL
   and parameter conventions"). Strict: standard-alphabet input ([+]/[/])
   and padded input ([=]) are both rejected, matching
   [base64ct::Base64UrlUnpadded]'s decoder exactly (see
   [sdks/local-rp/conformance/url_params.json]'s negative cases).

   Hand-rolled rather than pulling in a base64 opam package: this is
   ~30 lines of table lookup with zero external dependency, consistent
   with this SDK's minimal-dependency footprint (AGENTS.md: "every
   dependency is a liability"). *)

exception Decode_error of string

let url_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

let decode_table =
  let t = Array.make 256 (-1) in
  String.iteri (fun i c -> t.(Char.code c) <- i) url_alphabet;
  t

let is_url_safe_char c = decode_table.(Char.code c) >= 0

let b64url_encode (data : string) : string =
  let n = String.length data in
  let buf = Buffer.create (((n + 2) / 3) * 4) in
  let byte i = Char.code data.[i] in
  let i = ref 0 in
  while !i + 3 <= n do
    let b0 = byte !i and b1 = byte (!i + 1) and b2 = byte (!i + 2) in
    let v = (b0 lsl 16) lor (b1 lsl 8) lor b2 in
    Buffer.add_char buf url_alphabet.[(v lsr 18) land 0x3f];
    Buffer.add_char buf url_alphabet.[(v lsr 12) land 0x3f];
    Buffer.add_char buf url_alphabet.[(v lsr 6) land 0x3f];
    Buffer.add_char buf url_alphabet.[v land 0x3f];
    i := !i + 3
  done;
  let remaining = n - !i in
  if remaining = 1 then begin
    let b0 = byte !i in
    let v = b0 lsl 16 in
    Buffer.add_char buf url_alphabet.[(v lsr 18) land 0x3f];
    Buffer.add_char buf url_alphabet.[(v lsr 12) land 0x3f]
  end
  else if remaining = 2 then begin
    let b0 = byte !i and b1 = byte (!i + 1) in
    let v = (b0 lsl 16) lor (b1 lsl 8) in
    Buffer.add_char buf url_alphabet.[(v lsr 18) land 0x3f];
    Buffer.add_char buf url_alphabet.[(v lsr 12) land 0x3f];
    Buffer.add_char buf url_alphabet.[(v lsr 6) land 0x3f]
  end;
  Buffer.contents buf

(* Strict base64url decode: rejects the standard alphabet ([+]/[/]), any
   [=] padding present in the input string itself, and a length that is
   [4k+1] (impossible for any byte count). *)
let b64url_decode (str : string) : string =
  let n = String.length str in
  if not (String.for_all is_url_safe_char str) then raise (Decode_error (Printf.sprintf "not valid unpadded base64url: %S" str));
  if n mod 4 = 1 then raise (Decode_error (Printf.sprintf "invalid base64url length: %S" str));
  let buf = Buffer.create ((n * 3) / 4) in
  let value_at i = decode_table.(Char.code str.[i]) in
  let i = ref 0 in
  while !i + 4 <= n do
    let v = (value_at !i lsl 18) lor (value_at (!i + 1) lsl 12) lor (value_at (!i + 2) lsl 6) lor value_at (!i + 3) in
    Buffer.add_char buf (Char.chr ((v lsr 16) land 0xff));
    Buffer.add_char buf (Char.chr ((v lsr 8) land 0xff));
    Buffer.add_char buf (Char.chr (v land 0xff));
    i := !i + 4
  done;
  let remaining = n - !i in
  if remaining = 2 then begin
    let v = (value_at !i lsl 18) lor (value_at (!i + 1) lsl 12) in
    Buffer.add_char buf (Char.chr ((v lsr 16) land 0xff))
  end
  else if remaining = 3 then begin
    let v = (value_at !i lsl 18) lor (value_at (!i + 1) lsl 12) lor (value_at (!i + 2) lsl 6) in
    Buffer.add_char buf (Char.chr ((v lsr 16) land 0xff));
    Buffer.add_char buf (Char.chr ((v lsr 8) land 0xff))
  end;
  Buffer.contents buf

let signed_local_rp_login_request_to_url_param (signed : Types.Signed_local_rp_login_request.t) : string =
  b64url_encode (Types.Signed_local_rp_login_request.to_cbor signed)

let signed_local_rp_login_request_from_url_param (param : string) : Types.Signed_local_rp_login_request.t =
  let cbor_bytes = b64url_decode param in
  try Types.Signed_local_rp_login_request.of_cbor cbor_bytes
  with Cbor.Decode_error msg -> raise (Decode_error (Printf.sprintf "CBOR decode failed: %s" msg))

let local_rp_encrypted_callback_to_url_param (callback : Types.Local_rp_encrypted_callback.t) : string =
  b64url_encode (Types.Local_rp_encrypted_callback.to_cbor callback)

let local_rp_encrypted_callback_from_url_param (param : string) : Types.Local_rp_encrypted_callback.t =
  let cbor_bytes = b64url_decode param in
  try Types.Local_rp_encrypted_callback.of_cbor cbor_bytes
  with Cbor.Decode_error msg -> raise (Decode_error (Printf.sprintf "CBOR decode failed: %s" msg))
