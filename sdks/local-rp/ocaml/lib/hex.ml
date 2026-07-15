(* Minimal hex codec. No dependency needed: this is ~10 lines and every
   other candidate (a full "hex" opam package) would be a liability for
   something this small (AGENTS.md: "every dependency is a liability").
   Lowercase output, matching every [_hex] field in the conformance
   vectors. *)

exception Error of string

let encode (s : string) : string =
  let buf = Buffer.create (String.length s * 2) in
  String.iter (fun c -> Buffer.add_string buf (Printf.sprintf "%02x" (Char.code c))) s;
  Buffer.contents buf

let digit_value c =
  match c with
  | '0' .. '9' -> Char.code c - Char.code '0'
  | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
  | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
  | _ -> raise (Error (Printf.sprintf "invalid hex digit: %c" c))

let decode (s : string) : string =
  let n = String.length s in
  if n mod 2 <> 0 then raise (Error (Printf.sprintf "odd-length hex string (%d chars)" n));
  String.init (n / 2) (fun i ->
      let hi = digit_value s.[i * 2] in
      let lo = digit_value s.[(i * 2) + 1] in
      Char.chr ((hi lsl 4) lor lo))
