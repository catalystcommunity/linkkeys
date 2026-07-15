(* Hand-written canonical/deterministic CBOR encoder+decoder.
   There is no csilgen OCaml target yet (a request has been filed -- see
   ~/repos/catalystcommunity/csilgen/docs/csilgen-requests/), so this module
   is a byte-for-byte port of the same algorithm already ported by hand into
   every other local-RP SDK that lacks a generated codec (see
   sdks/local-rp/ruby/lib/linkkeys_local_rp/cbor.rb, whose header this one
   mirrors closely).

   This is a *definite-length*, canonical CBOR implementation: no
   indefinite-length ("streaming") items are ever produced or accepted,
   floats always encode as 64-bit doubles, and map keys are emitted in the
   caller-supplied association list's order (the per-struct encoders in
   types.ml build that order to match each struct's declared field order --
   verified byte-for-byte against every [*_cbor_hex] fixture in
   sdks/local-rp/conformance/), not any generic lexicographic sort -- except
   that [encode] itself DOES still sort map entries by the bytewise
   lexicographic order of their *encoded* keys (RFC 8949 Section 4.2.1 core
   deterministic encoding) so this encoder is correct on its own terms for
   any [value], not only the ones the hand-written struct encoders happen to
   pre-order by hand.

   Byte-string vs text-string dispatch: OCaml's [string] is used for both
   CBOR byte strings and CBOR text strings (there is no separate binary
   type in ordinary use), so the [value] variant below tags each
   occurrence explicitly with [Bytes] or [Text] rather than trying to
   infer the CBOR major type from the OCaml value the way Ruby's
   encoding-tagged String does. *)

type value =
  | Null
  | Bool of bool
  | Int of int
  | Float of float
  | Bytes of string
  | Text of string
  | Array of value list
  | Map of (value * value) list
  | Tag of int * value

exception Decode_error of string
exception Encode_error of string

(* ------------------------------------------------------------------ *)
(* Encoding                                                            *)
(* ------------------------------------------------------------------ *)

let encode_head (buf : Buffer.t) (major : int) (n : int) : unit =
  let mt = major lsl 5 in
  if n < 0 then raise (Encode_error "negative length/argument in CBOR head")
  else if n < 24 then Buffer.add_char buf (Char.chr (mt lor n))
  else if n < 0x100 then begin
    Buffer.add_char buf (Char.chr (mt lor 24));
    Buffer.add_char buf (Char.chr (n land 0xff))
  end
  else if n < 0x10000 then begin
    Buffer.add_char buf (Char.chr (mt lor 25));
    Buffer.add_char buf (Char.chr ((n lsr 8) land 0xff));
    Buffer.add_char buf (Char.chr (n land 0xff))
  end
  else if n < 0x100000000 then begin
    Buffer.add_char buf (Char.chr (mt lor 26));
    for i = 3 downto 0 do
      Buffer.add_char buf (Char.chr ((n lsr (i * 8)) land 0xff))
    done
  end
  else begin
    Buffer.add_char buf (Char.chr (mt lor 27));
    for i = 7 downto 0 do
      Buffer.add_char buf (Char.chr ((n lsr (i * 8)) land 0xff))
    done
  end

let rec encode_value (buf : Buffer.t) (v : value) : unit =
  match v with
  | Null -> Buffer.add_char buf '\xf6'
  | Bool false -> Buffer.add_char buf '\xf4'
  | Bool true -> Buffer.add_char buf '\xf5'
  | Int n -> if n >= 0 then encode_head buf 0 n else encode_head buf 1 (-1 - n)
  | Float f ->
    Buffer.add_char buf '\xfb';
    let bits = Int64.bits_of_float f in
    for i = 7 downto 0 do
      Buffer.add_char buf
        (Char.chr (Int64.to_int (Int64.logand (Int64.shift_right_logical bits (i * 8)) 0xffL)))
    done
  | Tag (t, inner) ->
    encode_head buf 6 t;
    encode_value buf inner
  | Bytes s ->
    encode_head buf 2 (String.length s);
    Buffer.add_string buf s
  | Text s ->
    encode_head buf 3 (String.length s);
    Buffer.add_string buf s
  | Array items ->
    encode_head buf 4 (List.length items);
    List.iter (encode_value buf) items
  | Map pairs ->
    encode_head buf 5 (List.length pairs);
    (* RFC 8949 Section 4.2.1: sort by the bytewise lexicographic order of
       the *encoded* key bytes. OCaml's [String.compare] is a bytewise
       comparison of unsigned char codes (0..255), matching the RFC's
       "lower values sort first" rule exactly. *)
    let encoded_pairs = List.map (fun (k, v) -> (encode k, k, v)) pairs in
    let sorted =
      List.stable_sort (fun (ka, _, _) (kb, _, _) -> String.compare ka kb) encoded_pairs
    in
    List.iter (fun (_, k, v) -> encode_value buf k; encode_value buf v) sorted

and encode (v : value) : string =
  let buf = Buffer.create 64 in
  encode_value buf v;
  Buffer.contents buf

(* ------------------------------------------------------------------ *)
(* Decoding                                                            *)
(* ------------------------------------------------------------------ *)

let byte_at (bytes : string) (pos : int) : int =
  if pos < 0 || pos >= String.length bytes then raise (Decode_error "unexpected end of CBOR input");
  Char.code bytes.[pos]

let decode_arg (bytes : string) (pos : int) (low : int) : int * int =
  if low <= 23 then (low, pos + 1)
  else if low = 24 then (byte_at bytes (pos + 1), pos + 2)
  else if low = 25 then
    let b0 = byte_at bytes (pos + 1) and b1 = byte_at bytes (pos + 2) in
    ((b0 lsl 8) lor b1, pos + 3)
  else if low = 26 then
    let b i = byte_at bytes (pos + 1 + i) in
    ((b 0 lsl 24) lor (b 1 lsl 16) lor (b 2 lsl 8) lor b 3, pos + 5)
  else if low = 27 then begin
    let b i = byte_at bytes (pos + 1 + i) in
    let v = ref 0 in
    for i = 0 to 7 do
      v := (!v lsl 8) lor b i
    done;
    (!v, pos + 9)
  end
  else raise (Decode_error "bad CBOR argument length marker")

let rec decode_value (bytes : string) (pos : int) : value * int =
  let ib = byte_at bytes pos in
  let major = ib lsr 5 in
  let low = ib land 0x1f in
  if major = 7 then
    match low with
    | 20 -> (Bool false, pos + 1)
    | 21 -> (Bool true, pos + 1)
    | 22 | 23 -> (Null, pos + 1)
    | 26 ->
      let b i = byte_at bytes (pos + 1 + i) in
      let bits = Int32.logor
          (Int32.shift_left (Int32.of_int (b 0)) 24)
          (Int32.logor (Int32.shift_left (Int32.of_int (b 1)) 16)
             (Int32.logor (Int32.shift_left (Int32.of_int (b 2)) 8) (Int32.of_int (b 3))))
      in
      (Float (Int32.float_of_bits bits), pos + 5)
    | 27 ->
      let b i = byte_at bytes (pos + 1 + i) in
      let bits = ref 0L in
      for i = 0 to 7 do
        bits := Int64.logor (Int64.shift_left !bits 8) (Int64.of_int (b i))
      done;
      (Float (Int64.float_of_bits !bits), pos + 9)
    | _ -> raise (Decode_error "unsupported CBOR simple value")
  else begin
    let arg, pos = decode_arg bytes pos low in
    match major with
    | 0 -> (Int arg, pos)
    | 1 -> (Int (-1 - arg), pos)
    | 2 ->
      if pos + arg > String.length bytes then raise (Decode_error "byte string exceeds input");
      (Bytes (String.sub bytes pos arg), pos + arg)
    | 3 ->
      if pos + arg > String.length bytes then raise (Decode_error "text string exceeds input");
      (Text (String.sub bytes pos arg), pos + arg)
    | 4 ->
      let items = ref [] in
      let p = ref pos in
      for _ = 1 to arg do
        let item, np = decode_value bytes !p in
        items := item :: !items;
        p := np
      done;
      (Array (List.rev !items), !p)
    | 5 ->
      let pairs = ref [] in
      let p = ref pos in
      for _ = 1 to arg do
        let k, np = decode_value bytes !p in
        let v, np2 = decode_value bytes np in
        pairs := (k, v) :: !pairs;
        p := np2
      done;
      (Map (List.rev !pairs), !p)
    | 6 ->
      let inner, np = decode_value bytes pos in
      (Tag (arg, inner), np)
    | _ -> raise (Decode_error "bad CBOR major type")
  end

let decode (bytes : string) : value =
  try
    let v, pos = decode_value bytes 0 in
    if pos <> String.length bytes then raise (Decode_error "trailing bytes after decoding one CBOR item");
    v
  with
  | Decode_error _ as e -> raise e
  | Invalid_argument msg -> raise (Decode_error (Printf.sprintf "malformed CBOR: %s" msg))

(* ------------------------------------------------------------------ *)
(* Accessors used by types.ml's hand-written struct codecs             *)
(* ------------------------------------------------------------------ *)

let as_map = function
  | Map m -> m
  | _ -> raise (Decode_error "expected a CBOR map")

let as_array = function
  | Array a -> a
  | _ -> raise (Decode_error "expected a CBOR array")

let as_text = function
  | Text s -> s
  | _ -> raise (Decode_error "expected a CBOR text string")

let as_bytes = function
  | Bytes s -> s
  | _ -> raise (Decode_error "expected a CBOR byte string")

let as_int = function
  | Int n -> n
  | _ -> raise (Decode_error "expected a CBOR integer")

let as_bool = function
  | Bool b -> b
  | _ -> raise (Decode_error "expected a CBOR bool")

let field (m : (value * value) list) (name : string) : value option =
  List.find_map (fun (k, v) -> if k = Text name then Some v else None) m

let field_exn (m : (value * value) list) (name : string) : value =
  match field m name with
  | Some v -> v
  | None -> raise (Decode_error (Printf.sprintf "missing field: %s" name))

let field_text (m : (value * value) list) (name : string) : string = as_text (field_exn m name)
let field_text_opt (m : (value * value) list) (name : string) : string option =
  Option.map as_text (field m name)
let field_bytes (m : (value * value) list) (name : string) : string = as_bytes (field_exn m name)
let field_bool_opt (m : (value * value) list) (name : string) : bool option =
  Option.map as_bool (field m name)
let field_array (m : (value * value) list) (name : string) : value list = as_array (field_exn m name)
