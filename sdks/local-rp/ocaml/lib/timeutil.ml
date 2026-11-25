(* RFC3339 timestamp parsing shared by every module that checks freshness.

   Every "current time" in this SDK is an explicit [float] (Unix epoch
   seconds, UTC) parameter, never read from the system clock internally --
   mirroring [liblinkkeys]'s discipline of taking [now] as an argument so
   verification stays deterministic and testable (the sole exception is
   [Revocation.count_valid_signers]'s wall-clock default, documented there,
   matching the Rust reference's [check_signing_key_valid]).

   OCaml's stdlib has no RFC3339 parser and [Unix.mktime] is local-time-zone
   dependent (unsuitable for a portable, deterministic UTC parse), so this
   module hand-rolls both directions using Howard Hinnant's [days_from_civil]
   / [civil_from_days] algorithm -- a well-known, TZ-independent, proleptic
   Gregorian <-> day-count conversion that is exact under C-style truncating
   integer division (which is also OCaml's [/]). *)

exception Bad_timestamp of string

(* Days since 1970-01-01 for the given proleptic-Gregorian civil date. *)
let days_from_civil (y : int) (m : int) (d : int) : int =
  let y = if m <= 2 then y - 1 else y in
  let era = (if y >= 0 then y else y - 399) / 400 in
  let yoe = y - (era * 400) in
  (* [0, 399] *)
  let mp = (m + 9) mod 12 in
  (* [0, 11] *)
  let doy = ((153 * mp) + 2) / 5 + d - 1 in
  (* [0, 365] *)
  let doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy in
  (* [0, 146096] *)
  (era * 146097) + doe - 719468

let civil_from_days (z : int) : int * int * int =
  let z = z + 719468 in
  let era = (if z >= 0 then z else z - 146096) / 146097 in
  let doe = z - (era * 146097) in
  (* [0, 146096] *)
  let yoe = (doe - (doe / 1460) + (doe / 36524) - (doe / 146096)) / 365 in
  (* [0, 399] *)
  let y = yoe + (era * 400) in
  let doy = doe - ((365 * yoe) + (yoe / 4) - (yoe / 100)) in
  (* [0, 365] *)
  let mp = ((5 * doy) + 2) / 153 in
  (* [0, 11] *)
  let d = doy - (((153 * mp) + 2) / 5) + 1 in
  (* [1, 31] *)
  let m = mp + if mp < 10 then 3 else -9 in
  (* [1, 12] *)
  let y = if m <= 2 then y + 1 else y in
  (y, m, d)

let fail fmt = Printf.ksprintf (fun s -> raise (Bad_timestamp s)) fmt

let is_digit c = c >= '0' && c <= '9'

let days_in_month (y : int) (m : int) : int =
  match m with
  | 2 -> if (y mod 4 = 0 && y mod 100 <> 0) || y mod 400 = 0 then 29 else 28
  | 4 | 6 | 9 | 11 -> 30
  | _ -> 31

(* Strict RFC 3339 parse into (whole Unix seconds, fraction digits). The
   fraction keeps at most nine digits (later digits are ignored) and has no
   trailing zeros, so [""] means "a whole second". It accepts the same
   relaxations as the Rust reference: a [t] or space separator, a [z] offset,
   and a leap second [:60] read as [:59]. It refuses anything else -- no
   surrounding whitespace, no missing seconds, an offset with a colon only. *)
let parse_parts (s : string) : int * string =
  let len = String.length s in
  let num pos n =
    let sub = String.sub s pos n in
    if not (String.for_all is_digit sub) then fail "not RFC 3339: %S" s;
    int_of_string sub
  in
  if len < 20 then fail "not RFC 3339 (too short): %S" s;
  if s.[4] <> '-' || s.[7] <> '-' || s.[13] <> ':' || s.[16] <> ':' then fail "not RFC 3339: %S" s;
  if s.[10] <> 'T' && s.[10] <> 't' && s.[10] <> ' ' then fail "not RFC 3339 (no T separator): %S" s;
  let year = num 0 4 and month = num 5 2 and day = num 8 2 in
  let hour = num 11 2 and minute = num 14 2 and sec = num 17 2 in
  let pos = ref 19 in
  let frac =
    if !pos < len && s.[!pos] = '.' then begin
      incr pos;
      let start = !pos in
      while !pos < len && is_digit s.[!pos] do
        incr pos
      done;
      if !pos = start then fail "not RFC 3339 (empty fraction): %S" s;
      let digits = String.sub s start (min 9 (!pos - start)) in
      (* Drop trailing zeros: "500" and "5" are the same fraction. *)
      let n = ref (String.length digits) in
      while !n > 0 && digits.[!n - 1] = '0' do
        decr n
      done;
      String.sub digits 0 !n
    end
    else ""
  in
  let rest = String.sub s !pos (len - !pos) in
  let offset_seconds =
    if rest = "Z" || rest = "z" then 0
    else if String.length rest = 6 && (rest.[0] = '+' || rest.[0] = '-') && rest.[3] = ':' then begin
      let digits = String.sub rest 1 2 ^ String.sub rest 4 2 in
      if not (String.for_all is_digit digits) then fail "not RFC 3339 (bad offset): %S" s;
      let oh = int_of_string (String.sub rest 1 2) and om = int_of_string (String.sub rest 4 2) in
      if oh > 23 || om > 59 then fail "not RFC 3339 (bad offset): %S" s;
      (if rest.[0] = '+' then 1 else -1) * ((oh * 3600) + (om * 60))
    end
    else fail "not RFC 3339 (no valid offset): %S" s
  in
  if month < 1 || month > 12 || day < 1 || day > days_in_month year month || hour > 23 || minute > 59 || sec > 60 then
    fail "not RFC 3339 (field out of range): %S" s;
  let sec = if sec = 60 then 59 else sec in
  let days = days_from_civil year month day in
  ((days * 86400) + (hour * 3600) + (minute * 60) + sec - offset_seconds, frac)

(* Parse an RFC 3339 timestamp into Unix epoch seconds (UTC, as a float so
   fractional seconds survive). See [parse_parts] for what it accepts. *)
let parse_rfc3339 (s : string) : float =
  let secs, frac = parse_parts s in
  float_of_int secs +. if frac = "" then 0.0 else float_of_string ("0." ^ frac)

(* Whole Unix seconds as RFC 3339 UTC text, [YYYY-MM-DDTHH:MM:SS], no offset. *)
let format_whole (secs : int) : string =
  let days = if secs >= 0 then secs / 86400 else ((secs + 1) / 86400) - 1 in
  let rem = secs - (days * 86400) in
  let y, m, d = civil_from_days days in
  Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02d" y m d (rem / 3600) (rem mod 3600 / 60) (rem mod 60)

(* The CSIL wire form of a timestamp: RFC 3339 in UTC with [Z]. The
   fraction is written in groups of three digits (none, 3, 6 or 9), as the
   Rust reference writes it. Raises [Bad_timestamp] if [s] is not RFC 3339. *)
let normalize_rfc3339 (s : string) : string =
  let secs, frac = parse_parts s in
  let frac =
    if frac = "" then ""
    else
      let width = (String.length frac + 2) / 3 * 3 in
      "." ^ frac ^ String.make (width - String.length frac) '0'
  in
  format_whole secs ^ frac ^ "Z"

(* A timestamp inside a signed tuple payload is whole Unix seconds (a CBOR
   integer). A fraction of a second was never signed, so this raises
   [Bad_timestamp]; it does not round. *)
let whole_unix_seconds (s : string) : int =
  match parse_parts s with
  | secs, "" -> secs
  | _ -> fail "a signed timestamp must be a whole number of seconds: %S" s

(* Render Unix epoch seconds as RFC3339 UTC with a Z suffix. Not
   wire-normative (only the parsed instant is ever compared -- see the
   design doc's Wire Precision), but whole-second precision is used
   whenever there is no meaningful sub-second component. *)
let to_rfc3339 (t : float) : string =
  let days = int_of_float (Float.floor (t /. 86400.)) in
  let day_start = float_of_int days *. 86400. in
  let rem = t -. day_start in
  let y, m, d = civil_from_days days in
  let total_sec = int_of_float (Float.floor rem) in
  let frac = rem -. float_of_int total_sec in
  let hh = total_sec / 3600 in
  let mm = total_sec mod 3600 / 60 in
  let ss = total_sec mod 60 in
  if frac < 1e-9 then Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ" y m d hh mm ss
  else begin
    let micros = int_of_float (Float.round (frac *. 1e6)) in
    if micros >= 1_000_000 then Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ" y m d hh mm (ss + 1)
    else Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ" y m d hh mm ss micros
  end
