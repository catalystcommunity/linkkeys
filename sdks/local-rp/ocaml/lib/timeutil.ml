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

(* Parse an RFC3339 timestamp into Unix epoch seconds (UTC, as a float so
   fractional seconds survive). Requires an explicit timezone offset (Z or
   +HH:MM/-HH:MM) -- a bare local-time string is rejected rather than
   silently treated as UTC or local time. *)
let parse_rfc3339 (raw : string) : float =
  let s = String.trim raw in
  let len = String.length s in
  if len < 20 then fail "timestamp too short: %S" s;
  (try
     if s.[4] <> '-' || s.[7] <> '-' then fail "bad date separators: %S" s;
     if s.[10] <> 'T' && s.[10] <> 't' then fail "missing T separator: %S" s;
     let year = int_of_string (String.sub s 0 4) in
     let month = int_of_string (String.sub s 5 2) in
     let day = int_of_string (String.sub s 8 2) in
     let rest = String.sub s 11 (len - 11) in
     if String.length rest < 9 then fail "time part too short: %S" s;
     if rest.[2] <> ':' || rest.[5] <> ':' then fail "bad time separators: %S" s;
     let hour = int_of_string (String.sub rest 0 2) in
     let minute = int_of_string (String.sub rest 3 2) in
     let sec = int_of_string (String.sub rest 6 2) in
     let after_sec = String.sub rest 8 (String.length rest - 8) in
     let frac, after_frac =
       if String.length after_sec > 0 && after_sec.[0] = '.' then begin
         let idx = ref 1 in
         while
           !idx < String.length after_sec
           && (let c = after_sec.[!idx] in
               c >= '0' && c <= '9')
         do
           incr idx
         done;
         let digits = String.sub after_sec 1 (!idx - 1) in
         let frac = if digits = "" then 0.0 else float_of_string ("0." ^ digits) in
         (frac, String.sub after_sec !idx (String.length after_sec - !idx))
       end
       else (0.0, after_sec)
     in
     if after_frac = "" then fail "timestamp has no timezone offset: %S" s;
     let offset_seconds =
       if after_frac = "Z" || after_frac = "z" then 0
       else begin
         let sign =
           match after_frac.[0] with
           | '+' -> 1
           | '-' -> -1
           | _ -> fail "timestamp has no timezone offset: %S" s
         in
         let body = String.sub after_frac 1 (String.length after_frac - 1) in
         let body =
           if String.length body = 4 && not (String.contains body ':') then
             String.sub body 0 2 ^ ":" ^ String.sub body 2 2
           else body
         in
         if String.length body <> 5 || body.[2] <> ':' then fail "bad offset: %S" s;
         let oh = int_of_string (String.sub body 0 2) in
         let om = int_of_string (String.sub body 3 2) in
         sign * ((oh * 3600) + (om * 60))
       end
     in
     if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || sec > 60 then
       fail "field out of range: %S" s;
     let days = days_from_civil year month day in
     (float_of_int ((days * 86400) + (hour * 3600) + (minute * 60) + sec - offset_seconds)) +. frac
   with
  | Bad_timestamp _ as e -> raise e
  | Failure msg -> fail "unparseable RFC3339 timestamp %S: %s" s msg
  | Invalid_argument msg -> fail "unparseable RFC3339 timestamp %S: %s" s msg)

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
