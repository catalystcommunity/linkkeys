(* Shared JSON-vector loading helpers for the conformance test suite.

   Vectors live in sdks/local-rp/conformance/, made available to this
   test's sandbox via test/dune's glob_files_rec deps stanza covering
   ../../conformance -- so at runtime (dune executes tests with cwd set to the build
   directory mirroring this source directory) the relative path below
   resolves correctly under `dune runtest`. *)

open Linkkeys_local_rp
module J = Yojson.Safe.Util

(* The conformance vectors live in sdks/local-rp/conformance/, a sibling of
   this dune-project's root (sdks/local-rp/ocaml/) -- i.e. outside this
   dune workspace, which rules out declaring it as a tracked `deps` glob
   ("path outside the workspace"). `dune runtest`'s default (unsandboxed)
   rule execution runs this test binary with cwd literally at
   [_build/default/test/] on the real filesystem, with `_build` created
   directly inside the invoked project root (ocaml/) -- so a plain
   relative traversal reaches the real, adjacent conformance/ directory:
   test/ -> default/ -> _build/ -> ocaml/ -> local-rp/ -> conformance/. *)
let conformance_dir = "../../../../conformance"

let read_json (name : string) : Yojson.Safe.t = Yojson.Safe.from_file (Filename.concat conformance_dir name)

let str (j : Yojson.Safe.t) : string = J.to_string j
let str_opt (j : Yojson.Safe.t) : string option = J.to_string_option j
let bool_ (j : Yojson.Safe.t) : bool = J.to_bool j
let bool_opt (j : Yojson.Safe.t) : bool option = J.to_bool_option j
let field (name : string) (j : Yojson.Safe.t) : Yojson.Safe.t = J.member name j
let field_opt (name : string) (j : Yojson.Safe.t) : Yojson.Safe.t option = match J.member name j with `Null -> None | v -> Some v
let list_ (j : Yojson.Safe.t) : Yojson.Safe.t list = J.to_list j

let hex (name : string) (j : Yojson.Safe.t) : string = Hex.decode (str (field name j))
let hex_opt (name : string) (j : Yojson.Safe.t) : string option = Option.map Hex.decode (field_opt name j |> Option.map str)
let text (name : string) (j : Yojson.Safe.t) : string = str (field name j)
let text_opt (name : string) (j : Yojson.Safe.t) : string option = field_opt name j |> Option.map str
let strings (name : string) (j : Yojson.Safe.t) : string list = list_ (field name j) |> List.map str

let domain_public_key_of_json (j : Yojson.Safe.t) : Types.Domain_public_key.t =
  {
    key_id = text "key_id" j;
    public_key = hex "public_key_hex" j;
    fingerprint = text "fingerprint_hex" j;
    algorithm = text "algorithm" j;
    key_usage = text "key_usage" j;
    created_at = text "created_at" j;
    expires_at = text "expires_at" j;
    revoked_at = text_opt "revoked_at" j;
    signed_by_key_id = text_opt "signed_by_key_id" j;
    key_signature = hex_opt "key_signature_hex" j;
  }

let claim_signature_of_json (j : Yojson.Safe.t) : Types.Claim_signature.t =
  { domain = text "domain" j; signed_by_key_id = text "signed_by_key_id" j; signature = hex "signature_hex" j }

(* [Alcotest.check'] with a plain [bool] result, since most of this suite's
   assertions are "did verification succeed or fail" rather than
   structural equality. *)
let check_bool (msg : string) (expected : bool) (actual : bool) : unit = Alcotest.(check bool) msg expected actual
