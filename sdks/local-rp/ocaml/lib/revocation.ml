(* Sibling-signed key revocation certificate verification.

   Mirrors [crates/liblinkkeys/src/revocation.rs]. Only verification is
   ported here -- building/signing a revocation certificate is a
   domain-admin/server-side operation, out of scope for a local-RP SDK.
   This SDK verifies revocation certificates fetched alongside domain keys
   ([Rpc.fetch_domain_keys]) so it can drop a key a quorum-verified sibling
   revocation targets BEFORE any envelope or claim verification consults
   the key set.

   Wire-precision gotchas, per [sdks/local-rp/conformance/README.md]'s
   [revocations.json] section (these are exactly what the vectors punish):

   - The signed payload is [CBOR([tag, target_key_id, target_fingerprint,
     revoked_at, signing_domain])] -- a FIVE-element CBOR array with the
     domain-separation tag [linkkeys-key-revocation-v1] first. This is the
     older house tuple pattern, NOT the local-RP envelopes' two-element
     [CBOR([context, payload])] framing.
   - The verifier recomputes each signature's payload from that signature's
     WIRE [domain] field; the [domain] parameter only *filters* which
     signatures are eligible. (This is what defeats cross-domain signature
     reuse: a signature whose wire [domain] lies about its binding
     recomputes to different bytes and fails.)
   - Sibling-key validity (expiry/revocation) is a WALL-CLOCK check in the
     Rust implementation ([check_signing_key_valid] takes no [now]); this
     port defaults [now] to the wall clock and only accepts an override for
     tests.
   - Invalid signatures are silently skipped; distinctness is by signer key
     id; the only failure mode is an insufficient count of valid signers. *)

(* Minimum number of distinct sibling signatures required to revoke a key. *)
let revocation_quorum = 2

let revocation_tag = "linkkeys-key-revocation-v1"

(* The canonical signed bytes: CBOR([tag, target_key_id,
   target_fingerprint, revoked_at, signing_domain]) -- the signing
   sibling's domain is bound per-signature to stop cross-domain reuse. *)
let revocation_payload (target_key_id : string) (target_fingerprint : string) (revoked_at : string)
    (signing_domain : string) : string =
  Cbor.encode
    (Array
       [ Text revocation_tag; Text target_key_id; Text target_fingerprint; Text revoked_at; Text signing_domain ])

(* Count the DISTINCT signer key ids whose signature survives every
   filtering rule (not the target, wire domain equals [domain], signer key
   present + currently-valid signing key) and cryptographically verifies
   over the recomputed payload. [now] defaults to the wall clock (see
   module docs) -- the override exists for deterministic tests only. *)
let count_valid_signers ?now (cert : Types.Revocation_certificate.t) (domain_keys : Types.Domain_public_key.t list)
    (domain : string) : int =
  let now = match now with Some n -> n | None -> Unix.gettimeofday () in
  let module SS = Set.Make (String) in
  let valid_signers =
    List.fold_left
      (fun acc (sig_ : Types.Claim_signature.t) ->
        if sig_.signed_by_key_id = cert.target_key_id then acc
        else if sig_.domain <> domain then acc
        else
          match List.find_opt (fun (k : Types.Domain_public_key.t) -> k.key_id = sig_.signed_by_key_id) domain_keys with
          | None -> acc
          | Some key ->
            if key.key_usage <> "sign" then acc
            else if Crypto.signing_key_validity key.expires_at key.revoked_at now <> Crypto.Valid then acc
            else
              let payload = revocation_payload cert.target_key_id cert.target_fingerprint cert.revoked_at sig_.domain in
              let ok = try Crypto.resolve_and_verify key.algorithm payload sig_.signature key.public_key; true with _ -> false in
              if ok then SS.add sig_.signed_by_key_id acc else acc)
      SS.empty cert.signatures
  in
  SS.cardinal valid_signers

(* Verify a revocation certificate against a domain's public key set.
   Requires at least [revocation_quorum] DISTINCT signing keys of [domain],
   each currently valid and NOT the target key, to have signed the
   canonical payload. *)
let verify_revocation_certificate ?now (cert : Types.Revocation_certificate.t) (domain_keys : Types.Domain_public_key.t list)
    (domain : string) : unit =
  let got = count_valid_signers ?now cert domain_keys domain in
  if got < revocation_quorum then Error.raise_ (Error.Revocation_insufficient (got, revocation_quorum))

(* Apply quorum-verified revocation certificates to a trusted key set: any
   key a valid certificate targets is dropped, no matter what the fetched
   key entry itself says (its own [revoked_at] may well be unset -- that is
   the whole point of the sibling-certificate channel). Certificates that
   fail verification are ignored. Returns the filtered list. *)
let apply_revocations ?now (trusted : Types.Domain_public_key.t list) (revocations : Types.Revocation_certificate.t list)
    (domain : string) : Types.Domain_public_key.t list =
  List.fold_left
    (fun result (cert : Types.Revocation_certificate.t) ->
      match verify_revocation_certificate ?now cert result domain with
      | () -> List.filter (fun (k : Types.Domain_public_key.t) -> k.key_id <> cert.target_key_id) result
      | exception Error.Sdk_error (Error.Revocation_insufficient _) -> result)
    trusted revocations
