(* Claim signature/revocation/expiry verification.

   Mirrors [crates/liblinkkeys/src/claims.rs] for exactly the pieces
   [Complete_login.complete_local_login] needs: per-signer-domain signature
   quorum, revocation, and expiry. [sign_claim] is included only so this
   package's own flow tests can build fake claims (IDP-side operation; the
   SDK itself only ever verifies claims returned from a ticket redemption,
   never signs them). *)

let claim_payload_tag = "linkkeys-claim-v1alpha"

type domain_key_set = { domain : string; keys : Types.Domain_public_key.t list }

type claim_spec = {
  claim_id : string;
  claim_type : string;
  claim_value : string;
  user_id : string;
  subject_domain : string;
  attested_at : string;
  expires_at : string option;
}

type claim_signer = { domain : string; key_id : string; algorithm : string; private_key : string }

(* The subject is bound as the single full identity [user_id@subject_domain]
   (not the bare user_id), so a claim about a user_id at one domain can't be
   replayed as the same user_id at another. [signing_domain] -- the
   attestor for THIS signature -- is bound per-signature.

   [claim_value] is bound as a CBOR BYTE string, matching the Rust
   reference exactly ([crates/liblinkkeys/src/claims.rs],
   `serde_bytes::Bytes::new(claim_value)` in its `claim_sign_payload`
   tuple) -- a claim value may carry arbitrary bytes, and encoding it as
   text here would compute different signature bytes than every real
   signer/verifier. *)
let claim_sign_payload (claim_id : string) (claim_type : string) (claim_value : string) (user_id : string)
    (subject_domain : string) (signing_domain : string) (expires_at : string option) (attested_at : string) : string =
  let subject = Printf.sprintf "%s@%s" user_id subject_domain in
  Cbor.encode
    (Array
       [
         Text claim_payload_tag;
         Text claim_id;
         Text claim_type;
         Bytes claim_value;
         Text subject;
         Text signing_domain;
         (match expires_at with Some e -> Text e | None -> Null);
         Text attested_at;
       ])

(* Sign a claim with one or more keys, producing a Claim carrying one
   ClaimSignature per signer. IDP-side operation; see module docs. *)
let sign_claim (spec : claim_spec) (signers : claim_signer list) : Types.Claim.t =
  let signatures =
    List.map
      (fun (signer : claim_signer) ->
        let payload =
          claim_sign_payload spec.claim_id spec.claim_type spec.claim_value spec.user_id spec.subject_domain signer.domain
            spec.expires_at spec.attested_at
        in
        let signature = Crypto.sign_with_algorithm signer.algorithm payload signer.private_key in
        ({ domain = signer.domain; signed_by_key_id = signer.key_id; signature } : Types.Claim_signature.t))
      signers
  in
  {
    claim_id = spec.claim_id;
    user_id = spec.user_id;
    claim_type = spec.claim_type;
    claim_value = spec.claim_value;
    signatures;
    attested_at = spec.attested_at;
    created_at = spec.attested_at;
    expires_at = spec.expires_at;
    revoked_at = None;
  }

let verify_one_signature (sig_ : Types.Claim_signature.t) (payload : string) (keys : Types.Domain_public_key.t list)
    (now : float) : unit =
  let key =
    match List.find_opt (fun (k : Types.Domain_public_key.t) -> k.key_id = sig_.signed_by_key_id) keys with
    | Some k -> k
    | None -> Error.raise_ (Error.Key_not_found sig_.signed_by_key_id)
  in
  if key.key_usage <> "sign" then Error.raise_ (Error.Signature_invalid "key is not a signing key");
  (match Crypto.signing_key_validity key.expires_at key.revoked_at now with
  | Crypto.Revoked -> Error.raise_ (Error.Key_revoked key.key_id)
  | Crypto.Expired | Crypto.Bad_expiry -> Error.raise_ (Error.Key_expired key.key_id)
  | Crypto.Valid -> ());
  try Crypto.resolve_and_verify key.algorithm payload sig_.signature key.public_key with
  | Crypto.Unsupported_algorithm a -> Error.raise_ (Error.Unsupported_algorithm a)
  | Crypto.Verification_failed _ -> Error.raise_ (Error.Signature_invalid "claim signature verification failed")

(* Every distinct domain that signed must contribute at least one signature
   from a currently-valid key of that domain. *)
let verify_claim_signatures (claim : Types.Claim.t) (subject_domain : string) (domain_keys : domain_key_set list)
    (now : float) : unit =
  if claim.signatures = [] then Error.raise_ Error.Claim_unsigned;
  let domains = List.sort_uniq compare (List.map (fun (s : Types.Claim_signature.t) -> s.domain) claim.signatures) in
  List.iter
    (fun signing_domain ->
      let key_set =
        match List.find_opt (fun (s : domain_key_set) -> s.domain = signing_domain) domain_keys with
        | Some s -> s
        | None -> Error.raise_ (Error.Domain_keys_unavailable signing_domain)
      in
      let payload =
        claim_sign_payload claim.claim_id claim.claim_type claim.claim_value claim.user_id subject_domain signing_domain
          claim.expires_at claim.attested_at
      in
      let satisfied =
        List.exists
          (fun (sig_ : Types.Claim_signature.t) ->
            if sig_.domain <> signing_domain then false
            else
              try
                verify_one_signature sig_ payload key_set.keys now;
                true
              with Error.Sdk_error _ -> false)
          claim.signatures
      in
      if not satisfied then Error.raise_ (Error.Domain_unverified signing_domain))
    domains

(* Full claim verification: the cryptographic per-domain quorum plus the
   claim's own revocation and expiry. All must pass. *)
let verify_claim (claim : Types.Claim.t) (subject_domain : string) (domain_keys : domain_key_set list) (now : float) : unit =
  verify_claim_signatures claim subject_domain domain_keys now;
  if claim.revoked_at <> None then Error.raise_ Error.Claim_revoked;
  match claim.expires_at with
  | None -> ()
  | Some expires_at ->
    let expires = try Timeutil.parse_rfc3339 expires_at with Timeutil.Bad_timestamp msg -> Error.raise_ (Error.Bad_timestamp msg) in
    if now > expires then Error.raise_ Error.Claim_expired
