(* Crypto primitives for the local-RP SDK.

   Backed by the MirageOS ecosystem per the design doc's OCaml language-
   matrix row: [mirage-crypto-ec] (Ed25519 + X25519), [mirage-crypto]
   (AES-256-GCM + ChaCha20-Poly1305), the [hkdf] package (RFC 5869
   HKDF-SHA256), [digestif] (SHA-256 for fingerprints). All four are
   actively maintained MirageOS-project packages; no vendored-C route or
   libsodium dependency is used (libsodium's AES-256-GCM is
   AES-NI-hardware-gated and not portable -- the whole reason the design
   doc rules out a libsodium-centric route for every SDK language in this
   project).

   Every function here is pure with respect to protocol state: no network,
   no filesystem, no implicit "current time" reads (see
   [signing_key_validity], which takes [now] explicitly) -- matching
   [liblinkkeys]'s own discipline. The one necessary exception is
   randomness: key generation and nonce/state generation need it, gated
   through [ensure_rng] below. *)

exception Error of string

let cs_of_string = Cstruct.of_string
let string_of_cs = Cstruct.to_string

(* ------------------------------------------------------------------ *)
(* RNG bootstrap                                                       *)
(* ------------------------------------------------------------------ *)

(* Lazily bring the default [Mirage_crypto_rng] generator into a working
   state using the Unix entropy source (getrandom(2)/CPU RNG -- see
   [Mirage_crypto_rng_unix]'s module docs), exactly once per process,
   UNLESS a caller (e.g. a deterministic test) has already installed its
   own default generator via [Mirage_crypto_rng.set_default_generator].
   Probing with a zero-length [generate] is the standard idiom for "is a
   default generator installed" since the library does not expose that as
   a query directly. *)
let ensure_rng () : unit =
  try ignore (Mirage_crypto_rng.generate 0) with
  | Mirage_crypto_rng.Unseeded_generator | Mirage_crypto_rng.No_default_generator ->
    Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna)

let random_bytes (n : int) : string =
  ensure_rng ();
  string_of_cs (Mirage_crypto_rng.generate n)

(* ------------------------------------------------------------------ *)
(* Signing algorithm registry (mirrors liblinkkeys's [SigningAlgorithm]) *)
(* ------------------------------------------------------------------ *)

module SigningAlgorithm = struct
  let ed25519 = "ed25519"
  let parse_str s = if s = ed25519 then Some ed25519 else None
  let all_supported = [ ed25519 ]
end

(* ------------------------------------------------------------------ *)
(* AEAD suite registry (Wire Precision: "AEAD suite registry")         *)
(* ------------------------------------------------------------------ *)

module AeadSuite = struct
  type t =
    | Aes256Gcm
    | Chacha20Poly1305

  let aes_256_gcm_str = "aes-256-gcm"
  let chacha20_poly1305_str = "chacha20-poly1305"

  let to_str = function
    | Aes256Gcm -> aes_256_gcm_str
    | Chacha20Poly1305 -> chacha20_poly1305_str

  let parse_str = function
    | s when s = aes_256_gcm_str -> Some Aes256Gcm
    | s when s = chacha20_poly1305_str -> Some Chacha20Poly1305
    | _ -> None

  let all_supported = [ Aes256Gcm; Chacha20Poly1305 ]
  let all_supported_str = List.map to_str all_supported

  (* Pick the first suite in [advertised] (preference order) this
     implementation supports. Used by whichever side chooses among an
     advertised list, so a suite outside the advertised list can never be
     selected. *)
  let select_supported (advertised : string list) : t option =
    List.find_map parse_str advertised
end

(* ------------------------------------------------------------------ *)
(* Ed25519                                                              *)
(* ------------------------------------------------------------------ *)

(* Returns (public_key_bytes, private_key_bytes) -- private is the raw
   32-byte seed (RFC 8032), matching every [private_key_hex]/[seed_hex]
   pair in the conformance vectors, which are always identical for
   Ed25519. *)
let generate_ed25519_keypair () : string * string =
  ensure_rng ();
  let priv, pub = Mirage_crypto_ec.Ed25519.generate () in
  ( string_of_cs (Mirage_crypto_ec.Ed25519.pub_to_cstruct pub),
    string_of_cs (Mirage_crypto_ec.Ed25519.priv_to_cstruct priv) )

let sign_ed25519 (private_key : string) (message : string) : string =
  if String.length private_key <> 32 then raise (Error "Ed25519 private key must be 32 bytes");
  match Mirage_crypto_ec.Ed25519.priv_of_cstruct (cs_of_string private_key) with
  | Error _ -> raise (Error "invalid Ed25519 private key")
  | Ok priv -> string_of_cs (Mirage_crypto_ec.Ed25519.sign ~key:priv (cs_of_string message))

let verify_ed25519 (public_key : string) (message : string) (signature : string) : bool =
  if String.length public_key <> 32 then raise (Error "Ed25519 public key must be 32 bytes");
  match Mirage_crypto_ec.Ed25519.pub_of_cstruct (cs_of_string public_key) with
  | Error _ -> false
  | Ok pub ->
    (try
       Mirage_crypto_ec.Ed25519.verify ~key:pub (cs_of_string signature) ~msg:(cs_of_string message)
     with _ -> false)

exception Unsupported_algorithm of string

let sign_with_algorithm (algorithm : string) (message : string) (private_key : string) : string =
  if algorithm <> SigningAlgorithm.ed25519 then raise (Unsupported_algorithm algorithm);
  sign_ed25519 private_key message

(* Raises on failure (mirroring the Ruby reference's
   [verify_with_algorithm]/[resolve_and_verify] split, folded into one
   function here since OCaml callers pattern-match on exceptions rather
   than rescuing a class hierarchy). *)
exception Verification_failed of string

let resolve_and_verify (algorithm : string) (message : string) (signature : string) (public_key : string) : unit =
  if algorithm <> SigningAlgorithm.ed25519 then raise (Unsupported_algorithm algorithm);
  if not (verify_ed25519 public_key message signature) then
    raise (Verification_failed "signature verification failed")

(* ------------------------------------------------------------------ *)
(* X25519                                                               *)
(* ------------------------------------------------------------------ *)

(* Returns (public_key_bytes, private_key_bytes), both 32 bytes. A
   dedicated encryption keypair -- NEVER derived from an Ed25519 signing
   key (design doc: "Encryption Key Is Separate, Not Derived"). We
   generate our own 32 raw random bytes and feed them through
   [X25519.secret_of_cs] rather than [X25519.gen_key]: the [Dh] module
   type (which [X25519] implements) exposes no "secret -> raw bytes"
   accessor, only [secret_of_cs] (raw bytes -> secret * public) and
   [gen_key] (-> secret * public, no raw private access at all) -- so
   generating the raw bytes ourselves is the only way to get a private
   key this SDK can actually export (design doc: "Byte Storage Helpers"
   requires exactly that). [secret_of_cs] on 32 bytes only fails for
   wrong length, which can't happen here, so the internal retry loop below
   is unreachable in practice; it exists purely so this function has no
   partial-match hazard rather than asserting a "cannot happen". *)
let generate_x25519_keypair () : string * string =
  ensure_rng ();
  let rec go () =
    let raw = random_bytes 32 in
    match Mirage_crypto_ec.X25519.secret_of_cs (cs_of_string raw) with
    | Ok (_secret, pub) -> (string_of_cs pub, raw)
    | Error _ -> go ()
  in
  go ()

let x25519_public_from_private (private_key : string) : string =
  if String.length private_key <> 32 then raise (Error "X25519 private key must be 32 bytes");
  match Mirage_crypto_ec.X25519.secret_of_cs (cs_of_string private_key) with
  | Ok (_secret, pub) -> string_of_cs pub
  | Error _ -> raise (Error "invalid X25519 private key")

(* Reject an all-zero ECDH output -- the signal a low-order/non-
   contributory X25519 public key forces regardless of the other party's
   private key. [mirage-crypto-ec]'s own [key_exchange] already detects
   this (it returns [Error `Low_order] for exactly this condition -- see
   its [is_zero] check in [mirage_crypto_ec.ml]) and [x25519_diffie_hellman]
   below maps that to this same exception, so this standalone helper is
   redundant there; it is kept and exported as defense-in-depth for any
   future call site that computes a shared secret through a different
   path. *)
let reject_low_order (shared_secret : string) : unit =
  if shared_secret = String.make 32 '\000' then
    raise (Error "non-contributory (low-order) public key rejected")

let x25519_diffie_hellman (private_key : string) (peer_public_key : string) : string =
  if String.length private_key <> 32 then raise (Error "X25519 private key must be 32 bytes");
  if String.length peer_public_key <> 32 then raise (Error "X25519 public key must be 32 bytes");
  match Mirage_crypto_ec.X25519.secret_of_cs (cs_of_string private_key) with
  | Error _ -> raise (Error "invalid X25519 private key")
  | Ok (secret, _pub) -> (
    match Mirage_crypto_ec.X25519.key_exchange secret (cs_of_string peer_public_key) with
    | Ok shared -> string_of_cs shared
    | Error `Low_order -> raise (Error "non-contributory (low-order) public key rejected")
    | Error _ -> raise (Error "X25519 key exchange failed"))

(* ------------------------------------------------------------------ *)
(* Fingerprint                                                         *)
(* ------------------------------------------------------------------ *)

(* sha256(public_key_bytes) lowercase hex -- the canonical LinkKeys
   fingerprint format used everywhere (DNS fp=, TLS SPKI pinning, local RP
   identity). Uses [digestif] directly on OCaml strings (rather than
   [Mirage_crypto.Hash.SHA256] via a Cstruct round-trip) since this is the
   hottest, most-called primitive in the SDK and digestif's string-native
   API plus built-in [to_hex] avoids both a Cstruct conversion and a
   hand-rolled hex encode at every call site. *)
let fingerprint (public_key : string) : string =
  Digestif.SHA256.to_hex (Digestif.SHA256.digest_string public_key)

(* ------------------------------------------------------------------ *)
(* Signing key validity (revocation/expiry gate)                       *)
(* ------------------------------------------------------------------ *)

type key_validity =
  | Valid
  | Revoked
  | Expired
  | Bad_expiry

(* [now] is an explicit epoch-seconds float (never read from the system
   clock in this module, mirroring liblinkkeys's WASM-viable discipline). *)
let signing_key_validity (expires_at : string) (revoked_at : string option) (now : float) : key_validity =
  match revoked_at with
  | Some _ -> Revoked
  | None -> (
    match Timeutil.parse_rfc3339 expires_at with
    | exception Timeutil.Bad_timestamp _ -> Bad_expiry
    | expires -> if now > expires then Expired else Valid)

(* ------------------------------------------------------------------ *)
(* HKDF-SHA256 (RFC 5869)                                               *)
(* ------------------------------------------------------------------ *)

module Hkdf_sha256 = Hkdf.Make (Mirage_crypto.Hash.SHA256)

(* Full extract-then-expand, no salt. RFC 5869: an absent salt is treated
   as a string of HashLen zero bytes; passing an explicit zero-length
   Cstruct as the salt reaches the same HMAC computation either way (HMAC
   zero-pads any key shorter than the block size up to the block size, so
   an empty-string salt and a 32-byte all-zero salt both reduce to the
   same 64-byte all-zero HMAC key) -- this was verified directly against
   sdks/local-rp/conformance/callback_box.json's positive cases for BOTH
   suites during the crypto probe before this module was written out in
   full. *)
let hkdf_sha256_expand (shared_secret : string) (info : string) (length : int) : string =
  let prk = Hkdf_sha256.extract ~salt:(Cstruct.create 0) (cs_of_string shared_secret) in
  string_of_cs (Hkdf_sha256.expand ~prk ~info:(cs_of_string info) length)

(* ------------------------------------------------------------------ *)
(* AEAD                                                                 *)
(* ------------------------------------------------------------------ *)

let cipher_name_for = AeadSuite.to_str

let aead_encrypt (suite : AeadSuite.t) (key : string) (nonce : string) (aad : string) (plaintext : string) : string =
  let key_cs = cs_of_string key and nonce_cs = cs_of_string nonce and aad_cs = cs_of_string aad in
  let pt_cs = cs_of_string plaintext in
  try
    match suite with
    | AeadSuite.Aes256Gcm ->
      let k = Mirage_crypto.Cipher_block.AES.GCM.of_secret key_cs in
      string_of_cs (Mirage_crypto.Cipher_block.AES.GCM.authenticate_encrypt ~key:k ~nonce:nonce_cs ~adata:aad_cs pt_cs)
    | AeadSuite.Chacha20Poly1305 ->
      let k = Mirage_crypto.Chacha20.of_secret key_cs in
      string_of_cs (Mirage_crypto.Chacha20.authenticate_encrypt ~key:k ~nonce:nonce_cs ~adata:aad_cs pt_cs)
  with Invalid_argument msg -> raise (Error (Printf.sprintf "AEAD encryption failed (%s): %s" (cipher_name_for suite) msg))

let aead_decrypt (suite : AeadSuite.t) (key : string) (nonce : string) (aad : string) (ciphertext : string) : string
    =
  if String.length ciphertext < 16 then raise (Error "ciphertext too short to contain an AEAD tag");
  let key_cs = cs_of_string key and nonce_cs = cs_of_string nonce and aad_cs = cs_of_string aad in
  let ct_cs = cs_of_string ciphertext in
  let result =
    try
      match suite with
      | AeadSuite.Aes256Gcm ->
        let k = Mirage_crypto.Cipher_block.AES.GCM.of_secret key_cs in
        Mirage_crypto.Cipher_block.AES.GCM.authenticate_decrypt ~key:k ~nonce:nonce_cs ~adata:aad_cs ct_cs
      | AeadSuite.Chacha20Poly1305 ->
        let k = Mirage_crypto.Chacha20.of_secret key_cs in
        Mirage_crypto.Chacha20.authenticate_decrypt ~key:k ~nonce:nonce_cs ~adata:aad_cs ct_cs
    with Invalid_argument msg ->
      raise (Error (Printf.sprintf "AEAD decryption failed (%s): %s" (cipher_name_for suite) msg))
  in
  match result with
  | Some pt -> string_of_cs pt
  | None -> raise (Error "AEAD authentication failed")
