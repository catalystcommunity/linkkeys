(* [generate_local_rp_identity] and the raw-byte storage helpers (design
   doc: "SDK API Shape", "Byte Storage Helpers").

   A local RP identity is exactly one Ed25519 signing keypair, one X25519
   encryption keypair, and a self-signed [SignedLocalRpDescriptor] binding
   them together. There is no continuity story across rotation --
   generating a new identity means a new fingerprint, full stop.

   Security note (design doc, "Byte Storage Helpers"): the private key
   fields in [key_material] do not directly identify a user, but they
   control this app's entire local RP identity -- anyone holding them can
   sign login requests and redeem claim tickets as this app. Store them
   with ordinary application-secret care (the same care as a database
   credential or API key), not merely as configuration. *)

(* Default local RP key lifetime: 10 years (design doc, "One Signing Key
   and One Encryption Key"). *)
let default_lifetime = 3650.0 *. 86400.0

type config = {
  app_name : string;
  now : float;
  local_domain_hint : string option;
  supported_suites : string list option;
  lifetime : float option;
}

let make_config ~app_name ~now ?local_domain_hint ?supported_suites ?lifetime () : config =
  { app_name; now; local_domain_hint; supported_suites; lifetime }

(* A local RP's full key material: signing keypair, encryption keypair,
   the self-signed descriptor binding them (which also carries app_name,
   local_domain_hint, supported_suites, and the created/expires
   timestamps), and the identity fingerprint.

   Private key fields are raw 32-byte values -- see the module docs'
   security note before persisting them. *)
type key_material = {
  signing_private_key : string;
  signing_public_key : string;
  encryption_private_key : string;
  encryption_public_key : string;
  descriptor : Types.Signed_local_rp_descriptor.t;
  fingerprint : string;
}

(* [generate_local_rp_identity(config) -> LocalRpKeyMaterial] (design doc,
   "SDK API Shape"). Generates a fresh Ed25519 signing keypair and a
   SEPARATE X25519 encryption keypair (never algebraically derived --
   design doc's "Encryption Key Is Separate, Not Derived"), builds and
   self-signs the [SignedLocalRpDescriptor] binding them, and returns
   everything the app needs to persist. *)
let generate_local_rp_identity_exn (config : config) : key_material =
  if String.trim config.app_name = "" then Error.raise_ (Error.Invalid_config "app_name must not be empty");
  let signing_public_key, signing_private_key = Crypto.generate_ed25519_keypair () in
  let encryption_public_key, encryption_private_key = Crypto.generate_x25519_keypair () in
  let suites = match config.supported_suites with Some s -> s | None -> Crypto.AeadSuite.all_supported_str in
  if suites = [] then Error.raise_ (Error.Invalid_config "supported_suites must not be empty");
  let lifetime = match config.lifetime with Some l -> l | None -> default_lifetime in
  let created_at = Timeutil.to_rfc3339 config.now in
  let expires_at = Timeutil.to_rfc3339 (config.now +. lifetime) in
  let descriptor =
    Local_rp.build_local_rp_descriptor ~app_name:config.app_name ~local_domain_hint:config.local_domain_hint
      ~signing_public_key ~encryption_public_key ~supported_suites:suites ~created_at ~expires_at
  in
  let fingerprint = descriptor.fingerprint in
  let signed_descriptor = Local_rp.sign_local_rp_descriptor descriptor signing_private_key in
  { signing_private_key; signing_public_key; encryption_private_key; encryption_public_key; descriptor = signed_descriptor; fingerprint }

let generate_local_rp_identity (config : config) : (key_material, Error.t) result = Error.capture (fun () -> generate_local_rp_identity_exn config)

(* ------------------------------------------------------------------ *)
(* Byte storage helpers (design doc: "Byte Storage Helpers")           *)
(* ------------------------------------------------------------------ *)

let signing_key_to_bytes (key : string) : string = key

let signing_key_from_bytes (data : string) : (string, Error.t) result =
  if String.length data <> 32 then Error (Error.Invalid_key_length (Printf.sprintf "signing key must be 32 bytes, got %d" (String.length data)))
  else Ok data

let encryption_key_to_bytes (key : string) : string = key

let encryption_key_from_bytes (data : string) : (string, Error.t) result =
  if String.length data <> 32 then
    Error (Error.Invalid_key_length (Printf.sprintf "encryption key must be 32 bytes, got %d" (String.length data)))
  else Ok data

(* The canonical fingerprint string form -- a pass-through, since in this
   SDK the fingerprint IS a hex string already. *)
let fingerprint_to_string (fp : string) : string = fp

(* Parse/validate a fingerprint string: exactly 64 lowercase-normalized
   hex characters (a SHA-256 digest). Rejects anything else so a
   malformed value can never silently pass as a pin or an identity. *)
let fingerprint_from_string (str : string) : (string, Error.t) result =
  if Dns.valid_fingerprint str then Ok (String.lowercase_ascii str)
  else Error (Error.Invalid_config (Printf.sprintf "not a valid fingerprint (want 64 hex chars): %S" str))

(* Magic prefix for the identity-bundle byte format below. This is an
   SDK-local storage convenience, NOT a protocol wire format -- nothing in
   the design doc's Wire Precision governs it, and no conformance vector
   covers it. Versioned so a future incompatible layout change fails
   loudly instead of silently misparsing. *)
let identity_bundle_magic = "LKI1"

(* [local_rp_identity_to_bytes(identity) -> bytes] (design doc, "SDK API
   Shape" + "Byte Storage Helpers": "identity bundle"). Packs both private
   keys and the signed descriptor (which already carries both public keys,
   app_name, local_domain_hint, supported_suites, and the created/expires
   timestamps) into one opaque blob an app can store as a single
   secret/config value. Layout: MAGIC(4) || signing_private_key(32) ||
   encryption_private_key(32) || descriptor_len(4, BE) || descriptor_cbor. *)
let local_rp_identity_to_bytes (identity : key_material) : string =
  let descriptor_bytes = Types.Signed_local_rp_descriptor.to_cbor identity.descriptor in
  let len = String.length descriptor_bytes in
  let len_prefix = Bytes.create 4 in
  Bytes.set_uint8 len_prefix 0 ((len lsr 24) land 0xff);
  Bytes.set_uint8 len_prefix 1 ((len lsr 16) land 0xff);
  Bytes.set_uint8 len_prefix 2 ((len lsr 8) land 0xff);
  Bytes.set_uint8 len_prefix 3 (len land 0xff);
  identity_bundle_magic ^ identity.signing_private_key ^ identity.encryption_private_key ^ Bytes.to_string len_prefix
  ^ descriptor_bytes

(* The inverse of [local_rp_identity_to_bytes]. Public keys and the
   fingerprint are read back out of the embedded descriptor rather than
   re-derived from the private keys, exactly mirroring what was stored;
   this function does no signature/expiry verification (that is
   [check_expirations]'s and the protocol verification chain's job). *)
let local_rp_identity_from_bytes_exn (data : string) : key_material =
  let header_len = 4 + 32 + 32 + 4 in
  if String.length data < header_len then Error.raise_ (Error.Decode_failed "identity bundle too short");
  if String.sub data 0 4 <> identity_bundle_magic then
    Error.raise_ (Error.Decode_failed "identity bundle has an unrecognized magic prefix");
  let signing_private_key = String.sub data 4 32 in
  let encryption_private_key = String.sub data 36 32 in
  let len_bytes = String.sub data 68 4 in
  let descriptor_len =
    (Char.code len_bytes.[0] lsl 24) lor (Char.code len_bytes.[1] lsl 16) lor (Char.code len_bytes.[2] lsl 8) lor Char.code len_bytes.[3]
  in
  if String.length data - header_len <> descriptor_len then
    Error.raise_ (Error.Decode_failed "identity bundle descriptor length does not match available bytes");
  let descriptor_bytes = String.sub data header_len descriptor_len in
  let signed_descriptor =
    try Types.Signed_local_rp_descriptor.of_cbor descriptor_bytes
    with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed (Printf.sprintf "identity bundle descriptor: %s" msg))
  in
  let descriptor =
    try Types.Local_rp_descriptor.of_cbor signed_descriptor.descriptor
    with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed (Printf.sprintf "identity bundle descriptor payload: %s" msg))
  in
  if String.length descriptor.signing_public_key <> 32 then
    Error.raise_ (Error.Decode_failed "descriptor signing_public_key was not 32 bytes");
  if String.length descriptor.encryption_public_key <> 32 then
    Error.raise_ (Error.Decode_failed "descriptor encryption_public_key was not 32 bytes");
  {
    signing_private_key;
    signing_public_key = descriptor.signing_public_key;
    encryption_private_key;
    encryption_public_key = descriptor.encryption_public_key;
    descriptor = signed_descriptor;
    fingerprint = descriptor.fingerprint;
  }

let local_rp_identity_from_bytes (data : string) : (key_material, Error.t) result = Error.capture (fun () -> local_rp_identity_from_bytes_exn data)
