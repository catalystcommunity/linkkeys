(* linkkeys_local_rp -- OCaml SDK for LinkKeys' DNS-less local RP identity
   mode ([dns-less-local-rp-design.md] at the repo root -- read it first;
   this library implements its "SDK API Shape" section, OCaml-idiomatic:
   big-config records with optional-labelled arguments, one closed
   [Error.t] variant, and duck-typed [Transport.t]/[Dns.resolver] seams
   (one-function records rather than module types, so a test fake is a
   one-line value)).

   This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
   self-hosted service with no public DNS) use LinkKeys for login without
   running its own DNS-pinned relying party. The app's identity is the
   fingerprint of a locally-generated signing key (SSH-host-key style), not
   a domain.

   Quickstart
   ----------

   {[
     (* Once, at install/setup time -- persist the returned bytes with
        ordinary application-secret care. *)
     let identity =
       Linkkeys_local_rp.generate_local_rp_identity
         (Linkkeys_local_rp.Identity.make_config ~app_name:"My LAN Jukebox" ~now:(Unix.gettimeofday ()) ())
       |> Result.get_ok
     in
     let stored_bytes = Linkkeys_local_rp.local_rp_identity_to_bytes identity in

     (* Later, per login attempt: *)
     let identity = Linkkeys_local_rp.local_rp_identity_from_bytes stored_bytes |> Result.get_ok in
     let redirect, pending =
       Linkkeys_local_rp.begin_local_login
         (Linkkeys_local_rp.Begin_login.make_config ~key_material:identity
            ~callback_url:"http://jukebox.lan:8080/auth/callback" ~user_domain:"example.com"
            ~now:(Unix.gettimeofday ()) ())
       |> Result.get_ok
     in
     (* App: persist [pending] (e.g. via [Begin_login.pending_login_to_fields]
        into a session), then redirect the browser to [redirect.redirect_url]. *)

     (* On callback (app's HTTP handler received [arrived_url] with an
        [encrypted_token=] query parameter): *)
     let verified =
       Linkkeys_local_rp.complete_local_login
         (Linkkeys_local_rp.Complete_login.make_config ~key_material:identity ~pending ~encrypted_token ~arrived_url
            ~now:(Unix.gettimeofday ()) ())
       |> Result.get_ok
     in
     (* verified.user_id, verified.user_domain, verified.claims, ... --
        session creation, local user records, and authorization are all the
        app's own responsibility. *)
   ]}

   Storage and single-use responsibilities this SDK assigns to the app
   ---------------------------------------------------------------------

   - Key material: persist the bytes from [local_rp_identity_to_bytes] with
     ordinary application-secret care (same tier as a database credential
     or API key) -- see [Identity]'s module docs.
   - [pending_login]: persist it between [begin_local_login] and
     [complete_local_login], and discard it after one completion attempt.
     This package owns no storage and cannot enforce single-use itself.
   - Sessions, local user records, authorization: entirely the app's. This
     package returns verified protocol facts; it never creates a session
     or writes to an app database.

   Security notes
   --------------

   - Revoking this local RP identity at the IDP kills future logins AND any
     outstanding claim tickets immediately -- but it does NOT reach into
     sessions the app already minted from a prior successful login.
   - Key rotation is not supported as a continuity operation: generating a
     new identity means a new fingerprint and re-approval at every LinkKeys
     domain.
   - Domain keys fetched over the network are only ever trusted after DNS
     [fp=] pinning ([Rpc] module) -- an unpinned/unauthenticated key can
     never reach the verification chain.
   - The default DNS resolver is a hand-rolled UDP TXT query against the
     system's configured nameserver ([Dns.default_resolver]); LAN resolver
     spoofing is an accepted, documented tradeoff for this mode. Inject a
     hardened DNS resolver value if your deployment needs more. *)

module Cbor = Cbor
module Hex = Hex
module Timeutil = Timeutil
module Crypto = Crypto
module Types = Types
module Dns = Dns
module Transport = Transport
module Tls_client = Tls_client
module Rpc = Rpc
module Url_params = Url_params
module Error = Error
module Identity = Identity
module Begin_login = Begin_login
module Complete_login = Complete_login

(* Whitebox-only surface (SEC fix, "Low" finding -- restrict the public
   surface): [Local_rp], [Claims], and [Revocation] contain the granular
   envelope / callback / claim / revocation verification SUB-STEPS
   [complete_local_login] composes into one atomic, fully-checked login
   (e.g. [Local_rp.verify_local_rp_callback_payload],
   [Local_rp.open_local_rp_callback], [Claims.verify_claim],
   [Revocation.apply_revocations]). Calling one of these directly and
   treating "no exception raised" as "the user is logged in" would
   silently skip everything else in the chain -- ticket redemption,
   identity binding, required-claims enforcement, revocation, and more.
   They are intentionally NOT part of [generate_local_rp_identity] /
   [begin_local_login] / [complete_local_login] / [check_expirations] /
   the byte helpers / the network seams -- this package's supported public
   API -- so an app can't stumble into one by accident. They remain
   reachable, on purpose, only through this explicitly-named [Internal]
   module, so this package's own whitebox test suite
   (test/run_tests.ml) can keep exercising them directly; application code
   should never need to open [Internal]. *)
module Internal = struct
  module Local_rp = Local_rp
  module Claims = Claims
  module Revocation = Revocation
end

let generate_local_rp_identity = Identity.generate_local_rp_identity
let local_rp_identity_to_bytes = Identity.local_rp_identity_to_bytes
let local_rp_identity_from_bytes = Identity.local_rp_identity_from_bytes
let signing_key_to_bytes = Identity.signing_key_to_bytes
let signing_key_from_bytes = Identity.signing_key_from_bytes
let encryption_key_to_bytes = Identity.encryption_key_to_bytes
let encryption_key_from_bytes = Identity.encryption_key_from_bytes
let fingerprint_to_string = Identity.fingerprint_to_string
let fingerprint_from_string = Identity.fingerprint_from_string
let begin_local_login = Begin_login.begin_local_login
let complete_local_login = Complete_login.complete_local_login

(* [check_expirations(identity, now) -> ExpirationStatus] (design doc,
   "SDK API Shape" / "Expiration Helper"). Thin wrapper taking the
   identity's descriptor [expires_at] directly. The SDK reports facts; the
   app decides whether to warn admins, warn users, block login, renew, or
   ignore. *)
type expiration_level = Local_rp.expiration_level =
  | Level_ok
  | Level_notice
  | Level_warning
  | Level_critical
  | Level_expired

type expiration_status = Local_rp.expiration_status = { level : expiration_level; expires_at : float; now : float }

let check_expirations (identity : Identity.key_material) (now : float) : (expiration_status, Error.t) result =
  Error.capture (fun () ->
      let descriptor =
        try Types.Local_rp_descriptor.of_cbor identity.descriptor.descriptor
        with Cbor.Decode_error msg -> Error.raise_ (Error.Decode_failed msg)
      in
      Local_rp.check_expirations descriptor.expires_at now)
