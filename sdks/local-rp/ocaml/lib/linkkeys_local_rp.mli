(* Public interface for [linkkeys_local_rp] (SEC fix, "Low" finding --
   restrict the public surface; see [linkkeys_local_rp.ml]'s doc comment
   for the quickstart and [Internal]'s doc comment above its definition
   there for the rationale). This file's only job is access control: an
   .mli on the library's top wrapping module governs exactly what an
   external consumer (any other dune package/executable depending on this
   library -- including this package's own [test/] executable) can see as
   [Linkkeys_local_rp.*]; it has no effect on how the modules inside
   [lib/] see each other (sibling [.ml] files keep referencing e.g.
   [Local_rp.xxx] directly, unaffected by what's re-exported here).

   Exposed: the intended app-facing API -- [generate_local_rp_identity],
   the byte storage helpers, [begin_local_login], [complete_local_login],
   [check_expirations], the act-as grantee calls ([Act_as]) -- plus [Browser] (the [_linkkeys_apis] [https=]
   discovery + route-URL helpers [begin_local_login] composes, reusable by
   regular-RP glue), the network seams ([Transport.t],
   [Dns.resolver]) an app may need to inject a fake (tests) or a hardened
   resolver (production), [Rpc]/[Tls_client] (documented, reusable
   building blocks for a custom RPC client alongside this SDK -- see
   example.md), and the plain data/utility modules ([Types], [Crypto],
   [Cbor], [Hex], [Timeutil], [Url_params], [Error]) those signatures are
   built from.

   Deliberately NOT re-exported at this top level: [Local_rp], [Claims],
   [Revocation] -- see [Internal]'s doc comment in the .ml for why. *)

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
module Browser = Browser
module Begin_login = Begin_login
module Complete_login = Complete_login
module Act_as = Act_as

val generate_local_rp_identity : Identity.config -> (Identity.key_material, Error.t) result
val local_rp_identity_to_bytes : Identity.key_material -> string
val local_rp_identity_from_bytes : string -> (Identity.key_material, Error.t) result
val signing_key_to_bytes : string -> string
val signing_key_from_bytes : string -> (string, Error.t) result
val encryption_key_to_bytes : string -> string
val encryption_key_from_bytes : string -> (string, Error.t) result
val fingerprint_to_string : string -> string
val fingerprint_from_string : string -> (string, Error.t) result
val begin_local_login : Begin_login.config -> (Begin_login.local_login_redirect * Begin_login.pending_login, Error.t) result
val complete_local_login : Complete_login.config -> (Complete_login.verified_local_login, Error.t) result

(* Act-as grants, grantee side only ([Act_as]). A local RP can be a grantee
   after its home domain approved it. It cannot be an audience. *)
val begin_act_as : Act_as.begin_config -> (Act_as.act_as_redirect * Act_as.pending_act_as, Error.t) result
val complete_act_as : Act_as.pending_act_as -> string -> (string, Error.t) result
val refresh_act_as_grant : Act_as.refresh_config -> (Types.Signed_act_as_grant.t * bool, Error.t) result

val present_act_as :
  grant:Types.Signed_act_as_grant.t ->
  audience:Types.Application_ref.t ->
  request_digest:string ->
  now:float ->
  nonce:string ->
  Identity.key_material ->
  Types.Act_as_credential.t

(* Re-exported (as manifest type equations, not copies -- these ARE
   [Local_rp.expiration_level]/[Local_rp.expiration_status]) purely so
   [check_expirations]'s return type is nameable here without re-exposing
   the rest of [Local_rp]. *)
type expiration_level = Local_rp.expiration_level =
  | Level_ok
  | Level_notice
  | Level_warning
  | Level_critical
  | Level_expired

type expiration_status = Local_rp.expiration_status = { level : expiration_level; expires_at : float; now : float }

val check_expirations : Identity.key_material -> float -> (expiration_status, Error.t) result

(* Whitebox-only escape hatch -- see this module's doc comment above and
   the longer rationale on [Internal] in [linkkeys_local_rp.ml]. *)
module Internal : sig
  module Local_rp = Local_rp
  module Claims = Claims
  module Revocation = Revocation
end
