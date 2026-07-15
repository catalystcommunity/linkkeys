# frozen_string_literal: true

require_relative 'linkkeys_local_rp/version'
require_relative 'linkkeys_local_rp/cbor'
require_relative 'linkkeys_local_rp/types'
require_relative 'linkkeys_local_rp/timeutil'
require_relative 'linkkeys_local_rp/crypto'
require_relative 'linkkeys_local_rp/url_params'
require_relative 'linkkeys_local_rp/local_rp'
require_relative 'linkkeys_local_rp/claims'
require_relative 'linkkeys_local_rp/revocation'
require_relative 'linkkeys_local_rp/dns'
require_relative 'linkkeys_local_rp/tls'
require_relative 'linkkeys_local_rp/transport'
require_relative 'linkkeys_local_rp/rpc'
require_relative 'linkkeys_local_rp/identity'
require_relative 'linkkeys_local_rp/begin'
require_relative 'linkkeys_local_rp/complete'

# linkkeys_local_rp -- Ruby SDK for LinkKeys' DNS-less local RP identity
# mode (`dns-less-local-rp-design.md` at the repo root -- read it first;
# this gem implements its "SDK API Shape" section, Ruby-idiomatically
# adapted: keyword-argument big-config structs, typed error class
# hierarchies per module, and duck-typed Transport/DnsResolver seams).
#
# This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
# self-hosted service with no public DNS) use LinkKeys for login without
# running its own DNS-pinned relying party. The app's identity is the
# fingerprint of a locally-generated signing key (SSH-host-key style), not
# a domain.
#
# Quickstart
# ----------
#
# ```ruby
# require "linkkeys_local_rp"
#
# # Once, at install/setup time -- persist the returned bytes with ordinary
# # application-secret care.
# identity = LinkkeysLocalRp.generate_local_rp_identity(
#   LinkkeysLocalRp::Identity::GenerateLocalRpIdentityConfig.new(
#     app_name: "My LAN Jukebox", now: Time.now.utc
#   )
# )
# stored_bytes = LinkkeysLocalRp.local_rp_identity_to_bytes(identity)
#
# # Later, per login attempt:
# identity = LinkkeysLocalRp.local_rp_identity_from_bytes(stored_bytes)
# redirect, pending = LinkkeysLocalRp.begin_local_login(
#   LinkkeysLocalRp::Begin::BeginLocalLoginConfig.new(
#     key_material: identity,
#     callback_url: "http://jukebox.lan:8080/auth/callback",
#     user_domain: "example.com",
#     now: Time.now.utc
#   )
# )
# # App: persist `pending` (e.g. pending.to_h into a session), then redirect
# # the browser to redirect.redirect_url.
#
# # On callback (app's HTTP handler received `arrived_url` with an
# # `encrypted_token=` query parameter):
# verified = LinkkeysLocalRp.complete_local_login(
#   identity, pending, encrypted_token, arrived_url, Time.now.utc
# )
# # verified.user_id, verified.user_domain, verified.claims, ... -- session
# # creation, local user records, and authorization are all the app's own
# # responsibility.
# ```
#
# Storage and single-use responsibilities this SDK assigns to the app
# ---------------------------------------------------------------------
#
# - Key material: persist the bytes from `local_rp_identity_to_bytes` with
#   ordinary application-secret care (same tier as a database credential or
#   API key) -- see `Identity` module docs.
# - `PendingLogin`: persist it (e.g. via `.to_h`/`.from_h`) between
#   `begin_local_login` and `complete_local_login`, and discard it after
#   one completion attempt. This package owns no storage and cannot
#   enforce single-use itself.
# - Sessions, local user records, authorization: entirely the app's. This
#   package returns verified protocol facts; it never creates a session or
#   writes to an app database.
#
# Security notes
# --------------
#
# - Revoking this local RP identity at the IDP kills future logins AND any
#   outstanding claim tickets immediately -- but it does NOT reach into
#   sessions the app already minted from a prior successful login.
# - Key rotation is not supported as a continuity operation: generating a
#   new identity means a new fingerprint and re-approval at every LinkKeys
#   domain.
# - Domain keys fetched over the network are only ever trusted after DNS
#   `fp=` pinning (`Rpc` module) -- an unpinned/unauthenticated key can
#   never reach the verification chain.
# - The default DNS resolver is the OS-configured system resolver via
#   `Resolv::DNS` (stdlib); LAN resolver spoofing is an accepted,
#   documented tradeoff for this mode. Inject a hardened DNS resolver
#   object if your deployment needs more.
module LinkkeysLocalRp
  module_function

  def generate_local_rp_identity(config) = Identity.generate_local_rp_identity(config)
  def local_rp_identity_to_bytes(identity) = Identity.local_rp_identity_to_bytes(identity)
  def local_rp_identity_from_bytes(bytes) = Identity.local_rp_identity_from_bytes(bytes)
  def signing_key_to_bytes(key) = Identity.signing_key_to_bytes(key)
  def signing_key_from_bytes(bytes) = Identity.signing_key_from_bytes(bytes)
  def encryption_key_to_bytes(key) = Identity.encryption_key_to_bytes(key)
  def encryption_key_from_bytes(bytes) = Identity.encryption_key_from_bytes(bytes)
  def fingerprint_to_string(fingerprint) = Identity.fingerprint_to_string(fingerprint)
  def fingerprint_from_string(str) = Identity.fingerprint_from_string(str)

  def begin_local_login(config) = Begin.begin_local_login(config)

  def complete_local_login(key_material, pending, encrypted_token, arrived_url, now, **kwargs)
    Complete.complete_local_login(key_material, pending, encrypted_token, arrived_url, now, **kwargs)
  end

  # `check_expirations(identity, now) -> ExpirationStatus` (design doc,
  # "SDK API Shape" / "Expiration Helper"). Thin wrapper taking the
  # identity's descriptor expires_at directly. The SDK reports facts; the
  # app decides whether to warn admins, warn users, block login, renew, or
  # ignore.
  def check_expirations(identity, now)
    descriptor = Types::LocalRpDescriptor.from_cbor(identity.descriptor.descriptor)
    LocalRp.check_expirations(descriptor.expires_at, now)
  end
end
