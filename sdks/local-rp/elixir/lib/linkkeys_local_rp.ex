defmodule LinkkeysLocalRp do
  @moduledoc """
  Elixir SDK for LinkKeys' DNS-less local RP identity mode
  (`dns-less-local-rp-design.md` at the repo root — read it first; this
  package implements its "SDK API Shape" section, Elixir-idiomatically
  adapted).

  This mode lets a locally-installed app (a LAN jukebox, a desktop tool, a
  self-hosted service with no public DNS) use LinkKeys for login without
  running its own DNS-pinned relying party. The app's identity is the
  fingerprint of a locally-generated signing key (SSH-host-key style), not
  a domain.

  ## Return-value convention

  Fallible operations return `{:ok, result}` / `{:error, reason}` (never
  raise for ordinary protocol failures — a tampered signature or an
  expired timestamp is an expected outcome the app must branch on, not an
  exceptional program state). Pure input-shape violations (e.g. a caller
  passing a 31-byte "32-byte" key, or an empty `app_name`) raise, because
  those indicate an integration bug rather than a protocol-verification
  failure. This mirrors ordinary Elixir/OTP convention (`File.read/1` vs
  `File.read!/1`-style reasoning) rather than a single uniform scheme.

  ## Quickstart

      alias LinkkeysLocalRp, as: LocalRp

      # Once, at install/setup time -- persist the returned bytes with
      # ordinary application-secret care.
      identity = LocalRp.generate_local_rp_identity(app_name: "My LAN Jukebox", now: DateTime.utc_now())
      stored_bytes = LocalRp.local_rp_identity_to_bytes(identity)

      # Later, per login attempt:
      identity = LocalRp.local_rp_identity_from_bytes(stored_bytes)

      {redirect, pending} =
        LocalRp.begin_local_login(
          key_material: identity,
          callback_url: "http://jukebox.lan:8080/auth/callback",
          user_domain: "example.com",
          now: DateTime.utc_now()
        )

      # App: persist `pending` (e.g. PendingLogin.to_map(pending) into a
      # session), then redirect the browser to redirect.redirect_url.

      # On callback (app's HTTP handler received `arrived_url` with an
      # `encrypted_token=` query parameter):
      {:ok, verified} =
        LocalRp.complete_local_login(
          key_material: identity,
          pending: pending,
          encrypted_token: encrypted_token,
          arrived_url: arrived_url,
          now: DateTime.utc_now()
        )

      # verified.user_id, verified.user_domain, verified.claims, ... --
      # session creation, local user records, and authorization are all
      # the app's own responsibility.

  ## Storage and single-use responsibilities this SDK assigns to the app

  - **Key material**: persist the bytes from `local_rp_identity_to_bytes/1`
    with ordinary application-secret care (same tier as a database
    credential or API key).
  - **`PendingLogin`**: persist it (e.g. via
    `LinkkeysLocalRp.Begin.PendingLogin.to_map/1` /
    `from_map/1`) between `begin_local_login/1` and
    `complete_local_login/1`, and discard it after one completion
    attempt. This package owns no storage and cannot enforce single-use
    itself.
  - **Sessions, local user records, authorization**: entirely the app's.
    This package returns verified protocol facts; it never creates a
    session or writes to an app database.

  ## Security notes

  - Revoking this local RP identity at the IDP kills future logins AND any
    outstanding claim tickets immediately — but it does **not** reach into
    sessions the app already minted from a prior successful login.
  - Key rotation is not supported as a continuity operation: generating a
    new identity means a new fingerprint and re-approval at every LinkKeys
    domain.
  - Domain keys fetched over the network are only ever trusted after DNS
    `fp=` pinning (`LinkkeysLocalRp.Rpc`) — an unpinned/unauthenticated key
    can never reach the verification chain.
  - The default DNS resolver is the OS-configured system resolver via
    OTP's `:inet_res`; LAN resolver spoofing is an accepted, documented
    tradeoff for this mode. Inject a hardened resolver function if your
    deployment needs more.
  """

  alias LinkkeysLocalRp.Begin
  alias LinkkeysLocalRp.Complete
  alias LinkkeysLocalRp.Identity

  # -- Identity ------------------------------------------------------

  defdelegate generate_local_rp_identity(config), to: Identity
  defdelegate local_rp_identity_to_bytes(identity), to: Identity
  defdelegate local_rp_identity_from_bytes(bytes), to: Identity
  defdelegate signing_key_to_bytes(key), to: Identity
  defdelegate signing_key_from_bytes(bytes), to: Identity
  defdelegate encryption_key_to_bytes(key), to: Identity
  defdelegate encryption_key_from_bytes(bytes), to: Identity
  defdelegate fingerprint_to_string(fingerprint), to: Identity
  defdelegate fingerprint_from_string(text), to: Identity
  defdelegate check_expirations(identity, now), to: Identity

  # -- Login flow ------------------------------------------------------

  defdelegate begin_local_login(config), to: Begin
  defdelegate complete_local_login(config), to: Complete
end
