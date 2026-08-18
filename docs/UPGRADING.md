# Upgrade Notes

This file collects the steps an operator must do when they upgrade across the
named versions. Put the applicable entries in the release notes of each
release.

## Upgrading to the release after 0.14.3

### Re-vouch encryption keys made before 0.14.1 (required)

Version 0.14.1 changed the vouch domain-separation tag from
`linkkeys-key-vouch-v1` to `linkkeys-key-vouch-v1alpha`. A vouch is a
signature that a signing key makes over the encryption key, one time, when the
encryption key is created. Vouches made before 0.14.1 do not verify on peers
that run 0.14.1 or later. Peers then drop the encryption key, and cross-domain
logins to the affected domain fail at the token-encryption step.

Domains initialized before 2026-07-16 are affected. Do one of these:

- Restart the server. On start, `serve` now examines the domain's own vouches
  and re-signs each vouch that does not verify under the current tag.
- Or run `linkkeys domain re-vouch` on the server. The command shows, for each
  encryption key, whether the vouch was already valid or was re-signed.

Both procedures are idempotent and safe to repeat.

Related repair: `linkkeys domain init` no longer counts revoked encryption
keys. A domain whose only encryption key was revoked can run `domain init`
again to generate a new one.

### The authorize API now speaks CBOR, and API errors are structured (breaking)

`POST /rp/authorize/validate` and `POST /rp/authorize/finalize` no longer
accept or return JSON. The request and response bodies are CSIL CBOR
(`AuthorizeValidateRequest`, `AuthorizeFinalizeRequest`, and their responses in
`csil/linkkeys.csil`). Update client apps that call these routes.

Every API failure now returns a CBOR `ApiError` body: a machine-readable
`code` and a human-readable `message` that names the failed step. The codes a
client must handle on finalize:

- `request_already_used` — the login request is spent; start a new login.
- `rp_key_fetch_failed` — the relying party's keys could not be fetched or
  pinned; its operator checks DNS records and endpoint.
- `rp_encrypt_key_untrusted` — the relying party has no vouched encryption
  key; its operator runs `linkkeys domain re-vouch`.
- `signing_failed`, `storage_failed` — fault on the identity provider; its
  operator checks the server log.

A failed finalize no longer consumes the login request: the relying-party key
fetch happens before the single-use nonce burn, so the same signed request can
be retried after the cause is repaired.
