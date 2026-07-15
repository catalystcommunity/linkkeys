# Regular (DNS-pinned) LinkKeys login in OCaml

This directory (`linkkeys_local_rp`) implements **local-RP** identity: a
locally-installed app authenticates using the fingerprint of its own signing
key instead of a domain. Read `dns-less-local-rp-design.md` at the repo root
and this package's own [`README.md`](./README.md) if that's what you want — a
LAN box, a desktop tool, a service with no public DNS.

This document is for the *other*, far more common case: your app has a public
domain and you want to accept logins from users who prove their identity
against **their own** DNS-pinned LinkKeys domain. That's "regular" LinkKeys —
the protocol's primary mode. There is no separate OCaml client SDK for it;
instead you run a small LinkKeys server next to your app in **RP mode**, and
your app talks to that server over the CSIL-RPC TCP transport. This SDK has no
packaged client for that transport (no csilgen OCaml target exists yet — see
"Why there's no packaged client" below), so this walkthrough hand-writes the
~540 lines of glue, reusing this SDK's own already-exported modules
(`Cbor`, `Rpc`, `Tls_client`, `Transport`) wherever they fit and hand-rolling
only what's specific to the `Rp` service that this SDK's `Types` module
doesn't cover.

Everything below was verified against this repo's own code as of this
writing: `docs/DEPLOYING-RP.md`, `demoappsite/src/main.rs` (the reference
integration this walkthrough parallels), `csil/linkkeys.csil` (the `Rp`
service and its request/response types, "Relying Party (Rp) helper Types"),
`crates/linkkeys/src/tcp/mod.rs` (envelope auth), and this SDK's own
`lib/cbor.ml`, `lib/rpc.ml`, `lib/tls_client.ml`, `lib/transport.ml`,
`lib/types.ml`. The OCaml code below was compiled and its non-network parts
(CBOR round trips, the CSIL-RPC envelope, frame codec, HMAC auth-state) were
run — see "What was compiled and run" at the end.

## Architecture

```
┌──────────────────────────────────────────────────┐
│            Your Application Stack                 │
│                                                     │
│  ┌──────────────┐    ┌────────────────────────┐   │
│  │  Your OCaml  │    │   LinkKeys RP Server    │   │
│  │     App      │───►│  (same linkkeys image)  │   │
│  │ (this doc)   │    │                         │   │
│  │              │    │  rp.enabled             │   │
│  │  Sessions    │    │  Holds domain keys      │   │
│  │  Redirects   │    │  Signs auth requests    │   │
│  │              │    │  Decrypts tokens        │   │
│  └──────────────┘    └────────────────────────┘   │
│                                                     │
│  App calls its RP server over TCP CSIL-RPC,        │
│  authenticated with an API key. The app never      │
│  touches a private key.                            │
└──────────────────────────────────────────────────┘
```

Your app is **not** the relying party in the protocol sense — the RP server
is. It holds the domain key pair, signs the outgoing auth request, and
decrypts the token the IDP sends back. Your app is a thin client of that
server: it never sees a private key, only an API key that authorizes it to
call the `Rp` service's helper operations.

## Prerequisites

### 1. Deploy your own RP server

Follow `docs/DEPLOYING-RP.md` end to end: same LinkKeys Docker image/Helm
chart as a full IDP, but with `rp.enabled: true` (no login UI, no human user
accounts, service accounts only). Come back here once it's running.

### 2. Initialize domain keys

```sh
linkkeys domain init
```

### 3. Create a service account for your app, with the `api_access` relation

Every `Rp` operation (`sign-request`, `decrypt-token`, `verify-assertion`,
`userinfo-fetch`, `issue-attestation`) is authenticated by API key **and**
requires the caller to hold the `api_access` relation on the domain — a valid
key alone is not enough (SEC-06, `crates/linkkeys/src/services/
authorization.rs`, `required_relation_for_op`: "must require a dedicated
api_access relation, not merely a valid API key — otherwise any active user's
key can drive those oracles"). `user create` grants it at creation time in
one step:

```sh
linkkeys user create my-webapp "My Web Application" --api-key --relation api_access

# User created: id=<uuid>
# API key: <key>
# (save this -- it will not be shown again)
```

If you already created the service account without `--relation api_access`,
grant it after the fact (idempotent, safe to re-run) directly against the
local database from inside the RP pod:

```sh
linkkeys relation grant-local my-webapp api_access
```

### 4. Get the RP server's TLS fingerprints (for pinning)

Your OCaml app connects to its own RP server as a TLS client and pins its
certificate the same way any LinkKeys peer would — this is not a CA-verified
connection. List the RP server's active signing keys from inside the RP pod:

```sh
linkkeys domain list-keys
# ID                                     USAGE    STATUS     FINGERPRINT
# <uuid>                                 sign     active     <fingerprint>
```

Collect the `sign`/`active` fingerprint(s) into a comma-separated list — this
is `RP_FINGERPRINTS` below.

### 5. Publish DNS for the RP server's own domain

The RP server signs the outgoing auth request as *its own* domain. The
issuing IDP needs to resolve that domain's public key to encrypt the token
back to your RP server. Publish what `linkkeys domain dns-check` prints:

```
_linkkeys.<rp-domain> TXT "v=lk1 api=https://<rp-domain> fp=<fingerprint1> fp=<fingerprint2> ..."
_linkkeys_apis.<rp-domain> TXT "v=lk1 tcp=<rp-domain> https=<rp-domain>"
```

This is a **different** domain from the one your end user types into your
login form — that one is the user's own LinkKeys IDP, resolved by the RP
server, not something your app looks up itself.

### Environment variables this app needs

| Variable | Where it comes from |
|---|---|
| `RP_TCP_ADDR` | `host:port` of your RP server's TCP listener (step 1); the RP server is a co-located sidecar, so this is a static address your app is configured with, not something rediscovered over DNS on every login |
| `RP_FINGERPRINTS` | Comma-separated fingerprints from step 4 |
| `RP_API_KEY` | The API key printed in step 3 -- store it the same tier as a database credential, never log it |
| `AUTH_STATE_HMAC_KEY` | An app-owned secret (32+ random bytes, generated once, e.g. `Linkkeys_local_rp.Crypto.random_bytes 32`) used only to sign the `auth_state` this walkthrough round-trips through the browser between `/login` and `/callback` -- **not** part of the LinkKeys protocol, purely this document's own CSRF/correlation mechanism (see "`auth_state.ml` — the signed auth-state pattern" below) |

## The flow, over TCP CSIL-RPC ONLY

The old `POST /v1alpha/*.json` HTTP routes were removed when server-to-server
traffic moved to TCP CSIL-RPC, and the generic HTTP RPC carrier
(`POST /csil/v1/rpc`) rejects `verify-assertion`/`userinfo-fetch` outright —
both need the outbound server-to-server context (an onward TLS-pinned call to
the *issuing* IDP) that only the TCP carrier has. **TCP CSIL-RPC is the only
transport that can complete this flow.** `docs/DEPLOYING-RP.md`'s "Web App
Integration" section documents the same four operations this walkthrough
uses (the CSIL `Rp` service defines a fifth, `issue-attestation`, for signing
a claim on the RP's behalf — a separate feature from the login flow, out of
scope here):

1. **`Rp/sign-request`** — `{callback_url, nonce, ?requested_claims,
   ?flow_context}` → `{signed_request}`.
2. Redirect the browser to
   `https://<user_domain>/auth/authorize?signed_request=<signed_request>`
   (optionally `&user_hint=<hint>`). `user_domain` is whatever LinkKeys
   domain the user chose — not your RP server's own domain.
3. The user authenticates and consents at their IDP, which redirects back to
   your `callback_url` with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** — `{encrypted_token}` → `{signed_assertion}`.
5. **`Rp/verify-assertion`** — `{signed_assertion, expected_domain}` →
   `{assertion, verified}`, plus your own explicit nonce and domain equality
   checks against the returned `assertion` (see "App responsibilities").
   Nonce single-use is your app's job — this call does not enforce it.
6. **`Rp/userinfo-fetch`** (optional) — `{token, api_base, domain}` →
   `UserInfo{user_id, domain, display_name, claims}`.

Two wire-level traps worth calling out explicitly, because getting either one
wrong fails silently as an opaque auth error, not a type error:

- **The CSIL-RPC envelope's `auth` field carries the *raw* API key — no
  `"Bearer "` prefix.** That convention belongs only to the HTTP surfaces.
  Prefixing it here is a silent auth mismatch against the stored key
  (`crates/linkkeys/src/tcp/mod.rs`'s `authenticate_tcp_request` reads
  `envelope.auth` verbatim).
- **This is TCP-only.** There is no HTTP fallback for `Rp/verify-assertion`
  or `Rp/userinfo-fetch` at all — don't reach for `Linkkeys_local_rp.Rpc`
  expecting it to grow an HTTP mode; there isn't one to grow into.

## Why there's no packaged client — and what this walkthrough reuses

This SDK (`sdks/local-rp/ocaml`) implements **local-RP** identity, a
different mode with a different wire shape (`Local_rp_login_request`, sealed
boxes, no domain key). Its own README documents why there's no generated
codec at all in this language yet: no csilgen OCaml target exists (a request
is filed at
`~/repos/catalystcommunity/csilgen/docs/csilgen-requests/ocaml-target-does-not-exist.md`),
so `Cbor`, `Types`, and the envelope/framing half of `Rpc` are hand-written
here rather than generated. The same gap applies to the `Rp` service used in
this document — there is no generated OCaml codec for `RpSignRequest`/
`RpVerifyResponse`/etc. either, packaged or not.

What this walkthrough reuses **unmodified** from the SDK (all public — no
`.mli` files restrict any module in this library, so every one of these is a
supported dependency surface for an external consumer, not an internal
implementation detail):

- **`Cbor`** — the canonical/deterministic CBOR encoder and decoder in full:
  `encode`, `decode`, and the `as_*`/`field_*` accessors. Its `Map` encoding
  sorts entries by the bytewise order of their *encoded* key bytes
  regardless of the order given to it (RFC 8949 §4.2.1), so hand-written
  struct encoders below don't need to match the server's exact field order —
  only the field names and CBOR types need to be right.
- **`Transport.default_transport`** — the TCP dial seam (permissive by
  default; this app dials its own sidecar RP server, not a LAN box of
  unknown trust, but the seam is the same one).
- **`Tls_client.connect`/`extract_hostname`/`write`/`read_exact`/`close`** —
  the SPKI-Ed25519-pin TLS client, unchanged. See "TLS caveat carried
  forward" below.
- **`Rpc.send_frame`/`Rpc.read_frame`/`Rpc.decode_response`** — the 4-byte
  length-prefix framing and response-envelope decoder. Reused as-is:
  response envelopes (`status`/`error`/`payload`) have no `auth` field, so
  nothing about `Rp`'s auth requirement affects the decode side.
- **`Types.Claim_signature`** — matches CSIL `ClaimSignature`
  (`domain`/`signed_by_key_id`/`signature`) exactly; reused for `UserInfo`'s
  claim signatures.

What this walkthrough does **not** reuse, and hand-writes instead:

- **`Rpc.encode_request`** builds a *request* envelope with no `auth` field
  — correct for this SDK's own two operations (`DomainKeys/get-domain-keys`,
  `LocalRp/redeem-claim-ticket`), which are unauthenticated at the transport
  layer by design. Every `Rp` operation needs `auth`, so this walkthrough
  defines its own `encode_request_with_auth` (`rp_client.ml` below) rather
  than changing the SDK's function.
- **`Rpc.call`** (the full dial+TLS+send+recv convenience wrapper) hard-codes
  `Rpc.encode_request` internally, so it can't carry `auth` either. This
  walkthrough's `Rp_client.call` is an equivalent ~25-line routine built from
  the same reused primitives above (`Transport`, `Tls_client`, `Rpc.send_frame`/
  `read_frame`/`decode_response`) plus the new auth-carrying encoder.
- **The `Rp`-specific payload types** (`RpSignRequest`, `RpVerifyResponse`,
  `IdentityAssertion`, `UserInfo`, ...). This SDK's `Types` module documents
  itself as covering "exactly the 19 CSIL types this SDK touches" for the
  local-RP flow — none of the `Rp` service's types are among them. Hand-
  written below in `rp_types.ml`, in the same style (and reusing
  `Types.Claim_signature` where it already matches).
- **`Types.Claim`** is not reused either, though it now could be — see the
  note in "Code walkthrough" below. (A `claim_value` bytes-vs-text wire bug
  originally forced a fresh copy; the SDK has since been fixed, and the
  local copy is kept only so `rp_types.ml` stays a self-contained block of
  all the `Rp`-side types this document defines.)

## Setting up the scratch project (how this was compiled)

There is no published opam package for this SDK yet (it's a plain source
tree checked into this repo, not on opam), so a real external app depends on
it by vendoring `sdks/local-rp/ocaml/lib` into its own tree (git submodule,
subtree, or a straight copy) as a dune library, then depending on it by the
library name the vendored `lib/dune` declares (`linkkeys_local_rp`). To
compile this document's code against this repo's actual, current SDK source
(rather than a hand-copied approximation of it) without checking anything
new into this repo, the verification for this document used a directory
symlink standing in for that vendoring step:

```sh
mkdir -p /scratch/ocaml_regular_rp_example/bin
ln -s /path/to/linkkeys/sdks/local-rp/ocaml/lib \
      /scratch/ocaml_regular_rp_example/linkkeys_local_rp_lib
```

```
;; dune-project
(lang dune 3.0)
```

```
;; bin/dune
(executable
 (name main)
 (libraries linkkeys_local_rp digestif))
```

`dune` follows the symlinked `linkkeys_local_rp_lib/` directory as an
ordinary subdirectory of the workspace and picks up its own `lib/dune`
(`(library (name linkkeys_local_rp) ...)`), so `(libraries linkkeys_local_rp)`
resolves to the real SDK code, unmodified, with no copy drifting out of
sync. `digestif` is listed directly because `auth_state.ml` below uses its
HMAC functions; it's already a transitive dependency of `linkkeys_local_rp`
(used internally for fingerprints), so no new opam package installation was
needed — see this SDK's own README package table.

## Code walkthrough

### `rp_types.ml` — the `Rp` service's CSIL types, hand-coded

```ocaml
(* Hand-written CBOR codecs for the CSIL types the `Rp` service (regular,
   DNS-pinned relying-party mode) needs on the wire (csil/linkkeys.csil,
   "Relying Party (Rp) helper Types" section, ~line 714 in this repo).
   There is no csilgen OCaml target yet, so these are hand-ported directly
   from the CSIL struct definitions -- the same approach the local-RP SDK's
   own `Types` module documents for itself ("hand-written CBOR struct
   codecs ... no csilgen OCaml target").

   Reused as-is from the SDK, unmodified:
   - `Linkkeys_local_rp.Cbor`, the canonical CBOR encoder/decoder. Its
     `encode`'s `Map` case sorts entries by the bytewise order of their
     *encoded* key bytes (RFC 8949 4.2.1) regardless of the association
     list's order, so the field order below is for readability only, not
     wire correctness.
   - `Linkkeys_local_rp.Types.Claim_signature` (`domain`/`signed_by_key_id`/
     `signature`), which already matches CSIL `ClaimSignature` exactly.

   NOT reused (but now could be): `Linkkeys_local_rp.Types.Claim`. When
   this document was first written, that module encoded/decoded
   `claim_value` as a CBOR *text* string, though the CSIL says
   `claim_value: bytes` and the generated Rust codec
   (`crates/liblinkkeys/src/generated/codec.gen.rs`, search
   `cbor_bytes(&csil_v.claim_value)`) confirms the wire type is a CBOR
   byte string -- so a fresh, CSIL-correct copy was written here. The SDK
   has since been FIXED (`lib/types.ml` now encodes/decodes `claim_value`
   as bytes, with a regression test pinning the wire type), so the two
   codecs now agree; the local `Claim` below is kept only so this
   document's `rp_types.ml` block remains one self-contained set of the
   `Rp`-side types, not because `Types.Claim` is wrong. *)

open Linkkeys_local_rp
open Cbor

let opt_field name = function
  | None -> []
  | Some v -> [ (Cbor.Text name, v) ]

(* ------------------------------------------------------------------ *)
(* Claim request / consent shaping                                     *)
(* ------------------------------------------------------------------ *)

module Requested_claim = struct
  type t = { claim_type : string; datatype : string }

  let to_value (v : t) : Cbor.value =
    Cbor.Map [ (Text "claim_type", Text v.claim_type); (Text "datatype", Text v.datatype) ]

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    { claim_type = Cbor.field_text m "claim_type"; datatype = Cbor.field_text m "datatype" }
end

module Claim_request = struct
  type t = { required : Requested_claim.t list; optional : Requested_claim.t list }

  let to_value (v : t) : Cbor.value =
    Cbor.Map
      [
        (Text "required", Array (List.map Requested_claim.to_value v.required));
        (Text "optional", Array (List.map Requested_claim.to_value v.optional));
      ]

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    {
      required = List.map (fun v -> Requested_claim.of_map (Cbor.as_map v)) (Cbor.field_array m "required");
      optional = List.map (fun v -> Requested_claim.of_map (Cbor.as_map v)) (Cbor.field_array m "optional");
    }
end

module Auth_flow_context = struct
  type t = { flow : string; prior_session : string option; request_reason : string option }

  let to_value (v : t) : Cbor.value =
    Cbor.Map
      ([ (Text "flow", Text v.flow) ]
      @ opt_field "prior_session" (Option.map (fun s -> Cbor.Text s) v.prior_session)
      @ opt_field "request_reason" (Option.map (fun s -> Cbor.Text s) v.request_reason))

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    {
      flow = Cbor.field_text m "flow";
      prior_session = Cbor.field_text_opt m "prior_session";
      request_reason = Cbor.field_text_opt m "request_reason";
    }
end

(* ------------------------------------------------------------------ *)
(* Rp/sign-request                                                      *)
(* ------------------------------------------------------------------ *)

module Rp_sign_request = struct
  type t = {
    callback_url : string;
    nonce : string;
    requested_claims : Claim_request.t option;
    flow_context : Auth_flow_context.t option;
  }

  let to_value (v : t) : Cbor.value =
    Cbor.Map
      ([ (Text "callback_url", Text v.callback_url); (Text "nonce", Text v.nonce) ]
      @ opt_field "requested_claims" (Option.map Claim_request.to_value v.requested_claims)
      @ opt_field "flow_context" (Option.map Auth_flow_context.to_value v.flow_context))

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    {
      callback_url = Cbor.field_text m "callback_url";
      nonce = Cbor.field_text m "nonce";
      requested_claims = Option.map (fun v -> Claim_request.of_map (Cbor.as_map v)) (Cbor.field m "requested_claims");
      flow_context = Option.map (fun v -> Auth_flow_context.of_map (Cbor.as_map v)) (Cbor.field m "flow_context");
    }

  let to_cbor v = Cbor.encode (to_value v)
  let of_cbor data = of_map (Cbor.as_map (Cbor.decode data))
end

module Rp_sign_response = struct
  type t = { signed_request : string }

  let to_value (v : t) : Cbor.value = Cbor.Map [ (Text "signed_request", Text v.signed_request) ]
  let of_map (m : (Cbor.value * Cbor.value) list) : t = { signed_request = Cbor.field_text m "signed_request" }
  let to_cbor v = Cbor.encode (to_value v)
  let of_cbor data = of_map (Cbor.as_map (Cbor.decode data))
end

(* ------------------------------------------------------------------ *)
(* Rp/decrypt-token                                                     *)
(* ------------------------------------------------------------------ *)

module Rp_decrypt_request = struct
  type t = { encrypted_token : string }

  let to_value (v : t) : Cbor.value = Cbor.Map [ (Text "encrypted_token", Text v.encrypted_token) ]
  let of_map (m : (Cbor.value * Cbor.value) list) : t = { encrypted_token = Cbor.field_text m "encrypted_token" }
  let to_cbor v = Cbor.encode (to_value v)
  let of_cbor data = of_map (Cbor.as_map (Cbor.decode data))
end

module Rp_decrypt_response = struct
  type t = { signed_assertion : string }

  let to_value (v : t) : Cbor.value = Cbor.Map [ (Text "signed_assertion", Text v.signed_assertion) ]
  let of_map (m : (Cbor.value * Cbor.value) list) : t = { signed_assertion = Cbor.field_text m "signed_assertion" }
  let to_cbor v = Cbor.encode (to_value v)
  let of_cbor data = of_map (Cbor.as_map (Cbor.decode data))
end

(* ------------------------------------------------------------------ *)
(* Rp/verify-assertion                                                  *)
(* ------------------------------------------------------------------ *)

module Rp_verify_request = struct
  type t = { signed_assertion : string; expected_domain : string }

  let to_value (v : t) : Cbor.value =
    Cbor.Map [ (Text "signed_assertion", Text v.signed_assertion); (Text "expected_domain", Text v.expected_domain) ]

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    { signed_assertion = Cbor.field_text m "signed_assertion"; expected_domain = Cbor.field_text m "expected_domain" }

  let to_cbor v = Cbor.encode (to_value v)
  let of_cbor data = of_map (Cbor.as_map (Cbor.decode data))
end

module Identity_assertion = struct
  type t = {
    user_id : string;
    domain : string;
    audience : string;
    nonce : string;
    issued_at : string;
    expires_at : string;
    authorized_claims : string list;
    display_name : string option;
  }

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    {
      user_id = Cbor.field_text m "user_id";
      domain = Cbor.field_text m "domain";
      audience = Cbor.field_text m "audience";
      nonce = Cbor.field_text m "nonce";
      issued_at = Cbor.field_text m "issued_at";
      expires_at = Cbor.field_text m "expires_at";
      authorized_claims = List.map Cbor.as_text (Cbor.field_array m "authorized_claims");
      display_name = Cbor.field_text_opt m "display_name";
    }

  (* Only needed by this document's own round-trip test (there is no reason
     a real app would ever construct one to send) -- the wire direction
     that matters is `of_map`/`of_cbor`, decoding what `verify-assertion`
     hands back. *)
  let to_value (v : t) : Cbor.value =
    Cbor.Map
      ([
         (Text "user_id", Text v.user_id);
         (Text "domain", Text v.domain);
         (Text "audience", Text v.audience);
         (Text "nonce", Text v.nonce);
         (Text "issued_at", Text v.issued_at);
         (Text "expires_at", Text v.expires_at);
         (Text "authorized_claims", Array (List.map (fun s -> Cbor.Text s) v.authorized_claims));
       ]
      @ opt_field "display_name" (Option.map (fun s -> Cbor.Text s) v.display_name))
end

module Rp_verify_response = struct
  type t = { assertion : Identity_assertion.t; verified : bool }

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    { assertion = Identity_assertion.of_map (Cbor.as_map (Cbor.field_exn m "assertion"));
      verified = Cbor.as_bool (Cbor.field_exn m "verified") }

  let of_cbor data = of_map (Cbor.as_map (Cbor.decode data))
end

(* ------------------------------------------------------------------ *)
(* Rp/userinfo-fetch                                                    *)
(* ------------------------------------------------------------------ *)

module Rp_user_info_request = struct
  type t = { token : string; api_base : string; domain : string }

  let to_value (v : t) : Cbor.value =
    Cbor.Map [ (Text "token", Text v.token); (Text "api_base", Text v.api_base); (Text "domain", Text v.domain) ]

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    { token = Cbor.field_text m "token"; api_base = Cbor.field_text m "api_base"; domain = Cbor.field_text m "domain" }

  let to_cbor v = Cbor.encode (to_value v)
  let of_cbor data = of_map (Cbor.as_map (Cbor.decode data))
end

(* CSIL-correct `Claim` -- kept local so this block is self-contained; the
   SDK's `Linkkeys_local_rp.Types.Claim` is now wire-identical (see the
   module header above). `Claim_signature` IS reused unmodified. *)
module Claim = struct
  type t = {
    claim_id : string;
    user_id : string;
    claim_type : string;
    claim_value : string; (* raw bytes -- CSIL `bytes`, not text *)
    signatures : Types.Claim_signature.t list;
    attested_at : string;
    created_at : string;
    expires_at : string option;
    revoked_at : string option;
  }

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    {
      claim_id = Cbor.field_text m "claim_id";
      user_id = Cbor.field_text m "user_id";
      claim_type = Cbor.field_text m "claim_type";
      claim_value = Cbor.field_bytes m "claim_value";
      signatures = List.map (fun v -> Types.Claim_signature.of_map (Cbor.as_map v)) (Cbor.field_array m "signatures");
      attested_at = Cbor.field_text m "attested_at";
      created_at = Cbor.field_text m "created_at";
      expires_at = Cbor.field_text_opt m "expires_at";
      revoked_at = Cbor.field_text_opt m "revoked_at";
    }
end

module User_info = struct
  type t = { user_id : string; domain : string; display_name : string; claims : Claim.t list }

  let of_map (m : (Cbor.value * Cbor.value) list) : t =
    {
      user_id = Cbor.field_text m "user_id";
      domain = Cbor.field_text m "domain";
      display_name = Cbor.field_text m "display_name";
      claims = List.map (fun v -> Claim.of_map (Cbor.as_map v)) (Cbor.field_array m "claims");
    }

  let of_cbor data = of_map (Cbor.as_map (Cbor.decode data))
end
```

### `rp_client.ml` — the auth-carrying envelope and the four `Rp` calls

```ocaml
(* Talks to this app's own LinkKeys RP server over TCP CSIL-RPC (the `Rp`
   service; docs/DEPLOYING-RP.md's "Web App Integration" section, and
   `demoappsite/src/main.rs`'s `rp_call`, which this mirrors). This is NOT
   part of `sdks/local-rp/ocaml` -- that SDK implements a different mode
   (DNS-less local-RP identity). This app is a thin, key-less client of its
   own RP server, exactly like `demoappsite`: it holds no domain key of its
   own, authenticates every call with a bare API key riding the CSIL-RPC
   envelope's `auth` field, and pins the RP server's TLS certificate to a
   static, operator-configured fingerprint set (`RP_FINGERPRINTS`) rather
   than resolving it per call via DNS -- this app's RP server is a
   co-located sidecar whose address and fingerprints an operator already
   knows from "Prerequisites" in example.md, not something to rediscover
   over the network on every login. *)

open Linkkeys_local_rp

type config = { tcp_addr : string; fingerprints : string list; api_key : string }

type error = Rp_call_failed of string

let error_to_string (Rp_call_failed msg) = Printf.sprintf "RP call failed: %s" msg

(* The CSIL-RPC request envelope, WITH the `auth` field the `Rp` service
   requires and `Linkkeys_local_rp.Rpc.encode_request` deliberately omits
   (that function is for this SDK's own two ops that are *unauthenticated
   at the transport layer* -- `DomainKeys/get-domain-keys`,
   `LocalRp/redeem-claim-ticket`; see that module's doc comment). Per the
   CSIL-RPC transport spec (csilgen's `csil-rpc-transport.md`, section 1.1),
   `auth` is an OPTIONAL per-request credential for caller-scoped ops,
   riding the envelope as a bare string field -- NOT a `Bearer `-prefixed
   header; that convention belongs only to the deprecated HTTP surfaces.
   Passing `"Bearer <key>"` here is a silent, hard-to-diagnose auth
   mismatch against the stored key. *)
let encode_request_with_auth ~(api_key : string) (service : string) (op : string) (payload : string) : string =
  Cbor.encode
    (Map
       [
         (Text "v", Int 1);
         (Text "service", Text service);
         (Text "op", Text op);
         (Text "payload", Tag (24, Bytes payload));
         (Text "auth", Text api_key);
       ])

(* One request/response over a fresh, pinned TLS connection to this app's
   RP server. The dial/TLS/framing steps are reused verbatim from the SDK
   (`Transport.default_transport`, `Tls_client.connect`,
   `Rpc.send_frame`/`Rpc.read_frame`/`Rpc.decode_response`); only the
   envelope encoder above is new, because the SDK's own `Rpc.call` hard-
   codes the no-`auth` `Rpc.encode_request` for its two ops. No client
   certificate is presented here -- this app has no domain key, only the
   API key; the RP server is what holds the domain key. *)
let call (cfg : config) (op : string) (payload : string) : (string, error) result =
  let dial_result =
    try Ok (Transport.default_transport.dial cfg.tcp_addr) with Transport.Connect_failed msg -> Error (Rp_call_failed msg)
  in
  match dial_result with
  | Error e -> Error e
  | Ok raw -> (
    let hostname = Tls_client.extract_hostname cfg.tcp_addr in
    let tls_result =
      try Ok (Tls_client.connect ~server_hostname:hostname ~expected_fingerprints:cfg.fingerprints ~now:(Unix.gettimeofday ()) raw)
      with Tls_client.Error msg | Tls_client.Pin_mismatch msg -> Error (Rp_call_failed msg)
    in
    match tls_result with
    | Error e ->
      (try Unix.close raw with _ -> ());
      Error e
    | Ok tls ->
      Fun.protect
        ~finally:(fun () -> try Tls_client.close tls with _ -> ())
        (fun () ->
          try
            let request_bytes = encode_request_with_auth ~api_key:cfg.api_key "Rp" op payload in
            Rpc.send_frame (Tls_client.write tls) request_bytes;
            let response_bytes = Rpc.read_frame (Tls_client.read_exact tls) in
            let status, err, resp_payload = Rpc.decode_response response_bytes in
            if status <> 0 then
              Error (Rp_call_failed (Printf.sprintf "server error (%d): %s" status (Option.value err ~default:"unknown error")))
            else Ok resp_payload
          with
          | Tls_client.Error msg -> Error (Rp_call_failed msg)
          | Error.Sdk_error e -> Error (Rp_call_failed (Error.to_string e))))

(* -------------------------------------------------------------------- *)
(* The four `Rp` login-flow operations (csil/linkkeys.csil,               *)
(* `service Rp { ... }` -- `issue-attestation` is a separate feature)      *)
(* -------------------------------------------------------------------- *)

let ( >>= ) (r : ('a, error) result) (f : 'a -> ('b, error) result) : ('b, error) result =
  match r with Ok v -> f v | Error e -> Error e

let sign_request (cfg : config) (req : Rp_types.Rp_sign_request.t) : (Rp_types.Rp_sign_response.t, error) result =
  call cfg "sign-request" (Rp_types.Rp_sign_request.to_cbor req) >>= fun bytes ->
  try Ok (Rp_types.Rp_sign_response.of_cbor bytes) with Cbor.Decode_error msg -> Error (Rp_call_failed ("decode sign-request response: " ^ msg))

let decrypt_token (cfg : config) (encrypted_token : string) : (Rp_types.Rp_decrypt_response.t, error) result =
  call cfg "decrypt-token" (Rp_types.Rp_decrypt_request.to_cbor { encrypted_token }) >>= fun bytes ->
  try Ok (Rp_types.Rp_decrypt_response.of_cbor bytes)
  with Cbor.Decode_error msg -> Error (Rp_call_failed ("decode decrypt-token response: " ^ msg))

(* Callers MUST check `verified` themselves (see `Login_flow.handle_callback`
   below) -- an `Ok` result here only means the call round-tripped and
   decoded, not that the assertion is cryptographically trustworthy. *)
let verify_assertion (cfg : config) ~(signed_assertion : string) ~(expected_domain : string) :
    (Rp_types.Rp_verify_response.t, error) result =
  call cfg "verify-assertion" (Rp_types.Rp_verify_request.to_cbor { signed_assertion; expected_domain }) >>= fun bytes ->
  try Ok (Rp_types.Rp_verify_response.of_cbor bytes)
  with Cbor.Decode_error msg -> Error (Rp_call_failed ("decode verify-assertion response: " ^ msg))

let userinfo_fetch (cfg : config) (req : Rp_types.Rp_user_info_request.t) : (Rp_types.User_info.t, error) result =
  call cfg "userinfo-fetch" (Rp_types.Rp_user_info_request.to_cbor req) >>= fun bytes ->
  try Ok (Rp_types.User_info.of_cbor bytes) with Cbor.Decode_error msg -> Error (Rp_call_failed ("decode userinfo-fetch response: " ^ msg))
```

### `auth_state.ml` — the signed auth-state pattern

`demoappsite/src/main.rs` persists `{nonce, domain}` between `/login` and
`/callback` in a Rocket *private* cookie — automatically HMAC-signed and
encrypted by the framework's `CookieJar`. This SDK's dependency list has no
web framework opinion at all (`sdks/local-rp/ocaml` is a pure protocol
library, matching `liblinkkeys`'s own "no I/O" boundary from `AGENTS.md`), so
this walkthrough signs the state itself with `digestif`'s HMAC-SHA256 and
hands back a plain string any web layer can put wherever it likes — a cookie
value, a hidden form field, a server-side session row keyed by a random
session id. Nothing here depends on Rocket, Dream, or anything else:

```ocaml
(* HMAC-signed "auth state" -- what this app persists (cookie, session row,
   whatever) between redirecting the browser to the user's chosen LinkKeys
   domain and the callback arriving, so the callback handler can recover
   the `nonce` it minted and the `domain` the user typed, with tampering
   detectable. This is the framework-agnostic equivalent of what
   `demoappsite/src/main.rs`'s `AuthState` cookie gets via Rocket's
   *private* (encrypted+signed) cookie jar: a plain opaque string this
   module hands back to whatever session/cookie mechanism the app already
   uses (Dream's signed cookies, a server-side session row, a hidden form
   field, ...), not tied to any one web framework. *)

open Linkkeys_local_rp

type t = { nonce : string; domain : string }

(* `nonce` is this app's own hex-encoded random nonce (see
   `Login_flow.new_nonce`) and `domain` is a DNS hostname -- neither can
   contain a NUL byte, so it is a safe field separator here without a full
   escaping scheme. *)
let pack (t : t) : string = t.nonce ^ "\x00" ^ t.domain

let unpack (packed : string) : t option =
  match String.index_opt packed '\x00' with
  | None -> None
  | Some i -> Some { nonce = String.sub packed 0 i; domain = String.sub packed (i + 1) (String.length packed - i - 1) }

(* Sign with HMAC-SHA256 under a server-held secret (`hmac_key` -- an
   application secret, generated once and kept as durable config, the same
   tier as `RP_API_KEY`; NOT the RP server's API key itself). Output is
   `hex(payload) ^ ":" ^ hex(hmac)`: hex-encoding the packed payload (rather
   than handing back raw bytes) keeps the whole string `[0-9a-f:]`, so it's
   safe to drop straight into a cookie value or hidden form field without
   assuming the app's cookie layer does its own base64/URL-encoding. *)
let to_signed_string ~(hmac_key : string) (t : t) : string =
  let packed = pack t in
  let mac = Digestif.SHA256.(to_hex (hmac_string ~key:hmac_key packed)) in
  Hex.encode packed ^ ":" ^ mac

let of_signed_string ~(hmac_key : string) (s : string) : (t, string) result =
  match String.index_opt s ':' with
  | None -> Error "auth state malformed: missing signature separator"
  | Some i -> (
    let hex_packed = String.sub s 0 i in
    let given_mac_hex = String.sub s (i + 1) (String.length s - i - 1) in
    match (try Some (Hex.decode hex_packed) with Hex.Error _ -> None) with
    | None -> Error "auth state malformed: bad hex payload"
    | Some packed -> (
      let expected_mac = Digestif.SHA256.hmac_string ~key:hmac_key packed in
      match Digestif.SHA256.of_hex_opt given_mac_hex with
      | None -> Error "auth state malformed: bad hex signature"
      | Some given_mac ->
        (* Constant-time comparison (`Digestif.SHA256.equal`) so a
           tampered/guessed state string presented at the callback can't be
           used as a timing oracle against the HMAC. *)
        if not (Digestif.SHA256.equal expected_mac given_mac) then Error "auth state signature mismatch"
        else (
          match unpack packed with
          | None -> Error "auth state malformed: missing field separator"
          | Some t -> Ok t)))
```

### `login_flow.ml` — framework-agnostic `begin_login`/`handle_callback`

These two functions are the whole app-facing surface. Neither takes or
returns anything HTTP-framework-specific — a Dream route calls them exactly
the same way a Rocket route or a bare `Unix`-socket handler would, reading
`encrypted_token` out of whatever the framework calls its query-parameter
accessor and writing the resulting cookie with whatever the framework calls
its cookie setter:

```ocaml
(* Framework-agnostic login/callback glue: plain functions taking and
   returning plain values, no HTTP framework dependency baked in. Wire
   these into whatever your app already uses for routing/cookies -- this
   repo's own reference integration, `demoappsite/src/main.rs`, uses
   Rocket; a Dream-based OCaml app would call these same two functions from
   `Dream.get "/login" (fun req -> ...)` / `Dream.get "/callback" (fun req
   -> ...)` handlers, reading/writing `Dream.cookie`/`Dream.set_cookie`
   instead of Rocket's `CookieJar` -- nothing here is Rocket- or
   Dream-specific. *)

open Linkkeys_local_rp

let new_nonce () : string = Hex.encode (Crypto.random_bytes 16)

type begin_login_result = { redirect_url : string; auth_state : string }

(* Steps 1-2 of the flow (example.md, "The flow, over TCP CSIL-RPC"):
   `Rp/sign-request` against THIS app's own RP server, then the browser
   redirect to the LOGGING-IN USER'S OWN LinkKeys domain (`user_domain`) --
   not this app's RP server's domain, which is a separate address the user
   never sees. `auth_state` is the opaque signed string from
   `Auth_state.to_signed_string`; persist it (cookie, session row, ...) and
   hand it back unmodified to `handle_callback` when the browser returns. *)
let begin_login (rp : Rp_client.config) ~(hmac_key : string) ~(callback_url : string) ~(user_domain : string)
    ?(requested_claims : Rp_types.Claim_request.t option) () : (begin_login_result, string) result =
  let nonce = new_nonce () in
  let req : Rp_types.Rp_sign_request.t = { callback_url; nonce; requested_claims; flow_context = None } in
  match Rp_client.sign_request rp req with
  | Error e -> Error (Rp_client.error_to_string e)
  | Ok resp ->
    let auth_state = Auth_state.to_signed_string ~hmac_key { nonce; domain = user_domain } in
    (* `resp.signed_request` is already URL-param-encoded by the RP server
       (base64url-unpadded CBOR) -- forward it verbatim, as
       `demoappsite/src/main.rs` does; no extra percent-encoding needed. *)
    let redirect_url = Printf.sprintf "https://%s/auth/authorize?signed_request=%s" user_domain resp.signed_request in
    Ok { redirect_url; auth_state }

type verified_login = {
  user_id : string;
  user_domain : string;
  display_name : string option;
  claims : Rp_types.Claim.t list;
}

(* Nonces already redeemed at the callback. An in-process hash table is a
   placeholder for this walkthrough, not a production answer -- exactly
   parallel to the Go/Rust reference docs' `usedNonces`/`SeenNonces`: it
   resets on restart and isn't shared across replicas. A real deployment
   backs this with a unique DB constraint or a keyed cache entry with a TTL
   past the assertion's `expires_at`. Nothing in the `Rp` service enforces
   single-use for you at this layer -- see "App responsibilities" below. *)
let seen_nonces : (string, unit) Hashtbl.t = Hashtbl.create 64

(* Steps 3-6: decrypt the callback's token, verify the assertion, enforce
   nonce single-use and domain pinning, and (optionally) fetch the user's
   consented claims. `auth_state` is exactly the opaque string
   `begin_login` returned for this browser; the caller is responsible for
   having persisted and now retrieved it (e.g. read back out of the cookie
   it was stored in). *)
let handle_callback (rp : Rp_client.config) ~(hmac_key : string) ~(auth_state : string) ~(encrypted_token : string)
    ~(fetch_userinfo : bool) : (verified_login, string) result =
  match Auth_state.of_signed_string ~hmac_key auth_state with
  | Error msg -> Error ("auth state: " ^ msg)
  | Ok state -> (
    match Rp_client.decrypt_token rp encrypted_token with
    | Error e -> Error (Rp_client.error_to_string e)
    | Ok decrypted -> (
      (* App responsibility: always pass the domain the user originally
         typed as `expected_domain` -- never a value read back out of the
         token itself. This is what pins the result to the identity the
         user claimed to have (see example.md's "App responsibilities"). *)
      match Rp_client.verify_assertion rp ~signed_assertion:decrypted.signed_assertion ~expected_domain:state.domain with
      | Error e -> Error (Rp_client.error_to_string e)
      | Ok verify_resp ->
        if not verify_resp.verified then Error "assertion did not verify against the issuing domain's published keys"
        else (
          let assertion = verify_resp.assertion in
          (* `verified = true` only means the signature checks out -- it does
             NOT mean this assertion answers THIS login attempt. Nonce and
             domain re-checks, plus single-use enforcement, are entirely this
             app's job. *)
          if assertion.nonce <> state.nonce then Error "nonce mismatch -- possible replay attack"
          else if assertion.domain <> state.domain then Error "domain mismatch"
          else if Hashtbl.mem seen_nonces assertion.nonce then Error "this login has already been used"
          else begin
            Hashtbl.add seen_nonces assertion.nonce ();
            if not fetch_userinfo then
              Ok { user_id = assertion.user_id; user_domain = assertion.domain; display_name = assertion.display_name; claims = [] }
            else
              let req : Rp_types.Rp_user_info_request.t =
                { token = decrypted.signed_assertion; api_base = Printf.sprintf "https://%s" state.domain; domain = state.domain }
              in
              match Rp_client.userinfo_fetch rp req with
              | Error e -> Error (Rp_client.error_to_string e)
              | Ok info -> Ok { user_id = info.user_id; user_domain = info.domain; display_name = Some info.display_name; claims = info.claims }
          end)))
```

### Wiring it into a web framework (illustrative, not compiled)

`begin_login`/`handle_callback` are ordinary functions; any OCaml web
framework's route handler just calls them and translates the result into
that framework's redirect/cookie/error-page vocabulary. With
[Dream](https://aantron.github.io/dream/), the two routes would look
approximately like this (not compiled as part of this walkthrough — it
would need Dream itself as a dependency, which is out of scope for a
protocol-only verification pass):

```ocaml
let () =
  Dream.run
  @@ Dream.logger
  @@ Dream.router
       [
         Dream.get "/login" (fun request ->
             let user_domain = Dream.query request "domain" |> Option.value ~default:"" in
             match
               Login_flow.begin_login rp_config ~hmac_key ~callback_url:"https://app.example.com/callback" ~user_domain ()
             with
             | Error msg -> Dream.html ~status:`Bad_Gateway (Printf.sprintf "login failed: %s" msg)
             | Ok { redirect_url; auth_state } ->
               let%lwt response = Dream.redirect request redirect_url in
               Dream.set_cookie response request "auth_state" auth_state ~http_only:true ~secure:true;
               Lwt.return response);
         Dream.get "/callback" (fun request ->
             match (Dream.cookie request "auth_state", Dream.query request "encrypted_token") with
             | None, _ | _, None -> Dream.html ~status:`Bad_Request "missing auth_state or encrypted_token"
             | Some auth_state, Some encrypted_token -> (
               match Login_flow.handle_callback rp_config ~hmac_key ~auth_state ~encrypted_token ~fetch_userinfo:true with
               | Error msg -> Dream.html ~status:`Forbidden (Printf.sprintf "login could not be verified: %s" msg)
               | Ok login -> (* mint your app's own session from [login], then redirect *)
                 Dream.redirect request "/"));
       ]
```

## App responsibilities

Exactly as this SDK's own `README.md` says of its local-RP flow, none of
this is owned by `Linkkeys_local_rp` or the glue above — the protocol layer
returns verified facts, and everything below is on your app:

- **Nonce single-use.** `Rp/verify-assertion` tells you the assertion is
  cryptographically valid and which nonce it carries; it does **not** track
  which nonces you've already redeemed. `Login_flow.seen_nonces` is
  in-process and resets on restart — back it with a database row or a keyed
  cache entry with a TTL matching `assertion.expires_at`, shared across app
  instances.
- **Domain pinning at verify time.** Always pass the domain the user
  originally typed as `expected_domain`, and re-check `assertion.domain`
  against it after verifying — `verified = true` only means the signature
  checks out, not that it answers this login attempt.
- **The signed auth-state's `hmac_key` is an app secret**, generated once
  and never derived from or shared with `RP_API_KEY`. Losing it lets an
  attacker forge `auth_state` values (though not `Rp` calls themselves,
  which are separately authenticated); rotating it invalidates every
  in-flight login.
- **Sessions, local user records, authorization decisions.** `UserInfo`
  gives you `user_id`, `domain`, `display_name`, and `claims`; turning that
  into a session, a local account row, or an authorization decision is your
  app's own logic.
- **`RP_API_KEY` storage.** It authorizes your app to drive your RP
  server's signing/decryption oracles (SEC-06). Store and inject it the
  same way you would a database credential — never log it, never put it in
  a URL, never check it into source control.

## TLS caveat carried forward

`rp_client.ml`'s `Rp_client.call` above reuses `Tls_client.connect` exactly
as this SDK's own `Rpc.call` does. This SDK's `README.md` documents that
module's blocking `Tls.Engine` driver as real, reviewed TLS 1.2/1.3 client
code — not a stub — but **never exercised against a live LinkKeys server in
this environment** (none was reachable to test against), so it is
field-untested rather than merely unit-tested. That caveat applies with
exactly the same force to this document's `Rp_client.call`: it is the
identical TLS client code, now additionally carrying the `auth` field this
walkthrough adds. What *is* tested (both by the SDK's own `dune runtest` and
by this document's own run, see below) is everything up to and around that
byte stream — pin-extraction against a real certificate, the frame codec,
and the CBOR envelope/payload codecs — not the live handshake itself.

## Local-RP vs regular-RP: which one?

| | Local RP (`Linkkeys_local_rp`, this directory) | Regular RP (this document) |
|---|---|---|
| App identity | A locally-generated Ed25519 key fingerprint (SSH-host-key style) | A DNS domain your RP server owns |
| DNS required | No | Yes — `_linkkeys` + `_linkkeys_apis` TXT records |
| Where keys live | In the app itself (`Identity.local_rp_identity_to_bytes`) | In a separate RP server process your app talks to over TCP |
| Admission | Explicit per-domain approval (`linkkeys local-rp approve <fingerprint>`) — pending until an admin approves | Ordinary DNS-pinned trust, same as any LinkKeys peer |
| OCaml SDK | This package (`begin_local_login`/`complete_local_login`) | None packaged — hand-write the glue this document shows, reusing `Cbor`/`Rpc`/`Tls_client`/`Transport` |
| Best for | LAN tools, self-hosted apps with no public DNS, desktop apps | Any app that already has (or can get) a domain |

If your app has a domain, use this document's approach. If it doesn't (a LAN
jukebox, a local dev tool), see this package's own `README.md` and
`Linkkeys_local_rp.begin_local_login`/`complete_local_login` instead. The two
modes are not mutually exclusive at the protocol level, but they are
different code paths: regular-mode apps never call into this SDK's
`Identity`/`Begin_login`/`Complete_login` modules at all — those are the
local-RP surface. This document's glue calls only `Cbor`, `Rpc`,
`Tls_client`, and `Transport`, all of which are generic enough to serve both
modes.

## What was compiled and run

`rp_types.ml`, `rp_client.ml`, `auth_state.ml`, and `login_flow.ml` above are
copied verbatim from a scratch dune project built **outside** this repo
(`(lang dune 3.0)`, OCaml 5.2.1, dune from the `catalyst-tools` switch), with
`sdks/local-rp/ocaml/lib` symlinked in as a subdirectory so `(libraries
linkkeys_local_rp)` resolved against this repo's real, current SDK source —
not a hand-copied approximation of it, and nothing was added to or modified
in this repo to make that possible:

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
eval "$(opam env --root "$CATALYST_TOOLS/opam" --switch catalyst)"
dune build              # clean, zero warnings, dev profile (warnings-as-errors)
dune build --profile release   # also clean
dune exec bin/main.exe
```

The scratch project's `bin/main.ml` (not reproduced in full above — it's a
test harness, not app code) ran 18 assertions, all passing, covering exactly
the non-network parts of this walkthrough:

```
PASS  Rp_sign_request CBOR round trip
PASS  Rp_sign_request encodes to a CBOR map
PASS  RpVerifyResponse decode
PASS  UserInfo decode
PASS  Claim.claim_value decodes raw (non-UTF8) bytes exactly
PASS  Claim.signatures decode via reused Types.Claim_signature
PASS  envelope: v=1
PASS  envelope: service=Rp
PASS  envelope: op=decrypt-token
PASS  envelope: auth carries the raw API key, no 'Bearer ' prefix
PASS  envelope: payload is tag-24-wrapped and matches the original bytes
PASS  frame codec: length-prefixed round trip recovers the exact envelope
PASS  frame codec: consumed exactly the frame (4-byte length prefix + payload)
PASS  response envelope: status=0, no error
PASS  response envelope: payload decodes back to RpSignResponse
PASS  Auth_state round trip recovers nonce+domain
PASS  Auth_state rejects a tampered signature
PASS  Auth_state rejects the wrong hmac_key
```

Specifically exercised: the `Rp_sign_request`/`Rp_verify_response`/
`User_info`/`Claim` CBOR codecs round-trip correctly, including a
non-UTF-8 `claim_value` byte string (exercising the bytes-not-text wire
type the `Types.Claim` note above discusses — the SDK's own codec now
handles it identically); `Rp_client.encode_request_with_auth` produces an envelope
with the right `v`/`service`/`op`/`auth`/tag-24-`payload` shape; the
length-prefix frame codec (reused from `Rpc.send_frame`/`read_frame`)
round-trips both a request and a response envelope in-memory; and
`Auth_state`'s HMAC sign/verify round-trips and correctly rejects both a
bit-flipped signature and the wrong `hmac_key`.

**Not exercised**: any live network call. No RP/IDP pair was stood up in
this environment, so `Rp_client.call`'s dial-and-TLS-handshake path (and
therefore the whole four-op `Rp` flow end to end) was not run against a real
server — consistent with the TLS caveat above. The wire-level behavior this
document describes (envelope shape, auth field, frame format, response
codes) is read directly from `crates/linkkeys/src/tcp/mod.rs`,
`crates/linkkeys/src/web/rp.rs`, `csil/linkkeys.csil`, and this SDK's own
`rpc.ml`/`cbor.ml`, and verified structurally by the round trips above, not
exercised against a live server.
