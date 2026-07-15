# Accepting regular (DNS-pinned) LinkKeys logins from Elixir

This document is for an Elixir app developer who wants to let users log in
with **any** LinkKeys identity provider on the internet — the normal,
DNS-pinned protocol flow. That is **not** what the `linkkeys_local_rp`
package in this directory implements: `LinkkeysLocalRp` is the *DNS-less
local-RP* mode (`dns-less-local-rp-design.md` at the repo root) — apps with
no public DNS, identified by a locally-generated key fingerprint instead of
a domain. See "local-RP vs regular-RP" near the end before you start
copying code from here.

Everything non-network below (CBOR envelope encode/decode, the CSIL type
round-trips, redirect-URL construction, the HMAC-signed auth-state token,
nonce single-use, and the raw HTTP handler's request parsing/routing) was
actually executed against system Elixir while writing this document — see
"What actually ran" near the end. No file inside `linkkeys_local_rp/` was
modified to make this work.

## Architecture: your app never touches a private key

A regular LinkKeys login needs a relying-party (RP) server that holds a
LinkKeys **domain key** — it signs outbound auth requests and decrypts the
tokens that come back. Your Elixir app is not supposed to hold that key
itself. Instead you run a second, small deployment: the same `linkkeys`
server binary as any identity provider, just configured in RP mode (no
login UI, no human user accounts, `rp.enabled: true`). Your app talks to
*that* server over TCP CSIL-RPC, authenticated with a plain API key, and
never sees a private key. See `docs/DEPLOYING-RP.md` for the full
deployment (Helm chart, values, gateway TLS passthrough); this document
picks up once that RP server is running and focuses on the Elixir side.

```
 Browser              Your Elixir App           Your RP server           Identity Provider
    |                        |                         |                         |
    |--- log in with ------->|                         |                         |
    |    you@idp.example     |-- Rp/sign-request ----->|                         |
    |                        |<--- signed_request ------|                         |
    |<--- redirect to ------ |                         |                         |
    |     idp /auth/authorize|                         |                         |
    |------------------------------------ user authenticates at the IDP -------->|
    |<-------------------------------------------- redirect to your /callback ---|
    |    ?encrypted_token=...                           |                         |
    |--- GET /callback ----->|                         |                         |
    |                        |-- Rp/decrypt-token ----->|                         |
    |                        |<--- signed_assertion ----|                         |
    |                        |-- Rp/verify-assertion -->|-- verifies vs IDP's --->|
    |                        |<--- verified assertion --|    published keys       |
    |                        |-- Rp/userinfo-fetch ---->|-- redeems claims ------>|
    |                        |<--- UserInfo -------------|                         |
    |<--- session cookie ----|                         |                         |
```

Your RP server is itself a full participant in the DNS-pinned trust model
(it has its own `_linkkeys`/`_linkkeys_apis` TXT records), and your app's
connection *to* it is pinned the same way every other LinkKeys TCP peer
connection is: by the RP server's own DNS-published key fingerprints, not
by a certificate authority.

## Prerequisites

1. **Deploy your RP server.** Follow `docs/DEPLOYING-RP.md` end to end
   (Helm chart with `rp.enabled: true`). You need a real domain you
   control — this is what makes it "regular" (DNS-pinned) RP mode as
   opposed to local-RP mode — and its TCP endpoint (`tcpPort`, default
   `4987`, `LinkkeysLocalRp.Dns.default_tcp_port/0`) reachable from your
   app.

2. **Initialize domain keys and create a service account for your app**,
   inside the RP server:

   ```sh
   linkkeys domain init
   linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
   # Save the printed API key -- it will not be shown again.
   ```

   `--relation api_access` grants the `api_access` relation at creation
   time. This is **not optional and not automatic** — every `Rp` CSIL-RPC
   operation requires the caller's API key to carry the dedicated
   `api_access` relation on the RP's domain (SEC-06); a valid API key
   alone is rejected with `Forbidden`. This is enforced in
   `crates/linkkeys/src/tcp/mod.rs`'s dispatch
   (`required_relation_for_op("Rp", op)` in
   `crates/linkkeys/src/services/authorization.rs:102` maps every `Rp`
   operation to `RELATION_API_ACCESS`) specifically so a leaked ordinary
   user API key can't be used to drive the sign/decrypt oracles.

   If you already minted a key without `--relation`, or need to grant it
   to an already-existing service account, use the standalone grant
   command instead (DB-direct, idempotent, run where the RP server's
   database lives):

   ```sh
   linkkeys relation grant-local my-webapp api_access
   ```

   `deploy/live.sh` uses this same `relation grant-local` command for live
   deployments.

3. **Check DNS** for your RP server's own domain:

   ```sh
   linkkeys domain dns-check
   ```

   This prints the `_linkkeys` TXT record (`fp=` fingerprints — pin these
   in your app's config below) and the `_linkkeys_apis` TXT record
   (`tcp=`/`https=`) it expects to find published. Publish them. Your app
   pins to the `fp=` values directly (a small fixed list in
   configuration, the same way you'd pin a certificate's public key) — it
   does not need to re-resolve DNS on every call, though it's free to.

4. **Your app needs no DNS entries of its own** for this flow beyond a
   reachable `callback_url` the identity provider's browser redirect can
   reach.

## The login flow, wire-level

Everything below is TCP CSIL-RPC (`csil/linkkeys.csil`'s `Rp` service),
**never HTTP** — the old `POST /v1alpha/*.json` routes were removed when
S2S moved to TCP, and the generic HTTP RPC carrier that remains cannot
complete this flow: `verify-assertion` and `userinfo-fetch` need the
onward server-to-server context (to the *issuing* IDP) that only the TCP
carrier has. `docs/DEPLOYING-RP.md`'s "Web App Integration" section
documents this accurately; `demoappsite/src/main.rs` is the Rust reference
integration this document mirrors.

```
service Rp {
    sign-request:       RpSignRequest             -> RpSignResponse,
    decrypt-token:      RpDecryptRequest           -> RpDecryptResponse,
    verify-assertion:   RpVerifyRequest            -> RpVerifyResponse,
    userinfo-fetch:     RpUserInfoRequest          -> UserInfo,
    issue-attestation:  RpIssueAttestationRequest  -> RpIssueAttestationResponse
}
```

(`issue-attestation` is a different feature — your RP server issuing a
claim it signs itself about a *visiting* user, the way `demoappsite`'s
`/attest/linkidspec` route does — not part of the login flow and not
covered further here.)

1. **`Rp/sign-request`** `{callback_url, nonce, ?requested_claims,
   ?flow_context}` → `{signed_request}`. Your app generates a fresh
   single-use `nonce` and calls this before ever redirecting the browser.
   **The trap:** the CSIL-RPC request envelope's `auth` field carries the
   **raw API key** — no `"Bearer "` prefix. That convention belongs to
   the separate, browser-facing HTTPS surfaces this server also exposes;
   the TCP `Rp` envelope just wants the bare key string
   (`crates/csilgen-transport/src/rpc.rs`'s `RpcRequest.auth`, read
   verbatim by `authenticate_tcp_request` in
   `crates/linkkeys/src/tcp/mod.rs`). Prefixing it with `"Bearer "` here
   authenticates as nothing and gets you `Forbidden`.
2. **Redirect the browser** to
   `https://<user's chosen domain>/auth/authorize?...&signed_request=<...>`
   (`user_hint=` is optional — a login-form-prefill hint, not a trust
   input).
3. The identity provider authenticates the user and redirects the browser
   back to your `callback_url` with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** `{encrypted_token}` → `{signed_assertion}`.
5. **`Rp/verify-assertion`** `{signed_assertion, expected_domain}` →
   `{assertion, verified}`. `expected_domain` is the domain your app
   expected to authenticate against — the one you asked the user for at
   step 1. **Check `verified` explicitly** — an `{:ok, resp}` tuple only
   means the call round-tripped, not that the assertion is trustworthy.
   **Nonce single-use and the domain check are your app's job, not the
   server's**: compare `assertion.nonce` against the nonce you generated
   at step 1 and `assertion.domain` against the domain you asked for, and
   make sure the nonce comparison can't succeed twice (see "App
   responsibilities" below).
6. **`Rp/userinfo-fetch`** (optional) `{token, api_base, domain}` → claims.
   `token` is the `signed_assertion` string from step 4; `api_base` and
   `domain` identify the issuing IDP (your RP server redeems the claims
   from there — it holds the domain key needed to prove it's the
   assertion's audience, your app does not).

## Complete Elixir walkthrough

There's no packaged regular-RP client for Elixir — `LinkkeysLocalRp` in
this directory implements the *different*, DNS-less local-RP mode. What
follows builds a small RP client directly, reusing this package's public,
protocol-mode-agnostic pieces (`LinkkeysLocalRp.Transport`,
`LinkkeysLocalRp.Tls`, `LinkkeysLocalRp.Cbor`, `LinkkeysLocalRp.Dns`), and
inlining only the handful of things that are specific to
`LinkkeysLocalRp.Rpc`'s own private (`defp`) envelope framing — which, more
importantly than being private, has no `auth` field at all, because the
local-RP protocol it serves never authenticates with an API key.
`LinkkeysLocalRp.Types` likewise only covers the local-RP flow's own
types, so the `Rp` service's request/response types are hand-written below
from `csil/linkkeys.csil` directly, mirroring `LinkkeysLocalRp.Types`'s own
style exactly.

Zero hex dependencies, matching this SDK's own posture (`mix.exs`): OTP's
`:ssl`/`:gen_tcp` cover the TCP+TLS transport, `:crypto` covers HMAC, and
everything else here is plain Elixir/OTP stdlib. Tested against system
Elixir 1.20.2 / Erlang/OTP 29.

### `RegularRp.Types` — the `Rp` service's CSIL wire types

```elixir
defmodule RegularRp.Types do
  @moduledoc """
  Hand-written CSIL wire types for the `Rp` service (`csil/linkkeys.csil`,
  "Relying Party (Rp) helper Types" and "User Info" / "Auth Request"
  sections). `LinkkeysLocalRp.Types` in this SDK only covers the DNS-less
  local-RP flow's own types, not these -- there is no csilgen Elixir target
  yet (see `LinkkeysLocalRp.Cbor`'s moduledoc), so every sibling SDK's
  regular-RP example hand-writes this same set from the CSIL source; this
  mirrors that pattern and mirrors `LinkkeysLocalRp.Types`'s own style
  exactly (plain structs, `to_cbor/1`/`from_cbor/1`, `Cbor.Bytes` wrapping
  byte fields, optional fields omitted when `nil`).
  """

  alias LinkkeysLocalRp.Cbor

  defmodule RequestedClaim do
    @moduledoc "CSIL `RequestedClaim`."
    defstruct [:claim_type, :datatype]
  end

  defmodule ClaimRequest do
    @moduledoc "CSIL `ClaimRequest` -- what this app wants on first contact."
    defstruct [:required, :optional]
  end

  defmodule AuthFlowContext do
    @moduledoc "CSIL `AuthFlowContext` -- optional signed context shown by the IDP."
    defstruct [:flow, prior_session: nil, request_reason: nil]
  end

  defmodule ClaimSignature do
    @moduledoc "CSIL `ClaimSignature`."
    defstruct [:domain, :signed_by_key_id, :signature]
  end

  defmodule Claim do
    @moduledoc "CSIL `Claim`."
    defstruct [
      :claim_id,
      :user_id,
      :claim_type,
      :claim_value,
      :signatures,
      :attested_at,
      :created_at,
      expires_at: nil,
      revoked_at: nil
    ]
  end

  defmodule IdentityAssertion do
    @moduledoc "CSIL `IdentityAssertion` -- the verified protocol facts `Rp/verify-assertion` hands back."
    defstruct [
      :user_id,
      :domain,
      :audience,
      :nonce,
      :issued_at,
      :expires_at,
      :authorized_claims,
      display_name: nil
    ]
  end

  defmodule UserInfo do
    @moduledoc "CSIL `UserInfo` -- the response of `Rp/userinfo-fetch`."
    defstruct [:user_id, :domain, :display_name, :claims]
  end

  defmodule RpSignRequest do
    @moduledoc "CSIL `RpSignRequest` -- `Rp/sign-request` input."
    defstruct [:callback_url, :nonce, requested_claims: nil, flow_context: nil]
  end

  defmodule RpSignResponse do
    @moduledoc "CSIL `RpSignResponse`."
    defstruct [:signed_request]
  end

  defmodule RpDecryptRequest do
    @moduledoc "CSIL `RpDecryptRequest` -- `Rp/decrypt-token` input."
    defstruct [:encrypted_token]
  end

  defmodule RpDecryptResponse do
    @moduledoc "CSIL `RpDecryptResponse`."
    defstruct [:signed_assertion]
  end

  defmodule RpVerifyRequest do
    @moduledoc "CSIL `RpVerifyRequest` -- `Rp/verify-assertion` input."
    defstruct [:signed_assertion, :expected_domain]
  end

  defmodule RpVerifyResponse do
    @moduledoc "CSIL `RpVerifyResponse`."
    defstruct [:assertion, :verified]
  end

  defmodule RpUserInfoRequest do
    @moduledoc "CSIL `RpUserInfoRequest` -- `Rp/userinfo-fetch` input."
    defstruct [:token, :api_base, :domain]
  end

  # -- helpers -------------------------------------------------------------

  defp put_opt(map, _key, nil), do: map
  defp put_opt(map, key, value), do: Map.put(map, key, value)
  defp get(tree, key), do: Map.fetch!(tree, key)
  defp get_opt(tree, key), do: Map.get(tree, key)

  # -- RequestedClaim / ClaimRequest / AuthFlowContext ----------------------

  def requested_claim_to_tree(%RequestedClaim{} = v) do
    %{"claim_type" => v.claim_type, "datatype" => v.datatype}
  end

  def requested_claim_from_tree(tree) do
    %RequestedClaim{claim_type: get(tree, "claim_type"), datatype: get(tree, "datatype")}
  end

  def claim_request_to_tree(nil), do: nil

  def claim_request_to_tree(%ClaimRequest{} = v) do
    %{
      "required" => Enum.map(v.required, &requested_claim_to_tree/1),
      "optional" => Enum.map(v.optional, &requested_claim_to_tree/1)
    }
  end

  def claim_request_from_tree(nil), do: nil

  def claim_request_from_tree(tree) do
    %ClaimRequest{
      required: Enum.map(get(tree, "required"), &requested_claim_from_tree/1),
      optional: Enum.map(get(tree, "optional"), &requested_claim_from_tree/1)
    }
  end

  def auth_flow_context_to_tree(nil), do: nil

  def auth_flow_context_to_tree(%AuthFlowContext{} = v) do
    %{"flow" => v.flow}
    |> put_opt("prior_session", v.prior_session)
    |> put_opt("request_reason", v.request_reason)
  end

  def auth_flow_context_from_tree(nil), do: nil

  def auth_flow_context_from_tree(tree) do
    %AuthFlowContext{
      flow: get(tree, "flow"),
      prior_session: get_opt(tree, "prior_session"),
      request_reason: get_opt(tree, "request_reason")
    }
  end

  # -- ClaimSignature / Claim ------------------------------------------------

  def claim_signature_to_tree(%ClaimSignature{} = v) do
    %{"domain" => v.domain, "signed_by_key_id" => v.signed_by_key_id, "signature" => Cbor.bytes(v.signature)}
  end

  def claim_signature_from_tree(tree) do
    %ClaimSignature{
      domain: get(tree, "domain"),
      signed_by_key_id: get(tree, "signed_by_key_id"),
      signature: Cbor.bytes!(get(tree, "signature"))
    }
  end

  def claim_to_tree(%Claim{} = v) do
    %{
      "claim_id" => v.claim_id,
      "user_id" => v.user_id,
      "claim_type" => v.claim_type,
      "claim_value" => Cbor.bytes(v.claim_value),
      "signatures" => Enum.map(v.signatures, &claim_signature_to_tree/1),
      "attested_at" => v.attested_at,
      "created_at" => v.created_at
    }
    |> put_opt("expires_at", v.expires_at)
    |> put_opt("revoked_at", v.revoked_at)
  end

  def claim_from_tree(tree) do
    %Claim{
      claim_id: get(tree, "claim_id"),
      user_id: get(tree, "user_id"),
      claim_type: get(tree, "claim_type"),
      claim_value: Cbor.bytes!(get(tree, "claim_value")),
      signatures: Enum.map(get(tree, "signatures"), &claim_signature_from_tree/1),
      attested_at: get(tree, "attested_at"),
      created_at: get(tree, "created_at"),
      expires_at: get_opt(tree, "expires_at"),
      revoked_at: get_opt(tree, "revoked_at")
    }
  end

  # -- IdentityAssertion / UserInfo -----------------------------------------

  def identity_assertion_from_tree(tree) do
    %IdentityAssertion{
      user_id: get(tree, "user_id"),
      domain: get(tree, "domain"),
      audience: get(tree, "audience"),
      nonce: get(tree, "nonce"),
      issued_at: get(tree, "issued_at"),
      expires_at: get(tree, "expires_at"),
      authorized_claims: get(tree, "authorized_claims"),
      display_name: get_opt(tree, "display_name")
    }
  end

  # test-only encoder: the RP server produces IdentityAssertion on the wire;
  # this app never builds one to send. Kept here so the round-trip check
  # below can construct a realistic fixture without a live server.
  def identity_assertion_to_tree(%IdentityAssertion{} = v) do
    %{
      "user_id" => v.user_id,
      "domain" => v.domain,
      "audience" => v.audience,
      "nonce" => v.nonce,
      "issued_at" => v.issued_at,
      "expires_at" => v.expires_at,
      "authorized_claims" => v.authorized_claims
    }
    |> put_opt("display_name", v.display_name)
  end

  def user_info_from_tree(tree) do
    %UserInfo{
      user_id: get(tree, "user_id"),
      domain: get(tree, "domain"),
      display_name: get(tree, "display_name"),
      claims: Enum.map(get(tree, "claims"), &claim_from_tree/1)
    }
  end

  # -- RpSignRequest / RpSignResponse ---------------------------------------

  def rp_sign_request_to_tree(%RpSignRequest{} = v) do
    %{"callback_url" => v.callback_url, "nonce" => v.nonce}
    |> put_opt("requested_claims", claim_request_to_tree(v.requested_claims))
    |> put_opt("flow_context", auth_flow_context_to_tree(v.flow_context))
  end

  def rp_sign_request_to_cbor(%RpSignRequest{} = v), do: Cbor.encode(rp_sign_request_to_tree(v))

  def rp_sign_request_from_tree(tree) do
    %RpSignRequest{
      callback_url: get(tree, "callback_url"),
      nonce: get(tree, "nonce"),
      requested_claims: claim_request_from_tree(get_opt(tree, "requested_claims")),
      flow_context: auth_flow_context_from_tree(get_opt(tree, "flow_context"))
    }
  end

  def rp_sign_request_from_cbor(data), do: rp_sign_request_from_tree(Cbor.decode(data))

  def rp_sign_response_to_tree(%RpSignResponse{} = v), do: %{"signed_request" => v.signed_request}
  def rp_sign_response_to_cbor(%RpSignResponse{} = v), do: Cbor.encode(rp_sign_response_to_tree(v))

  def rp_sign_response_from_tree(tree), do: %RpSignResponse{signed_request: get(tree, "signed_request")}
  def rp_sign_response_from_cbor(data), do: rp_sign_response_from_tree(Cbor.decode(data))

  # -- RpDecryptRequest / RpDecryptResponse ---------------------------------

  def rp_decrypt_request_to_tree(%RpDecryptRequest{} = v), do: %{"encrypted_token" => v.encrypted_token}
  def rp_decrypt_request_to_cbor(%RpDecryptRequest{} = v), do: Cbor.encode(rp_decrypt_request_to_tree(v))

  def rp_decrypt_response_from_tree(tree),
    do: %RpDecryptResponse{signed_assertion: get(tree, "signed_assertion")}

  def rp_decrypt_response_from_cbor(data), do: rp_decrypt_response_from_tree(Cbor.decode(data))

  # -- RpVerifyRequest / RpVerifyResponse -----------------------------------

  def rp_verify_request_to_tree(%RpVerifyRequest{} = v) do
    %{"signed_assertion" => v.signed_assertion, "expected_domain" => v.expected_domain}
  end

  def rp_verify_request_to_cbor(%RpVerifyRequest{} = v), do: Cbor.encode(rp_verify_request_to_tree(v))

  def rp_verify_response_from_tree(tree) do
    %RpVerifyResponse{
      assertion: identity_assertion_from_tree(get(tree, "assertion")),
      verified: get(tree, "verified")
    }
  end

  def rp_verify_response_from_cbor(data), do: rp_verify_response_from_tree(Cbor.decode(data))

  # -- RpUserInfoRequest / UserInfo ------------------------------------------

  def rp_user_info_request_to_tree(%RpUserInfoRequest{} = v) do
    %{"token" => v.token, "api_base" => v.api_base, "domain" => v.domain}
  end

  def rp_user_info_request_to_cbor(%RpUserInfoRequest{} = v), do: Cbor.encode(rp_user_info_request_to_tree(v))

  def user_info_from_cbor(data), do: user_info_from_tree(Cbor.decode(data))
end
```

### `RegularRp.Client` — the RP-call glue

```elixir
defmodule RegularRp.Client do
  @moduledoc """
  A minimal regular-RP client: talks TCP CSIL-RPC to *your own* RP server
  (`docs/DEPLOYING-RP.md`), authenticated with an API key. Not part of
  `LinkkeysLocalRp` -- that package implements the different, DNS-less
  local-RP mode.

  Reused verbatim from the SDK (all public, protocol-mode-agnostic):
  `LinkkeysLocalRp.Transport.dial/2` (TCP dial), `LinkkeysLocalRp.Tls.dial_tls_pinned/4`
  + `extract_hostname/1` (fingerprint-pinned TLS, no client cert), and
  `LinkkeysLocalRp.Cbor` (the canonical CBOR codec). Inlined below:
  `LinkkeysLocalRp.Rpc`'s frame send/recv and envelope encode/decode are
  `defp` (private) and, more importantly, its envelope has no `auth` field
  -- the local-RP protocol it serves never authenticates with an API key,
  whereas every `Rp` op requires one in the CSIL-RPC envelope's `auth`
  field (`crates/csilgen-transport/src/rpc.rs`'s `RpcRequest.auth`, read by
  `authenticate_tcp_request` in `crates/linkkeys/src/tcp/mod.rs`).
  """

  alias LinkkeysLocalRp.Cbor
  alias LinkkeysLocalRp.Cbor.Tag
  alias LinkkeysLocalRp.Dns
  alias LinkkeysLocalRp.Tls
  alias LinkkeysLocalRp.Transport
  alias RegularRp.Types

  @csil_rpc_version 1
  @tag_encoded_cbor 24
  @max_frame_size 1024 * 1024

  defmodule RpConfig do
    @moduledoc "Your app's connection to its own RP server."
    defstruct [:tcp_addr, :fingerprints, :api_key, :domain]

    @type t :: %__MODULE__{
            tcp_addr: String.t(),
            fingerprints: [String.t()],
            api_key: String.t(),
            domain: String.t()
          }
  end

  defmodule RpCallError do
    defexception [:message]
  end

  # -- envelope framing (inlined: LinkkeysLocalRp.Rpc's own framing is
  #    `defp` and has no `auth` field -- see moduledoc) -----------------

  defp build_request_envelope(op, payload, api_key) do
    Cbor.encode(%{
      "v" => @csil_rpc_version,
      "service" => "Rp",
      "op" => op,
      "payload" => %Tag{tag: @tag_encoded_cbor, value: Cbor.bytes(payload)},
      "auth" => api_key
    })
  end

  defp parse_response_envelope(response_bytes) do
    case Cbor.decode(response_bytes) do
      %{"status" => 0} = tree ->
        case Map.get(tree, "payload") do
          %Tag{tag: @tag_encoded_cbor, value: v} -> {:ok, Cbor.bytes!(v)}
          _ -> {:ok, <<>>}
        end

      %{"status" => status} = tree ->
        {:error, %RpCallError{message: "server error (status=#{status}): #{Map.get(tree, "error")}"}}

      _ ->
        {:error, %RpCallError{message: "RPC response envelope is not a CBOR map with integer 'status'"}}
    end
  end

  defp send_frame(sock, data) do
    :ok = :ssl.send(sock, <<byte_size(data)::32>>)
    :ok = :ssl.send(sock, data)
  end

  defp recv_exact(sock, n) do
    case :ssl.recv(sock, n) do
      {:ok, data} when byte_size(data) == n -> {:ok, data}
      {:ok, _short} -> {:error, %RpCallError{message: "connection closed before expected bytes were received"}}
      {:error, reason} -> {:error, %RpCallError{message: "recv failed: #{inspect(reason)}"}}
    end
  end

  defp recv_frame(sock) do
    with {:ok, <<length::32>>} <- recv_exact(sock, 4) do
      if length > @max_frame_size do
        {:error, %RpCallError{message: "peer frame too large (#{length} bytes, max #{@max_frame_size})"}}
      else
        recv_exact(sock, length)
      end
    end
  end

  @doc """
  Call one `Rp/<op>` on your own RP server: TLS-pinned to its published
  `fp=` fingerprints, authenticated with your app's API key. Presents no
  client certificate -- your app holds no domain key, only the RP server
  does.
  """
  @spec rp_call(RpConfig.t(), String.t(), binary) :: {:ok, binary} | {:error, term}
  def rp_call(%RpConfig{} = cfg, op, payload) do
    with {:ok, raw_sock} <- Transport.dial(cfg.tcp_addr) do
      hostname = Tls.extract_hostname(cfg.tcp_addr)

      try do
        tls_sock = Tls.dial_tls_pinned(raw_sock, hostname, cfg.fingerprints)

        try do
          send_frame(tls_sock, build_request_envelope(op, payload, cfg.api_key))

          with {:ok, response_bytes} <- recv_frame(tls_sock) do
            parse_response_envelope(response_bytes)
          end
        after
          :ssl.close(tls_sock)
        end
      rescue
        e -> {:error, e}
      end
    end
  end

  @doc "Step 1: sign an auth request before ever redirecting the browser."
  @spec sign_request(RpConfig.t(), String.t(), String.t(), Types.ClaimRequest.t() | nil, Types.AuthFlowContext.t() | nil) ::
          {:ok, Types.RpSignResponse.t()} | {:error, term}
  def sign_request(cfg, callback_url, nonce, requested_claims \\ nil, flow_context \\ nil) do
    req = %Types.RpSignRequest{
      callback_url: callback_url,
      nonce: nonce,
      requested_claims: requested_claims,
      flow_context: flow_context
    }

    with {:ok, resp_bytes} <- rp_call(cfg, "sign-request", Types.rp_sign_request_to_cbor(req)) do
      {:ok, Types.rp_sign_response_from_cbor(resp_bytes)}
    end
  end

  @doc "Step 4: exchange the callback's `encrypted_token` for the signed assertion inside it."
  @spec decrypt_token(RpConfig.t(), String.t()) :: {:ok, Types.RpDecryptResponse.t()} | {:error, term}
  def decrypt_token(cfg, encrypted_token) do
    req = %Types.RpDecryptRequest{encrypted_token: encrypted_token}

    with {:ok, resp_bytes} <- rp_call(cfg, "decrypt-token", Types.rp_decrypt_request_to_cbor(req)) do
      {:ok, Types.rp_decrypt_response_from_cbor(resp_bytes)}
    end
  end

  @doc """
  Step 5: verify the decrypted assertion against the issuing domain's
  published keys. Callers MUST check `resp.verified` -- an `:ok` tuple
  only means the call round-tripped, not that the assertion is trustworthy.
  """
  @spec verify_assertion(RpConfig.t(), String.t(), String.t()) :: {:ok, Types.RpVerifyResponse.t()} | {:error, term}
  def verify_assertion(cfg, signed_assertion, expected_domain) do
    req = %Types.RpVerifyRequest{signed_assertion: signed_assertion, expected_domain: expected_domain}

    with {:ok, resp_bytes} <- rp_call(cfg, "verify-assertion", Types.rp_verify_request_to_cbor(req)) do
      {:ok, Types.rp_verify_response_from_cbor(resp_bytes)}
    end
  end

  @doc "Step 6 (optional): fetch the user's consented claims via your RP server."
  @spec userinfo_fetch(RpConfig.t(), String.t(), String.t(), String.t()) ::
          {:ok, Types.UserInfo.t()} | {:error, term}
  def userinfo_fetch(cfg, token, api_base, domain) do
    req = %Types.RpUserInfoRequest{token: token, api_base: api_base, domain: domain}

    with {:ok, resp_bytes} <- rp_call(cfg, "userinfo-fetch", Types.rp_user_info_request_to_cbor(req)) do
      {:ok, Types.user_info_from_cbor(resp_bytes)}
    end
  end

  @doc """
  Look up the IDP's own `_linkkeys_apis` TXT record for its `https=` base
  URL; fall back to `https://<domain>` if there is none -- matching the
  Rust reference client's `resolve_api_base` (`demoappsite/src/main.rs`).
  Reuses `LinkkeysLocalRp.Dns`'s record name + parser, not a reimplementation.
  """
  @spec resolve_api_base(Dns.resolver(), String.t()) :: String.t()
  def resolve_api_base(dns, domain) do
    fallback = "https://#{domain}"
    name = Dns.linkkeys_apis_dns_name(domain)

    with {:ok, txts} <- dns.(name) do
      Enum.find_value(txts, fallback, fn txt ->
        case safe_parse_apis(txt) do
          %Dns.LinkKeysApis{https_base: base} when is_binary(base) -> base
          _ -> nil
        end
      end)
    else
      _ -> fallback
    end
  end

  defp safe_parse_apis(txt) do
    Dns.parse_linkkeys_apis_txt(txt)
  rescue
    _ -> nil
  end

  @doc "Percent-encode one query value (unreserved chars pass through, everything else is %XX)."
  def url_encode(s) do
    s
    |> to_string()
    |> :binary.bin_to_list()
    |> Enum.map(fn
      c when c in ?A..?Z or c in ?a..?z or c in ?0..?9 or c in [?-, ?_, ?., ?~] -> <<c>>
      c -> "%" <> (Integer.to_string(c, 16) |> String.upcase() |> String.pad_leading(2, "0"))
    end)
    |> IO.iodata_to_binary()
  end

  @doc """
  Build the browser-redirect URL to the user's chosen LinkKeys domain.
  `GET /auth/authorize` only reads `signed_request` and `user_hint`
  (`crates/linkkeys/src/web/mod.rs`'s route signature) -- `relying_party`
  and `callback_url`/`nonce` are carried inside the signed request itself,
  not re-read from the query string, but sending them too (as the Rust
  reference `demoappsite` does) costs nothing and helps a human eyeballing
  the redirect.
  """
  @spec build_authorize_redirect(String.t(), String.t(), String.t(), String.t(), String.t() | nil) :: String.t()
  def build_authorize_redirect(api_base, callback_url, nonce, signed_request, user_hint) do
    params = [
      {"callback_url", callback_url},
      {"nonce", nonce},
      {"user_hint", user_hint || ""},
      {"signed_request", signed_request}
    ]

    query = params |> Enum.map(fn {k, v} -> "#{k}=#{url_encode(v)}" end) |> Enum.join("&")
    "#{api_base}/auth/authorize?#{query}"
  end
end
```

### `RegularRp.AuthState` — the signed-state pattern

`demoappsite/src/main.rs` (the Rust reference integration) keeps its
per-login correlation data (`nonce`, `domain`, `api_base`) in a Rocket
**private** (encrypted) cookie between the redirect and the callback. This
module gets the same effect — tamper-evident, provably-app-minted
correlation state — without requiring a cookie jar with built-in
encryption, by HMAC-signing a small CBOR payload instead:

```elixir
defmodule RegularRp.AuthState do
  @moduledoc """
  A signed, stateless "auth state" token: the login-flow correlation data
  (`nonce`, `domain`, `api_base`) that `demoappsite/src/main.rs` (the Rust
  reference integration) instead keeps in a Rocket **private** (encrypted)
  cookie between the redirect and the callback. This module doesn't require
  a cookie jar with built-in encryption, so it signs the payload with
  HMAC-SHA256 (`:crypto.mac/4`, already an `extra_applications` dependency
  via `:crypto` -- zero hex deps) instead: the payload isn't secret (a
  nonce, a domain name, a URL), it only needs to be tamper-evident and
  provably minted by this app, which HMAC gives you without an AEAD.

  If your web framework already gives you an encrypted+signed session
  (Phoenix's `Plug.Session` with a `:cookie` store, for instance), you can
  drop this module entirely and keep the same three fields in that session
  instead -- this is only here because "any web layer" (per this doc's own
  brief) can't be assumed to have one.

  A signed token by itself only proves *authenticity*, not *single-use* --
  see `RegularRp.UsedNonces` for the other half.
  """

  @tag_len 32

  defmodule Payload do
    @moduledoc "The correlation data carried between the redirect and the callback."
    defstruct [:nonce, :domain, :api_base, :expires_at]
  end

  @doc "Sign `payload` into an opaque, URL-safe token. `secret` is a per-app symmetric key (e.g. `Application.fetch_env!/2`-loaded, never the RP API key itself)."
  @spec sign(Payload.t(), binary) :: String.t()
  def sign(%Payload{} = payload, secret) when is_binary(secret) do
    body =
      LinkkeysLocalRp.Cbor.encode(%{
        "nonce" => payload.nonce,
        "domain" => payload.domain,
        "api_base" => payload.api_base,
        "expires_at" => payload.expires_at
      })

    tag = :crypto.mac(:hmac, :sha256, secret, body)
    Base.url_encode64(body <> tag, padding: false)
  end

  @doc """
  Verify and decode a token minted by `sign/2`. Fails closed: a bad
  signature, a corrupt encoding, or an expired token are each their own
  distinguishable error (constant-time comparison via `:crypto.hash_equals/2`
  on the MAC to avoid a timing oracle on tampered tokens).
  """
  @spec verify(String.t(), binary, DateTime.t()) ::
          {:ok, Payload.t()} | {:error, :bad_encoding | :bad_signature | :expired}
  def verify(token, secret, now \\ DateTime.utc_now()) when is_binary(secret) do
    with {:ok, raw} <- Base.url_decode64(token, padding: false),
         body_len = byte_size(raw) - @tag_len,
         true <- body_len > 0,
         <<body::binary-size(^body_len), tag::binary-size(@tag_len)>> <- raw,
         expected_tag = :crypto.mac(:hmac, :sha256, secret, body),
         true <- :crypto.hash_equals(tag, expected_tag) do
      tree = LinkkeysLocalRp.Cbor.decode(body)

      payload = %Payload{
        nonce: Map.fetch!(tree, "nonce"),
        domain: Map.fetch!(tree, "domain"),
        api_base: Map.fetch!(tree, "api_base"),
        expires_at: Map.fetch!(tree, "expires_at")
      }

      if DateTime.compare(now, DateTime.from_iso8601(payload.expires_at) |> elem(1)) == :gt do
        {:error, :expired}
      else
        {:ok, payload}
      end
    else
      _ -> {:error, :bad_signature}
    end
  rescue
    _ -> {:error, :bad_encoding}
  end
end

defmodule RegularRp.UsedNonces do
  @moduledoc """
  Single-use enforcement for login nonces. `RegularRp.AuthState` only
  proves a callback's state token is authentic and unexpired -- nothing
  about HMAC-signing stops the *same* signed token (or the same
  `encrypted_token` callback URL) from being replayed verbatim. The server
  does not track nonces for you either (`Rp/verify-assertion` returns
  `assertion.nonce`, it doesn't burn it) -- nonce single-use is entirely the
  app's job, called out explicitly in `docs/DEPLOYING-RP.md`'s "Web App
  Integration" section.

  This module is an ETS-backed placeholder: **fine for a single-node demo,
  not for production** -- a real deployment needs a nonce ledger every app
  instance can see (a unique DB constraint on `nonce`, or a shared
  short-TTL cache entry keyed by `nonce`, expiring at/after the assertion's
  own `expires_at`). See "App responsibilities" below for the same point
  made about every sibling SDK's example.
  """

  @table :regular_rp_used_nonces

  @doc "Create the backing ETS table. Call once at app boot."
  def init do
    if :ets.whereis(@table) == :undefined do
      :ets.new(@table, [:set, :public, :named_table])
    end

    :ok
  end

  @doc "Atomically claim `nonce`. Returns `true` the first time for a given nonce, `false` on every subsequent (replay) attempt."
  @spec claim(String.t()) :: boolean
  def claim(nonce) do
    :ets.insert_new(@table, {nonce, true})
  end
end
```

### `RegularRp.Flow` — wiring it together

```elixir
defmodule RegularRp.Flow do
  @moduledoc """
  Wires `RegularRp.Client` + `RegularRp.AuthState` + `RegularRp.UsedNonces`
  into the two calls a web handler needs: `begin_login/4` (redirect the
  browser to the IDP) and `handle_callback/4` (verify what comes back).
  Framework-agnostic on purpose -- see `RegularRp.PlainHandler` below for
  one way to hang these off plain `:gen_tcp` HTTP, and its note on the
  (trivial) Phoenix equivalent.
  """

  alias LinkkeysLocalRp.Dns
  alias RegularRp.AuthState
  alias RegularRp.Client
  alias RegularRp.UsedNonces

  @doc """
  Step 1-2: sign an auth request for `user_domain` and build the browser
  redirect. Returns `{:ok, redirect_url, state_token}` -- `state_token` is
  what the caller must hand back to the browser (a cookie, typically) and
  feed into `handle_callback/4` unchanged.
  """
  @spec begin_login(Client.RpConfig.t(), Dns.resolver(), String.t(), keyword) ::
          {:ok, String.t(), String.t()} | {:error, term}
  def begin_login(cfg, dns, user_domain, opts \\ []) do
    nonce = generate_nonce()
    callback_url = Keyword.fetch!(opts, :callback_url)
    requested_claims = Keyword.get(opts, :requested_claims)
    user_hint = Keyword.get(opts, :user_hint)

    with {:ok, sign_resp} <- Client.sign_request(cfg, callback_url, nonce, requested_claims) do
      api_base = Client.resolve_api_base(dns, user_domain)
      redirect_url = Client.build_authorize_redirect(api_base, callback_url, nonce, sign_resp.signed_request, user_hint)

      state_token =
        AuthState.sign(
          %AuthState.Payload{
            nonce: nonce,
            domain: user_domain,
            api_base: api_base,
            expires_at: DateTime.utc_now() |> DateTime.add(600, :second) |> DateTime.to_iso8601()
          },
          Keyword.fetch!(opts, :state_secret)
        )

      {:ok, redirect_url, state_token}
    end
  end

  @doc """
  Steps 3-6: given the callback's `encrypted_token` and the `state_token`
  this app minted at step 1, decrypt + verify + (optionally) fetch claims.
  Enforces every check that's this app's job and not the server's: state
  signature/expiry, nonce equality against the verified assertion, domain
  equality, and nonce single-use.
  """
  @spec handle_callback(Client.RpConfig.t(), String.t(), String.t(), binary) ::
          {:ok, RegularRp.Types.IdentityAssertion.t()} | {:error, term}
  def handle_callback(cfg, state_token, encrypted_token, state_secret) do
    with {:ok, state} <- AuthState.verify(state_token, state_secret),
         {:ok, decrypt_resp} <- Client.decrypt_token(cfg, encrypted_token),
         {:ok, verify_resp} <- Client.verify_assertion(cfg, decrypt_resp.signed_assertion, state.domain),
         :ok <- check_verified(verify_resp),
         :ok <- check_nonce(verify_resp.assertion, state),
         :ok <- check_domain(verify_resp.assertion, state),
         :ok <- check_single_use(verify_resp.assertion) do
      {:ok, verify_resp.assertion}
    end
  end

  @doc "Optional step 6, kept separate: fetch claims for an already-verified assertion."
  @spec fetch_claims(Client.RpConfig.t(), String.t(), String.t(), String.t()) ::
          {:ok, RegularRp.Types.UserInfo.t()} | {:error, term}
  def fetch_claims(cfg, decrypt_signed_assertion, api_base, domain) do
    Client.userinfo_fetch(cfg, decrypt_signed_assertion, api_base, domain)
  end

  defp check_verified(%{verified: true}), do: :ok
  defp check_verified(%{verified: false}), do: {:error, :assertion_not_verified}

  defp check_nonce(%{nonce: n}, %{nonce: n}), do: :ok
  defp check_nonce(_assertion, _state), do: {:error, :nonce_mismatch}

  defp check_domain(%{domain: d}, %{domain: d}), do: :ok
  defp check_domain(_assertion, _state), do: {:error, :domain_mismatch}

  defp check_single_use(%{nonce: nonce}) do
    if UsedNonces.claim(nonce), do: :ok, else: {:error, :nonce_already_used}
  end

  defp generate_nonce, do: 16 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)
end
```

### `RegularRp.PlainHandler` — a Plug-free HTTP illustration

Your web framework is your own choice; `RegularRp.Flow` above has no
opinion about it. This illustrates the two routes over raw `:gen_tcp` HTTP
(no `Plug`, no `Phoenix`, no dependency beyond OTP) so it's clear nothing
here requires a particular web stack. If your app *is* a Phoenix app, this
whole module becomes two ordinary, `plug`-free controller actions instead
— `Flow.begin_login/4` and `Flow.handle_callback/4` are exactly what those
actions call; only the request-line/cookie parsing below (which
`Plug.Conn` already does for you) goes away.

```elixir
defmodule RegularRp.PlainHandler do
  @moduledoc """
  A tiny HTTP/1.1 handler over raw `:gen_tcp` -- proof that this doc's flow
  needs nothing Plug-shaped. Two routes: `GET /auth/login?domain=...` (starts
  a login) and `GET /auth/callback?encrypted_token=...` (finishes one). If
  your app is a Phoenix app, this whole module is two `plug`-free
  `MyAppWeb.AuthController` actions instead -- `RegularRp.Flow.begin_login/4`
  and `.handle_callback/4` are exactly what the controller actions call;
  only the bytes-on-the-wire plumbing below (request-line/cookie parsing,
  `Plug.Conn` doing this for you in Phoenix) changes.
  """

  alias RegularRp.Flow

  defmodule Ctx do
    @moduledoc "Everything a request handler needs, threaded through explicitly (no process dictionary/application env reach-through)."
    defstruct [:rp_config, :dns, :state_secret, :base_url]
  end

  @doc "Start listening on `port`. Blocks the caller in an accept loop -- run it in its own `Task`/process in a real app."
  def start(port, %Ctx{} = ctx) do
    {:ok, listen_sock} = :gen_tcp.listen(port, [:binary, packet: :line, active: false, reuseaddr: true])
    accept_loop(listen_sock, ctx)
  end

  defp accept_loop(listen_sock, ctx) do
    {:ok, client_sock} = :gen_tcp.accept(listen_sock)
    Task.start(fn -> handle_connection(client_sock, ctx) end)
    accept_loop(listen_sock, ctx)
  end

  defp handle_connection(sock, ctx) do
    with {:ok, request_line} <- :gen_tcp.recv(sock, 0, 10_000),
         [method, target, _version] <- request_line |> String.trim() |> String.split(" ", parts: 3),
         :ok <- :inet.setopts(sock, packet: :httph_bin),
         {headers, _} <- recv_headers(sock, %{}) do
      :inet.setopts(sock, packet: :raw)
      %URI{path: path, query: query} = URI.parse(target)
      params = if query, do: URI.decode_query(query), else: %{}
      cookies = parse_cookies(Map.get(headers, "cookie", ""))

      route(method, path, params, cookies, sock, ctx)
    end
  after
    :gen_tcp.close(sock)
  end

  defp recv_headers(sock, acc) do
    case :gen_tcp.recv(sock, 0, 10_000) do
      {:ok, :http_eoh} ->
        {acc, sock}

      {:ok, {:http_header, _, name, _, value}} ->
        recv_headers(sock, Map.put(acc, name |> to_string() |> String.downcase(), to_string(value)))

      _other ->
        {acc, sock}
    end
  end

  defp parse_cookies(""), do: %{}

  defp parse_cookies(header) do
    header
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reduce(%{}, fn pair, acc ->
      case String.split(pair, "=", parts: 2) do
        [k, v] -> Map.put(acc, k, v)
        _ -> acc
      end
    end)
  end

  defp route("GET", "/auth/login", params, _cookies, sock, ctx) do
    user_domain = Map.get(params, "domain", "")

    if user_domain == "" do
      respond(sock, 400, "text/plain", "missing ?domain=")
    else
      callback_url = "#{ctx.base_url}/auth/callback"

      # requested_claims: nil falls back to the RP server's own
      # RP_CLAIMS_CONFIG defaults (see docs/DEPLOYING-RP.md); pass a
      # %RegularRp.Types.ClaimRequest{} here to override per call.
      case Flow.begin_login(ctx.rp_config, ctx.dns, user_domain,
             callback_url: callback_url,
             state_secret: ctx.state_secret
           ) do
        {:ok, redirect_url, state_token} ->
          headers = [
            {"Location", redirect_url},
            {"Set-Cookie", "lk_auth_state=#{state_token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600"}
          ]

          respond(sock, 302, headers, "")

        {:error, reason} ->
          respond(sock, 502, "text/plain", "could not start login: #{inspect(reason)}")
      end
    end
  end

  defp route("GET", "/auth/callback", params, cookies, sock, ctx) do
    encrypted_token = Map.get(params, "encrypted_token", "")
    state_token = Map.get(cookies, "lk_auth_state")

    cond do
      encrypted_token == "" ->
        respond(sock, 400, "text/plain", "missing ?encrypted_token=")

      is_nil(state_token) ->
        respond(sock, 400, "text/plain", "no pending login found -- it may have expired")

      true ->
        case Flow.handle_callback(ctx.rp_config, state_token, encrypted_token, ctx.state_secret) do
          {:ok, assertion} ->
            clear_cookie = {"Set-Cookie", "lk_auth_state=; Path=/; Max-Age=0"}
            respond(sock, 200, [clear_cookie], "logged in as #{assertion.user_id}@#{assertion.domain}\n")

          {:error, reason} ->
            respond(sock, 403, "text/plain", "login could not be verified: #{inspect(reason)}")
        end
    end
  end

  defp route(_method, _path, _params, _cookies, sock, _ctx) do
    respond(sock, 404, "text/plain", "not found")
  end

  defp respond(sock, status, content_type, body) when is_binary(content_type) do
    respond(sock, status, [{"Content-Type", content_type}], body)
  end

  defp respond(sock, status, headers, body) do
    status_line = "HTTP/1.1 #{status} #{status_text(status)}\r\n"

    header_lines =
      (headers ++ [{"Content-Length", to_string(byte_size(body))}, {"Connection", "close"}])
      |> Enum.map(fn {k, v} -> "#{k}: #{v}\r\n" end)
      |> IO.iodata_to_binary()

    :gen_tcp.send(sock, status_line <> header_lines <> "\r\n" <> body)
  end

  defp status_text(200), do: "OK"
  defp status_text(302), do: "Found"
  defp status_text(400), do: "Bad Request"
  defp status_text(403), do: "Forbidden"
  defp status_text(404), do: "Not Found"
  defp status_text(502), do: "Bad Gateway"
end
```

Wiring it up in a `mix run --no-halt`-able release or an
`Application.start/2` callback:

```elixir
ctx = %RegularRp.PlainHandler.Ctx{
  rp_config: %RegularRp.Client.RpConfig{
    tcp_addr: System.fetch_env!("RP_TCP_ADDR"),
    fingerprints: System.fetch_env!("RP_FINGERPRINTS") |> String.split(",") |> Enum.map(&String.trim/1),
    api_key: System.fetch_env!("RP_API_KEY"),
    domain: System.fetch_env!("RP_DOMAIN")
  },
  dns: &LinkkeysLocalRp.Dns.system_resolver/1,
  state_secret: System.fetch_env!("AUTH_STATE_SECRET") |> Base.decode64!(),
  base_url: System.fetch_env!("PUBLIC_ORIGIN")
}

RegularRp.UsedNonces.init()
Task.start_link(fn -> RegularRp.PlainHandler.start(8080, ctx) end)
```

## What actually ran

`RegularRp.Types`/`Client`/`AuthState`/`UsedNonces`/`Flow`/`PlainHandler`
above are copied verbatim from four `.exs` files compiled cleanly (zero
warnings) with `elixirc`, against this checkout's already-built
`sdks/local-rp/elixir` (`mix compile` first, then `elixirc -pa
_build/dev/lib/linkkeys_local_rp/ebin ...`), using only `LinkkeysLocalRp`'s
public API — no SDK file was modified.

Everything that doesn't need a live RP server + IDP — CBOR envelope
encode/decode, every CSIL type's round trip, the raw-API-key envelope
check, redirect-URL construction, the `AuthState` sign/verify/tamper/expiry
paths, and nonce single-use — was executed for real:

```
== 1. RpSignRequest CBOR round trip (with requested_claims + flow_context) ==
OK   RpSignRequest.from_cbor(to_cbor(req)) == req
== 2. The CSIL-RPC envelope carries the raw API key (no Bearer prefix) ==
OK   envelope.service == "Rp"
OK   envelope.op == "sign-request"
OK   envelope.auth is the raw key, not "Bearer lk_test_key_abc123"
OK   auth field has no Bearer prefix
== 3. RpSignResponse / RpDecryptRequest / RpDecryptResponse / RpVerifyRequest round trips ==
OK   RpSignResponse round trip
OK   RpDecryptRequest encodes encrypted_token
OK   RpDecryptResponse decodes
OK   RpVerifyRequest encodes expected_domain
== 4. RpVerifyResponse (IdentityAssertion) + UserInfo decode from a synthetic server response ==
OK   RpVerifyResponse.verified decodes true
OK   RpVerifyResponse.assertion round trips
OK   UserInfo.user_id decodes
OK   UserInfo.claims decodes one claim
OK   Claim.claim_value round trips through Cbor.Bytes
== 5. Redirect URL construction (Client.build_authorize_redirect) ==
OK   redirect targets the IDP's /auth/authorize
OK   redirect nonce round trips through URL encoding
OK   redirect signed_request round trips through URL encoding
OK   redirect callback_url round trips
== 6. RegularRp.AuthState: sign/verify round trip, tamper detection, expiry ==
OK   AuthState.verify recovers the exact signed payload
OK   AuthState.verify rejects a token signed with a different secret
OK   AuthState.verify rejects a single flipped bit
OK   AuthState.verify rejects an expired token
== 7. Nonce single-use (RegularRp.UsedNonces) ==
OK   first claim of a fresh nonce succeeds
OK   second claim of the same nonce is rejected (replay)
== 8. RegularRp.Flow.handle_callback: nonce/domain equality enforcement (no network) ==
OK   assertion.nonce != state.nonce is rejected
OK   assertion.domain != state.domain is rejected
== 9. RegularRp.Client.resolve_api_base against a fake DNS resolver ==
OK   resolve_api_base parses the https= field
OK   resolve_api_base falls back to https://<domain> when there is no _linkkeys_apis record

ALL CHECKS PASSED
```

`RegularRp.PlainHandler`'s socket/HTTP-parsing/routing code was also
exercised for real — start a live listener, make real `:gen_tcp`
connections against it, and confirm the request-line/query/cookie parsing
and route dispatch behave (the two branches that don't require a live RP
server: missing `?domain=`, missing `?encrypted_token=`, and an unknown
route):

```
GET /auth/login (no domain) ->
HTTP/1.1 400 Bad Request
Content-Type: text/plain
Content-Length: 16
Connection: close

missing ?domain=
OK   missing-domain request gets a real 400 over a real socket

GET /auth/callback (no encrypted_token) ->
HTTP/1.1 400 Bad Request
Content-Type: text/plain
Content-Length: 25
Connection: close

missing ?encrypted_token=
OK   missing-token callback gets a real 400 over a real socket
OK   unknown route gets a real 404 over a real socket

ALL HANDLER SMOKE CHECKS PASSED
```

The parts that genuinely need a live RP server + IDP to exercise
(`Client.rp_call`'s TLS dial, and the full `begin_login`/`handle_callback`
paths beyond the equality checks above) have no fake-carrier seam exposed
for this mode the way `dispatch_for_test` is for the Rust server-side
tests, and standing one up is outside a docs task — same scope limit the
sibling Python and Go examples in this repo note for the same reason.

## App responsibilities

This mirrors what every other LinkKeys SDK in this repo hands back to the
app (see this package's own `README.md`, "App developer responsibilities"):

- **Nonce single-use.** `RegularRp.Flow.handle_callback/4` compares the
  assertion's nonce against the one this app minted and rejects a
  mismatch, but `RegularRp.UsedNonces`'s ETS table is a single-node
  placeholder — persist it durably (a unique DB constraint on `nonce`, or
  a shared short-TTL cache entry keyed by `nonce`, expiring at/after the
  assertion's own `expires_at`) so a replayed `encrypted_token` can't be
  redeemed twice across app restarts or multiple app instances. Nothing
  in the `Rp` service enforces this for your app's callback step.
- **The auth-state token's secret.** `RegularRp.AuthState`'s `secret`
  argument is a symmetric HMAC key *your app* controls — generate it once
  (`:crypto.strong_rand_bytes(32)`), store it the same way you'd store a
  session-signing secret (environment/secret manager, never committed),
  and never confuse it with `RP_API_KEY` (they authorize different
  things: one signs your own short-lived correlation token, the other
  authorizes your RP server calls).
- **Sessions.** `Flow.handle_callback/4` returns verified protocol facts
  (`IdentityAssertion`: `user_id`, `domain`, `authorized_claims`, ...) and
  `Flow.fetch_claims/4` returns `UserInfo` — neither creates a session,
  sets a cookie, or touches a database. Building a local session/user
  record from those facts, and deciding how long it lives, is entirely
  your app's call.
- **API key storage.** `RpConfig.api_key` is a bearer credential for your
  RP server's `Rp` service — anyone holding it can mint
  sign/decrypt/verify calls as your app (though not forge assertions
  outright; the RP server's own domain key is what actually
  signs/decrypts). Store it the same way you'd store a database
  credential: environment/secret manager, never committed, never logged.
  Never log the API key, `encrypted_token`, `signed_assertion`, or claim
  values (`AGENTS.md`'s "Error Handling": never log keys, claim values,
  session tokens, or credentials).
- **Fingerprint pinning.** `RpConfig.fingerprints` is your trust anchor
  for the connection to your own RP server. Rotate it whenever the RP
  server's signing keys rotate (re-run `linkkeys domain dns-check` and
  update your app's config) — an out-of-date fingerprint list means
  `LinkkeysLocalRp.Tls.dial_tls_pinned/4` starts refusing the connection
  outright (fails closed, not open).

## local-RP vs regular-RP

This document covers the **regular** flow: your app runs its own
DNS-pinned RP server, and users log in with identities on any LinkKeys
domain that publishes standard `_linkkeys`/`_linkkeys_apis` DNS records.
That's almost certainly what you want for a normal web app.

`LinkkeysLocalRp`, the package that actually lives in this directory
(`sdks/local-rp/elixir/lib/linkkeys_local_rp/`), implements something
different: **DNS-less local-RP identity** (see `dns-less-local-rp-design.md`
at the repo root). That mode is for apps with **no public DNS at all** — a
LAN jukebox, a desktop tool, a self-hosted service on a home network —
where the app's identity is a locally-generated Ed25519 signing key
fingerprint (SSH-host-key style) rather than a domain, and it must be
individually approved per LinkKeys IDP before it can redeem claim tickets.
It needs no RP server of its own and never touches a domain key, but every
IDP has to explicitly trust its fingerprint first (`linkkeys local-rp
approve <fingerprint>`), and revoking that trust kills the app's access to
that IDP outright.

| | Local RP (`LinkkeysLocalRp`, this directory) | Regular RP (this document) |
|---|---|---|
| App identity | A locally-generated Ed25519 key fingerprint | A DNS domain your app owns |
| DNS required | No | Yes — `_linkkeys` + `_linkkeys_apis` TXT records |
| Where keys live | In the app itself | In a separate RP server process your app talks to over TCP |
| Admission | Explicit per-domain approval, pending until an admin approves | Ordinary DNS-pinned trust, same as any LinkKeys peer |
| Elixir code | `LinkkeysLocalRp.begin_local_login/1` / `.complete_local_login/1` | None packaged — hand-write the glue this document shows, reusing `LinkkeysLocalRp`'s exported transport/TLS/CBOR/DNS pieces |
| Best for | LAN tools, self-hosted apps with no public DNS, desktop apps | Any app that already has (or can get) a domain |

If your app has a domain, use this document's approach. If it doesn't (a
LAN jukebox, a local dev tool), see this package's own `README.md`
instead — its own "App developer responsibilities" and "Quickstart"
sections cover that flow the same way this document covers this one.
