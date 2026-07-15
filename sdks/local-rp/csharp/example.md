# Worked example: accepting regular (DNS-pinned) LinkKeys logins in C#/.NET

This document is **not** about the `LinkKeys.LocalRp` package this directory
implements. That package is for the *DNS-less local RP* mode
(`dns-less-local-rp-design.md` at the repo root) — apps with no public DNS,
identified by a locally-generated key fingerprint instead of a domain.

This document is for the far more common case: a C#/.NET web app that has (or
is willing to run) its own domain, and wants to accept logins from any
LinkKeys identity — "Sign in with LinkKeys" for `alice@example.com`. That's
**regular RP mode**. There is no packaged C# SDK for it (see "Why there's no
packaged client" below); this document shows you the glue you write yourself,
reusing the pieces of this local-RP SDK that are already `public` and safe to
depend on from outside the SDK's own assembly.

Everything below was built with `dotnet build` (0 warnings, 0 errors) as a
real external project referencing this SDK, and exercised end-to-end against
a live ASP.NET Core process — see "What was compiled and run" at the end.

## Architecture

Per `docs/DEPLOYING-RP.md`: your app runs alongside its **own** LinkKeys
server deployed in RP mode (the same Docker image/binary as a full identity
provider, different configuration — `ENABLE_RP_ENDPOINTS`/`rp.enabled` Helm
values). The RP server holds your domain's private keys, signs auth requests,
and decrypts callback tokens on your behalf. **Your app never touches private
keys** — it authenticates to its own RP server with a plain API key over TCP
CSIL-RPC and asks it to do the crypto.

```
┌──────────────────────────────────────────────────────────┐
│                   Your Application Stack                  │
│                                                            │
│   ┌──────────────┐  TCP CSIL-RPC   ┌────────────────────┐ │
│   │ C#/.NET App  │  (API-key auth, │  LinkKeys RP Server │ │
│   │              │  TLS pinned to  │  (same linkkeys     │ │
│   │  This doc's  │──DNS `fp=`────►│   image, RP config)  │ │
│   │  glue code   │                 │  Holds domain keys  │ │
│   └──────┬───────┘                 └──────────┬──────────┘ │
│          │ HTTP redirect                       │ TCP CSIL-RPC
└──────────┼──────────────────────────────────────┼──────────┘
           ▼                                       ▼
     user's browser                    the *user's* LinkKeys domain
   (goes to their IDP's                (verify-assertion / userinfo-fetch
    /auth/authorize)                    make an onward S2S call here)
```

## Prerequisites

1. **Deploy your RP server.** Follow `docs/DEPLOYING-RP.md` end to end
   (Helm chart with `rp.enabled: true`, `linkkeys domain init` inside the pod,
   and publish the `_linkkeys`/`_linkkeys_apis` DNS TXT records it prints via
   `linkkeys domain dns-check`). You need a real domain you control — this is
   what makes it "regular" (DNS-pinned) RP mode as opposed to local-RP mode.

2. **Create a service account (API key) for your app and grant it
   `api_access`.** Every `Rp` CSIL-RPC operation (`sign-request`,
   `decrypt-token`, `verify-assertion`, `userinfo-fetch`, `issue-attestation`)
   requires the caller's key to hold the dedicated `api_access` relation on
   the RP's domain (SEC-06). A bare valid API key is **not** enough — you'll
   get a `Forbidden` server error until it's granted, and nothing provisions
   it automatically.

   One command does both (mint the key and grant the relation together):

   ```sh
   kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
     linkkeys user create my-webapp "My Web Application" --api-key --relation api_access
   # Save the printed API key — it is shown exactly once.
   ```

   If you already minted a key without `--relation`, or need to repair an
   under-provisioned key, grant it separately (this is DB-direct and
   idempotent, so it's also how you bootstrap the very first key — `relation
   grant` over TCP needs an admin key to already exist; this doesn't):

   ```sh
   kubectl exec -n <rp-namespace> deploy/<rp-deployment> -- \
     linkkeys relation grant-local my-webapp api_access
   ```

   `api_access` is one of five relations `user create --relation`/`relation
   grant-local` validate against (`GRANTABLE_RELATIONS` in
   `services/authorization.rs`): `admin`, `manage_users`, `manage_claims`,
   `api_access`, `issue_claims`. Grant only `api_access` — least privilege for
   a pure RP delegate.

3. **Know your RP server's TCP address and pinned fingerprints.** Your app
   pins its TLS connection to the RP server the same way any LinkKeys peer
   pins a domain: to the SHA-256 fingerprints in that domain's `_linkkeys`
   DNS TXT record (`linkkeys domain dns-check` on the RP prints the exact
   value to publish, and you can read it back the same way). Configure your
   app with:
   - `RP_TCP_ADDR` — `host:port` for the RP server's CSIL-RPC listener
     (default TCP port is `4987`, `LinkKeys.LocalRp.Dns.Dns.DefaultTcpPort`).
   - `RP_FINGERPRINTS` — comma-separated fingerprint set, pinned to the RP's
     own `_linkkeys` record.
   - `RP_API_KEY` — the key from step 2.
   - `APP_BASE_URL` — this app's own public origin (used to build the
     callback URL it hands the RP server).

   These env var names match the reference Rust integration
   (`demoappsite/src/main.rs`'s `RpConfig`) — reuse them verbatim if you're
   deploying alongside this repo's Helm chart, or rename to taste.

## The login flow

Six steps, all but the browser redirect happening over TCP CSIL-RPC to your
own RP server (**not** the user's IDP — your RP server makes any onward
server-to-server calls to the IDP on your behalf):

1. **`Rp/sign-request`** `{callback_url, nonce, ?requested_claims,
   ?flow_context}` → `{signed_request}`. Your app picks a fresh single-use
   `nonce` and its own callback URL; the RP server signs an auth request with
   your domain key. Omit `requested_claims` to fall back to the RP server's
   own `RP_CLAIMS_CONFIG`-configured defaults.
2. **Redirect the browser** to
   `https://<user_domain>/auth/authorize?signed_request=<signed_request>`
   (optionally `&user_hint=<hint>`) — or, more precisely, to the user's
   domain's *published* HTTPS API base (its `_linkkeys_apis` TXT record's
   `https=` field), which normally equals `https://<user_domain>` but can be
   overridden. `user_domain` is whatever LinkKeys domain the *user* chose to
   log in with (e.g. from an `alice@example.com`-shaped identity string) —
   this is **not** your RP's own domain. The IDP's `GET /auth/authorize`
   route only reads `signed_request` and `user_hint`; no other query
   parameters matter.
3. The user authenticates and consents at their IDP, which redirects back to
   your `callback_url` with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** `{encrypted_token}` → `{signed_assertion}`. Only
   your RP server (holder of your domain's private key) can decrypt this.
5. **`Rp/verify-assertion`** `{signed_assertion, expected_domain}` →
   `{assertion, verified}`. Your RP server checks the assertion's signature
   against the *issuing* domain's published keys. **Check `verified` — a call
   that returns without throwing only means it round-tripped, not that the
   assertion is trustworthy.** Reject unless `verified == true`. Nonce
   single-use is your app's job (see below) — this call does not enforce it.
6. **Optional: `Rp/userinfo-fetch`** `{token, api_base, domain}` →
   `UserInfo{user_id, domain, display_name, claims}`. Fetches the user's
   consented claims. Skip it if you only need proof of identity (no claims).

## TCP-only, and the raw-API-key trap

Your app drives the RP server's `Rp` service over **TCP CSIL-RPC only**. The
old `POST /v1alpha/*.json` HTTP routes were removed when S2S moved to TCP, and
the generic HTTP RPC carrier cannot complete this flow — `verify-assertion`
and `userinfo-fetch` need the outbound S2S context only the TCP carrier has.
`docs/DEPLOYING-RP.md`'s "Web App Integration" section documents this same
constraint; treat it as current.

All five `Rp` operations are authenticated the same way: the API key rides
the CSIL-RPC envelope's `auth` field, not an application-level parameter or
header — **and it is the raw key, with no `"Bearer "` prefix.** That
convention belongs to the (removed) HTTP surface; the TCP envelope's `auth`
field is compared byte-for-byte against the stored key
(`crates/linkkeys/src/tcp/mod.rs`'s `authenticate_tcp_request` reads exactly
`envelope.auth`). Prefixing it with `"Bearer "` — an easy copy-paste habit
from HTTP integrations — will authenticate as the literal string `"Bearer
<key>"`, which doesn't exist, and you'll see an `Unauthenticated` server
error. This example's `RpClient.Call` passes the key straight through:

```csharp
var request = new RpcEnvelope.Request("Rp", op, null, payload, cfg.ApiKey);
```

## Why there's no packaged client — and what this example reuses

This SDK (`LinkKeys.LocalRp`) is scoped to the DNS-less local-RP protocol
only — its `Wire`/`Rpc` namespaces hand-write exactly the CBOR types and
CSIL-RPC envelope the `DomainKeys`/`LocalRp` services need, because **no
csilgen generator targets C# today**
(`~/repos/catalystcommunity/csilgen/docs/csilgen-requests/csharp-target-does-not-exist.md`).
The same gap means there's no generated `Rp`-service client either, packaged
or otherwise — this example hand-writes the same way, for the same reason.

This example reuses several things from the SDK, all **already `public`**
and safe for an external app to depend on:

- **`LinkKeys.LocalRp.Rpc.TlsPinning.ConnectPinned`** — the DNS-`fp=`-pinned
  TLS handshake. Exactly the trust construction the RP server itself expects
  a peer to use; reimplementing it would be both wasted effort and a
  correctness risk.
- **`LinkKeys.LocalRp.Rpc.StdTransport`**/`ITransport` — the TCP dial seam
  (permissive address policy by default, matching a co-located RP server that
  is routinely on a private address).
- **`LinkKeys.LocalRp.Rpc.RpcEnvelope`** — the CSIL-RPC request/response
  envelope codec (`Request`/`Response`, including the `auth` field).
- **`LinkKeys.LocalRp.Wire.Cbor`** — the canonical CBOR encoder/decoder
  (`VMapOf`, `PutText`, `RequireText`, etc.). Exported specifically so a
  consumer can hand-write additional wire types against it, which is exactly
  what `RpWire.cs` below does for the `Rp` service's types.
- **`LinkKeys.LocalRp.Wire.Types.Claim`/`ClaimSignature`** — reused directly
  rather than redefined, since `UserInfo.claims` carries the identical CSIL
  `Claim` shape the local-RP SDK already models.
- **`LinkKeys.LocalRp.Dns.Dns`**/`IDnsResolver`/`SystemDnsResolver` — the
  `_linkkeys_apis` TXT record parser and the zero-dependency DNS TXT client,
  reused to resolve the user's domain's HTTPS API base.

**What it does *not* reuse, and why:** `Rpc/StreamFraming.cs` (the 4-byte
length-prefix frame I/O) is `internal` to the SDK assembly — visible only to
the SDK's own test project via `InternalsVisibleTo`. Rather than changing the
SDK to export it, this example **inlines** an equivalent ~20-line routine
(`RpClient.SendFrame`/`ReadFrame` below), built from nothing but `Stream`.
Likewise, `Wire/Codec.cs`'s per-type `Enc*`/`Dec*` helpers (e.g. `EncClaim`)
are `private` — only the top-level `EncodeClaim`/`DecodeClaim` (which
round-trip a *standalone* `Claim` to/from its own byte string) are `public`.
Embedding a `Claim` as one entry in `UserInfo.claims`'s array needs the
map-level encoder, not the standalone one, so `RpWire.cs` hand-writes a
small `EncClaimSignature`/`DecClaim` pair — the same few lines the SDK's own
`Codec.cs` has internally, just not exported for this purpose. If a future
regular-RP C# SDK gets packaged, all of this (`RpWire.cs`, `RpClient.cs`)
is the piece it would centralize.

## The code

### Referencing the SDK

A real external app references the published `LinkKeys.LocalRp` NuGet
package (once one exists) or this repo directly via a git-based/local
`ProjectReference`:

```xml
<ItemGroup>
  <ProjectReference Include="path/to/linkkeys/sdks/local-rp/csharp/src/LinkKeys.LocalRp/LinkKeys.LocalRp.csproj" />
</ItemGroup>
```

This example was compiled as an ASP.NET Core minimal-API project (`dotnet new
web`) with exactly that `ProjectReference` added to its `.csproj`, target
framework `net8.0` (matching the SDK's own).

### `RpWire.cs` — hand-written `Rp` service wire types + CBOR codec

```csharp
using LinkKeys.LocalRp.Wire;

namespace RegularRpDemo.Rp;

/// <summary>
/// Hand-written CSIL wire types for the <c>Rp</c> service
/// (<c>csil/linkkeys.csil</c>, "Relying Party (Rp) helper Types" section). No csilgen
/// C# target exists yet (the local-RP SDK's own <c>Wire/Types.cs</c> explains why), and
/// even if it did, these types are <c>Rp</c>-specific and outside the local-RP SDK's own
/// scope (it only carries the DNS-less <c>LocalRp</c> service's types). So this app
/// hand-writes exactly the structures it needs, the same way the local-RP SDK
/// hand-writes its own.
///
/// <see cref="LinkKeys.LocalRp.Wire.Types.Claim"/> and
/// <see cref="LinkKeys.LocalRp.Wire.Types.ClaimSignature"/> ARE reused from the SDK
/// (public, and byte-for-byte the same CSIL <c>Claim</c>/<c>ClaimSignature</c> structs
/// this service also returns) rather than redefined here.
/// </summary>
public static class RpTypes
{
    public sealed record RequestedClaim(string ClaimType, string Datatype);

    public sealed record ClaimRequest(IReadOnlyList<RequestedClaim> Required, IReadOnlyList<RequestedClaim> Optional);

    /// <summary>Optional signed context for first-login vs. claims-update flows. Not used by this walkthrough; included for CSIL completeness.</summary>
    public sealed record AuthFlowContext(string Flow, string? PriorSession, string? RequestReason);

    public sealed record RpSignRequest(string CallbackUrl, string Nonce, ClaimRequest? RequestedClaims, AuthFlowContext? FlowContext);

    public sealed record RpSignResponse(string SignedRequest);

    public sealed record RpDecryptRequest(string EncryptedToken);

    public sealed record RpDecryptResponse(string SignedAssertion);

    public sealed record RpVerifyRequest(string SignedAssertion, string ExpectedDomain);

    public sealed record IdentityAssertion(
        string UserId,
        string Domain,
        string Audience,
        string Nonce,
        string IssuedAt,
        string ExpiresAt,
        IReadOnlyList<string> AuthorizedClaims,
        string? DisplayName);

    public sealed record RpVerifyResponse(IdentityAssertion Assertion, bool Verified);

    public sealed record RpUserInfoRequest(string Token, string ApiBase, string Domain);

    public sealed record UserInfo(
        string UserId,
        string Domain,
        string DisplayName,
        IReadOnlyList<LinkKeys.LocalRp.Wire.Types.Claim> Claims);
}

/// <summary>
/// CSIL-CBOR encode/decode for <see cref="RpTypes"/>, built on the local-RP SDK's public
/// <see cref="Cbor"/> primitives (canonical map ordering, tag/array/int helpers) — reused
/// rather than reimplemented, since <c>Cbor</c> is exported specifically for this
/// purpose. Only <see cref="Codec"/>'s per-type Enc*/Dec* helpers are SDK-internal
/// (`private`), so the handful this app needs (<c>Claim</c>/<c>ClaimSignature</c>
/// embedding) are hand-written here the same way the SDK itself hand-writes them —
/// there's no way around that short of exporting SDK internals.
/// </summary>
public static class RpCodec
{
    // -----------------------------------------------------------------
    // RequestedClaim / ClaimRequest / AuthFlowContext
    // -----------------------------------------------------------------

    private static Cbor.Value EncRequestedClaim(RpTypes.RequestedClaim v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "claim_type", v.ClaimType);
        Cbor.PutText(e, "datatype", v.Datatype);
        return Cbor.VMapOf(e);
    }

    private static Cbor.Value EncClaimRequest(RpTypes.ClaimRequest v)
    {
        var e = new List<Cbor.Entry>
        {
            Cbor.EntryOf("required", Cbor.VArrayOf(v.Required.Select(EncRequestedClaim).ToList())),
            Cbor.EntryOf("optional", Cbor.VArrayOf(v.Optional.Select(EncRequestedClaim).ToList())),
        };
        return Cbor.VMapOf(e);
    }

    private static Cbor.Value EncAuthFlowContext(RpTypes.AuthFlowContext v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "flow", v.Flow);
        Cbor.PutOptText(e, "prior_session", v.PriorSession);
        Cbor.PutOptText(e, "request_reason", v.RequestReason);
        return Cbor.VMapOf(e);
    }

    // -----------------------------------------------------------------
    // RpSignRequest / RpSignResponse
    // -----------------------------------------------------------------

    public static byte[] EncodeRpSignRequest(RpTypes.RpSignRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "callback_url", v.CallbackUrl);
        Cbor.PutText(e, "nonce", v.Nonce);
        if (v.RequestedClaims is not null)
        {
            e.Add(Cbor.EntryOf("requested_claims", EncClaimRequest(v.RequestedClaims)));
        }

        if (v.FlowContext is not null)
        {
            e.Add(Cbor.EntryOf("flow_context", EncAuthFlowContext(v.FlowContext)));
        }

        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static RpTypes.RpSignResponse DecodeRpSignResponse(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new RpTypes.RpSignResponse(Cbor.RequireText(m, "signed_request"));
    }

    // -----------------------------------------------------------------
    // RpDecryptRequest / RpDecryptResponse
    // -----------------------------------------------------------------

    public static byte[] EncodeRpDecryptRequest(RpTypes.RpDecryptRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "encrypted_token", v.EncryptedToken);
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    public static RpTypes.RpDecryptResponse DecodeRpDecryptResponse(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new RpTypes.RpDecryptResponse(Cbor.RequireText(m, "signed_assertion"));
    }

    // -----------------------------------------------------------------
    // RpVerifyRequest / RpVerifyResponse
    // -----------------------------------------------------------------

    public static byte[] EncodeRpVerifyRequest(RpTypes.RpVerifyRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "signed_assertion", v.SignedAssertion);
        Cbor.PutText(e, "expected_domain", v.ExpectedDomain);
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    private static RpTypes.IdentityAssertion DecIdentityAssertion(Cbor.Value m) => new(
        Cbor.RequireText(m, "user_id"),
        Cbor.RequireText(m, "domain"),
        Cbor.RequireText(m, "audience"),
        Cbor.RequireText(m, "nonce"),
        Cbor.RequireText(m, "issued_at"),
        Cbor.RequireText(m, "expires_at"),
        Cbor.AsArray(Cbor.Require(m, "authorized_claims")).Select(Cbor.AsText).ToList(),
        Cbor.OptText(m, "display_name"));

    public static RpTypes.RpVerifyResponse DecodeRpVerifyResponse(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new RpTypes.RpVerifyResponse(
            DecIdentityAssertion(Cbor.Require(m, "assertion")),
            Cbor.AsBool(Cbor.Require(m, "verified")));
    }

    // -----------------------------------------------------------------
    // RpUserInfoRequest / UserInfo
    // -----------------------------------------------------------------

    public static byte[] EncodeRpUserInfoRequest(RpTypes.RpUserInfoRequest v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "token", v.Token);
        Cbor.PutText(e, "api_base", v.ApiBase);
        Cbor.PutText(e, "domain", v.Domain);
        return Cbor.Encode(Cbor.VMapOf(e));
    }

    // Claim/ClaimSignature map-level (de)serialization. Types reused from the SDK
    // (LinkKeys.LocalRp.Wire.Types); the map shape is hand-written here because the
    // SDK's own equivalent (Wire/Codec.cs's EncClaim/DecClaim) is `private` — it only
    // exists to embed a Claim inside the SDK's own LocalRp response types, not as a
    // general-purpose export. Field-for-field identical to csil/linkkeys.csil's Claim.
    private static Cbor.Value EncClaimSignature(LinkKeys.LocalRp.Wire.Types.ClaimSignature v)
    {
        var e = new List<Cbor.Entry>();
        Cbor.PutText(e, "domain", v.Domain);
        Cbor.PutText(e, "signed_by_key_id", v.SignedByKeyId);
        Cbor.PutBytes(e, "signature", v.Signature);
        return Cbor.VMapOf(e);
    }

    private static LinkKeys.LocalRp.Wire.Types.ClaimSignature DecClaimSignature(Cbor.Value m) => new(
        Cbor.RequireText(m, "domain"),
        Cbor.RequireText(m, "signed_by_key_id"),
        Cbor.RequireBytes(m, "signature"));

    private static LinkKeys.LocalRp.Wire.Types.Claim DecClaim(Cbor.Value m) => new(
        Cbor.RequireText(m, "claim_id"),
        Cbor.RequireText(m, "user_id"),
        Cbor.RequireText(m, "claim_type"),
        Cbor.RequireBytes(m, "claim_value"),
        Cbor.AsArray(Cbor.Require(m, "signatures")).Select(DecClaimSignature).ToList(),
        Cbor.RequireText(m, "attested_at"),
        Cbor.RequireText(m, "created_at"),
        Cbor.OptText(m, "expires_at"),
        Cbor.OptText(m, "revoked_at"));

    public static RpTypes.UserInfo DecodeUserInfo(byte[] data)
    {
        var m = Cbor.Decode(data);
        return new RpTypes.UserInfo(
            Cbor.RequireText(m, "user_id"),
            Cbor.RequireText(m, "domain"),
            Cbor.RequireText(m, "display_name"),
            Cbor.AsArray(Cbor.Require(m, "claims")).Select(DecClaim).ToList());
    }
}
```

### `RpClient.cs` — the RP-call glue

```csharp
using LinkKeys.LocalRp.Rpc;

namespace RegularRpDemo.Rp;

/// <summary>
/// This app's connection to its own co-located RP server (see
/// <c>docs/DEPLOYING-RP.md</c>): a TCP CSIL-RPC address, the RP server's DNS-pinned TLS
/// fingerprints, and the API key minted for this app (see example.md's Prerequisites —
/// <c>linkkeys user create ... --relation api_access</c>).
/// </summary>
public sealed record RpConfig(string TcpAddr, IReadOnlyList<string> Fingerprints, string ApiKey)
{
    public static RpConfig FromEnvironment()
    {
        var tcpAddr = Environment.GetEnvironmentVariable("RP_TCP_ADDR");
        var fingerprintsRaw = Environment.GetEnvironmentVariable("RP_FINGERPRINTS");
        var apiKey = Environment.GetEnvironmentVariable("RP_API_KEY");

        if (string.IsNullOrWhiteSpace(tcpAddr) || string.IsNullOrWhiteSpace(fingerprintsRaw) || string.IsNullOrWhiteSpace(apiKey))
        {
            throw new InvalidOperationException("RP_TCP_ADDR, RP_FINGERPRINTS, and RP_API_KEY must all be set");
        }

        var fingerprints = fingerprintsRaw
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();

        return new RpConfig(tcpAddr, fingerprints, apiKey);
    }
}

/// <summary>
/// Calls the RP server's <c>Rp</c> service over CSIL-RPC/TCP, TLS-pinned to
/// <see cref="RpConfig.Fingerprints"/>. This is this app's own glue, not part of the
/// local-RP SDK — the SDK's <c>RpcClient</c> only calls the <c>DomainKeys</c>/<c>LocalRp</c>
/// services its own DNS-less mode needs. It reuses what the SDK exports for exactly this
/// purpose: <see cref="TlsPinning.ConnectPinned"/> for the pinned handshake,
/// <see cref="StdTransport"/> for the dial, and <see cref="RpcEnvelope"/> for the
/// envelope shape. The one piece it cannot reuse is frame I/O
/// (<c>Rpc/StreamFraming.cs</c> is `internal` to the SDK assembly — visible only to its
/// own test project via <c>InternalsVisibleTo</c>), so <see cref="SendFrame"/>/
/// <see cref="ReadFrame"/> below inline the same ~20-line 4-byte-length-prefix routine,
/// built from nothing but <see cref="Stream"/>.
/// </summary>
public static class RpClient
{
    /// <summary>Mirrors the SDK's own frame cap (<c>Rpc/StreamFraming.cs</c>'s <c>MaxFrameSize</c>) so a forged length prefix can't drive an unbounded allocation.</summary>
    private const int MaxFrameSize = 1024 * 1024;

    private static void SendFrame(Stream stream, byte[] data)
    {
        int len = data.Length;
        stream.Write([(byte)(len >> 24), (byte)(len >> 16), (byte)(len >> 8), (byte)len]);
        stream.Write(data);
        stream.Flush();
    }

    private static byte[] ReadFrame(Stream stream)
    {
        var lenBuf = ReadExact(stream, 4);
        int len = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
        if (len < 0 || len > MaxFrameSize)
        {
            throw new InvalidOperationException($"peer frame too large ({len} bytes, max {MaxFrameSize})");
        }

        return ReadExact(stream, len);
    }

    private static byte[] ReadExact(Stream stream, int n)
    {
        var buf = new byte[n];
        int off = 0;
        while (off < n)
        {
            int read = stream.Read(buf, off, n - off);
            if (read <= 0)
            {
                throw new InvalidOperationException("connection closed before expected bytes arrived");
            }

            off += read;
        }

        return buf;
    }

    private static string ExtractHostname(string hostPort)
    {
        int idx = hostPort.LastIndexOf(':');
        return idx == -1 ? hostPort : hostPort[..idx];
    }

    /// <summary>
    /// Make one API-key-authenticated CSIL-RPC call to the <c>Rp</c> service on this
    /// app's own RP server. The API key rides the envelope's <c>auth</c> field raw — NOT
    /// prefixed with <c>"Bearer "</c> (that's an HTTP-surface convention this TCP
    /// envelope does not use; see <c>crates/linkkeys/src/tcp/mod.rs</c>'s
    /// <c>authenticate_tcp_request</c>, which reads exactly <c>envelope.auth</c>). Every
    /// <c>Rp</c> op additionally requires the key to hold the <c>api_access</c> relation
    /// server-side (SEC-06) — see example.md's Prerequisites.
    /// </summary>
    private static byte[] Call(RpConfig cfg, string op, byte[] payload)
    {
        var transport = new StdTransport();
        var raw = transport.Dial(cfg.TcpAddr);
        var hostname = ExtractHostname(cfg.TcpAddr);
        using var tls = TlsPinning.ConnectPinned(raw, hostname, cfg.Fingerprints);

        var request = new RpcEnvelope.Request("Rp", op, null, payload, cfg.ApiKey);
        SendFrame(tls, request.Encode());
        var respBytes = ReadFrame(tls);
        var resp = RpcEnvelope.DecodeResponse(respBytes);

        if (!resp.IsOk)
        {
            throw new InvalidOperationException($"Rp/{op}: server error ({resp.StatusCode}): {resp.Error}");
        }

        return resp.Payload;
    }

    public static RpTypes.RpSignResponse SignRequest(RpConfig cfg, RpTypes.RpSignRequest req) =>
        RpCodec.DecodeRpSignResponse(Call(cfg, "sign-request", RpCodec.EncodeRpSignRequest(req)));

    public static RpTypes.RpDecryptResponse DecryptToken(RpConfig cfg, RpTypes.RpDecryptRequest req) =>
        RpCodec.DecodeRpDecryptResponse(Call(cfg, "decrypt-token", RpCodec.EncodeRpDecryptRequest(req)));

    public static RpTypes.RpVerifyResponse VerifyAssertion(RpConfig cfg, RpTypes.RpVerifyRequest req) =>
        RpCodec.DecodeRpVerifyResponse(Call(cfg, "verify-assertion", RpCodec.EncodeRpVerifyRequest(req)));

    public static RpTypes.UserInfo UserInfoFetch(RpConfig cfg, RpTypes.RpUserInfoRequest req) =>
        RpCodec.DecodeUserInfo(Call(cfg, "userinfo-fetch", RpCodec.EncodeRpUserInfoRequest(req)));
}
```

### `AuthStateCookie.cs` — the HMAC-signed auth-state cookie

`demoappsite/src/main.rs`'s reference integration keeps its `AuthState`
(nonce + domain, minted before the redirect and re-checked on callback) in a
Rocket "private" (encrypted) cookie. A minimal API has no built-in
private-cookie jar, so this app achieves the same tamper-evidence with a
plain HMAC-SHA256-signed cookie: the payload is not secret (nonce, domain,
and the resolved API base — none of it sensitive), but it **must** be
tamper-evident, because the callback handler trusts it to decide which
nonce/domain to check the verified assertion against.

```csharp
using System.Security.Cryptography;
using System.Text;

namespace RegularRpDemo.Rp;

/// <summary>
/// The state this app must remember, server-side-verifiably, between redirecting the
/// browser to the user's IDP and the callback arriving: which <c>nonce</c> it minted
/// (<c>Rp/sign-request</c>'s input) and which domain it addressed the request to. The
/// callback step re-checks both against the verified assertion (see Program.cs) — this
/// is the app's own replay/confusion defense; <c>Rp/verify-assertion</c> does not enforce
/// it. <c>demoappsite/src/main.rs</c>'s reference integration keeps the equivalent
/// <c>AuthState</c> in a Rocket "private" (encrypted) cookie; this app achieves the same
/// tamper-evidence with a plain HMAC-SHA256-signed cookie, since a minimal API has no
/// built-in private-cookie jar.
/// </summary>
public sealed record AuthState(string Nonce, string Domain, string ApiBase, DateTimeOffset ExpiresAt);

/// <summary>
/// Signs/verifies <see cref="AuthState"/> as an HMAC-SHA256-authenticated cookie value:
/// <c>base64url(payload) + "." + base64url(HMAC-SHA256(key, base64url(payload)))</c>.
/// This is authentication, not secrecy — the payload (nonce + domain + expiry) is not
/// sensitive, but it MUST be tamper-evident, because the callback handler trusts it to
/// decide which nonce/domain to check the verified assertion against. Without the HMAC, a
/// network/XSS attacker who can set cookies could rewrite <c>Domain</c> to redirect a
/// legitimate callback's trust check at an attacker-chosen domain.
/// </summary>
public sealed class AuthStateCookieSigner(byte[] key)
{
    private const string Separator = ".";

    public string Sign(AuthState state)
    {
        var payload = $"{state.Nonce}|{state.Domain}|{state.ApiBase}|{state.ExpiresAt.ToUnixTimeSeconds()}";
        var payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payload));
        var sig = ComputeHmac(payloadB64);
        return $"{payloadB64}{Separator}{Base64UrlEncode(sig)}";
    }

    /// <summary>Verify the HMAC and expiry, returning <c>null</c> for any failure (malformed, tampered, or expired) rather than throwing — a missing/invalid auth-state cookie is an ordinary "your login expired, try again" case, not an exceptional one.</summary>
    public AuthState? Verify(string cookieValue)
    {
        var parts = cookieValue.Split(Separator, 2);
        if (parts.Length != 2)
        {
            return null;
        }

        var expectedSig = ComputeHmac(parts[0]);
        byte[] actualSig;
        try
        {
            actualSig = Base64UrlDecode(parts[1]);
        }
        catch (FormatException)
        {
            return null;
        }

        if (!CryptographicOperations.FixedTimeEquals(expectedSig, actualSig))
        {
            return null;
        }

        string payload;
        try
        {
            payload = Encoding.UTF8.GetString(Base64UrlDecode(parts[0]));
        }
        catch (FormatException)
        {
            return null;
        }

        var fields = payload.Split('|');
        if (fields.Length != 4 || !long.TryParse(fields[3], out var expiresUnix))
        {
            return null;
        }

        var expiresAt = DateTimeOffset.FromUnixTimeSeconds(expiresUnix);
        if (DateTimeOffset.UtcNow > expiresAt)
        {
            return null;
        }

        return new AuthState(fields[0], fields[1], fields[2], expiresAt);
    }

    private byte[] ComputeHmac(string payloadB64) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(payloadB64));

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }

        return Convert.FromBase64String(padded);
    }
}
```

### `Program.cs` — wiring it into ASP.NET Core minimal-API handlers

```csharp
using System.Collections.Concurrent;
using System.Security.Cryptography;
using LinkKeys.LocalRp.Dns;
using RegularRpDemo.Rp;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// ---------------------------------------------------------------------
// Wiring — see example.md's Prerequisites for RP_TCP_ADDR/RP_FINGERPRINTS/RP_API_KEY.
// ---------------------------------------------------------------------

var rpConfig = RpConfig.FromEnvironment();
var dnsResolver = new SystemDnsResolver(); // LinkKeys.LocalRp.Dns — the SDK's public DNS TXT client, reused as-is.
var appBaseUrl = Environment.GetEnvironmentVariable("APP_BASE_URL") ?? "https://localhost:5001";

// Signs the auth-state cookie (nonce/domain/api_base correlation across the redirect).
// A real deployment should persist this key (so a process restart mid-login doesn't
// invalidate in-flight logins) rather than mint a fresh one at startup.
var cookieSigner = new AuthStateCookieSigner(RandomNumberGenerator.GetBytes(32));

// Toy in-memory stand-ins for what a real app already has: a session store and a
// single-use-nonce ledger. See "App responsibilities" in example.md — neither
// survives a restart or works behind more than one replica; a real app needs a durable
// equivalent (DB table, Redis, ...).
var sessions = new ConcurrentDictionary<string, SessionData>();
var usedNonces = new ConcurrentDictionary<string, bool>();

// ---------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------

app.MapGet("/", (HttpContext ctx) =>
{
    if (ctx.Request.Cookies.TryGetValue("lk_session", out var sessionId) && sessions.TryGetValue(sessionId, out var session))
    {
        return Results.Content(DashboardHtml(session), "text/html");
    }

    return Results.Content(LoginFormHtml(null), "text/html");
});

app.MapPost("/auth/login", async (HttpContext ctx) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var identity = form["identity"].ToString().Trim();
    var (userHint, domain) = ParseIdentity(identity);

    if (string.IsNullOrEmpty(domain))
    {
        return Results.Content(LoginFormHtml("Please enter your identity (e.g. you@example.com)"), "text/html");
    }

    // Resolve the user's chosen domain's browser-facing HTTPS API base via its
    // `_linkkeys_apis` TXT record (the `https=` field), reusing the SDK's public DNS
    // parsing helpers exactly as `demoappsite/src/main.rs`'s `resolve_api_base` and the
    // Go sibling example's `resolveAPIBase` do. Falls back to `https://{domain}` if the
    // domain publishes no override.
    var apiBase = ResolveApiBase(dnsResolver, domain);

    var nonce = Guid.NewGuid().ToString();
    var callbackUrl = $"{appBaseUrl}/auth/callback";

    RpTypes.RpSignResponse signResult;
    try
    {
        signResult = RpClient.SignRequest(rpConfig, new RpTypes.RpSignRequest(
            CallbackUrl: callbackUrl,
            Nonce: nonce,
            // Omitting RequestedClaims falls back to the RP server's own
            // RP_CLAIMS_CONFIG-configured defaults, per docs/DEPLOYING-RP.md. Pass an
            // explicit RpTypes.ClaimRequest here to override per-request.
            RequestedClaims: null,
            FlowContext: null));
    }
    catch (Exception e)
    {
        return Results.Content(LoginFormHtml($"Failed to contact RP service: {e.Message}"), "text/html");
    }

    var authState = new AuthState(nonce, domain, apiBase, DateTimeOffset.UtcNow.AddMinutes(10));
    ctx.Response.Cookies.Append("lk_auth_state", cookieSigner.Sign(authState), new CookieOptions
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        MaxAge = TimeSpan.FromMinutes(10),
    });

    var redirectUrl = $"{apiBase}/auth/authorize" +
        $"?signed_request={Uri.EscapeDataString(signResult.SignedRequest)}" +
        (userHint is not null ? $"&user_hint={Uri.EscapeDataString(userHint)}" : "");

    return Results.Redirect(redirectUrl);
});

app.MapGet("/auth/callback", (HttpContext ctx, string? encrypted_token) =>
{
    if (string.IsNullOrEmpty(encrypted_token))
    {
        return Results.Content(ErrorHtml("Missing encrypted_token"), "text/html");
    }

    if (!ctx.Request.Cookies.TryGetValue("lk_auth_state", out var authStateCookie))
    {
        return Results.Content(ErrorHtml("No auth state found — the login flow may have expired"), "text/html");
    }

    ctx.Response.Cookies.Delete("lk_auth_state", new CookieOptions { Path = "/" }); // single use, regardless of outcome

    var authState = cookieSigner.Verify(authStateCookie);
    if (authState is null)
    {
        return Results.Content(ErrorHtml("Auth state cookie failed verification or expired"), "text/html");
    }

    // 1. Decrypt the callback token. Only this app's RP server (holder of this app's
    //    domain private key) can do this.
    RpTypes.RpDecryptResponse decryptResult;
    try
    {
        decryptResult = RpClient.DecryptToken(rpConfig, new RpTypes.RpDecryptRequest(encrypted_token));
    }
    catch (Exception e)
    {
        return Results.Content(ErrorHtml($"Failed to decrypt token: {e.Message}"), "text/html");
    }

    // 2. Verify the assertion against the ISSUING domain's published keys — the domain
    //    this app originally addressed the sign-request to, from the auth-state cookie,
    //    not anything client-supplied on this request.
    RpTypes.RpVerifyResponse verifyResult;
    try
    {
        verifyResult = RpClient.VerifyAssertion(rpConfig, new RpTypes.RpVerifyRequest(decryptResult.SignedAssertion, authState.Domain));
    }
    catch (Exception e)
    {
        return Results.Content(ErrorHtml($"Failed to verify assertion: {e.Message}"), "text/html");
    }

    // A round-tripped call is not a trustworthy one — `Verified` is the actual signature
    // check result and MUST be checked explicitly.
    if (!verifyResult.Verified)
    {
        return Results.Content(ErrorHtml("Assertion did not verify against the issuing domain's published keys"), "text/html");
    }

    var assertion = verifyResult.Assertion;

    // 3. Nonce + domain checks against THIS app's own stored state — Rp/verify-assertion
    //    does not enforce either; that is entirely this app's job.
    if (assertion.Nonce != authState.Nonce)
    {
        return Results.Content(ErrorHtml("Nonce mismatch — possible replay attack"), "text/html");
    }

    if (assertion.Domain != authState.Domain)
    {
        return Results.Content(ErrorHtml("Domain mismatch"), "text/html");
    }

    // 4. Single-use enforcement. See "App responsibilities" — usedNonces is an in-memory
    //    placeholder; persist this durably (unique DB constraint, or a cache entry with a
    //    TTL past assertion.ExpiresAt) so a leaked/replayed encrypted_token can't be
    //    redeemed twice server-side.
    if (!usedNonces.TryAdd(assertion.Nonce, true))
    {
        return Results.Content(ErrorHtml("This login has already been redeemed"), "text/html");
    }

    // 5. Optional: fetch the user's consented claims via this app's RP server (which
    //    proves possession of this app's domain key on the app's behalf). Skippable if
    //    the app only needs proof of identity.
    var claims = new List<ClaimView>();
    try
    {
        var userInfo = RpClient.UserInfoFetch(rpConfig, new RpTypes.RpUserInfoRequest(decryptResult.SignedAssertion, authState.ApiBase, authState.Domain));
        claims.AddRange(userInfo.Claims.Select(c => new ClaimView(
            c.ClaimType,
            System.Text.Encoding.UTF8.GetString(c.ClaimValue),
            c.Signatures.Select(s => s.Domain).Distinct().ToList())));
    }
    catch (Exception e)
    {
        // Non-fatal: this app asked for proof of identity only, or the fetch failed —
        // continue with an authenticated session and no claims rather than failing login.
        app.Logger.LogWarning("userinfo-fetch failed (continuing without claims): {Message}", e.Message);
    }

    var sessionId = Guid.NewGuid().ToString();
    sessions[sessionId] = new SessionData(assertion.UserId, assertion.Domain, assertion.DisplayName ?? assertion.UserId, claims);

    ctx.Response.Cookies.Append("lk_session", sessionId, new CookieOptions
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        MaxAge = TimeSpan.FromHours(24),
    });

    return Results.Redirect("/");
});

app.MapPost("/logout", (HttpContext ctx) =>
{
    if (ctx.Request.Cookies.TryGetValue("lk_session", out var sessionId))
    {
        sessions.TryRemove(sessionId, out _);
    }

    ctx.Response.Cookies.Delete("lk_session", new CookieOptions { Path = "/" });
    return Results.Redirect("/");
});

app.Run();

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

/// <summary>Parse "user@domain" or just "domain" into (user_hint, domain) — mirrors <c>demoappsite/src/main.rs</c>'s <c>parse_identity</c>.</summary>
static (string? UserHint, string Domain) ParseIdentity(string input)
{
    var at = input.LastIndexOf('@');
    if (at > 0 && at < input.Length - 1)
    {
        return (input[..at], input[(at + 1)..]);
    }

    return (null, input);
}

/// <summary>Resolve a domain's HTTPS API base via its <c>_linkkeys_apis</c> TXT record, using the local-RP SDK's public DNS parsing helpers. Falls back to <c>https://{domain}</c> if no record/override is published.</summary>
static string ResolveApiBase(LinkKeys.LocalRp.Dns.IDnsResolver dns, string domain)
{
    var fallback = $"https://{domain}";
    try
    {
        var name = LinkKeys.LocalRp.Dns.Dns.LinkKeysApisDnsName(domain);
        foreach (var txt in dns.TxtLookup(name))
        {
            try
            {
                var apis = LinkKeys.LocalRp.Dns.Dns.ParseLinkKeysApisTxt(txt);
                if (apis.HttpsBase is not null)
                {
                    return apis.HttpsBase;
                }
            }
            catch (DnsParseError)
            {
                // try the next TXT record
            }
        }
    }
    catch (Exception)
    {
        // DNS lookup failed outright — fall back rather than blocking login.
    }

    return fallback;
}

static string HtmlEscape(string s) => System.Net.WebUtility.HtmlEncode(s);

static string LoginFormHtml(string? error)
{
    var errorHtml = error is not null ? $"<p style=\"color:#b42318\">{HtmlEscape(error)}</p>" : "";
    return $$"""
        <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Regular RP Demo</title></head>
        <body>
        <h1>Regular RP Demo</h1>
        <p>Authenticated with <strong>LinkKeys</strong> (regular, DNS-pinned RP mode).</p>
        {{errorHtml}}
        <form method="POST" action="/auth/login">
          <label for="identity">Your Identity</label><br/>
          <input id="identity" type="text" name="identity" placeholder="you@example.com" autofocus />
          <button type="submit">Log In with LinkKeys</button>
        </form>
        </body></html>
        """;
}

static string DashboardHtml(SessionData session)
{
    var claimsHtml = session.Claims.Count == 0
        ? "<p><em>No claims shared.</em></p>"
        : string.Concat(session.Claims.Select(c =>
            $"<li><strong>{HtmlEscape(c.ClaimType)}</strong>: {HtmlEscape(c.Value)} (signed by {HtmlEscape(string.Join(", ", c.SigningDomains))})</li>"));

    return $$"""
        <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Dashboard</title></head>
        <body>
        <h1>Welcome, {{HtmlEscape(session.DisplayName)}}</h1>
        <p>Identity: <code>{{HtmlEscape(session.UserId)}}@{{HtmlEscape(session.Domain)}}</code></p>
        <h3>Claims</h3>
        <ul>{{claimsHtml}}</ul>
        <form method="POST" action="/logout"><button type="submit">Log Out</button></form>
        </body></html>
        """;
}

static string ErrorHtml(string message) => $$"""
    <!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Error</title></head>
    <body><h1>Authentication Error</h1><p style="color:#b42318">{{HtmlEscape(message)}}</p><p><a href="/">Back to login</a></p></body></html>
    """;

sealed record ClaimView(string ClaimType, string Value, IReadOnlyList<string> SigningDomains);

sealed record SessionData(string UserId, string Domain, string DisplayName, IReadOnlyList<ClaimView> Claims);
```

## App responsibilities

Exactly parallel to what the local-RP SDK's own README.md documents for its
`LocalRp`/`Begin`/`Complete` surface — this glue code hands back verified
protocol facts, and these responsibilities are entirely yours, whether you
write this glue by hand (as here) or eventually use a packaged regular-RP
SDK:

- **Nonce single-use.** The callback handler above compares the assertion's
  nonce against the one this app minted and rejects a mismatch, and also
  checks it against `usedNonces` — but that dictionary is an in-memory
  placeholder. Persist it durably (a unique DB constraint, or a cache entry
  with a TTL past the assertion's `ExpiresAt`) so a replayed
  `encrypted_token` can't be redeemed twice server-side. Nothing in the `Rp`
  service enforces this for your app's callback step (the IDP does
  separately burn the assertion once, but only at the point your RP server
  calls `userinfo-fetch` — replay of the callback itself, before that point,
  is on you).
- **The auth-state cookie is authentication, not secrecy.** `AuthStateCookie.cs`
  HMAC-signs the pending nonce/domain/api_base so it can't be tampered with
  in transit or by a client-side attacker, but the *cookie signing key* is
  minted fresh at process startup in this example — a real deployment should
  persist it (or use ASP.NET Core's Data Protection API, which handles key
  persistence/rotation for you) so in-flight logins survive a restart, and
  should scope `lk_auth_state`'s lifetime tightly (this example uses 10
  minutes).
- **Sessions.** This example's `sessions` dictionary is a toy (process-local
  map). Use your app's real session mechanism, and make sure `lk_auth_state`
  (the state tying a browser to its in-flight login) and `lk_session` (the
  logged-in session) are separate cookies with separate lifetimes, and that
  `lk_auth_state` is single-use and short-lived.
- **API key storage.** `RP_API_KEY` (Prerequisites, step 2) authorizes
  signing and decrypting on your domain's behalf — treat it with the same
  care as a database credential, not as ordinary configuration. It's shown
  once at creation time and cannot be retrieved again (mint a new one and
  `deactivate-user`/re-grant if it leaks).
- **Local user records / authorization.** This glue returns
  `IdentityAssertion`/`UserInfo` — protocol facts. Mapping `UserId`+`Domain`
  to a local account, first-login provisioning, and any app-level
  authorization decisions are entirely your app's to make.

## Local-RP vs regular-RP

| | Local RP (`LinkKeys.LocalRp`, this directory) | Regular RP (this document) |
|---|---|---|
| App identity | A locally-generated Ed25519 key fingerprint (SSH-host-key style) | A DNS domain your app owns |
| DNS required | No | Yes — `_linkkeys` + `_linkkeys_apis` TXT records |
| Where keys live | In the app itself (`Identity.LocalRpIdentityToBytes`) | In a separate RP server process your app talks to over TCP |
| Admission | Explicit per-domain approval (`linkkeys local-rp approve <fingerprint>`) — pending until an admin approves | Ordinary DNS-pinned trust, same as any LinkKeys peer |
| C# SDK | This package (`Begin.BeginLocalLogin`/`Complete.CompleteLocalLogin`) | None packaged — hand-write the glue this document shows, reusing `Wire`/`Rpc`/`Dns` from this SDK |
| Best for | LAN tools, self-hosted apps with no public DNS, desktop apps | Any app that already has (or can get) a domain |

If your app has a domain, use this document's approach. If it doesn't (a LAN
jukebox, a local dev tool), see this package's own `README.md` instead.

## What was compiled and run

`RpWire.cs`, `RpClient.cs`, `AuthStateCookie.cs`, and `Program.cs` above are
copied verbatim from a real `dotnet new web` project built in a scratch
directory outside this repo, with a `ProjectReference` pointing at this
checkout's `sdks/local-rp/csharp/src/LinkKeys.LocalRp`:

```sh
source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"   # dotnet 8.0.422
dotnet build   # Build succeeded. 0 Warning(s), 0 Error(s)
```

It was then actually **run** (`dotnet run`) with dummy
`RP_TCP_ADDR`/`RP_FINGERPRINTS`/`RP_API_KEY` values, and exercised over HTTP:

- `GET /` returned `200` and the login form.
- `POST /auth/login` with `identity=alice@example.com` resolved
  `_linkkeys_apis.example.com` over real DNS (no record published, so it fell
  back to `https://example.com` as designed), attempted `Rp/sign-request`
  against the dummy RP address, and — since nothing was listening there —
  cleanly rendered `Failed to contact RP service: 127.0.0.1:4987: Connection
  refused` rather than throwing an unhandled exception, confirming the
  TLS-pinned dial, error propagation, and error-page rendering all work
  end-to-end. (Verifying a full successful round trip additionally requires a
  live RP server and IDP, which is what `docs/DEPLOYING-RP.md` and
  `demoappsite/` provide for manual/staging verification.)
