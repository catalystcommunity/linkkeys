# Accepting regular (DNS-pinned) LinkKeys logins from Java

This directory's `linkkeys-local-rp` SDK implements only the **DNS-less
local-RP** mode (`README.md`, `dns-less-local-rp-design.md`) — for apps with
no public domain of their own. This document is the opposite case: your app
**does** have a domain, or runs alongside one, and wants regular LinkKeys
login, where the identity provider the user logs into is verified against its
own DNS-published keys.

**There is no packaged regular-RP client for Java.** This walkthrough shows
you how to build one directly, reusing the public pieces of this SDK that
apply to any CSIL-RPC/TCP integration (`rpc.RpcEnvelope`, `rpc.TlsPinning`,
`rpc.Transport`/`rpc.StdTransport`, `wire.Cbor`, `dns.Dns`) and hand-writing
the small, `Rp`-service-specific slice this SDK doesn't cover. Every claim
below was checked against this repository's source and the code samples were
compiled against this SDK's built jar — see "How this was verified" at the
end.

## Architecture: you run your own RP server

A regular RP integration is **two processes**: your Java app, and a LinkKeys
server deployed in RP mode next to it (same Docker image, different config —
see `docs/DEPLOYING-RP.md`, which this walkthrough assumes you've read).
The RP server holds your domain's private keys, signs auth requests, and
decrypts tokens; your Java app never touches key material, only an API key.

```
┌──────────────────────────────────────────────────┐
│            Your Application Stack                │
│                                                  │
│  ┌──────────────┐    ┌────────────────────────┐  │
│  │  Your Java   │    │   LinkKeys RP Server   │  │
│  │  App         │───►│  (same linkkeys image) │  │
│  │              │TCP │                        │  │
│  │  Sessions    │CSIL│  Holds domain keys     │  │
│  │  Redirects   │-RPC│  Signs auth requests   │  │
│  │              │    │  Decrypts tokens       │  │
│  └──────────────┘    └────────────────────────┘  │
│                                                  │
│  Your app calls the RP server over TCP CSIL-RPC, │
│  API-key authenticated. It NEVER touches private │
│  keys.                                           │
└──────────────────────────────────────────────────┘
```

Your app's public URL (its `callback_url`) must live under the RP server's
own registered domain — the IDP-side handler rejects a callback host that
isn't the RP's domain or a subdomain of it (`callback_within_rp_domain` in
`crates/linkkeys/src/web/mod.rs`). In practice this means your app and its RP
server share a hostname, split by path at the gateway/ingress (the RP serves
`/v1alpha/*` and `/auth/*`; your app serves everything else) — exactly the
`demoappsite`/`linkidspec.com` reference deployment (`deploy/values-rp.yaml`,
`deploy/values-demoappsite.yaml`) does.

## Prerequisites

1. **Deploy your RP server.** Follow `docs/DEPLOYING-RP.md` in full: Helm
   deploy with RP-mode values, then `linkkeys domain init` and
   `linkkeys domain dns-check` to get your domain's key fingerprints, and
   publish the `_linkkeys`/`_linkkeys_apis` DNS TXT records it prints.

2. **Create an API-key identity for your app** (from that same doc):

   ```bash
   linkkeys user create my-java-app "My Java App" --api-key
   ```

   Save the printed key — it's shown once.

3. **Grant the `api_access` relation.** A bare valid API key is not enough —
   the hardened `Rp` service ops (SEC-06, `crates/linkkeys/src/services/
   authorization.rs`'s `RELATION_API_ACCESS`) additionally require this
   relation on the caller, or every `Rp/*` call comes back `Forbidden`. It is
   **not auto-provisioned** by `user create` unless you pass `--relation`
   there. The exact grant command (`crates/linkkeys/src/cli/mod.rs`'s
   `RelationCommands::GrantLocal`, run where the DB lives — e.g. inside the
   RP pod):

   ```bash
   linkkeys relation grant-local my-java-app api_access
   ```

   Idempotent — safe to re-run. (Equivalently, mint the key with the relation
   already attached: `linkkeys user create my-java-app "My Java App"
   --api-key --relation api_access`.) If you deploy via the repo's
   `deploy/live.sh` helper, the equivalent is:

   ```bash
   ./deploy/live.sh grant my-java-app api_access
   #  or, for a fresh key:
   ./deploy/live.sh api-key my-java-app api_access
   ```

4. **DNS.** Two records under your app's domain, published by whoever
   controls that zone (`docs/DEPLOYING-RP.md` "DNS" section has the exact
   format):
   - `_linkkeys.<your-domain>` — `fp=` key fingerprints (the trust anchor
     other domains use to verify your RP's signatures).
   - `_linkkeys_apis.<your-domain>` — `tcp=` (CSIL-RPC endpoint, default port
     4987) and `https=` (browser-facing API base). Peer IDPs use these to
     fetch your RP's keys over S2S.

   Your Java app does **not** need to DNS-resolve its own RP server — it's
   colocated and you already know its address. Give it directly via config:
   the RP server's `host:port` and the fingerprints from step 1's
   `dns-check` output (same posture `demoappsite`'s `RP_TCP_ADDR`/
   `RP_FINGERPRINTS` env vars take — see `demoappsite/src/main.rs`).

## The login flow, over TCP CSIL-RPC

`docs/DEPLOYING-RP.md`'s "Web App Integration" section documents this TCP
integration (an older revision described a since-removed HTTP JSON surface —
see "The HTTP path doesn't work for this" below for why HTTP cannot work).
TCP CSIL-RPC, calling the CSIL `Rp` service (`csil/linkkeys.csil`), is the
only way to complete this flow today:

1. **`Rp/sign-request`** `{callback_url, nonce, ?requested_claims}` →
   `{signed_request}`. Envelope auth carries your API key (the same `auth`
   field this SDK's own `RpcEnvelope.Request` already has —
   `crates/linkkeys/src/tcp/mod.rs`'s `authenticate_tcp_request` reads it).
2. Redirect the browser to
   `https://<user's home domain>/auth/authorize?signed_request=<...>`
   (optionally `&user_hint=`).
3. The browser comes back to your callback URL with `?encrypted_token=<...>`.
4. **`Rp/decrypt-token`** `{encrypted_token}` → `{signed_assertion}`.
5. **`Rp/verify-assertion`** `{signed_assertion, expected_domain}` →
   `{assertion, verified}`. **Nonce single-use is your app's job** — the
   protocol doesn't enforce it for you.
6. Optionally, **`Rp/userinfo-fetch`** `{token, api_base, domain}` → the
   user's claims.

This is exactly what `demoappsite/src/main.rs` (a real, running reference
integration, just in Rust rather than Java) does via the `linkkeys-rpc-client`
crate; the Java code below reproduces the same five calls.

## The Java walkthrough

### Project setup

Add this SDK as a dependency (published jar, or a `project()` reference if
you vendor this repo). No other runtime dependency is needed — everything
below only uses this SDK's public classes plus the JDK.

```groovy
dependencies {
    implementation files('path/to/linkkeys-local-rp-0.1.0.jar')
    // or, once published: implementation 'community.catalyst.linkkeys:linkkeys-local-rp:0.1.0'
}
```

### What's reused from this SDK, and what's inlined

| Need | Source |
|---|---|
| CSIL-RPC request/response envelope, `auth` field | `rpc.RpcEnvelope.Request`/`.Response` — public, reused directly |
| TLS connect + DNS-pinned fingerprint check | `rpc.TlsPinning.connectPinned` — public, reused directly |
| TCP dial seam | `rpc.Transport`, `rpc.StdTransport` — public, reused directly |
| Canonical CBOR encode/decode | `wire.Cbor` — public, reused directly |
| `_linkkeys_apis` TXT parsing (`https=`) | `dns.Dns.linkkeysApisDnsName`/`.parseLinkKeysApisTxt`, `dns.SystemDnsResolver` — public, reused directly |
| `Claim`/`ClaimSignature` wire shape | `wire.Types.Claim` + `wire.Codec.encodeClaim`/`.decodeClaim` — public, reused directly (identical shape in both services) |
| 4-byte length-prefix frame read/write | `rpc.StreamFraming` does this, but is **package-private** — reproduced inline (`RpRpc.sendFrame`/`.readFrame` below), not by modifying the SDK |
| `Rp`-service request/response types (`RpSignRequest`, `RpVerifyResponse`, `IdentityAssertion`, ...) | Not in this SDK at all (it only has `LocalRp` types) — hand-written below, following the exact pattern `wire.Types`/`wire.Codec` already use |

### `RpWire.java` — the `Rp` service's wire types

```java
package example.rp.wire;

import java.util.List;

/**
 * Hand-written wire types for the CSIL {@code Rp} service (the relying-party
 * helper ops a regular DNS-pinned RP server exposes: sign-request,
 * decrypt-token, verify-assertion, userinfo-fetch). These are NOT part of the
 * {@code linkkeys-local-rp} SDK — that SDK only implements the DNS-less
 * LOCAL-RP mode's {@code LocalRp} service. A regular-RP integration talks to
 * a completely different CSIL service, so it needs its own small set of wire
 * types, following exactly the same hand-written-pending-a-csilgen-Java-target
 * pattern the SDK's own {@code wire.Types} documents (see that class's docs
 * and the filed csilgen request).
 *
 * <p>Field names/shapes mirror {@code csil/linkkeys.csil}'s {@code Rp}
 * section and {@code crates/liblinkkeys/src/generated/types.rs} exactly.
 * {@code community.catalyst.linkkeys.localrp.wire.Types.Claim} and {@code
 * .ClaimSignature} are reused as-is from the SDK for {@link UserInfo#claims}
 * — the {@code Claim} shape is identical in both services, so there's no
 * reason to redefine it.
 */
public final class RpWire {
    private RpWire() {}

    public record RequestedClaim(String claimType, String datatype) {}

    public record ClaimRequest(List<RequestedClaim> required, List<RequestedClaim> optional) {}

    /** {@code flow} is "login" or "claims_update"; {@code priorSession}/{@code requestReason} are optional. */
    public record AuthFlowContext(String flow, String priorSession, String requestReason) {}

    public record RpSignRequest(
            String callbackUrl, String nonce, ClaimRequest requestedClaims, AuthFlowContext flowContext) {
        /** Convenience constructor for the common case: no claim override, no flow context. */
        public RpSignRequest(String callbackUrl, String nonce) {
            this(callbackUrl, nonce, null, null);
        }
    }

    public record RpSignResponse(String signedRequest) {}

    public record RpDecryptRequest(String encryptedToken) {}

    public record RpDecryptResponse(String signedAssertion) {}

    public record IdentityAssertion(
            String userId,
            String domain,
            String audience,
            String nonce,
            String issuedAt,
            String expiresAt,
            List<String> authorizedClaims,
            String displayName) {}

    public record RpVerifyRequest(String signedAssertion, String expectedDomain) {}

    public record RpVerifyResponse(IdentityAssertion assertion, boolean verified) {}

    public record RpUserInfoRequest(String token, String apiBase, String domain) {}

    public record UserInfo(
            String userId,
            String domain,
            String displayName,
            List<community.catalyst.linkkeys.localrp.wire.Types.Claim> claims) {}
}
```

### `RpCodec.java` — canonical CBOR for those types

```java
package example.rp.wire;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import community.catalyst.linkkeys.localrp.wire.Cbor;
import community.catalyst.linkkeys.localrp.wire.Cbor.Entry;
import community.catalyst.linkkeys.localrp.wire.Cbor.Value;
import community.catalyst.linkkeys.localrp.wire.Codec;
import community.catalyst.linkkeys.localrp.wire.Types.Claim;

import example.rp.wire.RpWire.AuthFlowContext;
import example.rp.wire.RpWire.ClaimRequest;
import example.rp.wire.RpWire.IdentityAssertion;
import example.rp.wire.RpWire.RequestedClaim;
import example.rp.wire.RpWire.RpDecryptRequest;
import example.rp.wire.RpWire.RpDecryptResponse;
import example.rp.wire.RpWire.RpSignRequest;
import example.rp.wire.RpWire.RpSignResponse;
import example.rp.wire.RpWire.RpUserInfoRequest;
import example.rp.wire.RpWire.RpVerifyRequest;
import example.rp.wire.RpWire.RpVerifyResponse;
import example.rp.wire.RpWire.UserInfo;

/**
 * Canonical CSIL CBOR encode/decode for {@link RpWire}'s types. Mirrors the
 * local-rp SDK's {@code wire.Codec} pattern exactly (same {@code
 * community.catalyst.linkkeys.localrp.wire.Cbor} helpers, same
 * canonical-sort-at-encode-time reasoning) for a different set of CSIL
 * structures ({@code Rp/*} instead of {@code LocalRp/*}).
 *
 * <p>Verified against {@code crates/liblinkkeys/src/generated/codec.gen.rs}'s
 * {@code csil_enc_rp_*}/{@code csil_dec_rp_*} functions: field order doesn't
 * matter (the SDK's {@code Cbor} encoder sorts canonically, and the Rust
 * decoder looks fields up by key regardless of order), and an absent optional
 * field is simply omitted from the map, never encoded as CBOR null.
 */
public final class RpCodec {
    private RpCodec() {}

    // -----------------------------------------------------------------
    // RequestedClaim / ClaimRequest / AuthFlowContext
    // -----------------------------------------------------------------

    static Value encRequestedClaim(RequestedClaim v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "claim_type", v.claimType());
        Cbor.putText(e, "datatype", v.datatype());
        return Cbor.vmap(e);
    }

    static RequestedClaim decRequestedClaim(Value m) {
        return new RequestedClaim(Cbor.requireText(m, "claim_type"), Cbor.requireText(m, "datatype"));
    }

    static Value encClaimRequest(ClaimRequest v) {
        List<Entry> e = new ArrayList<>();
        e.add(Cbor.entry("required", encArray(v.required(), RpCodec::encRequestedClaim)));
        e.add(Cbor.entry("optional", encArray(v.optional(), RpCodec::encRequestedClaim)));
        return Cbor.vmap(e);
    }

    static ClaimRequest decClaimRequest(Value m) {
        return new ClaimRequest(
                decArray(Cbor.require(m, "required"), RpCodec::decRequestedClaim),
                decArray(Cbor.require(m, "optional"), RpCodec::decRequestedClaim));
    }

    static Value encAuthFlowContext(AuthFlowContext v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "flow", v.flow());
        Cbor.putOptText(e, "prior_session", v.priorSession());
        Cbor.putOptText(e, "request_reason", v.requestReason());
        return Cbor.vmap(e);
    }

    // -----------------------------------------------------------------
    // RpSignRequest / RpSignResponse
    // -----------------------------------------------------------------

    public static byte[] encodeRpSignRequest(RpSignRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "callback_url", v.callbackUrl());
        Cbor.putText(e, "nonce", v.nonce());
        if (v.requestedClaims() != null) {
            e.add(Cbor.entry("requested_claims", encClaimRequest(v.requestedClaims())));
        }
        if (v.flowContext() != null) {
            e.add(Cbor.entry("flow_context", encAuthFlowContext(v.flowContext())));
        }
        return Cbor.encode(Cbor.vmap(e));
    }

    public static RpSignResponse decodeRpSignResponse(byte[] data) {
        Value m = Cbor.decode(data);
        return new RpSignResponse(Cbor.requireText(m, "signed_request"));
    }

    // -----------------------------------------------------------------
    // RpDecryptRequest / RpDecryptResponse
    // -----------------------------------------------------------------

    public static byte[] encodeRpDecryptRequest(RpDecryptRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "encrypted_token", v.encryptedToken());
        return Cbor.encode(Cbor.vmap(e));
    }

    public static RpDecryptResponse decodeRpDecryptResponse(byte[] data) {
        Value m = Cbor.decode(data);
        return new RpDecryptResponse(Cbor.requireText(m, "signed_assertion"));
    }

    // -----------------------------------------------------------------
    // IdentityAssertion / RpVerifyRequest / RpVerifyResponse
    // -----------------------------------------------------------------

    static IdentityAssertion decIdentityAssertion(Value m) {
        List<Value> authorized = Cbor.asArray(Cbor.require(m, "authorized_claims"));
        return new IdentityAssertion(
                Cbor.requireText(m, "user_id"),
                Cbor.requireText(m, "domain"),
                Cbor.requireText(m, "audience"),
                Cbor.requireText(m, "nonce"),
                Cbor.requireText(m, "issued_at"),
                Cbor.requireText(m, "expires_at"),
                authorized.stream().map(Cbor::asText).toList(),
                Cbor.optText(m, "display_name"));
    }

    public static byte[] encodeRpVerifyRequest(RpVerifyRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "signed_assertion", v.signedAssertion());
        Cbor.putText(e, "expected_domain", v.expectedDomain());
        return Cbor.encode(Cbor.vmap(e));
    }

    public static RpVerifyResponse decodeRpVerifyResponse(byte[] data) {
        Value m = Cbor.decode(data);
        return new RpVerifyResponse(
                decIdentityAssertion(Cbor.require(m, "assertion")), Cbor.asBool(Cbor.require(m, "verified")));
    }

    // -----------------------------------------------------------------
    // RpUserInfoRequest / UserInfo
    // -----------------------------------------------------------------

    public static byte[] encodeRpUserInfoRequest(RpUserInfoRequest v) {
        List<Entry> e = new ArrayList<>();
        Cbor.putText(e, "token", v.token());
        Cbor.putText(e, "api_base", v.apiBase());
        Cbor.putText(e, "domain", v.domain());
        return Cbor.encode(Cbor.vmap(e));
    }

    public static UserInfo decodeUserInfo(byte[] data) {
        Value m = Cbor.decode(data);
        List<Value> claimsList = Cbor.asArray(Cbor.require(m, "claims"));
        // Claim is already a public SDK type (wire.Types.Claim) with a public
        // codec (wire.Codec.encodeClaim/decodeClaim) -- reuse it by
        // round-tripping each array element through those public entry
        // points instead of hand-rolling claim decoding a second time. The
        // per-element re-encode is a few bytes of CBOR; clarity wins here.
        List<Claim> claims =
                claimsList.stream().map(item -> Codec.decodeClaim(Cbor.encode(item))).toList();
        return new UserInfo(
                Cbor.requireText(m, "user_id"),
                Cbor.requireText(m, "domain"),
                Cbor.requireText(m, "display_name"),
                claims);
    }

    // -----------------------------------------------------------------
    // Array helpers
    // -----------------------------------------------------------------

    private static <T> Value encArray(List<T> items, Function<T, Value> encOne) {
        List<Value> out = new ArrayList<>(items.size());
        for (T item : items) {
            out.add(encOne.apply(item));
        }
        return Cbor.varray(out);
    }

    private static <T> List<T> decArray(Value v, Function<Value, T> decOne) {
        List<Value> items = Cbor.asArray(v);
        List<T> out = new ArrayList<>(items.size());
        for (Value item : items) {
            out.add(decOne.apply(item));
        }
        return out;
    }
}
```

### `RpRpc.java` — the TCP CSIL-RPC round trip to your own RP server

```java
package example.rp;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.List;

import javax.net.ssl.SSLSocket;

import community.catalyst.linkkeys.localrp.SdkException;
import community.catalyst.linkkeys.localrp.rpc.RpcEnvelope;
import community.catalyst.linkkeys.localrp.rpc.StdTransport;
import community.catalyst.linkkeys.localrp.rpc.TlsPinning;
import community.catalyst.linkkeys.localrp.rpc.Transport;

/**
 * CSIL-RPC to OUR OWN co-located "Rp" server (see {@code
 * docs/DEPLOYING-RP.md}) — API-key authenticated, TLS-pinned to the RP
 * server's DNS-published fingerprints. This is the regular-RP analogue of
 * what {@code community.catalyst.linkkeys.localrp.rpc.RpcClient} does
 * internally for the DNS-less local-RP protocol.
 *
 * <p>{@code RpcClient.call} and {@code rpc.StreamFraming} do exactly this
 * (TLS-pin, send a length-prefixed CBOR envelope, read one back) but both are
 * package-private, so this class reproduces the same two public pieces of
 * the wire contract by hand rather than modifying the SDK:
 * {@link RpcEnvelope.Request}/{@link RpcEnvelope.Response} (public, carry the
 * {@code auth} field this class populates with the API key) and {@link
 * TlsPinning#connectPinned} (public). The 4-byte big-endian length-prefix
 * framing itself is trivial and specified by {@code
 * csil-rpc-transport.md &sect;2.3} — reproduced in {@link #sendFrame}/{@link
 * #readFrame} below, byte-for-byte what {@code rpc.StreamFraming} does.
 */
public final class RpRpc {
    private static final int MAX_FRAME_SIZE = 1024 * 1024;

    private final Transport transport = new StdTransport();
    private final String tcpAddr;
    private final List<String> fingerprints;
    private final String apiKey;

    public RpRpc(String tcpAddr, List<String> fingerprints, String apiKey) {
        this.tcpAddr = tcpAddr;
        this.fingerprints = fingerprints;
        this.apiKey = apiKey;
    }

    /** One request/response round trip to the {@code Rp} service, over a fresh TLS connection. */
    public byte[] call(String op, byte[] payload) {
        Socket raw = transport.dial(tcpAddr);
        String hostname = extractHostname(tcpAddr);
        try (SSLSocket tls = TlsPinning.connectPinned(raw, hostname, fingerprints)) {
            OutputStream out = tls.getOutputStream();
            InputStream in = tls.getInputStream();

            RpcEnvelope.Request request = new RpcEnvelope.Request("Rp", op, null, payload, apiKey);
            sendFrame(out, request.encode());
            byte[] respBytes = readFrame(in);
            RpcEnvelope.Response resp = RpcEnvelope.decodeResponse(respBytes);

            if (!resp.isOk()) {
                throw new SdkException(resp.status(), resp.error() == null ? "unknown error" : resp.error());
            }
            return resp.payload();
        } catch (IOException e) {
            throw new SdkException(SdkException.Kind.TRANSPORT, e.getMessage(), e);
        }
    }

    private static String extractHostname(String hostPort) {
        int idx = hostPort.lastIndexOf(':');
        return idx == -1 ? hostPort : hostPort.substring(0, idx);
    }

    private static void sendFrame(OutputStream out, byte[] data) throws IOException {
        int len = data.length;
        out.write(new byte[] {(byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len});
        out.write(data);
        out.flush();
    }

    private static byte[] readFrame(InputStream in) throws IOException {
        byte[] lenBuf = readExact(in, 4);
        int len = ((lenBuf[0] & 0xff) << 24)
                | ((lenBuf[1] & 0xff) << 16)
                | ((lenBuf[2] & 0xff) << 8)
                | (lenBuf[3] & 0xff);
        if (len < 0 || len > MAX_FRAME_SIZE) {
            throw new IOException("peer frame too large (" + len + " bytes, max " + MAX_FRAME_SIZE + ")");
        }
        return readExact(in, len);
    }

    private static byte[] readExact(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r < 0) {
                throw new EOFException("connection closed before expected bytes arrived");
            }
            off += r;
        }
        return buf;
    }
}
```

### `RpServer.java` — the login/callback handler pair

A plain `com.sun.net.httpserver.HttpServer` (JDK-builtin, no extra
dependency) is the natural shape here — swap it for your framework's
servlet/controller equivalent; the RP calls and their ordering don't change.

```java
package example.rp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import community.catalyst.linkkeys.localrp.dns.Dns;
import community.catalyst.linkkeys.localrp.dns.SystemDnsResolver;
import community.catalyst.linkkeys.localrp.wire.Types.Claim;

import example.rp.wire.RpCodec;
import example.rp.wire.RpWire.ClaimRequest;
import example.rp.wire.RpWire.RequestedClaim;
import example.rp.wire.RpWire.RpDecryptRequest;
import example.rp.wire.RpWire.RpDecryptResponse;
import example.rp.wire.RpWire.RpSignRequest;
import example.rp.wire.RpWire.RpSignResponse;
import example.rp.wire.RpWire.RpUserInfoRequest;
import example.rp.wire.RpWire.RpVerifyRequest;
import example.rp.wire.RpWire.RpVerifyResponse;
import example.rp.wire.RpWire.UserInfo;

/**
 * Minimal regular (DNS-pinned) LinkKeys RP integration for a Java app,
 * plumbing a plain {@link HttpServer} handler pair ({@code /login},
 * {@code /callback}) through {@link RpRpc} to the app's own co-located RP
 * server (see {@code docs/DEPLOYING-RP.md}).
 *
 * <p>This is deliberately a worked example, not a library: a real app would
 * fold this into its own routing/session framework. What matters is the
 * shape of the five calls and the two things this class is responsible for
 * that no SDK can do on its behalf: single-use nonce tracking and session
 * creation.
 */
public final class RpServer {
    /** One in-flight login: the domain + IDP API base recorded when we signed the request. */
    private record PendingLogin(String domain, String apiBase) {}

    /** What we keep after a verified login. A real app would persist this, not hold it in memory. */
    private record Session(String userId, String domain, String displayName, List<Claim> claims) {}

    private final RpRpc rp;
    private final String ownOrigin;
    // Single-use nonce -> pending login. A production app should also expire
    // entries that are never redeemed (e.g. a scheduled sweep by issued-at).
    private final Map<String, PendingLogin> pending = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public RpServer(RpRpc rp, String ownOrigin) {
        this.rp = rp;
        this.ownOrigin = ownOrigin;
    }

    // -----------------------------------------------------------------
    // GET /login?domain=example.com[&user_hint=alice]
    // -----------------------------------------------------------------
    private void handleLogin(HttpExchange exchange) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String domain = query.get("domain");
        if (domain == null || domain.isBlank()) {
            sendText(exchange, 400, "missing ?domain=");
            return;
        }
        String userHint = query.get("user_hint");

        // The claims this app needs. A production app would derive this from
        // its own config, not hardcode it -- shown inline here for brevity.
        ClaimRequest claimRequest = new ClaimRequest(
                List.of(new RequestedClaim("display_name", "text")),
                List.of(new RequestedClaim("email", "email")));

        String apiBase = resolveApiBase(domain);
        String nonce = UUID.randomUUID().toString();
        String callbackUrl = ownOrigin + "/callback?nonce=" + urlEncode(nonce);

        byte[] reqPayload =
                RpCodec.encodeRpSignRequest(new RpSignRequest(callbackUrl, nonce, claimRequest, null));
        byte[] respPayload = rp.call("sign-request", reqPayload);
        RpSignResponse signResponse = RpCodec.decodeRpSignResponse(respPayload);

        pending.put(nonce, new PendingLogin(domain, apiBase));

        StringBuilder redirect = new StringBuilder(apiBase)
                .append("/auth/authorize?signed_request=")
                .append(urlEncode(signResponse.signedRequest()));
        if (userHint != null && !userHint.isBlank()) {
            redirect.append("&user_hint=").append(urlEncode(userHint));
        }

        exchange.getResponseHeaders().add("Location", redirect.toString());
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    // -----------------------------------------------------------------
    // GET /callback?encrypted_token=...&nonce=...
    // -----------------------------------------------------------------
    private void handleCallback(HttpExchange exchange) throws IOException {
        Map<String, String> query = parseQuery(exchange.getRequestURI());
        String encryptedToken = query.get("encrypted_token");
        String nonce = query.get("nonce");
        if (encryptedToken == null || nonce == null) {
            sendText(exchange, 400, "missing encrypted_token or nonce");
            return;
        }

        // Single-use: remove-on-read. A second callback with the same nonce
        // (replay, or a double page load) finds nothing and is rejected.
        PendingLogin login = pending.remove(nonce);
        if (login == null) {
            sendText(exchange, 400, "unknown or already-used nonce");
            return;
        }

        byte[] decryptPayload =
                RpCodec.encodeRpDecryptRequest(new RpDecryptRequest(encryptedToken));
        RpDecryptResponse decrypted =
                RpCodec.decodeRpDecryptResponse(rp.call("decrypt-token", decryptPayload));

        byte[] verifyPayload = RpCodec.encodeRpVerifyRequest(
                new RpVerifyRequest(decrypted.signedAssertion(), login.domain()));
        RpVerifyResponse verified =
                RpCodec.decodeRpVerifyResponse(rp.call("verify-assertion", verifyPayload));

        if (!verified.verified()) {
            sendText(exchange, 400, "assertion did not verify");
            return;
        }
        // Defense in depth: the nonce/domain the assertion carries must match
        // what we recorded, even though the pending-map removal above already
        // enforces single-use of our own state.
        if (!verified.assertion().nonce().equals(nonce)) {
            sendText(exchange, 400, "nonce mismatch");
            return;
        }
        if (!verified.assertion().domain().equals(login.domain())) {
            sendText(exchange, 400, "domain mismatch");
            return;
        }

        byte[] userInfoPayload = RpCodec.encodeRpUserInfoRequest(
                new RpUserInfoRequest(decrypted.signedAssertion(), login.apiBase(), login.domain()));
        UserInfo userInfo = RpCodec.decodeUserInfo(rp.call("userinfo-fetch", userInfoPayload));

        String sessionId = UUID.randomUUID().toString();
        sessions.put(
                sessionId,
                new Session(userInfo.userId(), userInfo.domain(), userInfo.displayName(), userInfo.claims()));

        exchange.getResponseHeaders().add("Location", "/");
        // Demo-only cookie: no Secure attribute because this walkthrough runs
        // plain HTTP for brevity. A production deployment must run behind TLS
        // and add Secure here (see the module docs' TLS note).
        exchange.getResponseHeaders().add(
                "Set-Cookie", "session=" + sessionId + "; HttpOnly; Path=/; SameSite=Lax");
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    /**
     * Look up the target IDP's HTTPS API base from its {@code
     * _linkkeys_apis} TXT record, reusing the local-rp SDK's DNS parsing
     * ({@code dns.Dns}, public) rather than re-implementing TXT parsing.
     * Falls back to {@code https://<domain>} if no record is published.
     */
    private static String resolveApiBase(String domain) {
        SystemDnsResolver resolver = new SystemDnsResolver();
        String name = Dns.linkkeysApisDnsName(domain);
        for (String txt : resolver.txtLookup(name)) {
            try {
                Dns.LinkKeysApis apis = Dns.parseLinkKeysApisTxt(txt);
                if (apis.httpsBase() != null) {
                    return apis.httpsBase();
                }
            } catch (RuntimeException ignored) {
                // try the next TXT record
            }
        }
        return "https://" + domain;
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> out = new java.util.HashMap<>();
        String raw = uri.getRawQuery();
        if (raw == null || raw.isEmpty()) {
            return out;
        }
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            out.put(urlDecode(key), urlDecode(value));
        }
        return out;
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String urlDecode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static void sendText(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    // -----------------------------------------------------------------
    // Wiring
    // -----------------------------------------------------------------

    public static void main(String[] args) throws IOException {
        String tcpAddr = System.getenv().getOrDefault("RP_TCP_ADDR", "127.0.0.1:4987");
        List<String> fingerprints = new ArrayList<>();
        String fpEnv = System.getenv("RP_FINGERPRINTS");
        if (fpEnv != null) {
            for (String fp : fpEnv.split(",")) {
                if (!fp.isBlank()) {
                    fingerprints.add(fp.trim());
                }
            }
        }
        String apiKey = System.getenv().getOrDefault("RP_API_KEY", "");
        String ownOrigin = System.getenv().getOrDefault("APP_ORIGIN", "http://localhost:8080");
        int port = Integer.parseInt(System.getenv().getOrDefault("APP_PORT", "8080"));

        if (fingerprints.isEmpty()) {
            System.err.println("warning: RP_FINGERPRINTS not set -- TCP calls to the RP server will fail to pin its cert");
        }
        if (apiKey.isEmpty()) {
            System.err.println("warning: RP_API_KEY not set -- RP service calls will fail");
        }

        RpRpc rp = new RpRpc(tcpAddr, fingerprints, apiKey);
        RpServer app = new RpServer(rp, ownOrigin);

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/login", app::handleLogin);
        server.createContext("/callback", app::handleCallback);
        server.start();
        System.out.println("listening on http://localhost:" + port + " (RP at " + tcpAddr + ")");
    }
}
```

### Running it

```bash
export RP_TCP_ADDR=127.0.0.1:4987        # your RP server's host:port
export RP_FINGERPRINTS=<fp1>,<fp2>,<fp3> # from `linkkeys domain dns-check`
export RP_API_KEY=<the key from step 2>
export APP_ORIGIN=https://your-app-domain.example
export APP_PORT=8080
java -cp app.jar:linkkeys-local-rp-0.1.0.jar example.rp.RpServer
```

Point a browser at `http://localhost:8080/login?domain=<user's home domain>`
to start a login.

## Callback handling, summarized

`handleCallback` above does the whole verification chain in order:

1. Look up (and immediately remove) the pending login by `nonce` — this
   **is** the single-use enforcement; a replayed or unknown `nonce` finds
   nothing and is rejected before any RP call is made.
2. `Rp/decrypt-token` the `encrypted_token` query parameter.
3. `Rp/verify-assertion` the resulting `signed_assertion`, with
   `expected_domain` set to the domain you started the login for (from the
   pending-login record, not from anything the browser sent — the callback
   URL only carries `nonce` and `encrypted_token`).
4. Re-check `assertion.nonce`/`assertion.domain` against what you recorded,
   as defense in depth on top of the pending-map's single-use removal.
5. Optionally, `Rp/userinfo-fetch` for the user's claims, then build your
   application session.

## App responsibilities (not this SDK's job, not the protocol's job)

- **Nonce single-use.** Neither CSIL nor the RP server enforces this for
  you — `handleCallback`'s `pending.remove(nonce)` is the enforcement point.
  Use a real store (Redis, a DB table with a unique constraint) in
  production instead of the in-memory map above, especially behind more than
  one app instance.
- **API key storage.** Treat `RP_API_KEY` like any other high-value secret —
  a compromised key lets an attacker drive your `Rp/*` ops (though not
  forge signatures; the RP server holds the actual domain private key).
- **Sessions.** This walkthrough builds a `Session` record and a session
  cookie as the simplest illustration; a real app should sign/encrypt the
  cookie (or use an opaque ID against a server-side store, as shown) and set
  `Secure` once served over TLS.
- **TLS in front of your app.** The example above runs plain HTTP for
  brevity. The RP server's own TCP CSIL-RPC channel is separately
  TLS-pinned regardless (that's what `TlsPinning.connectPinned` enforces),
  but your app's own browser-facing HTTP endpoints need real TLS in
  production — `HttpServer` → `HttpsServer` with a real certificate, or a
  TLS-terminating reverse proxy in front.

## Local-RP vs. regular-RP: which one do you want?

| | This directory's SDK (local-RP) | This document (regular-RP) |
|---|---|---|
| Your app has a public domain | No | Yes (or runs alongside one) |
| Trust anchor | A locally-generated Ed25519 key fingerprint (SSH-host-key style), admin-approved per IDP | DNS `_linkkeys` TXT `fp=` records |
| Runs its own RP server | No — the SDK *is* the whole client | Yes — a co-located `linkkeys` server in RP mode |
| CSIL service | `LocalRp` (`redeem-claim-ticket`) | `Rp` (`sign-request`/`decrypt-token`/`verify-assertion`/`userinfo-fetch`) |
| Where the private key lives | Your app process (via `Identity`/`Begin`/`Complete`) | The RP server, never your app |
| Read next | `README.md`, `dns-less-local-rp-design.md` (repo root) | `docs/DEPLOYING-RP.md`, this file |

If your app is a LAN jukebox, a desktop tool, or anything without its own
DNS zone, use this directory's SDK instead — see its `README.md`.

## The HTTP path doesn't work for this

Older revisions of `docs/DEPLOYING-RP.md` documented
`POST /v1alpha/sign-request.json`, `/v1alpha/decrypt-token.json`, and
`/v1alpha/verify-assertion.json` as bearer-token-authed HTTP routes; the doc
now correctly describes the TCP integration. Checked against the current
server (`crates/linkkeys/src/web/mod.rs`'s `routes!` mount list): **none of
those three routes are registered**. Don't build against anything that still
references them.

What HTTP surface *does* exist is a generic CBOR-envelope carrier,
`POST /csil/v1/rpc` (`rpc_cbor` in `web/mod.rs`), which runs the same
`dispatch()` the TCP path uses and so can technically reach any CSIL-RPC
op — including `Rp/sign-request` and `Rp/decrypt-token` — by POSTing a raw
`RpcEnvelope.Request` as the body. But it cannot complete a login: **`Rp/
verify-assertion`, `Rp/userinfo-fetch`, and `Rp/issue-attestation` all
explicitly fail over this carrier** with `"operation unavailable on this
carrier"` (`dispatch_rp` in `crates/linkkeys/src/tcp/mod.rs` — these ops make
an onward server-to-server call to the issuing IDP, and only the TCP carrier
provides the outbound network context they need to do that). Since
verify-assertion is mandatory for every login, **TCP CSIL-RPC isn't just the
recommended transport here, it's the only one that works end to end** — use
it as shown above, not `/csil/v1/rpc`.

Separately, `GET /v1alpha/domain-keys` (CBOR, unauthenticated) is real and
still served — it's how peer IDPs fetch your RP's public keys for token
encryption — but it's server-to-server, not something your app code calls,
and it too carries a `// TODO: deprecated, remove later` comment pointing at
the same eventual TCP-only future as the other legacy `/v1alpha/*`
S2S routes (`domain-keys`, `users/<id>/keys`, `handshake`, `userinfo`).

## How this was verified

- Every wire shape (`RpSignRequest`, `RpVerifyResponse`, `IdentityAssertion`,
  `UserInfo`, `Claim`, ...) was checked against `csil/linkkeys.csil` and
  cross-checked against the field order/optionality the generated Rust codec
  produces (`crates/liblinkkeys/src/generated/codec.gen.rs`) — field order
  turned out not to matter (the Rust decoder looks up by key), and optional
  fields are omitted, never null.
- The flow (which calls, in which order, with which fields) mirrors
  `demoappsite/src/main.rs`, a real Rust RP integration running against a
  real IDP in this repo's live deployment (see `deploy/values-rp.yaml` /
  `deploy/values-demoappsite.yaml`).
- The `api_access` grant requirement and command were checked against
  `crates/linkkeys/src/services/authorization.rs`, `crates/linkkeys/src/
  tcp/mod.rs`'s `("Rp", op)` dispatch arm, `crates/linkkeys/src/cli/mod.rs`'s
  `RelationCommands::GrantLocal`, and `crates/linkkeys/tests/
  rp_authorize_api_access_test.rs`/`tcp_rp_test.rs` (which assert exactly
  this: a valid key without the relation is `Forbidden`).
- All four Java files above were compiled — not just eyeballed — against
  this SDK's real built jar
  (`sdks/local-rp/java/build/libs/linkkeys-local-rp-0.1.0.jar`, built with
  `source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh" && cd
  sdks/local-rp/java && gradle jar`) in a scratch Gradle project, with
  `-Xlint:all` and no warnings. The class/method references shown
  (`RpcEnvelope.Request`/`.Response`, `TlsPinning.connectPinned`,
  `StdTransport`, `Cbor.*`, `Dns.*`, `SystemDnsResolver`, `Types.Claim`,
  `Codec.encodeClaim`/`.decodeClaim`) are exactly what's public in this
  SDK today — nothing here required changing this directory's code.
