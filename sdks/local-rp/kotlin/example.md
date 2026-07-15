# Worked example: accepting REGULAR (DNS-pinned) LinkKeys logins from Kotlin

This directory's package (`linkkeys-local-rp-kotlin`) implements the **DNS-less
local-RP** identity mode — an app whose identity is a locally-generated
Ed25519 key fingerprint, no public DNS required (see this repo's
`dns-less-local-rp-design.md` and this directory's `README.md`).

This document is the *other* mode: **regular, DNS-pinned LinkKeys login**,
where your app's identity is a real domain name, published in DNS, verified
by every peer via TOFU-pinned `_linkkeys` TXT records. If you own a domain
and can publish DNS records for it, this is almost always the mode you want;
reach for the local-RP SDK only when you specifically have no public DNS
name to pin to (a LAN tool, a self-hosted box behind NAT, ...).

There is **no packaged regular-RP client for Kotlin, or even for Java**. This
document builds one from the pieces that already exist and are verified:
the Java SDK's `rpc`/`wire` packages (`../java`), driven from idiomatic
Kotlin. Every code block below was compiled against those packages via a
Gradle composite build (`includeBuild('../java')`, the same mechanism this
directory's own `settings.gradle` uses) — nothing here is hypothetical.

## Architecture

Per `docs/DEPLOYING-RP.md`: your Kotlin app runs alongside **its own LinkKeys
server in RP mode** — the same `linkkeys` binary/image, different
configuration (`rp.enabled: true` in the Helm chart, or `ENABLE_RP_ENDPOINTS`
outside Helm). Your app never touches a private key; it holds an API key and
talks to its RP server over TCP.

```
┌───────────────────────────────────────────────────────┐
│                Your Application Stack                 │
│                                                         │
│  ┌──────────────┐   TCP CSIL-RPC   ┌──────────────────┐ │
│  │ Kotlin App   │ ───────────────► │ LinkKeys RP      │ │
│  │ (this doc)   │  (API key auth)  │ Server           │ │
│  │              │                  │ (rp mode, holds  │ │
│  │ Sessions,    │                  │  domain keys)    │ │
│  │ redirects    │                  └────────┬─────────┘ │
│  └──────┬───────┘                           │ TCP        │
│         │ browser redirect                  │ (verify /  │
│         ▼                                   │  userinfo) │
└─────────┼───────────────────────────────────┼───────────┘
          │                                   ▼
          │                      ┌─────────────────────────┐
          └─────────────────────►│ User's home LinkKeys IDP │
             browser: GET         │ (any domain, DNS-pinned) │
             /auth/authorize      └─────────────────────────┘
```

Your app's RP server is itself a DNS-pinned domain (it publishes its own
`_linkkeys`/`_linkkeys_apis` TXT records — see "Prerequisites" below); your
app discovers *that* domain's TCP endpoint the same way any LinkKeys peer
discovers any other.

## Prerequisites

1. **Deploy your RP server.** Follow `docs/DEPLOYING-RP.md` in full — Helm
   values, `linkkeys domain init`, DNS `_linkkeys`/`_linkkeys_apis`
   publication. This document picks up after that's done.

2. **Create a service account and API key for your Kotlin app**, and grant it
   the `api_access` relation (`crates/linkkeys/src/services/authorization.rs`
   — `RELATION_API_ACCESS`). This is **not** auto-provisioned: the `Rp`
   service (`sign-request`, `decrypt-token`, `verify-assertion`,
   `userinfo-fetch`, `issue-attestation`) rejects a valid, active API key
   that lacks it (SEC-06 — see `crates/linkkeys/tests/tcp_rp_test.rs` and
   `crates/linkkeys/src/tcp/mod.rs`'s `("Rp", op)` dispatch arm, which checks
   `required_relation_for_op("Rp", op) == RELATION_API_ACCESS` before calling
   `dispatch_rp`). Grant it in one of two ways:

   ```sh
   # One step, at account-creation time:
   kubectl exec -n linkkeys-rp deploy/linkkeys-rp -- \
     linkkeys user create my-webapp "My Web Application" --api-key --relation api_access

   # Or, granted after the fact to an existing user (DB-direct, idempotent):
   kubectl exec -n linkkeys-rp deploy/linkkeys-rp -- \
     linkkeys relation grant-local my-webapp api_access
   ```

   Save the printed API key — it won't be shown again. Store it the way
   you'd store any other service credential (see "App responsibilities"
   below); never log it.

3. **DNS**: your RP server's `_linkkeys.<your-rp-domain>` and
   `_linkkeys_apis.<your-rp-domain>` TXT records must already be published
   (`docs/DEPLOYING-RP.md`, "DNS"). `linkkeys domain dns-check` on the RP pod
   prints the expected record text. Your Kotlin app needs no DNS records of
   its own — it only *resolves* its RP server's.

4. **Toolchain**: JDK 17 + Gradle 8.10.2, via the shared bundle:

   ```sh
   source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
   ```

## Project setup

Your app is its own Gradle project (this is *not* part of
`sdks/local-rp/kotlin` — it has no dependency on this directory's
`LocalRpIdentity`/`beginLocalLogin`/etc., which is the local-RP mode's own
surface). It depends on the sibling Java SDK the same way this directory
does — a composite build, not a published artifact:

```groovy
// settings.gradle
rootProject.name = 'my-webapp'
includeBuild('/path/to/linkkeys/sdks/local-rp/java')
```

```groovy
// build.gradle
plugins {
    id 'org.jetbrains.kotlin.jvm' version '2.2.20'
    id 'application'
}

dependencies {
    implementation 'community.catalyst.linkkeys:linkkeys-local-rp:0.1.0'
}

kotlin { jvmToolchain(17) }
application { mainClass = 'example.AppKt' }
```

The Java SDK's `wire`/`rpc` packages are the only reason this works without
hand-rolling CBOR and TLS pinning again: they're already byte-verified
against the conformance vectors and run on the exact JCA provider (JDK 17
`SunEC`) this project also targets — see this directory's own README,
"Architecture decision", for the fuller argument (it applies here too, just
for the `Rp` service instead of the local-RP protocol).

**What's public and reusable vs. what had to be inlined:** the Java SDK's
`rpc`/`wire` packages were written for the *local-RP* protocol
(`DomainKeys`/`LocalRp` services), but their low-level pieces are
service-agnostic and public:

| Reused from the Java SDK (public) | Inlined here (package-private in the SDK) |
|---|---|
| `rpc.RpcClient.discoverDomainEndpoint` — DNS `fp=`/`tcp=` lookup | `rpc.StreamFraming`'s 4-byte length-prefix framing |
| `rpc.TlsPinning.connectPinned` — mandatory SPKI pin check | `rpc.RpcClient.call`'s dial→TLS→frame→decode orchestration |
| `rpc.RpcEnvelope.Request`/`Response` — the CSIL-RPC envelope, incl. the `auth` field | — |
| `rpc.Transport`/`StdTransport` — the dial seam | — |
| `dns.DnsResolver`/`SystemDnsResolver` | — |
| `wire.Cbor` — the whole canonical-CBOR builder/accessor API | `wire.Codec`'s *specific* request/response mappings (those are for `DomainKeys`/`LocalRp`, not `Rp` — this doc hand-writes the `Rp` service's own mapping directly off the CSIL, using the same public `Cbor` primitives `Codec` itself is built on) |

Nothing in `sdks/local-rp/java` or `sdks/local-rp/kotlin` was modified to
produce this document; everything not in the left column above is
reproduced in the app code below.

## The flow

Regular login is TCP CSIL-RPC end to end. **The `/v1alpha/*.json` HTTP
routes are DEPRECATED** — `docs/DEPLOYING-RP.md` still lists them for
compatibility, but new integrations should not use them; see "A note on the
deprecated HTTP routes" at the end of this document.

1. Your app calls `Rp/sign-request` on its own RP server —
   `{callback_url, nonce, ?requested_claims}` → `{signed_request}`. Envelope
   auth (the CSIL-RPC `auth` field, not an HTTP header) carries the API key.
2. Your app redirects the browser to
   `https://<user's home domain>/auth/authorize?signed_request=<...>`
   (optionally `&user_hint=<...>` to pre-fill a username).
3. The user authenticates at their home IDP and approves the request. The
   browser is redirected back to your `callback_url` with
   `?encrypted_token=<...>`.
4. Your app calls `Rp/decrypt-token` — `{encrypted_token}` → `{signed_assertion}`.
5. Your app calls `Rp/verify-assertion` — `{signed_assertion, expected_domain}`
   → `{assertion, verified}`. `expected_domain` must be the home domain your
   app itself redirected to in step 2 (read from your own session state, never
   from the unverified assertion) — this is what pins the signature check to
   the right domain's keys.
6. Nonce single-use enforcement is **your app's job**: compare
   `assertion.nonce` against the nonce you generated in step 1 and reject a
   reused one. The SDK/protocol layer verifies the signature, not replay.
7. Optionally, your app calls `Rp/userinfo-fetch` — `{token, api_base,
   domain}` → `UserInfo{user_id, domain, display_name, claims}` — to fetch
   the user's released claims.

All five ops (`sign-request`, `decrypt-token`, `verify-assertion`,
`userinfo-fetch`, and `issue-attestation` if your app also issues attested
claims) live under the `Rp` CSIL service
(`csil/linkkeys.csil`, "Relying Party (Rp) helper Types" /
`service Rp { ... }`) and share one API-key-gated TCP client — the
`RegularRpClient` below.

## Kotlin walkthrough

Three files. All three compiled clean (`gradle compileKotlin` and
`gradle build`) against `../java` via the composite build described above.

### `RpWire.kt` — the `Rp` service's CBOR wire mapping

No codec for `RpSignRequest`/`RpVerifyResponse`/etc. exists anywhere (the
Java SDK's `wire.Codec` only carries the local-RP protocol's types). This
hand-writes the mapping directly from `csil/linkkeys.csil`'s field names,
using the same public `wire.Cbor` builder/accessor functions `Codec` itself
is built on — canonical-CBOR map encode/decode, nothing bespoke.

```kotlin
package example

import community.catalyst.linkkeys.localrp.wire.Cbor

// Hand-written CBOR mapping for the `Rp` CSIL service's request/response
// types (csil/linkkeys.csil, "Relying Party (Rp) helper Types"). No codec
// for these exists in the Java SDK's `wire.Codec` -- that class only carries
// the DNS-less local-RP protocol's types -- so this reuses the same public
// `wire.Cbor` builder/accessor functions the Java SDK's own Codec is written
// against, applied to the Rp service's field names directly from the CSIL.

fun encodeRpSignRequest(callbackUrl: String, nonce: String): ByteArray {
    val entries = mutableListOf<Cbor.Entry>()
    Cbor.putText(entries, "callback_url", callbackUrl)
    Cbor.putText(entries, "nonce", nonce)
    return Cbor.encode(Cbor.vmap(entries))
}

fun decodeRpSignResponse(bytes: ByteArray): String {
    val response = Cbor.decode(bytes)
    return Cbor.requireText(response, "signed_request")
}

fun encodeRpDecryptRequest(encryptedToken: String): ByteArray {
    val entries = mutableListOf<Cbor.Entry>()
    Cbor.putText(entries, "encrypted_token", encryptedToken)
    return Cbor.encode(Cbor.vmap(entries))
}

fun decodeRpDecryptResponse(bytes: ByteArray): String {
    val response = Cbor.decode(bytes)
    return Cbor.requireText(response, "signed_assertion")
}

fun encodeRpVerifyRequest(signedAssertion: String, expectedDomain: String): ByteArray {
    val entries = mutableListOf<Cbor.Entry>()
    Cbor.putText(entries, "signed_assertion", signedAssertion)
    Cbor.putText(entries, "expected_domain", expectedDomain)
    return Cbor.encode(Cbor.vmap(entries))
}

/** The subset of `IdentityAssertion` (csil/linkkeys.csil) this example acts
 *  on. `nonce` is what the app's [PendingLogin] check burns single-use;
 *  `domain` is the user's home LinkKeys domain (who signed the assertion);
 *  `audience` is this app's own RP domain (who the assertion was made out
 *  to). */
data class VerifiedAssertion(
    val userId: String,
    val domain: String,
    val audience: String,
    val nonce: String,
    val issuedAt: String,
    val expiresAt: String,
    val authorizedClaims: List<String>,
    val displayName: String?,
)

fun decodeRpVerifyResponse(bytes: ByteArray): VerifiedAssertion {
    val response = Cbor.decode(bytes)
    check(Cbor.asBool(Cbor.require(response, "verified"))) { "assertion did not verify" }
    val assertion = Cbor.require(response, "assertion")
    val authorizedClaims = Cbor.asArray(Cbor.require(assertion, "authorized_claims")).map { Cbor.asText(it) }
    return VerifiedAssertion(
        userId = Cbor.requireText(assertion, "user_id"),
        domain = Cbor.requireText(assertion, "domain"),
        audience = Cbor.requireText(assertion, "audience"),
        nonce = Cbor.requireText(assertion, "nonce"),
        issuedAt = Cbor.requireText(assertion, "issued_at"),
        expiresAt = Cbor.requireText(assertion, "expires_at"),
        authorizedClaims = authorizedClaims,
        displayName = Cbor.optText(assertion, "display_name"),
    )
}

fun encodeRpUserInfoRequest(token: String, apiBase: String, domain: String): ByteArray {
    val entries = mutableListOf<Cbor.Entry>()
    Cbor.putText(entries, "token", token)
    Cbor.putText(entries, "api_base", apiBase)
    Cbor.putText(entries, "domain", domain)
    return Cbor.encode(Cbor.vmap(entries))
}

data class UserClaim(val claimType: String, val claimValue: ByteArray)

data class UserInfo(
    val userId: String,
    val domain: String,
    val displayName: String,
    val claims: List<UserClaim>,
)

fun decodeUserInfo(bytes: ByteArray): UserInfo {
    val response = Cbor.decode(bytes)
    val claims = Cbor.asArray(Cbor.require(response, "claims")).map { claim ->
        UserClaim(
            claimType = Cbor.requireText(claim, "claim_type"),
            claimValue = Cbor.requireBytes(claim, "claim_value"),
        )
    }
    return UserInfo(
        userId = Cbor.requireText(response, "user_id"),
        domain = Cbor.requireText(response, "domain"),
        displayName = Cbor.requireText(response, "display_name"),
        claims = claims,
    )
}
```

### `RegularRpClient.kt` — the TCP CSIL-RPC client

```kotlin
package example

import community.catalyst.linkkeys.localrp.SdkException
import community.catalyst.linkkeys.localrp.dns.DnsResolver
import community.catalyst.linkkeys.localrp.dns.SystemDnsResolver
import community.catalyst.linkkeys.localrp.rpc.RpcClient
import community.catalyst.linkkeys.localrp.rpc.RpcEnvelope
import community.catalyst.linkkeys.localrp.rpc.StdTransport
import community.catalyst.linkkeys.localrp.rpc.TlsPinning
import community.catalyst.linkkeys.localrp.rpc.Transport
import java.io.InputStream
import java.io.OutputStream

/**
 * A thin CSIL-RPC client for this app's own `Rp` service, hosted by the RP
 * server this app is deployed alongside (docs/DEPLOYING-RP.md). There is no
 * packaged "regular RP" client for Kotlin or Java -- unlike the DNS-less
 * local-RP protocol (under `sdks/local-rp`), which ships a full generated-style
 * client, the `Rp` service is a thin server-to-server helper meant to be
 * called directly. This class reuses exactly the pieces of the Java SDK's
 * `rpc`/`wire` packages that are public and carrier-agnostic:
 *
 *  - [RpcClient.discoverDomainEndpoint] -- DNS `_linkkeys`/`_linkkeys_apis`
 *    TXT lookup for the RP server's own domain, fail-closed.
 *  - [TlsPinning.connectPinned] -- mandatory SPKI-fingerprint pin check
 *    before any application byte is sent or read.
 *  - [RpcEnvelope.Request]/[RpcEnvelope.Response] -- the CSIL-RPC envelope
 *    (tag-24 payload, `service`/`op`/`auth`), including the `auth` field
 *    that carries the API key -- this is how TCP requests authenticate
 *    (`crates/linkkeys/src/tcp/mod.rs`'s `authenticate_tcp_request` reads
 *    `envelope.auth` directly as the raw API key, no `Bearer ` prefix; that
 *    prefix is an HTTP-only convention, see the deprecated-HTTP note).
 *
 * The one piece that is NOT public -- `rpc.StreamFraming`'s 4-byte
 * big-endian length-prefix framing, and `RpcClient.call`'s orchestration of
 * it -- is reproduced here rather than reached into, per this doc's rule of
 * inlining what isn't exported instead of modifying the SDK. It is exactly
 * the framing `csil-rpc-transport.md` section 2.3 documents for the
 * byte-stream carrier, so there is nothing SDK-specific about it.
 */
class RegularRpClient(
    private val rpDomain: String,
    private val apiKey: String,
    private val dns: DnsResolver = SystemDnsResolver(),
    private val transport: Transport = StdTransport(),
) {
    /** Send one `Rp/<op>` request and return the decoded success payload, or
     *  throw [SdkException] on any transport/TLS/server-status failure. */
    fun call(op: String, payload: ByteArray): ByteArray {
        val endpoint = RpcClient.discoverDomainEndpoint(dns, rpDomain)
        val hostname = extractHostname(endpoint.tcpAddr())
        val raw = transport.dial(endpoint.tcpAddr())
        TlsPinning.connectPinned(raw, hostname, endpoint.fingerprints()).use { tls ->
            val request = RpcEnvelope.Request("Rp", op, null, payload, apiKey)
            sendFrame(tls.outputStream, request.encode())
            val response = RpcEnvelope.decodeResponse(readFrame(tls.inputStream))
            if (!response.isOk) {
                throw SdkException(response.status, response.error ?: "unknown error")
            }
            return response.payload
        }
    }

    private fun extractHostname(hostPort: String): String {
        if (hostPort.startsWith("[")) {
            val end = hostPort.indexOf(']')
            if (end != -1) return hostPort.substring(1, end)
        }
        val idx = hostPort.lastIndexOf(':')
        return if (idx == -1) hostPort else hostPort.substring(0, idx)
    }

    private fun sendFrame(out: OutputStream, data: ByteArray) {
        val len = data.size
        out.write(
            byteArrayOf(
                (len ushr 24).toByte(),
                (len ushr 16).toByte(),
                (len ushr 8).toByte(),
                len.toByte(),
            ),
        )
        out.write(data)
        out.flush()
    }

    private fun readFrame(input: InputStream): ByteArray {
        val lenBuf = readExact(input, 4)
        val len = ((lenBuf[0].toInt() and 0xff) shl 24) or
            ((lenBuf[1].toInt() and 0xff) shl 16) or
            ((lenBuf[2].toInt() and 0xff) shl 8) or
            (lenBuf[3].toInt() and 0xff)
        if (len !in 0..MAX_FRAME_SIZE) {
            throw SdkException(SdkException.Kind.PROTOCOL, "peer frame too large ($len bytes, max $MAX_FRAME_SIZE)")
        }
        return readExact(input, len)
    }

    private fun readExact(input: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val read = input.read(buf, off, n - off)
            if (read < 0) {
                throw SdkException(SdkException.Kind.TRANSPORT, "connection closed before expected bytes arrived")
            }
            off += read
        }
        return buf
    }

    companion object {
        // Mirrors rpc.StreamFraming.MAX_FRAME_SIZE -- same cap, same reason
        // (a forged length prefix must not drive an unbounded allocation).
        private const val MAX_FRAME_SIZE = 1024 * 1024
    }
}
```

### `App.kt` — login begin + callback handling

A plain `com.sun.net.httpserver.HttpServer` pair of handlers — no extra
dependency beyond what the composite build already provides (per this
project's own dependency-justification bar: every dependency is a
liability). Swap in Ktor/Spring/whatever your app already uses; the
protocol calls (`RegularRpClient.call`, the `RpWire.kt` codecs) don't care.

```kotlin
package example

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpHandler
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/** One browser's in-flight login: the nonce this app signed and the
 *  identity domain the user is authenticating against. Session storage and
 *  single-use nonce tracking are this app's job -- the SDK/protocol layer
 *  returns verified facts and owns no storage (see "App responsibilities"
 *  in example.md). */
private data class PendingLogin(val nonce: String, val homeDomain: String)

/** Minimal in-memory session store, standing in for a real app's session
 *  backend. The shape that matters: [begin] issues a fresh nonce per login
 *  attempt, and [consume] removes the pending entry and rejects a
 *  nonce/session mismatch or replay -- single-use, non-negotiable. */
private class SessionStore {
    private val pending = ConcurrentHashMap<String, PendingLogin>()
    private val redeemedNonces = ConcurrentHashMap.newKeySet<String>()

    fun begin(homeDomain: String): Pair<String, String> {
        val sessionId = randomToken()
        val nonce = randomToken()
        pending[sessionId] = PendingLogin(nonce, homeDomain)
        return sessionId to nonce
    }

    fun peek(sessionId: String): PendingLogin? = pending[sessionId]

    /** Removes the pending entry and marks its nonce redeemed. Returns false
     *  if the session is unknown, the nonce doesn't match what was signed,
     *  or that nonce was already redeemed -- any of those means "reject this
     *  callback," never "log the user in anyway." */
    fun consume(sessionId: String, assertionNonce: String): Boolean {
        val login = pending.remove(sessionId) ?: return false
        if (login.nonce != assertionNonce) return false
        return redeemedNonces.add(login.nonce)
    }

    private fun randomToken(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

/** Loaded once at startup. `rpApiKey` is the API key from
 *  `linkkeys user create ... --api-key`, granted the `api_access` relation
 *  (see example.md "Prerequisites") -- store it the way you'd store any
 *  other service credential, never log it. */
private class AppConfig {
    val rpDomain: String = System.getenv("LINKKEYS_RP_DOMAIN") ?: error("LINKKEYS_RP_DOMAIN not set")
    val rpApiKey: String = System.getenv("LINKKEYS_RP_API_KEY") ?: error("LINKKEYS_RP_API_KEY not set")
    val callbackUrl: String = System.getenv("APP_CALLBACK_URL") ?: "http://localhost:8080/auth/callback"
}

fun main() {
    val config = AppConfig()
    val client = RegularRpClient(rpDomain = config.rpDomain, apiKey = config.rpApiKey)
    val sessions = SessionStore()

    val server = HttpServer.create(InetSocketAddress(8080), 0)
    server.createContext("/login", LoginHandler(client, sessions, config))
    server.createContext("/auth/callback", CallbackHandler(client, sessions))
    server.executor = null
    server.start()
    println("Listening on http://localhost:8080/login?domain=<your-linkkeys-domain>")
}

/**
 * GET /login?domain=<home-domain>
 *
 * Signs an auth request for the user's identity domain and redirects the
 * browser there. This flow supports any DNS-pinned LinkKeys domain per
 * login -- unlike a fixed single-IDP integration, `domain` is whatever the
 * user tells you (a form field, a remembered preference, ...), not a
 * compile-time constant.
 */
private class LoginHandler(
    private val client: RegularRpClient,
    private val sessions: SessionStore,
    private val config: AppConfig,
) : HttpHandler {
    override fun handle(exchange: HttpExchange) {
        val homeDomain = parseQuery(exchange.requestURI)["domain"]
        if (homeDomain.isNullOrBlank()) {
            respond(exchange, 400, "Missing ?domain=<your-linkkeys-domain>")
            return
        }

        val (sessionId, nonce) = sessions.begin(homeDomain)
        val signResponse = client.call(
            "sign-request",
            encodeRpSignRequest(callbackUrl = config.callbackUrl, nonce = nonce),
        )
        val signedRequest = decodeRpSignResponse(signResponse)

        // signed_request is base64url (URL-safe, unpadded per
        // liblinkkeys::encoding), so it drops into the query string as-is.
        val redirectUrl = "https://$homeDomain/auth/authorize?signed_request=$signedRequest"

        exchange.responseHeaders.add("Set-Cookie", "lk_session=$sessionId; Path=/; HttpOnly; SameSite=Lax")
        exchange.responseHeaders.add("Location", redirectUrl)
        exchange.sendResponseHeaders(302, -1)
        exchange.close()
    }
}

/**
 * GET /auth/callback?encrypted_token=<...>
 *
 * Where the browser lands after the user approves (or denies) the login at
 * their identity domain. The `/v1alpha` JSON HTTP routes that could do this
 * instead are DEPRECATED (see example.md) -- this uses the TCP CSIL-RPC
 * `Rp` service throughout, same as `/login` above.
 */
private class CallbackHandler(
    private val client: RegularRpClient,
    private val sessions: SessionStore,
) : HttpHandler {
    override fun handle(exchange: HttpExchange) {
        val encryptedToken = parseQuery(exchange.requestURI)["encrypted_token"]
        val sessionId = readCookie(exchange, "lk_session")
        if (encryptedToken.isNullOrBlank() || sessionId == null) {
            respond(exchange, 400, "Missing encrypted_token or session cookie")
            return
        }
        val pending = sessions.peek(sessionId)
        if (pending == null) {
            respond(exchange, 400, "Unknown or expired session")
            return
        }

        val signedAssertion = decodeRpDecryptResponse(
            client.call("decrypt-token", encodeRpDecryptRequest(encryptedToken)),
        )

        // expected_domain is the identity domain we redirected the browser
        // to in LoginHandler -- verify-assertion checks the assertion's
        // signature against THAT domain's DNS-pinned keys, so this must not
        // be read from the (unverified) assertion itself.
        val assertion = decodeRpVerifyResponse(
            client.call(
                "verify-assertion",
                encodeRpVerifyRequest(signedAssertion = signedAssertion, expectedDomain = pending.homeDomain),
            ),
        )

        if (!sessions.consume(sessionId, assertion.nonce)) {
            respond(exchange, 400, "Nonce already used or session mismatch -- rejecting replay")
            return
        }

        val userInfo = decodeUserInfo(
            client.call(
                "userinfo-fetch",
                encodeRpUserInfoRequest(
                    token = signedAssertion,
                    apiBase = "https://${assertion.domain}",
                    domain = assertion.domain,
                ),
            ),
        )

        // From here on it's this app's own business: create/find a local
        // user record keyed by (assertion.domain, assertion.userId), mint an
        // app session, redirect into the app proper. This example just shows
        // what was learned from the protocol.
        val body = buildString {
            appendLine("Signed in as ${userInfo.displayName} (${userInfo.userId}@${userInfo.domain})")
            appendLine("Authorized claims: ${assertion.authorizedClaims.joinToString()}")
            for (claim in userInfo.claims) {
                appendLine("  ${claim.claimType} = ${String(claim.claimValue, StandardCharsets.UTF_8)}")
            }
        }
        respond(exchange, 200, body)
    }
}

private fun parseQuery(uri: URI): Map<String, String> {
    val raw = uri.rawQuery ?: return emptyMap()
    return raw.split("&").mapNotNull { pair ->
        val idx = pair.indexOf('=')
        if (idx < 0) return@mapNotNull null
        val key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8)
        val value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8)
        key to value
    }.toMap()
}

private fun readCookie(exchange: HttpExchange, name: String): String? {
    val header = exchange.requestHeaders.getFirst("Cookie") ?: return null
    return header.split(";").map { it.trim() }.firstNotNullOfOrNull { part ->
        val idx = part.indexOf('=')
        if (idx < 0 || part.substring(0, idx) != name) null else part.substring(idx + 1)
    }
}

private fun respond(exchange: HttpExchange, status: Int, body: String) {
    val bytes = body.toByteArray(StandardCharsets.UTF_8)
    exchange.sendResponseHeaders(status, bytes.size.toLong())
    exchange.responseBody.use { it.write(bytes) }
}
```

### Running it

```sh
export LINKKEYS_RP_DOMAIN=linkidspec.com      # your RP server's own DNS-pinned domain
export LINKKEYS_RP_API_KEY=lk_...             # from "Prerequisites", step 2
export APP_CALLBACK_URL=http://localhost:8080/auth/callback

source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
gradle run
# then: open http://localhost:8080/login?domain=<a-real-linkkeys-domain>
```

## App responsibilities

None of this is owned by the Java SDK or by `RegularRpClient` — same
boundary this directory's own README draws for the local-RP mode:

- **Nonce single-use**: enforced entirely by `SessionStore.consume` above.
  `Rp/verify-assertion` verifies the *signature*; it does not — and
  architecturally cannot, since the RP server is stateless across calls in
  this flow — track which nonces have already been redeemed. That's this
  app's job, every time.
- **Sessions**: `PendingLogin` (pre-callback) and whatever your app mints
  post-login are both entirely your app's storage. Neither the Java SDK nor
  the `Rp` CSIL service creates or persists a session.
- **API key storage**: the `LINKKEYS_RP_API_KEY` from "Prerequisites" is a
  bearer credential for your RP server's `Rp` service — anyone holding it can
  mint sign-requests and decrypt/verify tokens as your app. Store it the way
  you'd store a database credential (secrets manager, not source control, not
  logs).
- **Claim-derived authorization**: `UserInfo.claims` is a fact returned by
  the protocol; deciding what a user is allowed to do based on those claims
  is application logic, not protocol logic.

## Local-RP vs. regular-RP: which mode do I want?

| | Local-RP (this directory's SDK) | Regular, DNS-pinned (this document) |
|---|---|---|
| App identity | Fingerprint of a locally-generated Ed25519 key | A real domain name, published in DNS |
| Requires public DNS | No | Yes |
| Requires its own RP server | No — the app embeds the SDK directly | Yes — a `linkkeys` server in RP mode |
| Approval model | Per-fingerprint admin approval at each IDP (`linkkeys local-rp approve`) | Ordinary DNS-pinned trust; no per-app approval step |
| Typical use case | LAN tool, self-hosted box behind NAT, no public DNS name | Any normal web app that owns a domain |
| Kotlin package | This directory (`linkkeys-local-rp-kotlin`) | No packaged client — build on `../java`'s `rpc`/`wire`, as this document does |
| Entry points | `generateLocalRpIdentity`, `beginLocalLogin`, `completeLocalLogin` | `Rp/sign-request`, `Rp/decrypt-token`, `Rp/verify-assertion`, `Rp/userinfo-fetch` over TCP CSIL-RPC |

If you're not sure which one you need: if your app already has (or can get)
a domain name and can publish DNS TXT records for it, use regular/DNS-pinned
mode (this document). Local-RP mode exists specifically for the case where
that's not true.

## A note on the deprecated HTTP routes

`docs/DEPLOYING-RP.md` documents three `POST /v1alpha/*.json` routes
(`sign-request.json`, `decrypt-token.json`, `verify-assertion.json`) as an
alternative to the TCP `Rp` service, authenticated with an HTTP
`Authorization: Bearer <api-key>` header instead of the CSIL-RPC envelope's
`auth` field. **These are deprecated** — kept for existing integrations, not
recommended for new ones (see this repo's TCP-first migration: S2S traffic
moved to TCP CSIL-RPC, with HTTP S2S routes kept-but-deprecated; only
browsers are expected to keep using HTTPS). This document's `RegularRpClient`
uses the TCP path throughout for that reason; there is no Kotlin/Java example
of the HTTP path here on purpose.
