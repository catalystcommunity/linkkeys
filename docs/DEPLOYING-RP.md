# Deploying a LinkKeys Relying Party

A relying party (RP) is a LinkKeys server deployed with different configuration.
It uses the same Docker image and Helm chart as a full identity provider. The RP
holds domain keys, signs auth requests, and decrypts tokens on behalf of web
applications — but doesn't serve a login UI or manage human user accounts.

## Architecture

```
┌──────────────────────────────────────────────────┐
│            Your Application Stack                │
│                                                  │
│  ┌──────────────┐    ┌────────────────────────┐  │
│  │   Web App    │    │   LinkKeys RP Server   │  │
│  │  (any lang)  │───►│  (same linkkeys image) │  │
│  │              │    │                        │  │
│  │  HTML/CSS    │    │  ENABLE_RP_ENDPOINTS   │  │
│  │  Sessions    │    │  Holds domain keys     │  │
│  │  Redirects   │    │  Signs auth requests   │  │
│  │              │    │  Decrypts tokens       │  │
│  └──────────────┘    └────────────────────────┘  │
│                                                  │
│  Web app calls RP via bearer-token-authed HTTP.  │
│  Web app NEVER touches private keys.             │
└──────────────────────────────────────────────────┘
```

## Helm Deployment

Use the standard linkkeys Helm chart with RP-mode values:

```yaml
# values-rp.yaml
server:
  domainName: "linkidspec.com"
  domainKeyPassphrase: "<your-passphrase>"
  httpsPort: 8443
  tcpPort: 9000

database:
  backend: sqlite
  url: "/data/linkkeys-rp.db"

rp:
  enabled: true
  apiKeyAuth: true
  passwordAuth: false
```

Deploy:
```bash
helm install linkkeys-rp ./helm_chart -f values-rp.yaml -n linkkeys-rp
```

## Initial Setup

After the RP pod is running, exec into it to initialize domain keys and create
a service account for your web app:

```bash
# Initialize domain keys
kubectl exec -n linkkeys-rp deploy/linkkeys-rp -- \
  linkkeys domain init

# Create a service account for the web app
kubectl exec -n linkkeys-rp deploy/linkkeys-rp -- \
  linkkeys user create my-webapp "My Web Application" --api-key --relation api_access

# Save the printed API key — it won't be shown again
```

Then check your DNS TXT record:
```bash
kubectl exec -n linkkeys-rp deploy/linkkeys-rp -- \
  linkkeys domain dns-check
```

Publish the printed TXT record at `_linkkeys.linkidspec.com` in your DNS.

## Web App Integration

Your web app drives the RP server's `Rp` service over **TCP CSIL-RPC** (the
old `POST /v1alpha/*.json` HTTP routes were removed when S2S moved to TCP, and
the generic HTTP RPC carrier cannot complete this flow — `verify-assertion`
and `userinfo-fetch` need the outbound S2S context only the TCP carrier has):

```
Rp/sign-request      — sign an auth request before redirecting the user
Rp/decrypt-token     — decrypt the encrypted token from the callback
Rp/verify-assertion  — verify the decrypted assertion against the IDP
Rp/userinfo-fetch    — (optional) fetch the user's claims from the IDP
```

The CSIL-RPC request envelope's `auth` field carries the raw API key (no
`Bearer ` prefix — that convention belongs to the remaining HTTP surfaces).
Every `Rp` op additionally requires the caller to hold the `api_access`
relation (SEC-06); see Initial Setup above.

Worked, compile-verified examples per language live beside the local-RP SDKs:
`sdks/local-rp/<language>/example.md` (rust, go, typescript, python, php,
java, kotlin, ...). Rust apps can use the packaged `linkkeys-rpc-client`
crate; `demoappsite/` is the reference integration.

The RP server still serves `GET /v1alpha/domain-keys` and
`GET /v1alpha/domain-keys.json` publicly (no auth), so identity providers can
fetch the RP's public keys for token encryption.

## Demoappsite Example

The demoappsite is a reference integration. Deploy it with:

```yaml
# demoappsite values
rp:
  serviceUrl: "https://linkkeys-rp.linkkeys-rp.svc.cluster.local:8443"
  apiKey: "<the-api-key-from-above>"
  domain: "linkidspec.com"
demoapp:
  allowInvalidCerts: "true"  # only if RP uses self-signed certs
```

## Differences from a Full IDP

| Feature | Full IDP | RP Server |
|---------|---------|-----------|
| Domain keys | Yes | Yes |
| User accounts | Human users + services | Services only (API key auth) |
| Password login form | `/auth/authorize` | Disabled |
| RP endpoints | Optional | Enabled |
| Claims | Yes | Not typically used |
| TCP protocol | Yes | Yes |
| Same Docker image | Yes | Yes |
| Same Helm chart | Yes | Yes (different values) |

## DNS

Publish a `_linkkeys` TXT record for your RP domain:

```
_linkkeys.linkidspec.com TXT "v=lk1 api=https://linkidspec.com fp=<fingerprint1> fp=<fingerprint2> fp=<fingerprint3>"
```

The `domain dns-check` command shows the expected record. Identity providers
look up this record to fetch your public keys for token encryption.

Also publish a `_linkkeys_apis` record advertising your service endpoints. The
`tcp=` endpoint is the first-class, server-to-server transport (the
CSIL-RPC/LinkKeys protocol); `https=` is the browser-adjacent API base:

```
_linkkeys_apis.linkidspec.com TXT "v=lk1 tcp=linkidspec.com https=linkidspec.com"
```

The `tcp=` host (port defaults to 4987) is what peer IDPs/RPs dial — and, behind
a gateway, the SNI hostname they present. Server-to-server traffic
(domain-key fetch, userinfo redemption, attestation deposit, and an RP delegating
to its RP server) flows over `tcp=`; only browsers use the `https=` web API.

## Gateway: TLS passthrough for the protocol port

The LinkKeys TCP protocol does its own mutual TLS, authenticating both ends
against their DNS-published key fingerprints. A gateway must therefore **not**
terminate TLS on the protocol port — it must pass the connection through.

With the Gateway API, enable the chart's `gateway.tlsRoute` (SNI-routed
passthrough). It requires a Gateway listener with `protocol: TLS` and
`tls.mode: Passthrough` on the protocol port; the route matches the client's SNI
(your `tcp=` host) and forwards to the service's `tcp` port. Several domains can
share one passthrough listener, distinguished by SNI. Example values:

```yaml
gateway:
  tlsRoute:
    enabled: true
    parentGateway: contour
    parentNamespace: projectcontour
    parentSection: linkkeys-tls   # a protocol: TLS, mode: Passthrough listener
    hostnames:
      - linkidspec.com
```

For a gateway that routes a whole port (no SNI sharing), use `gateway.tcpRoute`
instead. Both work on any cluster with the Gateway API installed (TLSRoute is in
the experimental channel).
