# Deploying a LinkKeys Relying Party

A relying party (RP) is a LinkKeys server deployed with different configuration.
It uses the same Docker image and Helm chart as a full identity provider. The RP
holds domain keys, signs auth requests, and decrypts tokens on behalf of web
applications — but doesn't serve a login UI or manage human user accounts.

## Architecture

```
┌─────────────────────────────────────────────────┐
│            Your Application Stack                │
│                                                  │
│  ┌──────────────┐    ┌───────────────────────┐   │
│  │   Web App    │    │   LinkKeys RP Server   │   │
│  │  (any lang)  │───►│  (same linkkeys image) │   │
│  │              │    │                        │   │
│  │  HTML/CSS    │    │  ENABLE_RP_ENDPOINTS   │   │
│  │  Sessions    │    │  Holds domain keys     │   │
│  │  Redirects   │    │  Signs auth requests   │   │
│  │              │    │  Decrypts tokens        │   │
│  └──────────────┘    └───────────────────────┘   │
│                                                  │
│  Web app calls RP via bearer-token-authed HTTP.  │
│  Web app NEVER touches private keys.             │
└─────────────────────────────────────────────────┘
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
  linkkeys user create my-webapp "My Web Application" --api-key

# Save the printed API key — it won't be shown again
```

Then check your DNS TXT record:
```bash
kubectl exec -n linkkeys-rp deploy/linkkeys-rp -- \
  linkkeys domain dns-check
```

Publish the printed TXT record at `_linkkeys.linkidspec.com` in your DNS.

## Web App Integration

Your web app calls the RP's internal API with the bearer token:

```
POST /v1alpha/sign-request.json     — sign an auth request before redirecting the user
POST /v1alpha/decrypt-token.json    — decrypt the encrypted token from the callback
POST /v1alpha/verify-assertion.json — verify the decrypted assertion against the IDP
```

All requests require `Authorization: Bearer <api-key>`.

The web app also serves `GET /v1alpha/domain-keys` and `GET /v1alpha/domain-keys.json`
publicly (no auth), so identity providers can fetch the RP's public keys for
token encryption.

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
