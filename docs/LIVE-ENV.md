# Running a LinkKeys IDP on a domain you have lying around

This guide stands up a real, internet-reachable LinkKeys identity provider for a
domain you control, on a Kubernetes cluster, and sets up an **encrypted backup**
you can keep offline. The headline property: you can **tear the whole thing down
and rebuild it from scratch — even a newer version, even on different storage —
without changing any public DNS records**, and it keeps working.

It assumes a cluster with the [Contour](https://projectcontour.io/) Gateway API
(or any Gateway/ingress that can route HTTP to a service and terminate TLS) and a
durable storage class for the SQLite volume. The shared tooling is
`deploy/live.sh`; your host-specific settings live outside the repo in
`~/linkkeys/env`.

## Why DNS survives a rebuild

A domain's trust anchor is its `_linkkeys` TXT record, which lists SHA-256
**fingerprints of the domain signing keys**. Those fingerprints are deterministic
from the key material, and the private keys live encrypted (under
`DOMAIN_KEY_PASSPHRASE`) inside the database. So a domain's stable identity is
**its database + that passphrase**. A LinkKeys backup captures both. Restore them
and the keys come back byte-identical → the fingerprints are unchanged → the
`_linkkeys` record never has to change. The address (`A`) and `_linkkeys_apis`
records point at stable hostnames/your gateway, so they don't change either.

## 1. Configure

```sh
cp deploy/live.env.example ~/linkkeys/env
$EDITOR ~/linkkeys/env            # set NAMESPACE, RELEASE, DOMAIN, VALUES, ...
cp deploy/examples/values-idp-sqlite.yaml ~/linkkeys/values-<yourdomain>.yaml
$EDITOR ~/linkkeys/values-<yourdomain>.yaml   # set the hostnames + storage class
```

The values overlay is a normal Helm values file for `helm_chart/`. The key fields
for an IDP are `server.domainName` (your apex), `server.apiHostname` (the HTTPS
host), the `gateway.httpRoute.hostnames`, and `sqlite.persistence.storageClassName`.

## 2. Deploy

```sh
./deploy/live.sh deploy
```

This `helm upgrade --install`s the chart and generates a `DOMAIN_KEY_PASSPHRASE`
the first time, storing it only in the cluster secret and **reusing it on every
later deploy**. (Losing or changing this passphrase makes the encrypted domain
keys — and therefore your DNS-pinned identity — unrecoverable. The backup in
step 4 captures it so you don't depend solely on the cluster secret.)

## 3. Initialize keys and publish DNS

```sh
./deploy/live.sh init       # generates 3 signing keys + 1 encryption key, idempotent
```

This prints the exact records to publish. At your DNS provider, add:

| Record | Type | Value |
|---|---|---|
| `linkkeys.<domain>` | `A` | your gateway's public IP |
| `_linkkeys.<domain>` | `TXT` | `v=lk1 fp=<fp1> fp=<fp2> fp=<fp3>` |
| `_linkkeys_apis.<domain>` | `TXT` | `v=lk1 tcp=<domain> https=linkkeys.<domain>` |

If your DNS provider has a proxy toggle (e.g. Cloudflare's orange cloud), keep the
`linkkeys.<domain>` record **DNS-only / unproxied** — the LinkKeys TCP protocol
does its own mutual TLS and must not be passed through an HTTP proxy.

Re-run `./deploy/live.sh dns` any time to re-print the expected records, and use
it to verify what's actually resolving (it does a live lookup and flags
mismatches).

## 4. Back up (do this before you ever need it)

```sh
./deploy/live.sh backup
```

The server snapshots the entire database, serializes it to CBOR, and **encrypts
it in-process** before anything leaves the pod. The encrypted artifact lands in
`~/linkkeys/backups/<domain>/<timestamp>.lkbk`.

The **first** backup generates a random 256-bit **backup key** and prints it
**once**. Store it separately from the artifact (password manager / safe). It is
the only way to decrypt your backups. `ROTATE=1 ./deploy/live.sh backup` rotates
to a new key (and prints it); artifacts made with the old key still need the old
key.

The artifact also embeds `DOMAIN_KEY_PASSPHRASE` by default, so a single file +
its backup key is everything needed to fully restore a working domain. Take
backups on a schedule and keep copies off the cluster.

## 5. Tear down and rebuild — without touching DNS

This is the property the whole design exists for:

```sh
./deploy/live.sh backup            # make sure you have a current artifact + key
./deploy/live.sh down              # delete the namespace entirely
./deploy/live.sh deploy            # recreate (optionally a newer image tag)
./deploy/live.sh restore ~/linkkeys/backups/<domain>/<timestamp>.lkbk
```

Restore decrypts with your backup key, replaces the database with the snapshot,
and restarts so the server re-reads the keys. Because the signing keys are
restored byte-identical, the fingerprints — and your `_linkkeys` record — are
unchanged. Confirm with `./deploy/live.sh dns`: the expected and resolved
fingerprints should match, and your apps keep working. No DNS edits required.

> Restore is a wipe-and-replace; run it when the instance is idle. It refuses to
> overwrite a non-empty database unless forced, and will warn if the running
> `DOMAIN_KEY_PASSPHRASE` doesn't match the one in the backup (which it must, or
> the restored keys won't decrypt).

## Backups as a migration path

Because the backup is logical row data in a backend-neutral format (not a raw
SQLite file or a `pg_dump`), the same artifact is the basis for moving a domain
between storage backends in the future (e.g. SQLite → Postgres, or out to a
multi-node setup) without regenerating keys. v1 reads and writes the SQLite
backend.
