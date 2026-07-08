#!/usr/bin/env bash
#
# Drive a personal LinkKeys IDP on a domain you control: deploy, initialize
# keys, see the DNS records to publish, and take/restore encrypted backups.
#
# This is the shared tool; per-admin specifics (cluster, namespace, domain,
# values overlay, backup location) live OUTSIDE the repo in a small env file —
# by default ~/linkkeys/env — so secrets and host details never get committed.
#
#   cp deploy/live.env.example ~/linkkeys/env   # then edit it
#   ./deploy/live.sh deploy
#   ./deploy/live.sh init        # generate domain keys, print DNS records
#   ./deploy/live.sh dns         # re-print the records to publish
#   ./deploy/live.sh backup      # encrypted snapshot -> ~/linkkeys/backups/...
#   ./deploy/live.sh restore <file.lkbk>
#   ./deploy/live.sh down        # delete the namespace (full teardown)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

GREEN=$'\e[0;32m'; RED=$'\e[0;31m'; NC=$'\e[0m'
log() { echo "${GREEN}==> ${1}${NC}"; }
err() { echo "${RED}${1}${NC}" >&2; }

# --- config ---------------------------------------------------------------
LIVE_ENV="${LINKKEYS_LIVE_ENV:-$HOME/linkkeys/env}"
if [ -f "$LIVE_ENV" ]; then
    # shellcheck disable=SC1090
    set -a; . "$LIVE_ENV"; set +a
else
    err "No env file at $LIVE_ENV. Copy deploy/live.env.example to ~/linkkeys/env and edit it."
    exit 1
fi

: "${KUBECONFIG:=$HOME/.foundry/kubeconfig}"
export KUBECONFIG
: "${NAMESPACE:?set NAMESPACE in $LIVE_ENV}"
: "${RELEASE:?set RELEASE in $LIVE_ENV}"
: "${DOMAIN:?set DOMAIN in $LIVE_ENV}"
: "${VALUES:?set VALUES (path to your values overlay) in $LIVE_ENV}"
: "${BACKUP_DIR:=$HOME/linkkeys/backups}"
: "${HELM_CHART:=$REPO_ROOT/helm_chart}"

need() { command -v "$1" >/dev/null 2>&1 || { err "missing required tool: $1"; exit 1; }; }
need kubectl
need helm

deploy_pod() {
    kubectl -n "$NAMESPACE" get pod \
        -l "app.kubernetes.io/instance=${RELEASE}" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# --- commands -------------------------------------------------------------

cmd_deploy() {
    log "deploying ${RELEASE} to namespace ${NAMESPACE} (domain ${DOMAIN})"
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    # Generate the domain key passphrase once, then reuse it forever. Losing or
    # changing it makes the encrypted domain keys (hence DNS) unrecoverable.
    local passphrase
    passphrase="$(kubectl -n "$NAMESPACE" get secret "$RELEASE" \
        -o jsonpath='{.data.DOMAIN_KEY_PASSPHRASE}' 2>/dev/null | base64 -d || true)"
    if [ -z "$passphrase" ]; then
        log "generating a new DOMAIN_KEY_PASSPHRASE (stored only in the cluster secret)"
        passphrase="$(openssl rand -base64 32)"
    else
        log "reusing existing DOMAIN_KEY_PASSPHRASE from the cluster secret"
    fi

    # Generate a stable ROCKET_SECRET_KEY once, then reuse it (SEC-11) so browser
    # sessions survive restarts and are valid across replicas.
    local rocket_key
    rocket_key="$(kubectl -n "$NAMESPACE" get secret "$RELEASE" \
        -o jsonpath='{.data.ROCKET_SECRET_KEY}' 2>/dev/null | base64 -d || true)"
    if [ -z "$rocket_key" ]; then
        log "generating a new ROCKET_SECRET_KEY (stored only in the cluster secret)"
        rocket_key="$(openssl rand -base64 32)"
    else
        log "reusing existing ROCKET_SECRET_KEY from the cluster secret"
    fi

    helm upgrade --install "$RELEASE" "$HELM_CHART" \
        --namespace "$NAMESPACE" \
        -f "$VALUES" \
        --set "server.domainKeyPassphrase=${passphrase}" \
        --set "server.rocketSecretKey=${rocket_key}" \
        ${IMAGE_TAG:+--set image.tag="$IMAGE_TAG"}

    log "waiting for rollout"
    kubectl -n "$NAMESPACE" rollout status "deploy/${RELEASE}" --timeout=180s || true
    log "deployed. Next: ./deploy/live.sh init"
}

cmd_init() {
    local pod; pod="$(deploy_pod)"
    [ -n "$pod" ] || { err "no running pod for ${RELEASE}; run deploy first"; exit 1; }
    log "initializing domain keys (idempotent)"
    kubectl -n "$NAMESPACE" exec "$pod" -- linkkeys domain init
    echo
    cmd_dns
}

cmd_dns() {
    local pod; pod="$(deploy_pod)"
    [ -n "$pod" ] || { err "no running pod for ${RELEASE}; run deploy first"; exit 1; }
    log "DNS records to publish for ${DOMAIN}"
    kubectl -n "$NAMESPACE" exec "$pod" -- linkkeys domain dns-check || true
    echo
    echo "Also publish an address record so the hostnames above resolve to your"
    echo "gateway entrypoint, e.g.:"
    echo "  linkkeys.${DOMAIN}   A   ${PUBLIC_IP:-<your-gateway-public-ip>}"
    echo "(DNS-only / unproxied if your provider has a proxy toggle — the LinkKeys"
    echo " TCP protocol needs raw TLS, not an HTTP proxy.)"
}

cmd_api_key() {
    # Provision a service/admin identity with an API key and exactly the
    # relations it needs, then print the key ONCE. The hardened API surface
    # requires specific relations, not just a valid key:
    #   - an RP delegate (e.g. a demo app) needs:  api_access
    #   - an app-driven IDP key (create users / set claims / authenticate) needs:
    #                                              manage_users manage_claims
    #     (add api_access too if the app drives the /rp/authorize/* routes)
    # DB-direct and idempotent on relations; re-running mints a NEW key, so keep
    # the first one. Usage: live.sh api-key <username> <relation> [relation...]
    local username="${1:-}"; shift || true
    [ -n "$username" ] && [ "$#" -ge 1 ] || {
        err "usage: live.sh api-key <username> <relation> [relation...]"; exit 1; }
    local pod; pod="$(deploy_pod)"
    [ -n "$pod" ] || { err "no running pod for ${RELEASE}; run deploy first"; exit 1; }
    local rel_args=(); local r
    for r in "$@"; do rel_args+=(--relation "$r"); done
    log "creating API-key user '${username}' with relations: $*"
    kubectl -n "$NAMESPACE" exec "$pod" -- \
        linkkeys user create "$username" "$username" --api-key "${rel_args[@]}"
    echo "Save the API key above — it is not recoverable. Put it in the calling"
    echo "app's secret (e.g. the demo app's RP_API_KEY)."
}

cmd_grant() {
    # Grant a relation to an EXISTING user on this domain (DB-direct, idempotent).
    # Repairs an under-provisioned key without minting a new one — e.g. granting
    # api_access to a demo app's existing RP key.
    # Usage: live.sh grant <username-or-uuid> <relation>
    local user="${1:-}" relation="${2:-}"
    [ -n "$user" ] && [ -n "$relation" ] || {
        err "usage: live.sh grant <username-or-uuid> <relation>"; exit 1; }
    local pod; pod="$(deploy_pod)"
    [ -n "$pod" ] || { err "no running pod for ${RELEASE}; run deploy first"; exit 1; }
    log "granting '${relation}' to '${user}' on ${DOMAIN}"
    kubectl -n "$NAMESPACE" exec "$pod" -- linkkeys relation grant-local "$user" "$relation"
}

cmd_backup() {
    local pod; pod="$(deploy_pod)"
    [ -n "$pod" ] || { err "no running pod for ${RELEASE}; run deploy first"; exit 1; }
    mkdir -p "$BACKUP_DIR/$DOMAIN"
    local stamp out
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    out="$BACKUP_DIR/$DOMAIN/${stamp}.lkbk"
    log "writing encrypted backup -> $out"
    # The artifact (ciphertext) comes on stdout; the one-time backup key, if
    # generated/rotated, is printed on stderr and shown here — SAVE IT.
    kubectl -n "$NAMESPACE" exec "$pod" -- linkkeys backup ${ROTATE:+--rotate} > "$out"
    log "backup complete ($(wc -c < "$out") bytes)"
    echo "Store this file offline. If a BACKUP KEY was printed above, store it"
    echo "separately (password manager / safe) — it is the only way to decrypt it."
}

cmd_restore() {
    local file="${1:-}"
    [ -n "$file" ] && [ -f "$file" ] || { err "usage: live.sh restore <file.lkbk>"; exit 1; }
    local key="${LINKKEYS_BACKUP_KEY:-}"
    if [ -z "$key" ] && [ -n "${BACKUP_KEY_FILE:-}" ] && [ -f "$BACKUP_KEY_FILE" ]; then
        key="$(tr -d '[:space:]' < "$BACKUP_KEY_FILE")"
    fi
    if [ -z "$key" ]; then
        read -r -s -p "Backup key (hex): " key; echo
    fi
    local pod; pod="$(deploy_pod)"
    [ -n "$pod" ] || { err "no running pod for ${RELEASE}; run deploy first"; exit 1; }

    log "restoring $file into ${RELEASE} (the instance should be idle)"
    kubectl -n "$NAMESPACE" cp "$file" "$NAMESPACE/$pod:/tmp/restore.lkbk"
    kubectl -n "$NAMESPACE" exec "$pod" -- \
        env LINKKEYS_BACKUP_KEY="$key" linkkeys restore --in /tmp/restore.lkbk --force
    kubectl -n "$NAMESPACE" exec "$pod" -- rm -f /tmp/restore.lkbk
    log "restarting so the server re-reads the restored domain keys"
    kubectl -n "$NAMESPACE" rollout restart "deploy/${RELEASE}"
    kubectl -n "$NAMESPACE" rollout status "deploy/${RELEASE}" --timeout=180s || true
    log "restore complete — confirm fingerprints match your _linkkeys record"
}

cmd_down() {
    log "deleting namespace ${NAMESPACE} (this destroys the running instance)"
    echo "Make sure you have a current backup first (./deploy/live.sh backup)."
    read -r -p "Type the namespace to confirm: " confirm
    [ "$confirm" = "$NAMESPACE" ] || { err "confirmation mismatch; aborting"; exit 1; }
    kubectl delete namespace "$NAMESPACE"
}

usage() {
    cat >&2 <<EOF
live.sh command   (config: $LIVE_ENV)

  deploy             helm upgrade --install the IDP (idempotent passphrase)
  init               generate domain keys, then print DNS records
  dns                re-print the DNS records to publish
  api-key <user> <relation...>   mint an API-key identity with relations, print key once
  grant <user> <relation>        grant a relation to an existing user (idempotent)
  backup             write an encrypted snapshot to \$BACKUP_DIR
  restore <file>     restore from an encrypted artifact (instance should be idle)
  down               delete the namespace (full teardown)

Env (from $LIVE_ENV): NAMESPACE, RELEASE, DOMAIN, VALUES, [KUBECONFIG],
  [BACKUP_DIR], [BACKUP_KEY_FILE], [PUBLIC_IP], [IMAGE_TAG], [ROTATE=1]
EOF
    exit 1
}

case "${1:-}" in
    deploy)  shift; cmd_deploy "$@" ;;
    init)    shift; cmd_init "$@" ;;
    dns)     shift; cmd_dns "$@" ;;
    api-key) shift; cmd_api_key "$@" ;;
    grant)   shift; cmd_grant "$@" ;;
    backup)  shift; cmd_backup "$@" ;;
    restore) shift; cmd_restore "$@" ;;
    down)    shift; cmd_down "$@" ;;
    *)       usage ;;
esac
