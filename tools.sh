#!/usr/bin/env bash
#
# LinkKeys local dev workflow. One script to get a fresh clone testing.
#
#   ./tools.sh setup      # check deps, then run the SQLite suite (no container)
#   ./tools.sh test       # SQLite in-memory tests (fast path, no container)
#   ./tools.sh test-pg    # PostgreSQL tests (starts a dev DB container)
#   ./tools.sh test-all   # both backends — local parity with CI
#   ./tools.sh db-up      # start the dev PostgreSQL container (idempotent)
#   ./tools.sh db-down    # stop & remove the dev PostgreSQL container
#   ./tools.sh db-shell   # psql into the dev database
#   ./tools.sh fmt        # cargo fmt
#
# The SQLite path needs only Rust + system libs. The Postgres path also needs a
# container runtime; it is auto-detected in this order:
#   nerdctl (rootless) -> docker (rootless) -> sudo nerdctl -> sudo docker
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Make user-installed toolchains reachable from non-interactive shells.
for d in "$HOME/.local/bin" "$HOME/.cargo/bin"; do
    [ -d "$d" ] && export PATH="$d:$PATH"
done

# colors
GREEN=$'\e[0;32m'
RED=$'\e[0;31m'
NC=$'\e[0m'

# Dev Postgres container. Creds match the baked-in defaults in
# crates/linkkeys/src/db/mod.rs (default_database_url) and
# crates/linkkeys/tests/common/mod.rs (default_test_url), so the standard test
# commands need no env overrides.
PG_CONTAINER="linkkeys-dev-pg"
PG_IMAGE="postgres:17"
PG_USER="devuser"
PG_PASSWORD="devpass"
PG_DB="linkkeys"          # runtime DB (POSTGRES_DB creates it)
PG_TEST_DB="linkkeys_test"
PG_PORT="${LINKKEYS_PG_PORT:-5432}"

log_status() {
    echo "${GREEN}---------------------------------  ${1}  ---------------------------------${NC}"
}

err() { echo "${RED}$*${NC}" >&2; }

# ---------------------------------------------------------------------------
# Container runtime detection
# ---------------------------------------------------------------------------

# Resolved container command prefix (e.g. "nerdctl" or "sudo docker").
# Intentionally word-split at call sites, so used unquoted as $RT.
RT=""

detect_runtime() {
    [ -n "$RT" ] && return 0
    local candidate
    for candidate in "nerdctl" "docker" "sudo nerdctl" "sudo docker"; do
        # shellcheck disable=SC2086
        if $candidate info >/dev/null 2>&1; then
            RT="$candidate"
            log_status "using container runtime: ${RT}"
            return 0
        fi
    done
    err "No usable container runtime found."
    err "Tried (in order): nerdctl rootless, docker rootless, sudo nerdctl, sudo docker."
    err "Install/configure one of nerdctl or docker, then retry."
    err "The SQLite path ('./tools.sh test') needs no container if you just want tests."
    exit 1
}

# ---------------------------------------------------------------------------
# Dev database
# ---------------------------------------------------------------------------

container_running() {
    # shellcheck disable=SC2086
    $RT ps --filter "name=^${PG_CONTAINER}$" --format '{{.Names}}' 2>/dev/null | grep -q .
}

container_exists() {
    # shellcheck disable=SC2086
    $RT ps -a --filter "name=^${PG_CONTAINER}$" --format '{{.Names}}' 2>/dev/null | grep -q .
}

db_up() {
    detect_runtime
    if container_running; then
        log_status "dev postgres already running"
    elif container_exists; then
        log_status "starting existing dev postgres container"
        # shellcheck disable=SC2086
        $RT start "$PG_CONTAINER" >/dev/null
    else
        log_status "creating dev postgres container ($PG_IMAGE) on port $PG_PORT"
        # shellcheck disable=SC2086
        $RT run -d \
            --name "$PG_CONTAINER" \
            -e POSTGRES_USER="$PG_USER" \
            -e POSTGRES_PASSWORD="$PG_PASSWORD" \
            -e POSTGRES_DB="$PG_DB" \
            -p "${PG_PORT}:5432" \
            "$PG_IMAGE" >/dev/null
    fi

    log_status "waiting for postgres to accept connections"
    local i
    for i in $(seq 1 30); do
        # shellcheck disable=SC2086
        if $RT exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then
            ensure_test_db
            log_status "dev postgres ready (dbs: ${PG_DB}, ${PG_TEST_DB})"
            return 0
        fi
        sleep 1
    done
    err "postgres did not become ready in time"
    exit 1
}

ensure_test_db() {
    # Idempotently create the test database (the runtime DB comes from POSTGRES_DB).
    # shellcheck disable=SC2086
    if ! $RT exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tAc \
        "SELECT 1 FROM pg_database WHERE datname='${PG_TEST_DB}'" 2>/dev/null | grep -q 1; then
        # shellcheck disable=SC2086
        $RT exec "$PG_CONTAINER" createdb -U "$PG_USER" "$PG_TEST_DB"
    fi
}

db_down() {
    detect_runtime
    if container_exists; then
        log_status "removing dev postgres container"
        # shellcheck disable=SC2086
        $RT rm -f "$PG_CONTAINER" >/dev/null
    else
        log_status "no dev postgres container to remove"
    fi
}

db_shell() {
    detect_runtime
    if ! container_running; then
        err "dev postgres is not running — run './tools.sh db-up' first"
        exit 1
    fi
    # shellcheck disable=SC2086
    $RT exec -it "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB"
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_sqlite() {
    log_status "running tests (SQLite backend)"
    TEST_DATABASE_BACKEND=sqlite cargo test
    log_status "SQLite tests passed"
}

test_postgres() {
    db_up
    log_status "running tests (PostgreSQL backend)"
    # The baked-in default_test_url targets localhost:5432; only override the URL
    # when the dev moved the port off the default.
    if [ "$PG_PORT" = "5432" ]; then
        TEST_DATABASE_BACKEND=postgres cargo test
    else
        TEST_DATABASE_BACKEND=postgres \
        TEST_DATABASE_URL="postgres://${PG_USER}:${PG_PASSWORD}@localhost:${PG_PORT}/${PG_TEST_DB}" \
        cargo test
    fi
    log_status "PostgreSQL tests passed"
}

test_all() {
    test_sqlite
    test_postgres
    log_status "all backends passed"
}

fmt() {
    log_status "cargo fmt"
    cargo fmt
}

# ---------------------------------------------------------------------------
# Setup / preflight
# ---------------------------------------------------------------------------

distro_hint() {
    # Print an install hint for the missing packages, tailored to the host.
    local os_id=""
    [ -r /etc/os-release ] && os_id="$(. /etc/os-release && echo "${ID:-} ${ID_LIKE:-}")"
    echo ""
    case "$os_id" in
        *arch*)
            echo "  Arch:    sudo pacman -S --needed rust postgresql-libs sqlite pkgconf base-devel" ;;
        *debian*|*ubuntu*)
            echo "  Debian/Ubuntu: sudo apt-get install -y libpq-dev libsqlite3-dev pkg-config build-essential" ;;
        *)
            echo "  Debian/Ubuntu: sudo apt-get install -y libpq-dev libsqlite3-dev pkg-config build-essential"
            echo "  Arch:          sudo pacman -S --needed rust postgresql-libs sqlite pkgconf base-devel"
            echo "  macOS (brew):  brew install libpq sqlite pkg-config   # plus Xcode CLT for a C compiler" ;;
    esac
    echo "  Rust:    https://rustup.rs   (or your distro's rust package)"
}

setup() {
    log_status "checking dev prerequisites"
    local missing=0

    if ! command -v cargo >/dev/null 2>&1; then
        err "missing: cargo (Rust toolchain)"; missing=1
    fi
    if ! command -v pkg-config >/dev/null 2>&1; then
        err "missing: pkg-config"; missing=1
    fi
    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
        err "missing: a C compiler (cc/gcc)"; missing=1
    fi
    # libpq is a compile-time dep even for the SQLite path, because the workspace
    # builds with default = ["postgres","sqlite"].
    if command -v pkg-config >/dev/null 2>&1; then
        pkg-config --exists libpq   || { err "missing: libpq dev library";    missing=1; }
        pkg-config --exists sqlite3 || { err "missing: libsqlite3 dev library"; missing=1; }
    fi

    if [ "$missing" -ne 0 ]; then
        err "Some prerequisites are missing. Install them and re-run './tools.sh setup'."
        distro_hint
        exit 1
    fi

    log_status "prerequisites OK — running the SQLite suite"
    test_sqlite
    echo ""
    log_status "setup complete"
    echo "Next: './tools.sh test-pg' for the Postgres suite, or './tools.sh test-all' for both."
}

# ---------------------------------------------------------------------------

usage() {
    cat >&2 <<EOF
$(basename "$0") command

Commands:
  setup      Check dev prerequisites, then run the SQLite test suite
  test       Run tests against SQLite (in-memory, no container)
  test-pg    Run tests against PostgreSQL (starts a dev DB container)
  test-all   Run both backends (local parity with CI)
  db-up      Start the dev PostgreSQL container (idempotent)
  db-down    Stop & remove the dev PostgreSQL container
  db-shell   Open a psql shell into the dev database
  fmt        Run cargo fmt

Env:
  LINKKEYS_PG_PORT   Host port for the dev Postgres container (default 5432)
EOF
    exit 1
}

case "${1:-}" in
    setup)    shift; setup "$@" ;;
    test)     shift; test_sqlite "$@" ;;
    test-pg)  shift; test_postgres "$@" ;;
    test-all) shift; test_all "$@" ;;
    db-up)    shift; db_up "$@" ;;
    db-down)  shift; db_down "$@" ;;
    db-shell) shift; db_shell "$@" ;;
    fmt)      shift; fmt "$@" ;;
    *)        usage ;;
esac
