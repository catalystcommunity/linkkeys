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
#   ./tools.sh test-smtp  # test SMTP with an in-process relay
#   ./tools.sh smtp-up    # start the local captured-email inbox
#   ./tools.sh smtp-down  # stop and remove the local email inbox
#   ./tools.sh smtp-demo  # run a disposable LinkKeys + Mailpit browser demo
#   ./tools.sh fmt        # cargo fmt
#   ./tools.sh clippy     # cargo clippy (workspace, all targets)
#   ./tools.sh ui-build   # check and build the embedded SolidJS UI
#   ./tools.sh audit      # dependency advisories and license policy
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
MAILPIT_CONTAINER="linkkeys-dev-mailpit"
MAILPIT_IMAGE="axllent/mailpit:v1.31.0"
MAILPIT_SMTP_PORT="${LINKKEYS_MAILPIT_SMTP_PORT:-1025}"
MAILPIT_UI_PORT="${LINKKEYS_MAILPIT_UI_PORT:-8025}"
SMTP_DEMO_DIR=""

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

    local mapped_port
    # shellcheck disable=SC2086
    mapped_port="$($RT port "$PG_CONTAINER" 5432/tcp 2>/dev/null | sed -n 's/.*://p' | head -n 1)"
    if [ -n "$mapped_port" ] && [ "$mapped_port" != "$PG_PORT" ]; then
        if [ -n "${LINKKEYS_PG_PORT:-}" ]; then
            err "The existing PostgreSQL container uses port ${mapped_port}, not ${PG_PORT}. Run './tools.sh db-down' before you change LINKKEYS_PG_PORT."
            exit 1
        fi
        PG_PORT="$mapped_port"
        log_status "using the existing PostgreSQL port $PG_PORT"
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
# Local email capture
# ---------------------------------------------------------------------------

mailpit_running() {
    # shellcheck disable=SC2086
    $RT ps --filter "name=^${MAILPIT_CONTAINER}$" --format '{{.Names}}' 2>/dev/null | grep -q .
}

mailpit_exists() {
    # shellcheck disable=SC2086
    $RT ps -a --filter "name=^${MAILPIT_CONTAINER}$" --format '{{.Names}}' 2>/dev/null | grep -q .
}

smtp_up() {
    detect_runtime
    if mailpit_running; then
        local smtp_mapping ui_mapping
        # shellcheck disable=SC2086
        smtp_mapping="$($RT port "$MAILPIT_CONTAINER" 1025/tcp 2>/dev/null)"
        # shellcheck disable=SC2086
        ui_mapping="$($RT port "$MAILPIT_CONTAINER" 8025/tcp 2>/dev/null)"
        if ! printf '%s\n' "$smtp_mapping" | grep -q ":${MAILPIT_SMTP_PORT}$" \
            || ! printf '%s\n' "$ui_mapping" | grep -q ":${MAILPIT_UI_PORT}$"; then
            log_status "replacing local email inbox with the requested ports"
            # shellcheck disable=SC2086
            $RT rm -f "$MAILPIT_CONTAINER" >/dev/null
        else
            log_status "local email inbox already running"
        fi
    elif mailpit_exists; then
        log_status "replacing stopped local email inbox"
        # shellcheck disable=SC2086
        $RT rm -f "$MAILPIT_CONTAINER" >/dev/null
    fi
    if ! mailpit_running; then
        log_status "creating local email inbox ($MAILPIT_IMAGE)"
        # Bind both services to loopback. Mailpit is a development tool and has
        # no authentication in this configuration.
        # shellcheck disable=SC2086
        $RT run -d \
            --name "$MAILPIT_CONTAINER" \
            -p "127.0.0.1:${MAILPIT_SMTP_PORT}:1025" \
            -p "127.0.0.1:${MAILPIT_UI_PORT}:8025" \
            "$MAILPIT_IMAGE" >/dev/null
    fi
    log_status "local email inbox: http://127.0.0.1:${MAILPIT_UI_PORT}"
    echo "Use deploy/smtp.local.env for the LinkKeys SMTP settings."
}

smtp_down() {
    detect_runtime
    if mailpit_exists; then
        log_status "removing local email inbox"
        # shellcheck disable=SC2086
        $RT rm -f "$MAILPIT_CONTAINER" >/dev/null
    else
        log_status "no local email inbox to remove"
    fi
}

test_smtp() {
    log_status "running the SMTP protocol tests with an in-process relay"
    TEST_DATABASE_BACKEND=sqlite cargo test -p linkkeys --test notification_smtp_test
    TEST_DATABASE_BACKEND=sqlite cargo test -p linkkeys --test notification_outbox_test
    log_status "SMTP protocol tests passed"
}

cleanup_smtp_demo() {
    case "$SMTP_DEMO_DIR" in
        "$SCRIPT_DIR"/target/smtp-demo.*) rm -rf -- "$SMTP_DEMO_DIR" ;;
    esac
}

smtp_demo() {
    smtp_up
    mkdir -p "$SCRIPT_DIR/target"
    SMTP_DEMO_DIR="$(mktemp -d "$SCRIPT_DIR/target/smtp-demo.XXXXXX")"
    trap cleanup_smtp_demo EXIT
    local demo_db="$SMTP_DEMO_DIR/linkkeys.db"

    export DATABASE_BACKEND=sqlite
    export DATABASE_URL="$demo_db"
    export DOMAIN_NAME=localhost
    export DOMAIN_KEY_PASSPHRASE=linkkeys-smtp-demo-passphrase
    export SMTP_HOST=127.0.0.1
    export SMTP_PORT="$MAILPIT_SMTP_PORT"
    export SMTP_SECURITY=plaintext
    export SMTP_ALLOW_PLAINTEXT=true
    export SMTP_TLS_BACKEND=rustls
    export SMTP_FROM="LinkKeys local development <linkkeys@example.test>"
    export PUBLIC_ORIGIN=https://localhost:8443
    export OUTBOX_ENCRYPTION_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    export SMTP_TIMEOUT_SECONDS=5
    export OUTBOX_MAX_ATTEMPTS=3
    export OUTBOX_LEASE_SECONDS=30
    export OUTBOX_POLL_MILLISECONDS=250

    log_status "initializing the disposable SMTP demo"
    cargo run -q -p linkkeys -- domain init
    cargo run -q -p linkkeys -- user create demo-admin "Demo Administrator" --password demo-password-123 --admin

    echo
    echo "LinkKeys UI:  https://localhost:8443/app"
    echo "Email inbox:  http://127.0.0.1:${MAILPIT_UI_PORT}"
    echo "Username:     demo-admin"
    echo "Password:     demo-password-123"
    echo
    echo "The browser will warn about the disposable local certificate."
    echo "Stop LinkKeys with Ctrl-C. Then run './tools.sh smtp-down'."
    cargo run -p linkkeys -- serve
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

clippy() {
    log_status "cargo clippy (workspace, all targets, all features)"
    cargo clippy --workspace --all-targets --all-features -- -D warnings
}

ui_build() {
    log_status "checking and building the embedded web UI"
    if [ ! -d web-ui/node_modules ]; then
        (cd web-ui && npm ci)
    fi
    (cd web-ui && npm run build)
}

audit() {
    log_status "checking dependency advisories, licenses, and sources"
    if ! cargo deny --version >/dev/null 2>&1; then
        err "missing: cargo-deny (install with 'cargo install cargo-deny --locked')"
        exit 1
    fi
    cargo deny check
    (cd web-ui && npm audit --omit=optional)
}

# ---------------------------------------------------------------------------
# DNS-less local RP SDKs (sdks/local-rp/, dns-less-local-rp-design.md)
# ---------------------------------------------------------------------------

test_local_rp_rust() {
    log_status "running linkkeys-local-rp (Rust SDK) tests"
    # Standalone crate (own workspace), like the other 13 SDKs — run from its
    # dir, not `-p` from the root workspace (which excludes sdks/).
    (cd sdks/local-rp/rust && cargo test)
    log_status "linkkeys-local-rp tests passed"
}

test_local_rp_go() {
    log_status "running local-rp Go SDK tests"
    # shellcheck disable=SC1091
    source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
    (cd sdks/local-rp/go && go vet ./... && go test ./...)
    log_status "local-rp Go SDK tests passed"
}

test_local_rp_typescript() {
    log_status "running local-rp TypeScript SDK tests"
    # shellcheck disable=SC1091
    source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
    (cd sdks/local-rp/typescript && npm install --no-audit --no-fund && npm run typecheck && npm test)
    log_status "local-rp TypeScript SDK tests passed"
}

test_local_rp_java() {
    log_status "running local-rp Java SDK tests"
    # shellcheck disable=SC1091
    source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
    (cd sdks/local-rp/java && gradle test)
    log_status "local-rp Java SDK tests passed"
}

test_local_rp_kotlin() {
    log_status "running local-rp Kotlin SDK tests"
    # shellcheck disable=SC1091
    source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
    (cd sdks/local-rp/kotlin && gradle test)
    log_status "local-rp Kotlin SDK tests passed"
}

test_local_rp_csharp() {
    log_status "running local-rp C# SDK tests"
    # shellcheck disable=SC1091
    source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
    (cd sdks/local-rp/csharp && dotnet test)
    log_status "local-rp C# SDK tests passed"
}

test_local_rp_dart() {
    log_status "running local-rp Dart SDK tests"
    # shellcheck disable=SC1091
    source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
    (cd sdks/local-rp/dart && dart pub get && dart analyze && dart test)
    log_status "local-rp Dart SDK tests passed"
}

test_local_rp_ruby() {
    log_status "running local-rp Ruby SDK tests"
    (cd sdks/local-rp/ruby && ruby -Ilib -Itest test/run_all.rb)
    log_status "local-rp Ruby SDK tests passed"
}

test_local_rp_zig() {
    log_status "running local-rp Zig SDK tests"
    # shellcheck disable=SC1091
    source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
    (cd sdks/local-rp/zig && zig build test)
    log_status "local-rp Zig SDK tests passed"
}

test_local_rp_all() {
    test_local_rp_rust
    test_local_rp_go
    test_local_rp_typescript
    test_local_rp_python
    test_local_rp_php
    test_local_rp_java
    test_local_rp_kotlin
    test_local_rp_csharp
    test_local_rp_dart
    test_local_rp_ruby
    test_local_rp_elixir
    test_local_rp_c
    test_local_rp_zig
    test_local_rp_ocaml
    log_status "ALL local-rp SDK test suites passed"
}

test_local_rp_ocaml() {
    log_status "running local-rp OCaml SDK tests"
    # shellcheck disable=SC1091
    source "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/env.sh"
    eval "$(opam env --root "${CATALYST_TOOLS:-$HOME/.local/catalyst-tools}/opam" --switch catalyst)"
    (cd sdks/local-rp/ocaml && dune runtest)
    log_status "local-rp OCaml SDK tests passed"
}

test_local_rp_c() {
    log_status "running local-rp C SDK tests (ASan/UBSan)"
    (cd sdks/local-rp/c && make test)
    log_status "local-rp C SDK tests passed"
}

test_local_rp_elixir() {
    log_status "running local-rp Elixir SDK tests"
    (cd sdks/local-rp/elixir && mix test)
    log_status "local-rp Elixir SDK tests passed"
}

test_local_rp_php() {
    log_status "running local-rp PHP SDK tests"
    if command -v php >/dev/null 2>&1; then
        (cd sdks/local-rp/php && ./run-tests.sh)
    else
        # No system PHP: run in a container (see feedback: use nerdctl).
        (cd sdks/local-rp && sudo nerdctl run --rm -v "$(pwd)":/repo -w /repo/php php:8.3-cli ./run-tests.sh)
    fi
    log_status "local-rp PHP SDK tests passed"
}

test_local_rp_python() {
    log_status "running local-rp Python SDK tests"
    # Setup (one-time): see sdks/local-rp/python/README.md for venv creation.
    (cd sdks/local-rp/python && source .venv/bin/activate && python -m pytest -q)
    log_status "local-rp Python SDK tests passed"
}

generate_local_rp_sdks() {
    log_status "generate-local-rp-sdks"
    # The Rust SDK (sdks/local-rp/rust/) is a workspace member that path-depends
    # on liblinkkeys directly — there is no separate generation step for it (no
    # generated-client codegen to run; see that crate's Cargo.toml for the
    # layout rationale). This subcommand is a deliberate no-op for "rust" so the
    # command exists for layout/tooling parity with the other SDK languages
    # (dns-less-local-rp-design.md, "SDK Layout and Tooling") — once a
    # generated-language SDK (Go, TypeScript, ...) lands under sdks/local-rp/,
    # its csilgen generation step is added here.
    echo "rust: nothing to generate (consumes liblinkkeys directly) — see sdks/local-rp/rust/README.md"
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
    if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
        err "missing: Node.js and npm (needed when you change web-ui/)"; missing=1
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

    log_status "prerequisites OK — checking the UI and running the SQLite suite"
    ui_build
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
  smtp-up    Start a local email inbox on http://127.0.0.1:8025
  smtp-down  Stop and remove the local email inbox
  smtp-demo  Run a disposable SQLite server with a local email inbox
  test-smtp  Test SMTP delivery with an in-process relay and no SMTP account
  fmt        Run cargo fmt
  clippy     Run cargo clippy (workspace, all targets)
  ui-build   Check and build the embedded SolidJS UI
  audit      Check dependency advisories, licenses, and sources

  generate-local-rp-sdks   Regenerate DNS-less local-RP SDK bindings (sdks/local-rp/)
  test-local-rp-rust       Run the DNS-less local-RP Rust SDK's tests
  test-local-rp-go         Run the DNS-less local-RP Go SDK's tests
  test-local-rp-typescript Run the DNS-less local-RP TypeScript SDK's tests
  test-local-rp-java       Run the DNS-less local-RP Java SDK's tests
  test-local-rp-php        Run the DNS-less local-RP PHP SDK's tests (container fallback)
  test-local-rp-kotlin     Run the DNS-less local-RP Kotlin SDK's tests
  test-local-rp-csharp     Run the DNS-less local-RP C# SDK's tests
  test-local-rp-dart       Run the DNS-less local-RP Dart SDK's tests
  test-local-rp-ruby       Run the DNS-less local-RP Ruby SDK's tests
  test-local-rp-elixir     Run the DNS-less local-RP Elixir SDK's tests
  test-local-rp-c          Run the DNS-less local-RP C SDK's tests (ASan/UBSan)
  test-local-rp-zig        Run the DNS-less local-RP Zig SDK's tests
  test-local-rp-ocaml      Run the DNS-less local-RP OCaml SDK's tests
  test-local-rp-all        Run every local-RP SDK test suite sequentially
  test-local-rp-python     Run the DNS-less local-RP Python SDK's tests

Env:
  LINKKEYS_PG_PORT   Host port for the dev Postgres container (default 5432)
  LINKKEYS_MAILPIT_SMTP_PORT  Host port for local SMTP capture (default 1025)
  LINKKEYS_MAILPIT_UI_PORT    Host port for the local email UI (default 8025)
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
    smtp-up)  shift; smtp_up "$@" ;;
    smtp-down) shift; smtp_down "$@" ;;
    smtp-demo) shift; smtp_demo "$@" ;;
    test-smtp) shift; test_smtp "$@" ;;
    fmt)      shift; fmt "$@" ;;
    clippy)   shift; clippy "$@" ;;
    ui-build) shift; ui_build "$@" ;;
    audit)    shift; audit "$@" ;;
    generate-local-rp-sdks) shift; generate_local_rp_sdks "$@" ;;
    test-local-rp-rust)     shift; test_local_rp_rust "$@" ;;
    test-local-rp-go)       shift; test_local_rp_go "$@" ;;
    test-local-rp-typescript) shift; test_local_rp_typescript "$@" ;;
    test-local-rp-java)     shift; test_local_rp_java "$@" ;;
    test-local-rp-php)      shift; test_local_rp_php "$@" ;;
    test-local-rp-kotlin)   shift; test_local_rp_kotlin "$@" ;;
    test-local-rp-csharp)   shift; test_local_rp_csharp "$@" ;;
    test-local-rp-dart)     shift; test_local_rp_dart "$@" ;;
    test-local-rp-ruby)     shift; test_local_rp_ruby "$@" ;;
    test-local-rp-elixir)   shift; test_local_rp_elixir "$@" ;;
    test-local-rp-c)        shift; test_local_rp_c "$@" ;;
    test-local-rp-zig)      shift; test_local_rp_zig "$@" ;;
    test-local-rp-ocaml)    shift; test_local_rp_ocaml "$@" ;;
    test-local-rp-all)      shift; test_local_rp_all "$@" ;;
    test-local-rp-python)   shift; test_local_rp_python "$@" ;;
    *)        usage ;;
esac
