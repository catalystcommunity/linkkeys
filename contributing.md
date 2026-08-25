## Quick Setup

Clone, check your environment, and run the tests:

```sh
git clone <repo-url> && cd linkkeys
./tools.sh setup     # checks deps, then runs the SQLite suite
```

The SQLite suite uses an in-memory database. You do not have to create a
database.

### Prerequisites

- **Rust** (stable): via [rustup](https://rustup.rs) or your distro package.
- **System libraries**: `libpq` and `libsqlite3` development headers, `pkg-config`, and a C compiler. `libpq` is required even for the SQLite path because the workspace builds both backends by default.
- **A container runtime** (optional): needed for the PostgreSQL test path and
  the Mailpit browser demo. Use `nerdctl` or `docker`. `./tools.sh` detects the
  available command.
- **Node.js and npm**: required by `./tools.sh setup` and for web UI changes.
- **cargo-deny** (optional): needed for the dependency and license audit. Install it with `cargo install cargo-deny --locked`.
- **Language Runtimes** (ones you care about): We generate libraries for most popular languages, so you'll need those languages to run tests against, though setup will help with that, some are system installs it can't do for you.

`./tools.sh setup` checks the required Rust, Node.js, compiler, and database library prerequisites. It prints installation hints when a required item is missing. Install the optional tools only for the commands that use them.

### Common commands

```sh
./tools.sh test       # SQLite, in-memory, no container (fast path)
./tools.sh test-pg    # PostgreSQL — starts a dev DB container automatically
./tools.sh test-all   # both backends (local parity with CI)
./tools.sh db-up      # start the dev Postgres container (idempotent)
./tools.sh db-down    # stop & remove it
./tools.sh db-shell   # psql into the dev database
./tools.sh test-smtp  # SMTP protocol test; no SMTP account or container
./tools.sh smtp-up    # local captured-email inbox at http://127.0.0.1:8025
./tools.sh smtp-down  # stop and remove the local email inbox
./tools.sh smtp-demo  # disposable LinkKeys and Mailpit browser demo
./tools.sh fmt        # cargo fmt
./tools.sh clippy     # cargo clippy (workspace, all targets)
./tools.sh ui-build   # check and build the embedded SolidJS UI
./tools.sh audit      # dependency and license audit
```

Run `./tools.sh` with no arguments for the full command list.

The dev Postgres container (`postgres:17`, user/password `devuser`/`devpass`, databases `linkkeys` and `linkkeys_test`) matches the server's baked-in dev defaults, so the test commands need no environment overrides. Set `LINKKEYS_PG_PORT` if 5432 is already in use locally.

### Test email locally

Use the in-process relay for a fast SMTP protocol test:

```sh
./tools.sh test-smtp
```

Use the disposable demo for a manual verification or password reset:

```sh
./tools.sh smtp-demo
```

The command creates an isolated SQLite database. It also creates a domain and a
demo administrator. The command prints the LinkKeys URL, inbox URL, username,
and password. Open the LinkKeys URL and add a verified email address. Open
`http://127.0.0.1:8025` to read the message.

The inbox and SMTP port bind only to the local computer. This workflow does not
need an SMTP account or an internet email service. Press Ctrl-C to stop
LinkKeys. Run `./tools.sh smtp-down` when you finish.

## Testing & CI

Tests run against a real database inside a transaction that rolls back — no mocks for the database layer. Every test gets its own transaction, so the suite parallelizes safely. CI (`.reactorcide/jobs/test-postgres.yaml` and `test-sqlite.yaml`) runs both backends; `./tools.sh test-all` reproduces that locally. See [`AGENTS.md`](AGENTS.md) for the full testing and architecture conventions.

Of course, we use [Reactorcide](https://github.com/catalystcommunity/reactorcide/) for our CI/CD.

## Accepted implementation designs

Read these documents before you work on the related server paths:

- [Outbound communications and account recovery](docs/developing/outbound-communications-and-account-recovery.md)
  defines notification channels, the outbox, SMTP, email verification, and
  password recovery.
- [Runtime web UI and extensions](docs/developing/runtime-web-ui.md) defines the
  embedded SPA, CSIL browser access, themes, extensions, and full UI
  replacement.
