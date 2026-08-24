## Quick Setup

Clone, check your environment, and run the tests:

```sh
git clone <repo-url> && cd linkkeys
./tools.sh setup     # checks deps, then runs the SQLite suite
```

That's it for the fast path — the SQLite suite runs in-memory with no database to provision.

### Prerequisites

- **Rust** (stable): via [rustup](https://rustup.rs) or your distro package.
- **System libraries**: `libpq` and `libsqlite3` development headers, `pkg-config`, and a C compiler. `libpq` is required even for the SQLite path because the workspace builds both backends by default.
- **A container runtime** (optional): only needed for the Postgres test path. `nerdctl` or `docker` works; `./tools.sh` auto-detects one.
- **Language Runtimes** (ones you care about): We generate libraries for most popular languages, so you'll need those languages to run tests against, though setup will help with that, some are system installs it can't do for you.

`./tools.sh setup` checks all of the above and prints install hints for your distro if anything is missing.

### Common commands

```sh
./tools.sh test       # SQLite, in-memory, no container (fast path)
./tools.sh test-pg    # PostgreSQL — starts a dev DB container automatically
./tools.sh test-all   # both backends (local parity with CI)
./tools.sh db-up      # start the dev Postgres container (idempotent)
./tools.sh db-down    # stop & remove it
./tools.sh db-shell   # psql into the dev database
./tools.sh fmt        # cargo fmt
./tools.sh clippy     # cargo clippy (workspace, all targets)
```

Run `./tools.sh` with no arguments for the full command list.

The dev Postgres container (`postgres:17`, user/password `devuser`/`devpass`, databases `linkkeys` and `linkkeys_test`) matches the server's baked-in dev defaults, so the test commands need no environment overrides. Set `LINKKEYS_PG_PORT` if 5432 is already in use locally.

## Testing & CI

Tests run against a real database inside a transaction that rolls back — no mocks for the database layer. Every test gets its own transaction, so the suite parallelizes safely. CI (`.reactorcide/jobs/test-postgres.yaml` and `test-sqlite.yaml`) runs both backends; `./tools.sh test-all` reproduces that locally. See [`AGENTS.md`](AGENTS.md) for the full testing and architecture conventions.

Of course, we use [Reactorcide](https://github.com/catalystcommunity/reactorcide/) for our CI/CD.
