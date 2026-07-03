# LinkKeys

LinkKeys is authentication for everywhere. It solves three major problems with the internet today:

- Identity security is made hard when it shouldn't be, so let's make it easy to be secure.
- We are all tired of making new accounts or signing in to websites with social media logins.
- We would like to be able to know the user is a real person, or an adult, or local to us.

If you trust your domain admins (like you do with email) they handle all the technical headache, and everything else is easy on the user. Apps no longer have to pay for an Auth/SSO provider — they just use LinkKeys and develop their own app, so it's all win-win for everyone. One identity, used everywhere that will use LinkKeys. In fact, we think it will help eliminate spam and bots, too.

For the nerdier version:

LinkKeys is a domain-anchored identity protocol and server: domains hold keys, users hold claims, and relying parties verify them over a TCP-first, mutually authenticated protocol (with a browser HTTPS path for interactive flows). See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture and philosophy, and [`AGENTS.md`](AGENTS.md) for coding guidelines.

## Quickstart

Clone, check your environment, and run the tests:

```sh
git clone <repo-url> && cd linkkeys
./tools.sh setup     # checks deps, then runs the SQLite suite
```

That's it for the fast path — the SQLite suite runs in-memory with no database to provision.

### Prerequisites

- **Rust** (stable) — via [rustup](https://rustup.rs) or your distro package.
- **System libraries**: `libpq` and `libsqlite3` development headers, `pkg-config`, and a C compiler. `libpq` is required even for the SQLite path because the workspace builds both backends by default.
- **A container runtime** (optional) — only needed for the Postgres test path. `nerdctl` or `docker` works; `./tools.sh` auto-detects one.

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
