# LinkKeys Agent Guidelines

These are permanent workflow guidelines for working in this codebase. They apply regardless of what specific task is being done.

## Architecture Boundaries

- **`liblinkkeys`** is a pure library. No I/O, no database, no network. Protocol types, crypto, serialization, claims logic only. It must remain viable as a WASM target. Other languages and non-server consumers depend on this boundary.
- **`linkkeys`** is the server binary. CLI, database, network, HTTP, TCP all live here. It depends on `liblinkkeys`, never the reverse.
- **CSIL is the source of truth** for types and service interfaces. Generated code goes into `crates/liblinkkeys/src/generated/`. Hand-written code must not duplicate what CSIL defines.
- **SQLite compatibility** must be maintained alongside PostgreSQL. Use diesel's multi-backend support or feature-flag-switched builds. Never use Postgres-only SQL in migrations without a SQLite equivalent path. Migrations live in per-backend directories (`migrations/postgres/`, `migrations/sqlite/`).

## Code Generation

- Run `csilgen generate --input csil/linkkeys.csil --target rust --output crates/liblinkkeys/src/generated/` to regenerate types and service traits from CSIL.
- Generated files are checked in but must be reproducible. Never hand-edit generated files — fix the generator or the CSIL instead.
- If the generator lacks a capability we need, write a prompt describing the required change for a separate csilgen session. The csilgen repo lives at `~/repos/catalystcommunity/csilgen/` and has its own development lifecycle.
- Database models (diesel `Queryable`/`Insertable` structs) are in the server crate and may reference generated types from liblinkkeys but are not themselves generated yet. When a diesel generator exists, switch to it.

## Testing

- **All tests must pass at all times.** A failing test is a blocking issue regardless of whether it relates to current work.
- **DataUtils pattern**: Tests run against a real database (Postgres or SQLite), inside a transaction that rolls back. No mocks for the database layer. Test helpers build data hierarchically from a map, filling in defaults for fields the test doesn't care about.
- **Transaction isolation**: Each test gets its own transaction. Tests never see each other's data. This is non-negotiable — it's what makes parallel test execution safe and prevents coupling.
- **Don't couple tests to models**: Tests specify only the fields they care about. When a model gains a new required column, only tests that exercise that column need updating. The DataUtils factory fills defaults for everything else.
- **Dual-database testing**: Tests should be runnable against both Postgres and SQLite. Use `TEST_DATABASE_BACKEND=sqlite` or `TEST_DATABASE_BACKEND=postgres` to switch. CI runs both.

## Self-Review

- Before considering work complete, review the diff antagonistically. Look for: unnecessary complexity, missing error handling at system boundaries, security issues (OWASP top 10), coupling that violates architecture boundaries, tests that don't actually assert anything meaningful.
- Target: would you give this a 95% on a code review? If not, fix it.

## Commit Discipline

- Agents do not commit. The user commits separately.
- Keep changes focused. Don't fix unrelated things in the same logical change unless they're blocking.
- If tests are failing for unrelated reasons, fix them, but note it clearly so the user can commit separately if desired.

## csilgen Change Requests

When a change to csilgen is needed, create a markdown file in `docs/csilgen-requests/` describing:
1. What the generator should do differently
2. Why (with examples from linkkeys showing the gap)
3. Expected input CSIL and expected output code
4. Any test cases the csilgen change should include

This file becomes the prompt handed to a separate session working in the csilgen repo.

## Environment Variables

Standardized naming:
- `DATABASE_URL` — connection string (runtime + diesel CLI)
- `DATABASE_BACKEND` — `postgres` or `sqlite` (default: `postgres`)
- `TEST_DATABASE_URL` — test connection string
- `TEST_DATABASE_BACKEND` — test backend override
- `LOG_LEVEL`, `TCP_PORT`, `HTTPS_PORT` — server configuration

## Sync/Async Boundary

Generated CSIL traits are synchronous and infallible — they define pure business logic contracts. The server crate adds the fallible/async adapter layer:
- Rocket routes use `spawn_blocking` for diesel calls and return `Result<..., Status>`
- TCP handlers are already synchronous (thread-pool) so diesel calls are natural
- Errors are handled at the server boundary, not in the generated traits

## Error Handling

- Never log sensitive information (keys, claim values, session tokens, credentials).
- At system boundaries (user input, external APIs, network): validate and return helpful errors.
- Internal code: trust the type system and framework guarantees. Don't add defensive checks for impossible states.

## Dependencies

- Every dependency is a liability. Justify each one.
- Prefer standard library where reasonable.
- Security-critical dependencies (crypto, TLS) must be well-maintained and audited crates.
