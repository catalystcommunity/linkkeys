# Reactorcide CI

LinkKeys uses native Reactorcide workflows. Reactorcide discovers the
workflow files, selects them by event and path, and runs the job graph. No
lifecycle plugin is necessary.

- Workflow definitions live in `.reactorcide/workflows/`. Each workflow has a
  stable `id` (its security identity), an `on:` trigger block, an optional
  top-level `paths:` filter, and a `jobs:` map.
- Job bodies live in `.reactorcide/jobs/`. A workflow node references one
  with `job_file:`. The node map key is the job name. Secret grants match
  this name.
- Job scripts live in `.reactorcide/jobs/scripts/`.
- Reactorcide prepares the source checkout at `REACTORCIDE_CODE_DIR`
  (default `/job/src`). Jobs do not clone the application source themselves.
- `run_as` declares the deployed worker user. `run_local` only controls local
  execution behavior.

## Workflows

| Workflow file | id | Events | Path filter | Nodes |
| --- | --- | --- | --- | --- |
| `pr.yaml` | `linkkeys-pr` | PR opened/updated | none | conventional-commits → build, test-sqlite, test-postgres |
| `pr-server-image.yaml` | `linkkeys-pr-server-image` | PR opened/updated | `crates/**`, `Cargo.toml`, `Cargo.lock`, `Dockerfile` | server-build-test |
| `pr-demoappsite.yaml` | `linkkeys-pr-demoappsite` | PR opened/updated | `demoappsite/**` | demoappsite-build-test |
| `pr-website.yaml` | `linkkeys-pr-website` | PR opened/updated | `website/**` | website-build-test |
| `release.yaml` | `linkkeys-release` | PR merged | none | release |
| `deploy-server.yaml` | `linkkeys-deploy-server` | push to main | `version/VERSION.txt` | server-build-and-deploy → rp-deploy |
| `deploy-demoappsite.yaml` | `linkkeys-deploy-demoappsite` | push to main | `demoappsite/version/VERSION.txt` | demoappsite-build-and-deploy |
| `deploy-website.yaml` | `linkkeys-deploy-website` | push to main | `website/content/extra_files/VERSION.txt` | website-build-and-deploy |

All node names carry the `linkkeys-` prefix (for example
`linkkeys-server-build-and-deploy`). These names match the coordinator's
secret grants. Do not rename a node without moving its grant.

`linkkeys-server-deploy.yaml` is a job body with no workflow. Use it with an
overlay for a manual deploy of another instance.

## Local Runs

`reactorcide run-local` executes the same workflow files the coordinator
evaluates. The current repository is the default source and trusted CI
directory. Run these before you open a PR:

```bash
reactorcide run-local --event pull_request_updated .reactorcide/workflows/pr.yaml
```

Use `--event` and `--changed-file` to test event and path selection:

```bash
reactorcide run-local --event push \
  --changed-file version/VERSION.txt \
  --dry-run \
  .reactorcide/workflows/deploy-server.yaml
```

Use `--dry-run` to see the resolved node specs without execution. Use
`--max-parallel` to limit concurrent nodes.

If the evaluator container rejects an option (for example
`No such option: --workflow-file`), the default evaluator image is stale.
Pass the newest public image:

```bash
reactorcide run-local \
  --eval-image containers.catalystsquad.com/public/reactorcide/runnerbase:latest \
  --event pull_request_updated \
  .reactorcide/workflows/pr.yaml
```

The build and test jobs run as the Reactorcide runner user so CI can wrap
them with `runnerlib run`. They install Rust and OS packages at runtime and
set `CARGO_TARGET_DIR=/tmp/linkkeys-target`, so local runs do not leave
root-owned files in the working tree. The Postgres job also needs the runner
user because `initdb` refuses to run as root.

## Side-Effect Gates

Local runs are real CI. A job that pushes to a remote system has an
environment gate for the side effect, not a blanket local disable:

- `linkkeys-release`: set `SKIP_GITHUB=true` for a local run. The gate skips
  the remote reset, the version-bump push, and the GitHub release create.
  The version-bump file edits and the build still run.

Jobs that read secrets need the local Reactorcide secret store:

```bash
REACTORCIDE_SECRETS_PASSWORD="$(cat ~/.reactorcide-pass)" \
  reactorcide run-local --event push \
  --changed-file version/VERSION.txt \
  .reactorcide/workflows/deploy-server.yaml
```

Deploy workflows executed locally without `--dry-run` deploy for real. For a
local dev-domain redeploy, prefer the operator script:

```bash
~/linkkeys-redeploy.sh --build squizzlezig
```

## Remote-Only Behavior

`linkkeys-conventional-commits` prefers PR diff metadata from Reactorcide.
A local run falls back to `origin/main..HEAD`.

The live IDPs (todandlorna, catalystsquad) are deliberately not deployed by
any workflow. Only the demo RP (`linkkeys-rp-deploy`) rolls automatically,
in lockstep with the demoappsite it backs.
