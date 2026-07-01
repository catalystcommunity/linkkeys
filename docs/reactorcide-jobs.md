# Reactorcide Jobs

LinkKeys follows Reactorcide's trusted-CI / prepared-source model:

- job definitions and scripts live under `.reactorcide/jobs/`;
- Reactorcide prepares the source checkout at `REACTORCIDE_CODE_DIR` (default `/job/src`);
- jobs should not clone the application source themselves;
- `run_as` declares the deployed worker user, while `run_local` is only for local execution behavior.

## Local Runs

Local runs bind-mount the current working tree by default. These commands are useful before opening a PR:

```bash
reactorcide run-local --job-dir ./ .reactorcide/jobs/test-sqlite.yaml
reactorcide run-local --job-dir ./ .reactorcide/jobs/build.yaml
reactorcide run-local --job-dir ./ .reactorcide/jobs/test-postgres.yaml
```

The build/test jobs run in Reactorcide runnerbase as the runner user so CI can
wrap them with `runnerlib run` and prepare source before the command executes.
They install Rust and OS packages at runtime, and set
`CARGO_TARGET_DIR=/tmp/linkkeys-target` by default so local runs do not leave
root-owned files in the working tree.

The Postgres job also runs as the Reactorcide runner user because `initdb`
refuses to run as root.

## Remote-Only Jobs

These jobs are intentionally not general-purpose local commands:

- `linkkeys-conventional-commits` depends on PR diff metadata from Reactorcide.
- `linkkeys-release` pushes version commits and creates GitHub releases.

## Deploy Jobs

Deploy/build-push jobs can be run locally for emergency operations, but they
need local Reactorcide secrets for registry credentials and kubeconfig:

```bash
REACTORCIDE_SECRETS_PASSWORD="$(cat ~/.reactorcide-pass)" \
  reactorcide run-local --job-dir ./ .reactorcide/jobs/linkkeys-rp-deploy.yaml
```

For local dev-domain redeploys, prefer the existing operator script:

```bash
~/linkkeys-redeploy.sh --build squizzlezig
```
