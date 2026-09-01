"""Runnerlib lifecycle jobs for the LinkKeys CI workflows.

Job bodies live here as Python rather than as a shell block in a job YAML.
A shell block is re-quoted on its way to the runner's shell, which is how the
Go SDK job once died with

    sh: 43: Syntax error: Unterminated quoted string

*after* its tests had already passed and printed their success line -- so the
reported exit code was the shell's, not the suite's. Commands here run through
`subprocess.run` on an argument list, with no shell involved, so that class of
failure cannot happen.

Wiring: a job YAML sets `REACTORCIDE_CI_JOB` in its `environment:` block, and
that name selects a function from `CI_JOBS` at the bottom of this file.
Runnerlib discovers this file because it is named `plugin_*.py` and lives in
`.reactorcide/plugins/`, and it prefers the TRUSTED CI checkout over the
application source, so a pull request cannot introduce a plugin of its own.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional

from src.logging import log_stdout
from src.plugins import Plugin, PluginContext, PluginPhase


CONVENTIONAL_COMMIT_PATTERN = re.compile(
    r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(\(.+\))?!?: .+"
)

APT_PACKAGES_BASE = ["pkg-config", "build-essential"]
APT_PACKAGES_DB = ["libpq-dev", "libsqlite3-dev"]


def _run(
    command: List[str],
    *,
    cwd: Path,
    env: Optional[Dict[str, str]] = None,
    capture_output: bool = False,
) -> subprocess.CompletedProcess:
    """Run one command with no shell. A non-zero exit raises."""
    log_stdout(f"Running: {shlex.join(command)}")
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        text=True,
        capture_output=capture_output,
        env=env,
    )


def _apt_install(packages: List[str], *, cwd: Path) -> None:
    """Install build dependencies the runner image does not carry."""
    log_stdout("=== Installing system dependencies ===")
    _run(["sudo", "apt-get", "update"], cwd=cwd)
    _run(
        ["sudo", "apt-get", "install", "-y", "--no-install-recommends", *packages],
        cwd=cwd,
    )


def _cargo_environment() -> Dict[str, str]:
    """Return an environment with cargo on PATH and a writable target dir.

    The runner image ships a Rust toolchain under /usr/local/cargo. Putting
    both that and the user-local toolchain on PATH replaces the shell version's
    `. $HOME/.cargo/env`, which has no Python equivalent.
    """
    environment = os.environ.copy()
    home = Path(environment.get("HOME", "/home/runner"))
    environment["HOME"] = str(home)
    path_entries = [
        "/usr/local/cargo/bin",
        str(home / ".cargo" / "bin"),
        environment.get("PATH", ""),
    ]
    environment["PATH"] = ":".join(p for p in path_entries if p)
    # A shared target directory inside the pod. Each job is its own ephemeral
    # pod, so this is never shared BETWEEN jobs -- it only keeps the build out
    # of the source tree.
    environment.setdefault("CARGO_TARGET_DIR", "/tmp/linkkeys-target")
    return environment


def _postgres_environment(base: Dict[str, str]) -> Dict[str, str]:
    """Add the versioned PostgreSQL bin directory to PATH."""
    environment = dict(base)
    candidates = sorted(Path("/usr/lib/postgresql").glob("*/bin"))
    if not candidates:
        raise RuntimeError("No PostgreSQL bin directory under /usr/lib/postgresql")
    environment["PATH"] = f"{candidates[-1]}:{environment.get('PATH', '')}"
    return environment


def _git_diff_is_clean(paths: List[str], *, cwd: Path, what: str) -> None:
    """Fail when a checked-in generated artifact no longer matches its source."""
    result = subprocess.run(
        ["git", "diff", "--stat", "--", *paths],
        cwd=cwd,
        check=True,
        text=True,
        capture_output=True,
    )
    if result.stdout.strip():
        raise RuntimeError(
            f"{what} is out of date. Regenerate it and commit the result:\n"
            f"{result.stdout}"
        )


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


def conventional_commits(code_dir: Path) -> None:
    """Validate every commit message on the pull request."""
    base_url = os.environ.get("REACTORCIDE_BASE_URL", "")
    head_url = os.environ.get(
        "REACTORCIDE_HEAD_URL", os.environ.get("REACTORCIDE_SOURCE_URL", "")
    )
    base_ref = os.environ.get(
        "REACTORCIDE_BASE_REF", os.environ.get("REACTORCIDE_PR_BASE_REF", "main")
    )

    # For a fork pull request the prepared checkout is the PR head. Add the
    # trusted upstream as a second remote so base..HEAD ranges resolve, without
    # executing any CI definition from the fork.
    remote = "origin"
    if base_url and base_url != head_url:
        subprocess.run(
            ["git", "remote", "add", "upstream", base_url],
            cwd=code_dir,
            check=False,
            capture_output=True,
        )
        _run(["git", "fetch", "upstream", base_ref], cwd=code_dir)
        remote = "upstream"

    diff_base = os.environ.get("REACTORCIDE_DIFF_BASE") or f"{remote}/{base_ref}"

    log_stdout("=== Validating Conventional Commits ===")
    result = _run(
        ["git", "log", f"{diff_base}..HEAD", "--pretty=format:%H %s"],
        cwd=code_dir,
        capture_output=True,
    )

    failures = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        commit_hash, _, message = line.partition(" ")
        if CONVENTIONAL_COMMIT_PATTERN.match(message):
            log_stdout(f"OK: {message}")
        else:
            log_stdout(f"FAIL: {message} ({commit_hash})")
            failures.append(f"{commit_hash} {message}")

    if failures:
        raise RuntimeError(
            "Commit messages must match: type(scope)?: description\n"
            "Valid types: feat, fix, docs, style, refactor, perf, test, build, "
            "ci, chore, revert\n"
            "Offending commits:\n  " + "\n  ".join(failures)
        )

    log_stdout("All commits follow conventional commit format.")


def web_ui(code_dir: Path) -> None:
    """Build the embedded web UI and prove the committed assets match it.

    Split out of the SQLite job so it runs in parallel with the Rust work
    instead of adding minutes to the longest job on the critical path.
    """
    ui_dir = code_dir / "web-ui"
    if not ui_dir.is_dir():
        raise RuntimeError(f"web-ui directory not found: {ui_dir}")

    # The runner image carries no Node. This used to ride along on the SQLite
    # job's apt line, which is easy to lose when a job is split out.
    _apt_install(["nodejs", "npm"], cwd=code_dir)

    log_stdout("=== Building the embedded web UI ===")
    _run(["npm", "ci", "--no-audit", "--no-fund"], cwd=ui_dir)
    _run(["npm", "run", "build"], cwd=ui_dir)

    log_stdout("=== npm audit ===")
    _run(["npm", "audit", "--omit=optional"], cwd=ui_dir)

    # crates/linkkeys/assets/ui is checked in and embedded in the binary. If a
    # build changes it, the commit is missing the rebuilt asset.
    _git_diff_is_clean(
        ["crates/linkkeys/assets/ui"],
        cwd=code_dir,
        what="The embedded web UI in crates/linkkeys/assets/ui",
    )


def build(code_dir: Path) -> None:
    """Build the workspace in release mode, then audit dependencies."""
    _apt_install(APT_PACKAGES_BASE + APT_PACKAGES_DB, cwd=code_dir)
    environment = _cargo_environment()

    log_stdout("=== Building workspace (release) ===")
    _run(["cargo", "build", "--release"], cwd=code_dir, env=environment)

    # cargo-deny moved here from the SQLite job: it needs a cargo toolchain,
    # and this job is well off the critical path while that one is on it.
    log_stdout("=== cargo deny ===")
    if subprocess.run(
        ["cargo", "deny", "--version"], cwd=code_dir, env=environment, capture_output=True
    ).returncode != 0:
        _run(["cargo", "install", "cargo-deny", "--locked"], cwd=code_dir, env=environment)
    _run(["cargo", "deny", "check"], cwd=code_dir, env=environment)


def test_sqlite(code_dir: Path) -> None:
    """Run the test suite against SQLite, then check the conformance vectors."""
    _apt_install(APT_PACKAGES_BASE + APT_PACKAGES_DB, cwd=code_dir)
    environment = _cargo_environment()
    environment["TEST_DATABASE_BACKEND"] = "sqlite"

    log_stdout("=== Running tests (SQLite backend) ===")
    _run(["cargo", "test", "--all-features"], cwd=code_dir, env=environment)

    # The application-key conformance vectors are checked in and other-language
    # SDKs are validated against them, so they must stay reproducible from the
    # generator. It is deterministic by construction (fixed seeds, fixed
    # timestamps, injected randomness), so regenerating must be a no-op.
    log_stdout("=== Checking conformance vectors are reproducible ===")
    _run(
        ["cargo", "run", "-p", "liblinkkeys", "--example",
         "generate_application_key_vectors"],
        cwd=code_dir,
        env=environment,
    )
    _git_diff_is_clean(
        ["sdks/regular-rp/conformance"],
        cwd=code_dir,
        what="The application-key conformance vectors",
    )


def test_postgres(code_dir: Path) -> None:
    """Run the test suite against a job-local PostgreSQL cluster."""
    _apt_install(
        APT_PACKAGES_BASE + APT_PACKAGES_DB + ["postgresql", "postgresql-client"],
        cwd=code_dir,
    )
    environment = _postgres_environment(_cargo_environment())

    log_stdout("=== Starting PostgreSQL ===")
    pgdata = "/tmp/pgdata"
    _run(
        ["initdb", "-D", pgdata, "--auth=trust", "--username=runner"],
        cwd=code_dir,
        env=environment,
    )
    _run(
        ["pg_ctl", "-D", pgdata, "-l", "/tmp/pg.log",
         "-o", "-k /tmp -h 127.0.0.1 -p 5432", "-w", "start"],
        cwd=code_dir,
        env=environment,
    )
    _run(
        ["createdb", "-h", "/tmp", "-U", "runner", "linkkeys_test"],
        cwd=code_dir,
        env=environment,
    )

    environment["TEST_DATABASE_BACKEND"] = "postgres"
    environment["TEST_DATABASE_URL"] = "postgres://runner@127.0.0.1/linkkeys_test"

    log_stdout("=== Running tests (PostgreSQL backend) ===")
    _run(["cargo", "test"], cwd=code_dir, env=environment)


def _go_environment() -> Dict[str, str]:
    """Return Go cache paths the configured job user can write.

    These jobs run under a CI profile with `may_run_as_root: false`, but the
    runner image ships `GOPATH=/go`, which the runner user cannot create:

        go: could not create module cache: mkdir /go/pkg: permission denied
    """
    environment = os.environ.copy()
    home = Path(environment.get("HOME", "/home/runner"))
    gopath = home / ".cache" / "go"
    environment["GOPATH"] = str(gopath)
    environment["GOMODCACHE"] = str(gopath / "pkg" / "mod")
    environment["GOCACHE"] = str(home / ".cache" / "go-build")
    for path in (environment["GOMODCACHE"], environment["GOCACHE"]):
        Path(path).mkdir(parents=True, exist_ok=True)
    return environment


def test_regular_rp_go(code_dir: Path) -> None:
    """Test the regular-RP Go SDK against the application-key vectors.

    The suite replays the cross-language conformance vectors in
    `sdks/regular-rp/conformance/`. That replay is the only thing proving the
    Go implementation still agrees with the Rust reference in
    `crates/liblinkkeys/src/application_keys.rs`; a drift there is a silent
    verification difference between two implementations of one protocol.
    """
    sdk_dir = code_dir / "sdks" / "regular-rp" / "go"
    if not sdk_dir.is_dir():
        raise RuntimeError(f"Go SDK directory not found: {sdk_dir}")

    environment = _go_environment()
    _run(["go", "version"], cwd=sdk_dir, env=environment)

    log_stdout("=== gofmt ===")
    formatted = _run(
        ["gofmt", "-l", "."], cwd=sdk_dir, env=environment, capture_output=True
    )
    unformatted = formatted.stdout.strip()
    if unformatted:
        raise RuntimeError(f"gofmt found unformatted files:\n{unformatted}")

    log_stdout("=== go vet ===")
    _run(["go", "vet", "./..."], cwd=sdk_dir, env=environment)

    log_stdout("=== go test (race) ===")
    _run(["go", "test", "./...", "-race"], cwd=sdk_dir, env=environment)


CI_JOBS: Dict[str, Callable[[Path], None]] = {
    "conventional-commits": conventional_commits,
    "web-ui": web_ui,
    "build": build,
    "test-sqlite": test_sqlite,
    "test-postgres": test_postgres,
    "test-regular-rp-go": test_regular_rp_go,
}


class LinkKeysCIJobsPlugin(Plugin):
    """Run one selected LinkKeys CI job after source preparation."""

    def __init__(self):
        super().__init__(name="linkkeys_ci_jobs", priority=50)

    def supported_phases(self):
        return [PluginPhase.POST_SOURCE_PREP]

    def execute(self, context: PluginContext) -> None:
        if context.phase != PluginPhase.POST_SOURCE_PREP:
            return

        job_name = os.environ.get("REACTORCIDE_CI_JOB", "").strip()
        if not job_name:
            return

        job = CI_JOBS.get(job_name)
        if job is None:
            names = ", ".join(sorted(CI_JOBS))
            raise RuntimeError(
                f"Unknown REACTORCIDE_CI_JOB '{job_name}'. Valid jobs: {names}"
            )

        code_dir = Path(context.config.code_dir)
        if not code_dir.is_dir():
            raise RuntimeError(f"Code directory does not exist: {code_dir}")

        log_stdout(f"Starting runnerlib lifecycle job: {job_name}")
        job(code_dir)
        log_stdout(f"Completed runnerlib lifecycle job: {job_name}")
