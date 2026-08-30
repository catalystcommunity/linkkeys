"""Runnerlib lifecycle jobs for the LinkKeys CI workflows.

Job bodies live here as Python rather than as a shell block in a job YAML.
A shell block is re-quoted on its way to the runner's shell, which is how the
first version of the Go SDK job died with

    sh: 43: Syntax error: Unterminated quoted string

*after* its tests had already passed and printed their success line -- so the
reported exit code was the shell's, not the suite's. Commands here run through
`subprocess.run` on an argument list, with no shell involved, so that class of
failure cannot happen.

Wiring: a job YAML sets `REACTORCIDE_CI_JOB` in its `environment:` block, and
that name selects a function from `CI_JOBS` below. Runnerlib discovers this
file because it is named `plugin_*.py` and lives in `.reactorcide/plugins/`.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional

from src.logging import log_stdout
from src.plugins import Plugin, PluginContext, PluginPhase


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
