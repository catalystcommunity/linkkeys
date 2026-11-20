"""Trust-change guard for LinkKeys pull requests.

A pull request is TRUST-CRITICAL when it can change what LinkKeys trusts, or
the code that decides it. A trust-critical pull request passes only with an
approval that the CI event system (the Reactorcide coordinator) recorded:

- scope `APPROVAL_SCOPE`, exactly (never `*`);
- approver subject in `TRUST_APPROVERS` (identities the VCS provider
  authenticated, mapped by the coordinator; never a git author email);
- pinned to this exact head SHA and base SHA, not invalidated, not expired.

Git author and committer fields are text that anyone can write, so this guard
never reads them.

What makes a pull request trust-critical (any one is enough):
1. A changed path under `GUARDED_PREFIXES` (compared case-folded and
   NFKC-normalized, so look-alike paths do not slip past).
2. A changed file that carries `MARKER` before or after the change. Trust
   anchors, their loaders, and their verifiers carry the marker. Removing the
   marker is a change to a marked file.
3. An added or removed line, in ANY file, that matches a tripwire (a PEM block,
   an embedded certificate file, a reference to the anchor directory, the
   marker string, an `unsafe` opt-out).
4. A git-level change that can redirect content: a symlink or submodule, a
   `.gitattributes`/`.gitmodules`/`build.rs` file, a non-ASCII path, or a
   binary that looks like a certificate.

Every commit in base..HEAD is checked (merges by their combined diff, so an
edit hidden in a merge counts), and so is the whole-PR diff.

This file has no runnerlib imports. `plugin_ci_jobs.py` loads it by path,
from the trusted CI checkout, so a pull request cannot replace it.
LINKKEYS-TRUST-CRITICAL
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set

# --- Policy ----------------------------------------------------------------

# The whole CI directory is guarded: every plugin there runs in the same
# process as this guard, so any of them can sabotage it.
GUARDED_PREFIXES = (
    ".reactorcide/",
    "crates/linkkeys/assets/tpm-trust/",
)

MARKER = "LINKKEYS-TRUST-" + "CRITICAL"  # split so this line is not a match

APPROVAL_SCOPE = "linkkeys-trust-anchors"

# Coordinator subjects. `vcs_user:<provider>/<login>` is authenticated by the
# VCS provider. `reactorcide_group:<name>` needs a verified identity link and
# is provider-neutral, which is how a vcsstar identity will qualify.
TRUST_APPROVERS = frozenset({
    "vcs_user:github/todpunk",
    "vcs_user:github/junipuff",
    "reactorcide_group:linkkeys-trust-maintainers",
})

TRIPWIRES = (
    (re.compile(r"-----(BEGIN|END) [A-Z0-9 ]+-----"), "PEM block"),
    (re.compile(r"include_bytes!\s*\("), "embedded bytes (include_bytes!)"),
    (re.compile(r"include_str!\s*\([^)]*\.(pem|der|crt|cer|p7b|p7c|cab)\b", re.I),
     "embedded certificate file"),
    (re.compile(r"tpm-trust", re.I), "reference to the trust-anchor directory"),
    (re.compile(re.escape(MARKER)), "trust-critical marker"),
    (re.compile(r"\b(forbid|deny)\s*\(\s*unsafe_code\s*\)"), "unsafe-code policy"),
    (re.compile(r"#!\[allow\(\s*unsafe_code"), "unsafe-code opt-out"),
)

HYGIENE_BASENAMES = {".gitattributes", ".gitmodules", "build.rs"}
CERT_EXTENSIONS = {".pem", ".der", ".crt", ".cer", ".p7b", ".p7c", ".p12", ".pfx", ".cab"}
LINK_MODES = {"120000", "160000"}


# --- Git access ------------------------------------------------------------


class Git:
    """Git with no shell, no external diff drivers, and no textconv."""

    def __init__(self, code_dir: Path):
        self.code_dir = code_dir
        self.env = dict(os.environ, GIT_EXTERNAL_DIFF="", GIT_CONFIG_NOSYSTEM="1",
                        GIT_TERMINAL_PROMPT="0")

    def _run(self, args: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=self.code_dir,
                              env=self.env, capture_output=True, check=False)

    def __call__(self, *args: str, check: bool = True) -> str:
        result = self._run(list(args))
        if check and result.returncode != 0:
            raise RuntimeError(
                f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}"
            )
        return result.stdout.decode("utf-8", errors="surrogateescape")

    def blob(self, rev: str, path: str) -> Optional[bytes]:
        """File content at a revision, or None when the file is absent there."""
        result = self._run(["cat-file", "blob", f"{rev}:{path}"])
        return result.stdout if result.returncode == 0 else None


def _norm(path: str) -> str:
    return unicodedata.normalize("NFKC", path).casefold()


# --- Findings --------------------------------------------------------------


class Findings:
    """Why a PR is trust-critical: path -> reasons."""

    def __init__(self) -> None:
        self.reasons: Dict[str, Set[str]] = {}

    def add(self, where: str, why: str) -> None:
        self.reasons.setdefault(where, set()).add(why)

    def __bool__(self) -> bool:
        return bool(self.reasons)

    def render(self) -> str:
        return "\n".join(
            f"  {where}: {', '.join(sorted(whys))}" for where, whys in sorted(self.reasons.items())
        )


def _check_path(path: str, findings: Findings) -> None:
    n = _norm(path)
    if any(n.startswith(_norm(p)) for p in GUARDED_PREFIXES):
        findings.add(path, "guarded path")
    if not path.isascii():
        findings.add(path, "non-ASCII path")
    base = n.rsplit("/", 1)[-1]
    if base in HYGIENE_BASENAMES:
        findings.add(path, f"git/build control file ({base})")


def _check_content(git: Git, revs: Iterable[str], path: str, findings: Findings) -> None:
    marker = MARKER.encode()
    for rev in revs:
        data = git.blob(rev, path)
        if data is None:
            continue
        if marker in data:
            findings.add(path, "file carries the trust-critical marker")
        ext = os.path.splitext(path)[1].lower()
        if b"\x00" in data[:8000] and (ext in CERT_EXTENSIONS or data[:2] == b"\x30\x82"):
            findings.add(path, "binary certificate-like file")


def _scan_patch(patch: str, label: str, findings: Findings) -> None:
    current = "?"
    for line in patch.splitlines():
        if line.startswith("+++ ") or line.startswith("--- "):
            name = line[4:]
            if name != "/dev/null":
                current = name[2:] if name[:2] in ("a/", "b/") else name
            continue
        if line.startswith("diff --"):
            continue
        if line.startswith("Binary files "):
            findings.add(current, "binary change")  # refined by _check_content
            continue
        # Unified (+/-) and combined (++, +-, -+, --, " +", ...) diff lines.
        prefix = re.match(r"^([ +\-]{1,2})", line)
        if not prefix or "+" not in prefix.group(1) and "-" not in prefix.group(1):
            continue
        body = line[len(prefix.group(1)):]
        for pattern, why in TRIPWIRES:
            if pattern.search(body):
                findings.add(current, f"tripwire: {why} ({label})")


def _raw_modes(raw: str, findings: Findings) -> None:
    # `git diff --raw -z`: ":old new oldsha newsha status\0path\0[path2\0]"
    parts = raw.split("\x00")
    i = 0
    while i < len(parts):
        head = parts[i]
        if not head.startswith(":"):
            i += 1
            continue
        fields = head[1:].split()
        modes = [m for m in fields if re.fullmatch(r"\d{6}", m)]
        status = fields[-1] if fields else ""
        npaths = 2 if status[:1] in ("R", "C") else 1
        paths = parts[i + 1:i + 1 + npaths]
        if any(m in LINK_MODES for m in modes):
            for p in paths:
                findings.add(p, "symlink or submodule")
        i += 1 + npaths


# --- Analysis --------------------------------------------------------------


def analyze(git: Git, base: str, head: str) -> Findings:
    """Return every reason this PR is trust-critical (empty = not)."""
    findings = Findings()
    merge_base = git("merge-base", base, head).strip()
    if not merge_base:
        raise RuntimeError(f"no merge base between {base} and {head}")

    commits = [c for c in git("rev-list", "--parents", f"{base}..{head}").splitlines() if c.strip()]
    for line in commits:
        commit, *parents = line.split()
        label = commit[:12]
        if len(parents) > 1:
            names = git("diff-tree", "--no-commit-id", "--name-only", "--cc", "-z", commit)
            patch = git("show", "--format=", "--cc", "-U0", "--no-ext-diff", "--no-textconv",
                        "--no-color", commit)
        else:
            names = git("diff-tree", "--no-commit-id", "--name-only", "-r", "--root", "-z", commit)
            patch = git("show", "--format=", "-U0", "--no-ext-diff", "--no-textconv",
                        "--no-color", commit)
            _raw_modes(git("diff-tree", "--no-commit-id", "-r", "--root", "--raw", "-z", commit),
                       findings)
        for path in (p for p in names.split("\x00") if p):
            _check_path(path, findings)
            _check_content(git, [commit, *parents], path, findings)
        _scan_patch(patch, label, findings)

    # The whole-PR view: what the merge would actually change.
    names = git("diff", "--name-only", "-z", merge_base, head)
    for path in (p for p in names.split("\x00") if p):
        _check_path(path, findings)
        _check_content(git, [merge_base, head], path, findings)
    _raw_modes(git("diff", "--raw", "-z", merge_base, head), findings)
    _scan_patch(git("diff", "-U0", "--no-ext-diff", "--no-textconv", "--no-color",
                    merge_base, head), "whole PR", findings)
    return findings


def _parse_time(value: object) -> Optional[datetime]:
    """Parse an RFC 3339 time. None stays None; anything malformed raises ValueError."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"not a time string: {value!r}")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"time has no zone: {value!r}")
    return parsed


# Approval kinds the guard accepts. Absent or "head_ci" is the scoped form
# (`/reactorcide approve linkkeys-trust-anchors ...`, or `approvals create
# --workflow linkkeys-trust-anchors`); "content" is Reactorcide R2
# (`/reactorcide approve-content linkkeys-trust-anchors`). Any other kind is
# refused, so a new kind cannot match until someone reviews it here.
APPROVAL_KINDS = {None, "", "head_ci", "content"}
APPROVAL_ENV = ("REACTORCIDE_CI_APPROVALS", "REACTORCIDE_CONTENT_APPROVALS")


def _load_approvals(env: Dict[str, str]) -> List[dict]:
    """Approval records from the coordinator facts. Malformed input counts as none."""
    records: List[dict] = []
    for name in APPROVAL_ENV:
        try:
            value = json.loads(env.get(name) or "[]")
        except json.JSONDecodeError:
            continue
        if isinstance(value, list):
            records.extend(a for a in value if isinstance(a, dict))
    return records


def find_approval(env: Dict[str, str], head_sha: str, base_sha: str,
                  now: Optional[datetime] = None) -> Optional[dict]:
    """Return a coordinator approval that authorizes this exact head, or None."""
    now = now or datetime.now(timezone.utc)
    for a in _load_approvals(env):
        # R2 may name the label `label`; the scoped form uses `workflow_scope`.
        scope = a.get("label") if a.get("kind") == "content" and "label" in a else a.get("workflow_scope")
        try:
            expires = _parse_time(a.get("expires_at"))
        except ValueError:
            continue  # a malformed record never authorizes
        if (
            a.get("kind") in APPROVAL_KINDS
            and scope == APPROVAL_SCOPE
            and str(a.get("approver_subject", "")).strip().lower() in TRUST_APPROVERS
            and a.get("head_sha") == head_sha
            and a.get("base_sha") == base_sha
            and not a.get("invalidated_at")
            and (expires is None or expires > now)
        ):
            return a
    return None


def run(code_dir: Path, base_ref: str, env: Dict[str, str], log: Callable[[str], None]) -> None:
    """The CI job. Raises RuntimeError to fail the pull request."""
    git = Git(code_dir)

    if git("rev-parse", "--is-shallow-repository").strip() == "true":
        git("fetch", "--unshallow", "--quiet", check=False)
        if git("rev-parse", "--is-shallow-repository").strip() == "true":
            raise RuntimeError("shallow checkout: cannot see every commit in the PR")

    head_sha = git("rev-parse", "HEAD").strip()
    expected_head = env.get("REACTORCIDE_SHA", "").strip()
    if expected_head and expected_head != head_sha:
        raise RuntimeError(f"checkout HEAD {head_sha} is not the event head {expected_head}")
    base_sha = git("rev-parse", f"{base_ref}^{{commit}}").strip()

    findings = analyze(git, base_sha, head_sha)
    if not findings:
        log("Not trust-critical: no guarded path, marked file, tripwire, or git control change.")
        return

    log("Trust-critical changes:\n" + findings.render())
    approval = find_approval(env, head_sha, env.get("REACTORCIDE_DIFF_BASE", base_sha).strip())
    if approval:
        log(f"Approved by {approval['approver_subject']} at head {head_sha[:12]} "
            f"(approval {approval.get('approval_id', '?')}).")
        return

    raise RuntimeError(
        "This pull request is trust-critical and has no matching approval.\n"
        + findings.render() + "\n\n"
        f"Approvers: {', '.join(sorted(TRUST_APPROVERS))}.\n"
        f"The approval must bind head {head_sha} and base {base_sha}; any new push "
        "invalidates it. Git author names and emails are not accepted as proof.\n\n"
        "Ways to approve (see docs/trust-change-control.md section 4):\n"
        "  - Now: a group member creates a group approval (UI, or\n"
        f"    reactorcide approvals create --workflow {APPROVAL_SCOPE} "
        "--subject reactorcide_group:linkkeys-trust-maintainers ...).\n"
        f"  - After Reactorcide B1: comment /reactorcide approve {APPROVAL_SCOPE} "
        "<profile> <policy-revision>.\n"
        f"  - After Reactorcide R2: comment /reactorcide approve-content {APPROVAL_SCOPE}.\n"
        "Then close and reopen the PR so the approval is read (until Reactorcide R3).\n"
    )
