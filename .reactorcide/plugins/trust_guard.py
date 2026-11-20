"""Trust-change guard for LinkKeys pull requests.

A pull request is TRUST-CRITICAL when it can change what LinkKeys trusts, or
the code that decides it. The guard finds such pull requests. It does not
authorize them: the Reactorcide required review `REVIEW_ID` does that. A
maintainer accepts on the pull request, the coordinator posts the status
`Reactorcide Reviews`, and the GitHub ruleset requires that status.

The coordinator applies the review to the WHOLE pull request when any changed
path matches one of its path patterns. The patterns are a copy of
`REVIEW_PATHS_FILE`. The guard fails when:

- the pull request is trust-critical, but no changed path matches the review
  patterns, so the review would not apply (for example a PEM block added to an
  unmarked file, or an anchor changed and changed back inside the history);
- a file carries `MARKER` but no pattern in the pull request's copy of
  `REVIEW_PATHS_FILE` matches it (the list must follow the markers);
- the pull request's copy of `REVIEW_PATHS_FILE` drops a required pattern.

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
   file that looks like a certificate.

Every commit in base..HEAD is checked (merges by their combined diff, so an
edit hidden in a merge counts), and so is the whole-PR diff.

This file has no runnerlib imports. `plugin_ci_jobs.py` loads it by path,
from the trusted CI checkout, so a pull request cannot replace it.

Print the coordinator settings for `reactorcide trust set`:
    python3 -I .reactorcide/plugins/trust_guard.py --review-yaml
LINKKEYS-TRUST-CRITICAL
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unicodedata
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

# The coordinator required review that authorizes trust-critical changes.
REVIEW_ID = "linkkeys-trust-anchors"
REVIEW_DESCRIPTION = ("Trust anchors, their loaders and verifiers, git and build control "
                      "files, and the CI directory")
REVIEW_ACCEPT = ("reactorcide_group:linkkeys-trust-maintainers",)
REVIEW_PATHS_FILE = ".reactorcide/trust-review-paths.txt"
# A copy of the list that drops one of these is refused.
REQUIRED_PATTERNS = (".reactorcide/**", "crates/linkkeys/assets/tpm-trust/**")

# Markdown cannot load the anchor directory, so a mention there is not a
# signal. Code that loads it needs a path string in code, which still matches.
ANCHOR_DIR_REFERENCE = "reference to the trust-anchor directory"
PROSE_EXTENSIONS = {".md"}

TRIPWIRES = (
    (re.compile(r"-----(BEGIN|END) [A-Z0-9 ]+-----"), "PEM block"),
    (re.compile(r"include_bytes!\s*\("), "embedded bytes (include_bytes!)"),
    (re.compile(r"include_str!\s*\([^)]*\.(pem|der|crt|cer|p7b|p7c|cab)\b", re.I),
     "embedded certificate file"),
    (re.compile(r"tpm-trust", re.I), ANCHOR_DIR_REFERENCE),
    (re.compile(re.escape(MARKER)), "trust-critical marker"),
    (re.compile(r"\b(forbid|deny)\s*\(\s*unsafe_code\s*\)"), "unsafe-code policy"),
    (re.compile(r"#!\[allow\(\s*unsafe_code"), "unsafe-code opt-out"),
)

HYGIENE_BASENAMES = {".gitattributes", ".gitmodules", "build.rs"}
CERT_EXTENSIONS = {".pem", ".der", ".crt", ".cer", ".p7b", ".p7c", ".p12", ".pfx", ".cab"}
LINK_MODES = {"120000", "160000"}
# An X.509 certificate in DER is an ASN.1 SEQUENCE with a long-form length.
DER_SEQUENCE_STARTS = {b"\x30\x82", b"\x30\x83"}


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
        if ext in CERT_EXTENSIONS:
            findings.add(path, f"certificate file extension ({ext})")
        if data[:2] in DER_SEQUENCE_STARTS:
            findings.add(path, "DER-like content (ASN.1 SEQUENCE)")


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
            continue  # _check_content looks at the bytes
        # Unified (+/-) and combined (++, +-, -+, --, " +", ...) diff lines.
        prefix = re.match(r"^([ +\-]{1,2})", line)
        if not prefix or "+" not in prefix.group(1) and "-" not in prefix.group(1):
            continue
        body = line[len(prefix.group(1)):]
        prose = os.path.splitext(current)[1].lower() in PROSE_EXTENSIONS
        for pattern, why in TRIPWIRES:
            if prose and why == ANCHOR_DIR_REFERENCE:
                continue
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


# --- Required review --------------------------------------------------------


def glob_match(pattern: str, value: str) -> bool:
    """The coordinator's path match: case-sensitive, `**` crosses `/`, `*` does not."""
    expression = ["^"]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                expression.append(".*")
                i += 1
            else:
                expression.append("[^/]*")
        elif c == "?":
            expression.append("[^/]")
        else:
            expression.append(re.escape(c))
        i += 1
    expression.append(r"\Z")  # Go's `$`: the end of the text, never before a final newline
    return re.match("".join(expression), value, re.S) is not None


def parse_review_paths(text: str) -> List[str]:
    """One pattern per line; `#` starts a comment line; blank lines are skipped."""
    patterns = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def review_yaml(patterns: List[str]) -> str:
    """Settings for `reactorcide trust set`. Every value is quoted."""
    q = lambda v: "'" + v.replace("'", "''") + "'"
    lines = [
        f"# Generated from {REVIEW_PATHS_FILE} by trust_guard.py --review-yaml.",
        "required_reviews:",
        f"- id: {q(REVIEW_ID)}",
        f"  description: {q(REVIEW_DESCRIPTION)}",
        "  paths:",
        *[f"  - {q(p)}" for p in patterns],
        "  accept:",
        *[f"  - {q(a)}" for a in REVIEW_ACCEPT],
        "  count: 1",
    ]
    return "\n".join(lines) + "\n"


def _matches_any(path: str, patterns: Iterable[str]) -> bool:
    return any(glob_match(p, path) for p in patterns)


def list_problems(git: Git, head: str) -> List[str]:
    """Problems with the pull request's copy of the review path list."""
    data = git.blob(head, REVIEW_PATHS_FILE)
    if data is None:
        return [f"{REVIEW_PATHS_FILE} is missing"]
    try:
        patterns = parse_review_paths(data.decode("utf-8"))
    except UnicodeDecodeError:
        return [f"{REVIEW_PATHS_FILE} is not UTF-8"]
    problems = [f"{REVIEW_PATHS_FILE} must keep the pattern {p}"
                for p in REQUIRED_PATTERNS if p not in patterns]
    marked = git("grep", "-l", "-z", "-F", "-I", MARKER, head, "--", check=False)
    prefix = head + ":"
    for entry in (e for e in marked.split("\x00") if e):
        path = entry[len(prefix):] if entry.startswith(prefix) else entry
        if not _matches_any(path, patterns):
            problems.append(f"{path} carries the marker, but no pattern in "
                            f"{REVIEW_PATHS_FILE} matches it")
    return problems


def changed_paths(git: Git, merge_base: str, head: str) -> List[str]:
    """The paths the coordinator sees: the whole-PR diff, both sides of a rename."""
    names = git("diff", "--name-only", "--no-renames", "-z", merge_base, head)
    return [p for p in names.split("\x00") if p]


def _default_review_paths_file() -> Path:
    # .reactorcide/plugins/trust_guard.py -> .reactorcide/trust-review-paths.txt
    return Path(__file__).resolve().parent.parent / Path(REVIEW_PATHS_FILE).name


def run(code_dir: Path, base_ref: str, env: Dict[str, str], log: Callable[[str], None],
        review_paths_file: Optional[Path] = None) -> None:
    """The CI job. Raises RuntimeError to fail the pull request.

    `review_paths_file` is the trusted copy of the review list: the one in the
    CI checkout of the base, which is what the coordinator has applied.
    """
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

    trusted_file = review_paths_file or _default_review_paths_file()
    try:
        trusted = parse_review_paths(trusted_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise RuntimeError(f"cannot read the trusted review list {trusted_file}: {e}") from e
    if not trusted:
        raise RuntimeError(f"the trusted review list {trusted_file} has no patterns")

    findings = analyze(git, base_sha, head_sha)
    problems = list_problems(git, head_sha)

    merge_base = git("merge-base", base_sha, head_sha).strip()
    triggers = [p for p in changed_paths(git, merge_base, head_sha) if _matches_any(p, trusted)]

    if findings:
        log("Trust-critical changes:\n" + findings.render())
    if problems:
        raise RuntimeError(
            f"The review list {REVIEW_PATHS_FILE} does not match the repository:\n"
            + "\n".join(f"  {p}" for p in problems) + "\n\n"
            f"Add a pattern for each marked file. After the merge, apply the list with "
            f"`python3 -I .reactorcide/plugins/trust_guard.py --review-yaml` and "
            f"`reactorcide trust set` (docs/trust-change-control.md section 6).\n"
        )
    if not findings:
        log("Not trust-critical: no guarded path, marked file, tripwire, or git control change.")
        return
    if triggers:
        log(f"The required review {REVIEW_ID} applies to this pull request "
            f"(changed: {', '.join(sorted(triggers)[:5])}"
            f"{', ...' if len(triggers) > 5 else ''}). "
            "The merge needs a maintainer accept on status Reactorcide Reviews:\n"
            f"  /reactorcide accept {REVIEW_ID}")
        if REVIEW_PATHS_FILE in triggers:
            log(f"This pull request changes {REVIEW_PATHS_FILE}. After the merge, apply it "
                "with `reactorcide trust set` (docs/trust-change-control.md section 6).")
        return

    raise RuntimeError(
        "This pull request is trust-critical, but the required review "
        f"{REVIEW_ID} does not apply to it: no changed path matches {REVIEW_PATHS_FILE}.\n"
        + findings.render() + "\n\n"
        "Do one of these:\n"
        "  - Remove the trust signal from the change.\n"
        "  - Move the code into a file that carries the trust-critical marker, and add\n"
        f"    that file to {REVIEW_PATHS_FILE}.\n"
        "  - If the signal is only in the commit history (changed, then changed back),\n"
        "    squash the commits.\n"
        "Git author names and emails are not accepted as proof. "
        "See docs/trust-change-control.md.\n"
    )


def main(argv: List[str]) -> int:
    if argv[1:] == ["--review-yaml"]:
        sys.stdout.write(review_yaml(parse_review_paths(
            _default_review_paths_file().read_text(encoding="utf-8"))))
        return 0
    sys.stderr.write("usage: trust_guard.py --review-yaml\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
