"""Adversarial tests for trust_guard.py. Each case is a sneaky PR in a scratch repo.

Run from the repository root (needs git):
    python3 -I .reactorcide/plugins/trust_guard_test.py

Run it after every change to trust_guard.py. A new bypass idea gets a case here
first, then the fix.

Results:
- "pass":   not trust-critical.
- "review": trust-critical, and the required review applies (a maintainer
            accept is needed to merge).
- "fail":   the guard fails the PR.
"""
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

GUARD = str(Path(__file__).resolve().with_name("trust_guard.py"))
spec = importlib.util.spec_from_file_location("trust_guard", GUARD)
tg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tg)

MARK = "LINKKEYS-TRUST-" + "CRITICAL"
TOD = ("Tod Hansmann", "githubpub@todandlorna.com")  # spoofable, must not matter
EVE = ("Eve", "eve@example.com")
TRUST = "crates/linkkeys/assets/tpm-trust/tpm-roots.pem"
LOADER = "crates/liblinkkeys/src/device/evidence.rs"
LIST = tg.REVIEW_PATHS_FILE
BASE_LIST = "\n".join([
    "# test list",
    ".reactorcide/**",
    "crates/linkkeys/assets/tpm-trust/**",
    ".gitattributes",
    "**/.gitattributes",
    ".gitmodules",
    "build.rs",
    "**/build.rs",
    LOADER,
    "crates/liblinkkeys/src/lib.rs",
    "",
])
GIT_ENV = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")


def git(repo, *args, who=EVE):
    env = dict(GIT_ENV, GIT_AUTHOR_NAME=who[0], GIT_AUTHOR_EMAIL=who[1],
               GIT_COMMITTER_NAME=who[0], GIT_COMMITTER_EMAIL=who[1])
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, env=env,
                          check=True, capture_output=True).stdout.decode().strip()


def write(repo, path, data):
    p = Path(repo, path)
    p.parent.mkdir(parents=True, exist_ok=True)
    (p.write_bytes if isinstance(data, bytes) else p.write_text)(data)


def commit(repo, files, msg="feat: x", who=EVE):
    for path, data in files.items():
        if data is None:
            git(repo, "rm", "-q", "-r", path, who=who)
        else:
            write(repo, path, data)
    git(repo, "add", "-A", who=who)
    git(repo, "commit", "-q", "-m", msg, who=who)


def new_repo():
    repo = tempfile.mkdtemp()
    git(repo, "init", "-q", "-b", "main")
    commit(repo, {
        TRUST: "root-1\n",
        LOADER: f"// {MARK}\npub fn verify() -> bool {{ check_chain() }}\n",
        "crates/linkkeys/src/web.rs": "fn page() {}\n",
        "README.md": "readme\n",
        "crates/liblinkkeys/src/lib.rs": f"// {MARK}\n#![forbid(unsafe_code)]\npub mod device;\n",
        LIST: BASE_LIST,
    }, "chore: base", who=TOD)
    return repo


def run(repo, base, env_extra=None, trusted_list=BASE_LIST):
    head = git(repo, "rev-parse", "HEAD")
    env = {"REACTORCIDE_SHA": head}
    env.update(env_extra or {})
    trusted = Path(tempfile.mkdtemp(), "trust-review-paths.txt")
    if trusted_list is not None:
        trusted.write_text(trusted_list)
    logs = []
    try:
        tg.run(Path(repo), base, env, logs.append, review_paths_file=trusted)
    except RuntimeError as e:
        msg = str(e)
        known = ("does not apply to it", "does not match the repository", "is not the event head",
                 "cannot read the trusted review list", "has no patterns")
        return "fail" if any(k in msg for k in known) else "ERROR: " + msg.splitlines()[0][:90]
    text = "\n".join(logs)
    if "Not trust-critical" in text:
        return "pass"
    if f"required review {tg.REVIEW_ID} applies" in text:
        return "review"
    return "ERROR: no verdict logged"


results = []


def case(name, build, expect, **kw):
    repo = new_repo()
    base = git(repo, "rev-parse", "HEAD")
    build(repo)
    got = run(repo, base, **kw)
    results.append((name, expect, got))


def evil_merge(repo):
    git(repo, "checkout", "-q", "-b", "feature")
    commit(repo, {"a.rs": "a\n"})
    git(repo, "checkout", "-q", "main")
    commit(repo, {"b.rs": "b\n"}, who=TOD)
    git(repo, "checkout", "-q", "feature")
    git(repo, "merge", "-q", "--no-commit", "main")
    write(repo, LOADER, f"// {MARK}\npub fn verify() -> bool {{ true }}\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-edit")


def evil_merge_uncovered(repo):
    git(repo, "checkout", "-q", "-b", "feature")
    commit(repo, {"a.rs": "a\n"})
    git(repo, "checkout", "-q", "main")
    commit(repo, {"b.rs": "b\n"}, who=TOD)
    git(repo, "checkout", "-q", "feature")
    git(repo, "merge", "-q", "--no-commit", "main")
    write(repo, "crates/linkkeys/src/web.rs", "const R: &str = \"-----BEGIN CERTIFICATE-----\";\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--no-edit")


def symlink(repo):
    os.symlink("../crates/linkkeys/assets/tpm-trust", Path(repo, "docs-link"))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "docs: link")


def rename_out(repo):
    git(repo, "mv", TRUST, "crates/linkkeys/src/roots.txt")
    git(repo, "commit", "-q", "-m", "refactor: move")


WEB = "crates/linkkeys/src/web.rs"
ok_build = lambda r: commit(r, {WEB: "fn page() { render() }\n"})
pem = "const R: &str = \"-----BEGIN CERTIFICATE-----\";\n"

# --- not trust-critical ----------------------------------------------------
case("ordinary code change", ok_build, "pass")
case("Markdown mentions the anchor directory", lambda r: commit(r, {"docs/x.md": "See tpm-trust/.\n"}), "pass")
case("PNG image added", lambda r: commit(r, {"web-ui/logo.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"}), "pass")

# --- trust-critical, covered by the review: the merge needs an accept ------
covered = {
    "anchor change with SPOOFED todpunk author": lambda r: commit(r, {TRUST: "evil\n"}, who=TOD),
    "new file in anchor dir": lambda r: commit(r, {"crates/linkkeys/assets/tpm-trust/x.pem": "e\n"}),
    "delete anchor dir": lambda r: commit(r, {"crates/linkkeys/assets/tpm-trust": None}),
    "edit CI plugin": lambda r: commit(r, {".reactorcide/plugins/plugin_x.py": "import os\n"}),
    "edit marked loader, marker kept": lambda r: commit(r, {LOADER: f"// {MARK}\npub fn verify() -> bool {{ true }}\n"}),
    "strip marker from listed loader": lambda r: commit(r, {LOADER: "pub fn verify() -> bool { true }\n"}),
    "remove forbid(unsafe_code) in listed lib.rs": lambda r: commit(r, {"crates/liblinkkeys/src/lib.rs": f"// {MARK}\npub mod device;\n"}),
    "add .gitattributes": lambda r: commit(r, {".gitattributes": "*.pem filter=evil\n"}),
    "add nested build.rs": lambda r: commit(r, {"crates/linkkeys/build.rs": "fn main() {}\n"}),
    "evil edit of loader hidden in merge commit": evil_merge,
    "rename anchor out of the directory": rename_out,
    "PEM in unmarked file plus anchor change": lambda r: commit(r, {WEB: pem, TRUST: "root-2\n"}),
    "new marked file, added to the list": lambda r: commit(r, {
        "crates/x/verify.rs": f"// {MARK}\nfn v() {{}}\n", LIST: BASE_LIST + "crates/x/verify.rs\n"}),
    "PR adds its own PEM file to the list": lambda r: commit(r, {
        WEB: pem, LIST: BASE_LIST + WEB + "\n"}),
}
for name, build in covered.items():
    case(name, build, "review")

# --- trust-critical, NOT covered: the guard fails ----------------------------
uncovered = {
    "PEM block in unmarked file": lambda r: commit(r, {WEB: pem}),
    "include_bytes of a blob": lambda r: commit(r, {WEB: "static R: &[u8] = include_bytes!(\"../roots.bin\");\n"}),
    "include_str of a .der": lambda r: commit(r, {WEB: "static R: &str = include_str!(\"x.DER\");\n"}),
    "mention anchor dir in code": lambda r: commit(r, {WEB: "const D: &str = \"assets/tpm-trust\";\n"}),
    "case-variant guarded path": lambda r: commit(r, {"Crates/LinkKeys/Assets/TPM-Trust/x.pem": "e\n"}),
    "unicode look-alike dir (U+2010)": lambda r: commit(r, {"crates/linkkeys/assets/tpm‐trust/x.pem": "e\n"}),
    "symlink to anchor dir": symlink,
    "DER cert outside dir": lambda r: commit(r, {"crates/linkkeys/src/data.dat": b"\x30\x82\x01\x00\x00\x01\x02"}),
    "DER cert without NUL bytes": lambda r: commit(r, {"crates/linkkeys/src/data.dat": b"\x30\x82\x01\x01\x02\x03"}),
    ".crt file outside dir": lambda r: commit(r, {"crates/linkkeys/src/x.crt": "text\n"}),
    "change then revert anchor (history only)": lambda r: (commit(r, {TRUST: "evil\n"}), commit(r, {TRUST: "root-1\n"})),
    "PEM hidden in merge commit": evil_merge_uncovered,
    "new marked file, list not updated": lambda r: commit(r, {"crates/x/verify.rs": f"// {MARK}\nfn v() {{}}\n"}),
    "add marker to unlisted file": lambda r: commit(r, {WEB: f"// {MARK}\nfn page() {{}}\n"}),
}
for name, build in uncovered.items():
    case(name, build, "fail")

# --- the review list itself ------------------------------------------------
case("list drops .reactorcide/**", lambda r: commit(r, {LIST: BASE_LIST.replace(".reactorcide/**\n", "")}), "fail")
case("list drops tpm-trust/**", lambda r: commit(r, {LIST: BASE_LIST.replace("crates/linkkeys/assets/tpm-trust/**\n", "")}), "fail")
case("list drops a marked file", lambda r: commit(r, {LIST: BASE_LIST.replace(LOADER + "\n", "")}), "fail")
case("list deleted", lambda r: commit(r, {LIST: None}), "fail")
case("trusted list missing", ok_build, "fail", trusted_list=None)
case("trusted list empty", ok_build, "fail", trusted_list="# nothing\n")
case("trusted list lacks the PEM file; head list adds it", lambda r: commit(r, {
    WEB: pem, LIST: BASE_LIST + WEB + "\n"}), "review")

# --- event facts -----------------------------------------------------------
case("checkout HEAD differs from event head", ok_build, "fail",
     env_extra={"REACTORCIDE_SHA": "2" * 40})

# --- the coordinator's glob semantics ----------------------------------------
globs = [
    (".reactorcide/**", ".reactorcide/plugins/x.py", True),
    ("build.rs", "crates/a/build.rs", False),
    ("**/build.rs", "crates/a/build.rs", True),
    ("**/build.rs", "build.rs", False),
    ("crates/*.rs", "crates/a/b.rs", False),
    ("crates/linkkeys/assets/tpm-trust/**", "Crates/linkkeys/assets/tpm-trust/x", False),
    ("a.rs", "a.rs\nb", False),
    ("a.rs", "a.rs\n", False),
    ("x/**", "x/a\nb", True),
]
for pattern, value, want in globs:
    results.append((f"glob {pattern!r} vs {value!r}", str(want), str(tg.glob_match(pattern, value))))

ok = True
for name, expect, got in results:
    good = expect == got
    ok &= good
    print(f"{'ok ' if good else 'BAD'} expect={expect:6} got={got:6}  {name}")
print(f"\n{sum(e == g for _, e, g in results)}/{len(results)} as expected")
sys.exit(0 if ok else 1)
