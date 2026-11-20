"""Adversarial tests for trust_guard.py. Each case is a sneaky PR in a scratch repo.

Run from the repository root (needs git):
    python3 -I .reactorcide/plugins/trust_guard_test.py

Run it after every change to trust_guard.py. A new bypass idea gets a case here
first, then the fix.
"""
import importlib.util
import json
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
        "crates/liblinkkeys/src/lib.rs": "#![forbid(unsafe_code)]\npub mod device;\n",
    }, "chore: base", who=TOD)
    return repo


def approval(head, base, **over):
    a = {"approval_id": "a1", "workflow_scope": tg.APPROVAL_SCOPE,
         "approver_subject": "vcs_user:github/todpunk", "head_sha": head, "base_sha": base,
         "invalidated_at": None, "expires_at": None}
    a.update(over)
    return a


def run(repo, base, approvals=None, env_extra=None, content=None):
    head = git(repo, "rev-parse", "HEAD")
    env = {"REACTORCIDE_DIFF_BASE": base, "REACTORCIDE_SHA": head}
    if approvals is not None:
        env["REACTORCIDE_CI_APPROVALS"] = json.dumps(approvals(head, base))
    if content is not None:
        env["REACTORCIDE_CONTENT_APPROVALS"] = json.dumps(content(head, base))
    env.update(env_extra or {})
    try:
        tg.run(Path(repo), base, env, lambda m: None)
        return "pass"
    except RuntimeError as e:
        msg = str(e)
        if "no matching approval" in msg:
            return "fail"
        if "is not the event head" in msg:
            return "fail"
        return "ERROR: " + msg.splitlines()[0][:90]


results = []


def case(name, build, expect, approvals=None, env_extra=None, content=None):
    repo = new_repo()
    base = git(repo, "rev-parse", "HEAD")
    build(repo)
    got = run(repo, base, approvals, env_extra, content)
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


def symlink(repo):
    os.symlink("../crates/linkkeys/assets/tpm-trust", Path(repo, "docs-link"))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "docs: link")


ok_build = lambda r: commit(r, {"crates/linkkeys/src/web.rs": "fn page() { render() }\n"})

# --- not trust-critical ----------------------------------------------------
case("ordinary code change, no approval", ok_build, "pass")

# --- trust-critical: must fail without approval ----------------------------
attacks = {
    "anchor change with SPOOFED todpunk author": lambda r: commit(r, {TRUST: "evil\n"}, who=TOD),
    "new file in anchor dir": lambda r: commit(r, {"crates/linkkeys/assets/tpm-trust/x.pem": "e\n"}),
    "delete anchor dir": lambda r: commit(r, {"crates/linkkeys/assets/tpm-trust": None}),
    "edit CI plugin": lambda r: commit(r, {".reactorcide/plugins/plugin_x.py": "import os\n"}),
    "case-variant guarded path": lambda r: commit(r, {"Crates/LinkKeys/Assets/TPM-Trust/x.pem": "e\n"}),
    "unicode look-alike dir (U+2010)": lambda r: commit(r, {"crates/linkkeys/assets/tpm‐trust/x.pem": "e\n"}),
    "edit marked loader, marker kept": lambda r: commit(r, {LOADER: f"// {MARK}\npub fn verify() -> bool {{ true }}\n"}),
    "strip marker from loader": lambda r: commit(r, {LOADER: "pub fn verify() -> bool { true }\n"}),
    "PEM block in unrelated file": lambda r: commit(r, {"crates/linkkeys/src/web.rs": "const R: &str = \"-----BEGIN CERTIFICATE-----\";\n"}),
    "include_bytes of a blob": lambda r: commit(r, {"crates/linkkeys/src/web.rs": "static R: &[u8] = include_bytes!(\"../roots.bin\");\n"}),
    "include_str of a .der": lambda r: commit(r, {"crates/linkkeys/src/web.rs": "static R: &str = include_str!(\"x.DER\");\n"}),
    "mention anchor dir in code": lambda r: commit(r, {"crates/linkkeys/src/web.rs": "const D: &str = \"assets/tpm-trust\";\n"}),
    "add .gitattributes": lambda r: commit(r, {".gitattributes": "*.pem filter=evil\n"}),
    "add build.rs": lambda r: commit(r, {"crates/linkkeys/build.rs": "fn main() {}\n"}),
    "symlink to anchor dir": symlink,
    "binary DER cert outside dir": lambda r: commit(r, {"crates/linkkeys/src/data.dat": b"\x30\x82\x01\x00\x00\x01\x02"}),
    "remove forbid(unsafe_code)": lambda r: commit(r, {"crates/liblinkkeys/src/lib.rs": "pub mod device;\n"}),
    "evil edit hidden in merge commit": evil_merge,
    "change then revert anchor (history)": lambda r: (commit(r, {TRUST: "evil\n"}), commit(r, {TRUST: "root-1\n"})),
}
for name, build in attacks.items():
    case(name + " -> no approval", build, "fail")

# --- approvals -------------------------------------------------------------
anchor = lambda r: commit(r, {TRUST: "root-2\n"})
case("anchor change, valid approval", anchor, "pass", approvals=lambda h, b: [approval(h, b)])
case("anchor change, group approver", anchor, "pass",
     approvals=lambda h, b: [approval(h, b, approver_subject="reactorcide_group:linkkeys-trust-maintainers")])
case("anchor change, JuniPuff (mixed case)", anchor, "pass",
     approvals=lambda h, b: [approval(h, b, approver_subject="vcs_user:github/JuniPuff")])
bad = {
    "wildcard scope *": dict(workflow_scope="*"),
    "head-CI scope linkkeys-pr": dict(workflow_scope="linkkeys-pr"),
    "approver not allowed": dict(approver_subject="vcs_user:github/eve"),
    "project_owner subject": dict(approver_subject="project_owner"),
    "same login other provider": dict(approver_subject="vcs_user:gitlab/todpunk"),
    "invalidated": dict(invalidated_at="2026-11-14T00:00:00Z"),
    "expired": dict(expires_at="2020-01-01T00:00:00Z"),
    "stale head": dict(head_sha="0" * 40),
    "wrong base": dict(base_sha="1" * 40),
}
for name, over in bad.items():
    case(f"anchor change, approval {name}", anchor, "fail",
         approvals=lambda h, b, over=over: [approval(h, b, **over)])
case("anchor change, malformed approvals JSON", anchor, "fail",
     env_extra={"REACTORCIDE_CI_APPROVALS": "{not json"})
# --- Reactorcide R2 content approvals and the change period -----------------
def content_approval(h, b, **over):
    a = approval(h, b, kind="content", label=tg.APPROVAL_SCOPE)
    a.pop("workflow_scope")
    a.update(over)
    return a


case("content approval (label)", anchor, "pass", content=lambda h, b: [content_approval(h, b)])
case("content approval without label, scoped field", anchor, "pass",
     content=lambda h, b: [approval(h, b, kind="content")])
case("scoped approval with kind head_ci (change period)", anchor, "pass",
     approvals=lambda h, b: [approval(h, b, kind="head_ci")])
case("content approval, wrong label", anchor, "fail",
     content=lambda h, b: [content_approval(h, b, label="linkkeys-pr")])
case("content approval, label * ", anchor, "fail",
     content=lambda h, b: [content_approval(h, b, label="*")])
case("content approval, stale head", anchor, "fail",
     content=lambda h, b: [content_approval(h, b, head_sha="0" * 40)])
case("unknown approval kind", anchor, "fail",
     approvals=lambda h, b: [approval(h, b, kind="admin_override")])
case("bad expires_at type", anchor, "fail",
     approvals=lambda h, b: [approval(h, b, expires_at=12345)])
case("naive expires_at (no zone)", anchor, "fail",
     approvals=lambda h, b: [approval(h, b, expires_at="2999-01-01T00:00:00")])
case("malformed CI approvals, valid content approval", anchor, "pass",
     env_extra={"REACTORCIDE_CI_APPROVALS": "{bad"},
     content=lambda h, b: [content_approval(h, b)])

case("checkout HEAD differs from event head", ok_build, "fail",
     env_extra={"REACTORCIDE_SHA": "2" * 40})

ok = True
for name, expect, got in results:
    good = expect == got
    ok &= good
    print(f"{'ok ' if good else 'BAD'} expect={expect:4} got={got:4}  {name}")
print(f"\n{sum(e == g for _, e, g in results)}/{len(results)} as expected")
sys.exit(0 if ok else 1)
