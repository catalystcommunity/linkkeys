#!/usr/bin/env python3
"""
PR Merge Workflow for LinkKeys Website

This workflow handles the CI/CD pipeline when a PR with website changes
is merged to main:
1. Runs semver-tags to determine if there are releasable changes
2. If changes exist, updates website/content/extra_files/VERSION.txt and commits
3. Triggers the website-build-and-deploy job

Triggered by: GitHub webhook on PR merge to main (with website/ path filter)
"""
import json
import subprocess
import sys
import os
from pathlib import Path

# Reactorcide workflow helpers
try:
    from workflow import trigger_job, flush_triggers, git_info, WorkflowContext
except ImportError:
    print("Warning: workflow module not available, running in standalone mode")
    trigger_job = None
    flush_triggers = None


def run_command(cmd: list[str], check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command and return the result."""
    print(f"Running: {' '.join(cmd)}")
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True
    )


def setup_git():
    """Configure git for commits."""
    git_user = os.environ.get("GIT_USER_NAME", "Catalyst Community (automation)")
    git_email = os.environ.get("GIT_USER_EMAIL", "automation@catalystcommunity.dev")

    run_command(["git", "config", "--global", "user.name", git_user])
    run_command(["git", "config", "--global", "user.email", git_email])

    # Setup auth if token provided
    github_token = os.environ.get("GITHUB_TOKEN")
    if github_token:
        run_command([
            "git", "remote", "set-url", "origin",
            f"https://x-access-token:{github_token}@github.com/catalystcommunity/linkkeys.git"
        ])

    # Unshallow clone and fetch tags (runner uses shallow clone by default)
    run_command(["git", "fetch", "--unshallow"], check=False)
    run_command(["git", "fetch", "--tags"])

    # Runner checks out by SHA (detached HEAD) — switch to main so we can push
    run_command(["git", "checkout", "main"])


def download_semver_tags():
    """Download the semver-tags tool."""
    if Path("./semver-tags").exists():
        print("semver-tags already exists")
        return

    print("Downloading semver-tags...")
    subprocess.run(
        "curl -fsSL https://github.com/catalystcommunity/semver-tags/releases/download/v0.4.0/semver-tags.tar.gz | tar -xz",
        shell=True,
        check=True
    )
    os.chmod("./semver-tags", 0o755)


def run_semver_tags() -> tuple[bool, str]:
    """
    Run semver-tags and parse the results.
    Returns: (has_new_release, new_version)
    """
    result = run_command(["./semver-tags", "run", "--output_json"], check=False)
    if result.returncode != 0:
        print(f"semver-tags stderr: {result.stderr}")
        print(f"semver-tags stdout: {result.stdout}")
        # Non-zero exit may just mean no releasable changes
        if not result.stdout.strip():
            return False, ""
    output = result.stdout.strip()

    # Find the JSON object in output (skip any log lines)
    data = {}
    for line in reversed(output.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            data = json.loads(line)
            break

    if data.get("New_release_published") != "true":
        return False, ""

    new_tag = data.get("New_release_git_tag", "")
    new_version = new_tag.lstrip("v")
    return True, new_version


def update_version_file(new_version: str):
    """Update VERSION.txt with the new version."""
    version_file = Path("website/content/extra_files/VERSION.txt")
    print(f"Updating {version_file} to {new_version}")
    version_file.write_text(f"{new_version}\n")


def commit_and_push(new_version: str):
    """Commit and push the version change."""
    run_command(["git", "add", "website/content/extra_files/VERSION.txt"])
    run_command([
        "git", "commit", "-m",
        f"ci: bump website version to v{new_version}"
    ])
    run_command(["git", "push"])


def trigger_build_deploy(new_version: str):
    """Trigger the website-build-and-deploy job."""
    if trigger_job is not None:
        trigger_job(
            "linkkeys-website-build-and-deploy",
            env={"VERSION": new_version},
            depends_on=[],
            condition="all_success"
        )
        flush_triggers()
        print(f"Triggered website-build-and-deploy job for version {new_version}")
    else:
        # Write trigger file manually
        trigger_data = {
            "type": "trigger_job",
            "jobs": [{
                "job_name": "linkkeys-website-build-and-deploy",
                "env": {"VERSION": new_version},
                "source_type": "git",
                "source_url": "https://github.com/catalystcommunity/linkkeys.git",
                "source_ref": "main"
            }]
        }
        trigger_file = Path("/job/triggers.json")
        trigger_file.write_text(json.dumps(trigger_data, indent=2))
        print(f"Wrote trigger file for website-build-and-deploy job")


def main() -> int:
    print("=" * 60)
    print("LinkKeys Website PR Merge Workflow")
    print("=" * 60)

    # Change to repo root
    repo_root = os.environ.get("REACTORCIDE_REPOROOT", "/job/src")
    os.chdir(repo_root)
    print(f"Working directory: {os.getcwd()}")

    # Setup
    setup_git()
    download_semver_tags()

    # Check for new release
    print("\nChecking for releasable changes...")
    has_release, new_version = run_semver_tags()

    if not has_release:
        print("No new version to publish")
        return 0

    print(f"\nNew version: {new_version}")

    # Update version file
    update_version_file(new_version)

    # Commit and push
    commit_and_push(new_version)

    # Trigger build and deploy
    trigger_build_deploy(new_version)

    print("\n" + "=" * 60)
    print(f"Website version bump complete: {new_version}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
