#!/bin/sh
set -e

SEMVER_TAGS_VERSION="v0.4.0"
GHCLI_VERSION="2.63.2"

# PWD is set by the caller (release.yaml) to REACTORCIDE_CODE_DIR.

# -------------------------------------------------------------------
# 1. Install semver-tags
# -------------------------------------------------------------------
echo "=== Installing semver-tags ${SEMVER_TAGS_VERSION} ==="
wget -q "https://github.com/catalystcommunity/semver-tags/releases/download/${SEMVER_TAGS_VERSION}/semver-tags.tar.gz" \
  -O /tmp/semver-tags.tar.gz
tar -xzf /tmp/semver-tags.tar.gz -C /tmp
chmod +x /tmp/semver-tags
export PATH="/tmp:$PATH"

# NOTE: the caller (release.yaml) has already put us on the real main tip with
# full history + tags before invoking this script, so semver-tags sees every
# release and the version-bump commit below fast-forwards main.

# -------------------------------------------------------------------
# 2. Determine version bump from conventional commits
# -------------------------------------------------------------------
echo "=== Running semver-tags ==="
semver-tags run --output_json > /tmp/semver-output.txt 2>&1
OUTPUT=$(tail -1 /tmp/semver-output.txt)
echo "Output: ${OUTPUT}"

NEW_TAG=$(echo "${OUTPUT}" | grep -o '"New_release_git_tag":"[^"]*"' | cut -d'"' -f4)
PUBLISHED=$(echo "${OUTPUT}" | grep -o '"New_release_published":"[^"]*"' | cut -d'"' -f4)

if [ "${PUBLISHED}" != "true" ]; then
  echo "No new release needed."
  exit 0
fi

echo "=== New release: ${NEW_TAG} ==="
VERSION="${NEW_TAG#v}"

# The version files this release stamps, kept as one list so the edit and the
# git-add stay in lockstep.
VERSION_FILES="helm_chart/Chart.yaml website/content/extra_files/VERSION.txt demoappsite/helm/Chart.yaml demoappsite/version/VERSION.txt version/VERSION.txt"

# Stamp ${VERSION} into every version file. Deterministic and idempotent, so it
# can be re-applied after re-basing onto a newer main during the push retry.
apply_version_files() {
  sed -i "s/^version: .*/version: ${VERSION}/" helm_chart/Chart.yaml
  sed -i "s/^appVersion: .*/appVersion: \"${VERSION}\"/" helm_chart/Chart.yaml
  echo "${VERSION}" > website/content/extra_files/VERSION.txt
  sed -i "s/^version: .*/version: ${VERSION}/" demoappsite/helm/Chart.yaml
  sed -i "s/^appVersion: .*/appVersion: \"${VERSION}\"/" demoappsite/helm/Chart.yaml
  echo "${VERSION}" > demoappsite/version/VERSION.txt
  echo "${VERSION}" > version/VERSION.txt
}

# -------------------------------------------------------------------
# 3. Update versioned files and push the bump to main
# -------------------------------------------------------------------
echo "=== Updating versioned files to ${VERSION} ==="
apply_version_files

# SKIP_GITHUB=true skips push and release-create; on-disk file edits and the build still run.
if [ "${SKIP_GITHUB:-false}" = "true" ]; then
  echo "=== SKIP_GITHUB=true: skipping version-bump commit and push ==="
else
  git config user.name "Catalyst Community (automation)"
  git config user.email "automation@catalystcommunity.dev"
  git remote set-url origin "https://x-access-token:${GITHUB_PAT}@github.com/${REACTORCIDE_REPO}.git"
  # shellcheck disable=SC2086
  git add ${VERSION_FILES}
  git commit -m "ci: bump version to ${VERSION}" || echo "No version changes to commit"

  # Push the bump to main. We synced onto main's tip in step 1.5, so the first
  # push normally fast-forwards. If a CONCURRENT merge advances main between our
  # sync and this push, the push is non-fast-forward — re-base our bump onto the
  # fresh main and retry. Failure after every attempt is FATAL: we must never
  # `gh release create` for a commit that isn't on main.
  push_attempts=5
  n=0
  while ! git push origin HEAD:main; do
    n=$((n + 1))
    if [ "$n" -ge "$push_attempts" ]; then
      echo "ERROR: could not push the version bump to main after ${push_attempts} attempts — aborting to avoid an orphan release/tag."
      exit 1
    fi
    echo "=== main advanced; re-basing the bump onto the latest main (attempt ${n}/${push_attempts}) ==="
    git fetch --tags --prune --force origin "+refs/heads/main:refs/remotes/origin/main"
    git reset --hard origin/main
    apply_version_files
    # shellcheck disable=SC2086
    git add ${VERSION_FILES}
    if git diff --cached --quiet; then
      echo "main is already at ${VERSION} (a concurrent release landed it); nothing to push."
      exit 0
    fi
    git commit -m "ci: bump version to ${VERSION}"
  done
fi

# -------------------------------------------------------------------
# 4. Build the release binary
# -------------------------------------------------------------------
echo "=== Building linkkeys binary ==="
cargo build --release --bin linkkeys 2>&1

RELEASE_DIR="/tmp/release"
mkdir -p "${RELEASE_DIR}"

ARCHIVE_NAME="linkkeys-${VERSION}-linux-amd64"
# Honor CARGO_TARGET_DIR: release.yaml (and the other CI jobs) redirect cargo's
# output to /tmp/linkkeys-target, so the binary is NOT under ./target. Default to
# ./target when it isn't overridden.
tar -czf "${RELEASE_DIR}/${ARCHIVE_NAME}.tar.gz" -C "${CARGO_TARGET_DIR:-target}/release" linkkeys

# -------------------------------------------------------------------
# 5. Install gh CLI and create GitHub release
# -------------------------------------------------------------------
if [ "${SKIP_GITHUB:-false}" = "true" ]; then
  echo "=== SKIP_GITHUB=true: skipping GitHub release create ==="
  echo "=== Built artifact left in ${RELEASE_DIR} for inspection ==="
else
  # NOTE: do NOT guard on "tag already exists" here. `semver-tags run` (step 2)
  # created and pushed the ${NEW_TAG} tag before we got here, so the tag ALWAYS
  # exists at this point — guarding on it would skip release creation every time
  # (which is the bug that left tags without GitHub Releases). semver-tags is also
  # what makes this idempotent: on a re-run of an already-released version it
  # reports no new release and we exit back in step 2, so we only reach here for a
  # genuinely new release. Create the GitHub Release for the tag + attach the binary.
  echo "=== Creating GitHub release ==="
  wget -q "https://github.com/cli/cli/releases/download/v${GHCLI_VERSION}/gh_${GHCLI_VERSION}_linux_amd64.tar.gz" -O /tmp/gh.tar.gz
  tar -xzf /tmp/gh.tar.gz -C /tmp
  export PATH="/tmp/gh_${GHCLI_VERSION}_linux_amd64/bin:$PATH"

  GH_TOKEN="${GITHUB_PAT}" gh release create "${NEW_TAG}" \
    --repo "${REACTORCIDE_REPO}" \
    --title "${NEW_TAG}" \
    --generate-notes \
    ${RELEASE_DIR}/*

  echo "=== Released ${NEW_TAG} ==="
fi
