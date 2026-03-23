#!/bin/sh
set -e

SEMVER_TAGS_VERSION="v0.4.0"
GHCLI_VERSION="2.63.2"

cd /workspace

# -------------------------------------------------------------------
# 1. Install semver-tags
# -------------------------------------------------------------------
echo "=== Installing semver-tags ${SEMVER_TAGS_VERSION} ==="
wget -q "https://github.com/catalystcommunity/semver-tags/releases/download/${SEMVER_TAGS_VERSION}/semver-tags.tar.gz" \
  -O /tmp/semver-tags.tar.gz
tar -xzf /tmp/semver-tags.tar.gz -C /tmp
chmod +x /tmp/semver-tags
export PATH="/tmp:$PATH"

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

# -------------------------------------------------------------------
# 3. Update helm chart version
# -------------------------------------------------------------------
echo "=== Updating helm chart version to ${VERSION} ==="
sed -i "s/^version: .*/version: ${VERSION}/" helm_chart/Chart.yaml
sed -i "s/^appVersion: .*/appVersion: \"${VERSION}\"/" helm_chart/Chart.yaml

# Commit the version bump (semver-tags already tagged, so this is a follow-up commit)
git config user.name "Catalyst Community (automation)"
git config user.email "automation@catalystcommunity.dev"
git remote set-url origin "https://x-access-token:${GITHUB_PAT}@github.com/${REACTORCIDE_REPO}.git"
git add helm_chart/Chart.yaml
git commit -m "ci: bump helm chart version to ${VERSION}" || echo "No chart changes to commit"
git push || echo "Push failed, continuing with release"

# -------------------------------------------------------------------
# 4. Build the release binary
# -------------------------------------------------------------------
echo "=== Building linkkeys binary ==="
cargo build --release --bin linkkeys 2>&1

RELEASE_DIR="/tmp/release"
mkdir -p "${RELEASE_DIR}"

ARCHIVE_NAME="linkkeys-${VERSION}-linux-amd64"
tar -czf "${RELEASE_DIR}/${ARCHIVE_NAME}.tar.gz" -C target/release linkkeys

# -------------------------------------------------------------------
# 5. Install gh CLI and create GitHub release
# -------------------------------------------------------------------
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
