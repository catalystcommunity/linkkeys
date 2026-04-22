#!/usr/bin/env bash
set -euo pipefail

echo "================================================"
echo "LinkKeys Server Build and Deploy"
echo "================================================"

cd "${REACTORCIDE_REPOROOT:-/job/src}"

VERSION="$(cat version/VERSION.txt)"
echo "Building version: ${VERSION}"

# The `builder` capability provides a buildkitd sidecar reachable via
# BUILDKIT_HOST. We only need the buildctl client; the sidecar's buildkitd
# is operator-configured to treat the internal registry as plaintext HTTP.
export HOME="${HOME:-/root}"
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$HOME/.docker" "$LOCAL_BIN"
export PATH="$LOCAL_BIN:$PATH"

if ! command -v buildctl &> /dev/null; then
    echo "Installing buildctl..."
    BUILDKIT_VERSION=0.17.3
    curl -fsSL "https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz" -o /tmp/buildkit.tar.gz
    tar -xzf /tmp/buildkit.tar.gz -C "$LOCAL_BIN" --strip-components=1 bin/buildctl
    rm /tmp/buildkit.tar.gz
fi

echo "Waiting for builder sidecar..."
for i in $(seq 1 30); do
    if buildctl debug info >/dev/null 2>&1; then
        echo "builder sidecar is ready"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "ERROR: builder sidecar not ready after 30 seconds"
        exit 1
    fi
    sleep 1
done

if [[ -n "${REGISTRY_USER:-}" ]] && [[ -n "${REGISTRY_PASSWORD:-}" ]]; then
    AUTH=$(printf "%s:%s" "$REGISTRY_USER" "$REGISTRY_PASSWORD" | base64 -w 0)
    cat > "$HOME/.docker/config.json" <<EOF
{
  "auths": {
    "${REGISTRY_INTERNAL}": {"auth": "${AUTH}"},
    "${REGISTRY_EXTERNAL}": {"auth": "${AUTH}"}
  }
}
EOF
    export DOCKER_CONFIG="$HOME/.docker"
    echo "Registry authentication configured"
fi

INTERNAL_IMAGE="${REGISTRY_INTERNAL}/${REGISTRY_INTERNAL_PATH}"
EXTERNAL_IMAGE="${REGISTRY_EXTERNAL}/${REGISTRY_EXTERNAL_PATH}"

echo ""
echo "================================================"
echo "Building and pushing to internal registry"
echo "================================================"
buildctl build \
    --frontend dockerfile.v0 \
    --local context=. \
    --local dockerfile=. \
    --output "type=image,\"name=${INTERNAL_IMAGE}:${VERSION},${INTERNAL_IMAGE}:latest\",push=true"

echo ""
echo "================================================"
echo "Pushing to external registry (best-effort)"
echo "================================================"
if buildctl build \
    --frontend dockerfile.v0 \
    --local context=. \
    --local dockerfile=. \
    --output "type=image,\"name=${EXTERNAL_IMAGE}:${VERSION},${EXTERNAL_IMAGE}:latest\",push=true"; then
    echo "External push succeeded"
else
    echo "WARNING: External registry push failed (non-fatal)"
fi

echo ""
echo "================================================"
echo "Server image build complete!"
echo "Version: ${VERSION}"
echo "Internal: ${INTERNAL_IMAGE}:${VERSION}"
echo "External: ${EXTERNAL_IMAGE}:${VERSION}"
echo "================================================"
