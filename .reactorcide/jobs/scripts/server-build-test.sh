#!/usr/bin/env bash
set -euo pipefail

echo "================================================"
echo "LinkKeys Server Build Test"
echo "================================================"

cd "${REACTORCIDE_REPOROOT:-/job/src}"

export HOME="${HOME:-/root}"
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"
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

echo "Building image (test only, no push)..."
buildctl build \
    --frontend dockerfile.v0 \
    --local context=. \
    --local dockerfile=. \
    --output "type=image,name=linkkeys-server-test:build"

echo ""
echo "================================================"
echo "Server build test passed!"
echo "================================================"
