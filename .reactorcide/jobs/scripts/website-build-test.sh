#!/usr/bin/env bash
set -euo pipefail

cleanup() { kill %1 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT

echo "================================================"
echo "LinkKeys Website Build Test"
echo "================================================"

# Change to website directory
cd "${REACTORCIDE_REPOROOT:-/job/src}/website"

# Setup environment
export HOME="${HOME:-/root}"
export XDG_RUNTIME_DIR=/tmp/run-root
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$XDG_RUNTIME_DIR" "$LOCAL_BIN"
export PATH="$LOCAL_BIN:$PATH"

# Install buildctl if not present
if ! command -v buildctl &> /dev/null; then
    echo "Installing buildkit..."
    BUILDKIT_VERSION=0.17.3
    curl -fsSL "https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz" -o /tmp/buildkit.tar.gz
    tar -xzf /tmp/buildkit.tar.gz --strip-components=1 -C "$LOCAL_BIN"
    rm /tmp/buildkit.tar.gz
fi

# Start buildkitd with OCI worker
echo "Starting buildkitd..."
buildkitd \
    --oci-worker=true \
    --containerd-worker=false \
    --root="$HOME/.local/share/buildkit" \
    --addr="unix://$XDG_RUNTIME_DIR/buildkit/buildkitd.sock" &

# Wait for buildkitd to be ready
for i in $(seq 1 30); do
    if buildctl --addr="unix://$XDG_RUNTIME_DIR/buildkit/buildkitd.sock" debug info >/dev/null 2>&1; then
        echo "buildkitd is ready"
        break
    fi
    sleep 1
done

export BUILDKIT_HOST="unix://$XDG_RUNTIME_DIR/buildkit/buildkitd.sock"

# Build image (output to nowhere — just verify it builds)
echo "Building Docker image (test only, no push)..."
buildctl build \
    --frontend dockerfile.v0 \
    --local context=. \
    --local dockerfile=. \
    --output type=oci,dest=/dev/null

echo ""
echo "================================================"
echo "Website build test passed!"
echo "================================================"
