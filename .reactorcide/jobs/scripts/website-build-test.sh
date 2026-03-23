#!/usr/bin/env bash
set -euo pipefail

echo "================================================"
echo "LinkKeys Website Build Test"
echo "================================================"

# Change to website directory
cd "${REACTORCIDE_REPOROOT:-/job/src}/website"

# Setup environment
export HOME="${HOME:-/root}"
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"
export PATH="$LOCAL_BIN:$PATH"

# Install docker CLI if not present (uses DinD sidecar via DOCKER_HOST)
if ! command -v docker &> /dev/null; then
    echo "Installing docker CLI..."
    DOCKER_VERSION=27.5.1
    curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" -o /tmp/docker.tgz
    tar -xzf /tmp/docker.tgz --strip-components=1 -C "$LOCAL_BIN" docker/docker
    rm /tmp/docker.tgz
fi

# Build image (test only, no push)
echo "Building Docker image (test only, no push)..."
docker build -t linkkeys-website-test:build .

echo ""
echo "================================================"
echo "Website build test passed!"
echo "================================================"
