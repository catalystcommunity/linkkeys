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

if ! command -v docker &> /dev/null; then
    echo "Installing docker CLI..."
    DOCKER_VERSION=27.5.1
    curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" -o /tmp/docker.tgz
    tar -xzf /tmp/docker.tgz --strip-components=1 -C "$LOCAL_BIN" docker/docker
    rm /tmp/docker.tgz
fi

echo "Waiting for Docker daemon..."
for i in $(seq 1 30); do
    if docker info >/dev/null 2>&1; then
        echo "Docker daemon is ready"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "ERROR: Docker daemon not ready after 30 seconds"
        exit 1
    fi
    sleep 1
done

# Build from repo root
echo "Building Docker image (test only, no push)..."
docker build -t linkkeys-server-test:build -f Dockerfile .

echo ""
echo "================================================"
echo "Server build test passed!"
echo "================================================"
