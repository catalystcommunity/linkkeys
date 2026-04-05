#!/usr/bin/env bash
set -euo pipefail

echo "================================================"
echo "LinkKeys Server Build and Deploy"
echo "================================================"

cd "${REACTORCIDE_REPOROOT:-/job/src}"

VERSION="$(cat version/VERSION.txt)"
echo "Building version: ${VERSION}"

# ================================================
# Setup tools
# ================================================
export HOME="${HOME:-/root}"
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$HOME/.docker" "$LOCAL_BIN"
export PATH="$LOCAL_BIN:$PATH"

if ! command -v crane &> /dev/null; then
    echo "Installing crane..."
    CRANE_VERSION=0.20.3
    curl -fsSL "https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/go-containerregistry_Linux_x86_64.tar.gz" -o /tmp/crane.tar.gz
    tar -xzf /tmp/crane.tar.gz -C "$LOCAL_BIN" crane
    rm /tmp/crane.tar.gz
fi

# ================================================
# Build Docker Image
# ================================================
echo ""
echo "================================================"
echo "Building Docker Image"
echo "================================================"

INTERNAL_IMAGE="${REGISTRY_INTERNAL}/${REGISTRY_INTERNAL_PATH}"
EXTERNAL_IMAGE="${REGISTRY_EXTERNAL}/${REGISTRY_EXTERNAL_PATH}"

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
    echo "Registry authentication configured"
fi

echo "Building image: ${INTERNAL_IMAGE}:${VERSION}"

if [[ -n "${DOCKER_HOST:-}" ]]; then
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
    docker build -t "${INTERNAL_IMAGE}:${VERSION}" -f Dockerfile .

    IMAGE_TAR="/tmp/image.tar"
    docker save "${INTERNAL_IMAGE}:${VERSION}" -o "${IMAGE_TAR}"

    echo "Pushing to internal registry..."
    crane push --insecure "${IMAGE_TAR}" "${INTERNAL_IMAGE}:${VERSION}"
    crane push --insecure "${IMAGE_TAR}" "${INTERNAL_IMAGE}:latest"

    echo "Pushing to external registry..."
    crane push "${IMAGE_TAR}" "${EXTERNAL_IMAGE}:${VERSION}"
    crane push "${IMAGE_TAR}" "${EXTERNAL_IMAGE}:latest"

    rm "${IMAGE_TAR}"
    echo "Image pushed successfully"
else
    if ! command -v buildctl &> /dev/null; then
        echo "Installing buildkit..."
        BUILDKIT_VERSION=0.17.3
        curl -fsSL "https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz" -o /tmp/buildkit.tar.gz
        tar -xzf /tmp/buildkit.tar.gz --strip-components=1 -C "$LOCAL_BIN"
        rm /tmp/buildkit.tar.gz
    fi

    export XDG_RUNTIME_DIR=/tmp/run-root
    mkdir -p "$XDG_RUNTIME_DIR"

    echo "Starting buildkitd..."
    buildkitd \
        --oci-worker=true \
        --containerd-worker=false \
        --root="$HOME/.local/share/buildkit" \
        --addr="unix://$XDG_RUNTIME_DIR/buildkit/buildkitd.sock" &
    BUILDKITD_PID=$!
    trap "kill $BUILDKITD_PID 2>/dev/null || true; wait 2>/dev/null || true" EXIT

    for i in $(seq 1 30); do
        if buildctl --addr="unix://$XDG_RUNTIME_DIR/buildkit/buildkitd.sock" debug info >/dev/null 2>&1; then
            echo "buildkitd is ready"
            break
        fi
        sleep 1
    done

    export BUILDKIT_HOST="unix://$XDG_RUNTIME_DIR/buildkit/buildkitd.sock"

    echo "Building and pushing to internal registry..."
    buildctl build \
        --frontend dockerfile.v0 \
        --local context=. \
        --local dockerfile=. \
        --output "type=image,name=${INTERNAL_IMAGE}:${VERSION},push=true,registry.insecure=true"

    buildctl build \
        --frontend dockerfile.v0 \
        --local context=. \
        --local dockerfile=. \
        --output "type=image,name=${INTERNAL_IMAGE}:latest,push=true,registry.insecure=true"

    echo "Building and pushing to external registry..."
    buildctl build \
        --frontend dockerfile.v0 \
        --local context=. \
        --local dockerfile=. \
        --output "type=image,name=${EXTERNAL_IMAGE}:${VERSION},push=true"

    buildctl build \
        --frontend dockerfile.v0 \
        --local context=. \
        --local dockerfile=. \
        --output "type=image,name=${EXTERNAL_IMAGE}:latest,push=true"

    echo "Image pushed successfully"
fi

echo ""
echo "================================================"
echo "Server image build complete!"
echo "Version: ${VERSION}"
echo "Internal: ${INTERNAL_IMAGE}:${VERSION}"
echo "External: ${EXTERNAL_IMAGE}:${VERSION}"
echo "================================================"
