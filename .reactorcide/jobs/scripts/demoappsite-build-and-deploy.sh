#!/usr/bin/env bash
set -euo pipefail

echo "================================================"
echo "LinkKeys Demoappsite Build and Deploy"
echo "================================================"

cd "${REACTORCIDE_REPOROOT:-/job/src}"

VERSION="$(cat demoappsite/version/VERSION.txt)"
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

if ! command -v helm &> /dev/null; then
    echo "Installing helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | USE_SUDO=false HELM_INSTALL_DIR="$LOCAL_BIN" bash
fi

if ! command -v kubectl &> /dev/null; then
    echo "Installing kubectl..."
    KUBECTL_VERSION=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
    curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o "$LOCAL_BIN/kubectl"
    chmod +x "$LOCAL_BIN/kubectl"
fi

# ================================================
# Build Docker Image
# ================================================
echo ""
echo "================================================"
echo "Building Docker Image"
echo "================================================"

INTERNAL_IMAGE="${REGISTRY_INTERNAL}/${REGISTRY_INTERNAL_PATH}"

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

    # Build from repo root with demoappsite Dockerfile
    docker build -t "${INTERNAL_IMAGE}:${VERSION}" -f demoappsite/Dockerfile .

    IMAGE_TAR="/tmp/image.tar"
    docker save "${INTERNAL_IMAGE}:${VERSION}" -o "${IMAGE_TAR}"

    echo "Pushing image via crane..."
    crane push --insecure "${IMAGE_TAR}" "${INTERNAL_IMAGE}:${VERSION}"
    crane push --insecure "${IMAGE_TAR}" "${INTERNAL_IMAGE}:latest"
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

    buildctl build \
        --frontend dockerfile.v0 \
        --local context=. \
        --local dockerfile=./demoappsite \
        --output "type=image,name=${INTERNAL_IMAGE}:${VERSION},push=true,registry.insecure=true"

    buildctl build \
        --frontend dockerfile.v0 \
        --local context=. \
        --local dockerfile=./demoappsite \
        --output "type=image,name=${INTERNAL_IMAGE}:latest,push=true,registry.insecure=true"

    echo "Image pushed successfully"
fi

# ================================================
# Deploy to Kubernetes
# ================================================
echo ""
echo "================================================"
echo "Deploying to Kubernetes"
echo "================================================"

mkdir -p ~/.kube
echo "${KUBECONFIG_CONTENT}" > ~/.kube/config
chmod 600 ~/.kube/config

kubectl create namespace "${K8S_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret docker-registry regcred \
    --namespace "${K8S_NAMESPACE}" \
    --save-config \
    --dry-run=client \
    --docker-server="${REGISTRY_INTERNAL}" \
    --docker-username="${REGISTRY_USER:-}" \
    --docker-password="${REGISTRY_PASSWORD:-}" \
    -o yaml | kubectl apply -f -

echo "Deploying with Helm (local chart)..."

# Preserve existing RP API key from the cluster secret (if it exists)
EXISTING_RP_KEY=$(kubectl -n "${K8S_NAMESPACE}" get secret "${HELM_RELEASE}" -o jsonpath='{.data.RP_API_KEY}' 2>/dev/null | base64 -d || true)

# Write runtime overrides to temp file
RUNTIME_VALUES="/tmp/runtime-values.yaml"
cat > "${RUNTIME_VALUES}" <<VALS
image:
  repository: ${INTERNAL_IMAGE}
  tag: "${VERSION}"
VALS

if [[ -n "${EXISTING_RP_KEY}" ]]; then
    cat >> "${RUNTIME_VALUES}" <<VALS
rp:
  apiKey: "${EXISTING_RP_KEY}"
VALS
    echo "Preserved existing RP API key"
fi

# Include deploy values if they exist (gateway, RP config, etc.)
DEPLOY_VALUES_ARGS=""
if [[ -f ./deploy/values-demoappsite.yaml ]]; then
    DEPLOY_VALUES_ARGS="-f ./deploy/values-demoappsite.yaml"
fi

helm upgrade \
    --install \
    --create-namespace \
    --namespace "${K8S_NAMESPACE}" \
    "${HELM_RELEASE}" \
    ./demoappsite/helm \
    ${DEPLOY_VALUES_ARGS} \
    -f "${RUNTIME_VALUES}"

rm -f "${RUNTIME_VALUES}"

echo ""
echo "================================================"
echo "Demoappsite deployment complete!"
echo "Version: ${VERSION}"
echo "Domain: linkidspec.com"
echo "================================================"
