#!/usr/bin/env bash
set -euo pipefail

echo "================================================"
echo "LinkKeys Website Build and Deploy"
echo "================================================"

# Change to repo root
cd "${REACTORCIDE_REPOROOT:-/job/src}"

# Get version from VERSION.txt
VERSION="$(cat website/content/extra_files/VERSION.txt)"
echo "Building version: ${VERSION}"

# Change to website directory for build
cd website

# ================================================
# Build Docker Image
# ================================================
echo ""
echo "================================================"
echo "Building Docker Image"
echo "================================================"

# Setup environment
export HOME="${HOME:-/root}"
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$HOME/.docker" "$LOCAL_BIN"
export PATH="$LOCAL_BIN:$PATH"

# Install docker CLI if not present (uses DinD sidecar via DOCKER_HOST)
if ! command -v docker &> /dev/null; then
    echo "Installing docker CLI..."
    DOCKER_VERSION=27.5.1
    curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_VERSION}.tgz" -o /tmp/docker.tgz
    tar -xzf /tmp/docker.tgz --strip-components=1 -C "$LOCAL_BIN" docker/docker
    rm /tmp/docker.tgz
fi

# Install helm if not present
if ! command -v helm &> /dev/null; then
    echo "Installing helm..."
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | USE_SUDO=false HELM_INSTALL_DIR="$LOCAL_BIN" bash
fi

# Install kubectl if not present
if ! command -v kubectl &> /dev/null; then
    echo "Installing kubectl..."
    KUBECTL_VERSION=$(curl -fsSL https://dl.k8s.io/release/stable.txt)
    curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl" -o "$LOCAL_BIN/kubectl"
    chmod +x "$LOCAL_BIN/kubectl"
fi

# For internal registry (insecure HTTP)
INTERNAL_IMAGE="${REGISTRY_INTERNAL}/${REGISTRY_INTERNAL_PATH}"

# Setup registry auth
if [[ -n "${REGISTRY_USER:-}" ]] && [[ -n "${REGISTRY_PASSWORD:-}" ]]; then
    echo "${REGISTRY_PASSWORD}" | docker login "${REGISTRY_INTERNAL}" -u "${REGISTRY_USER}" --password-stdin
    echo "${REGISTRY_PASSWORD}" | docker login "${REGISTRY_EXTERNAL}" -u "${REGISTRY_USER}" --password-stdin
    echo "Registry authentication configured"
fi

# Build image using Docker daemon (provided by DinD sidecar in k8s)
echo "Building image: ${INTERNAL_IMAGE}:${VERSION}"
docker build -t "${INTERNAL_IMAGE}:${VERSION}" -t "${INTERNAL_IMAGE}:latest" .

# Push both tags
echo "Pushing image..."
docker push "${INTERNAL_IMAGE}:${VERSION}"
docker push "${INTERNAL_IMAGE}:latest"

echo "Image pushed successfully"

# ================================================
# Deploy to Kubernetes
# ================================================
echo ""
echo "================================================"
echo "Deploying to Kubernetes"
echo "================================================"

# Setup kubeconfig
mkdir -p ~/.kube
echo "${KUBECONFIG_CONTENT}" > ~/.kube/config
chmod 600 ~/.kube/config

# Add Helm repo
helm repo add catalyst-helm https://raw.githubusercontent.com/catalystcommunity/charts/main
helm repo update

# Create namespace if it doesn't exist
kubectl create namespace "${K8S_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# Create/update registry pull secret
kubectl create secret docker-registry regcred \
    --namespace "${K8S_NAMESPACE}" \
    --save-config \
    --dry-run=client \
    --docker-server="${REGISTRY_INTERNAL}" \
    --docker-username="${REGISTRY_USER:-}" \
    --docker-password="${REGISTRY_PASSWORD:-}" \
    -o yaml | kubectl apply -f -

# Deploy with Helm
echo "Deploying with Helm..."
helm upgrade \
    --install \
    --create-namespace \
    --namespace "${K8S_NAMESPACE}" \
    "${HELM_RELEASE}" \
    "${HELM_CHART}" \
    --version "${HELM_CHART_VERSION}" \
    --set image.repository="${INTERNAL_IMAGE}" \
    --set image.tag="${VERSION}" \
    --set imagePullSecrets[0].name=regcred \
    -f values.yaml

echo ""
echo "================================================"
echo "Website deployment complete!"
echo "Version: ${VERSION}"
echo "================================================"
