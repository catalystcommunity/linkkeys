#!/usr/bin/env bash
set -euo pipefail

echo "================================================"
echo "LinkKeys Website Build and Deploy"
echo "================================================"

cd "${REACTORCIDE_REPOROOT:-/job/src}"

VERSION="$(cat website/content/extra_files/VERSION.txt)"
echo "Building version: ${VERSION}"

cd website

# The `builder` capability provides a buildkitd sidecar reachable via
# BUILDKIT_HOST. We only need the buildctl client.
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
    export DOCKER_CONFIG="$HOME/.docker"
    echo "Registry authentication configured"
fi

echo ""
echo "================================================"
echo "Building and pushing Docker image"
echo "================================================"
buildctl build \
    --frontend dockerfile.v0 \
    --local context=. \
    --local dockerfile=. \
    --output "type=image,\"name=${INTERNAL_IMAGE}:${VERSION},${INTERNAL_IMAGE}:latest\",push=true"

echo ""
echo "================================================"
echo "Deploying to Kubernetes"
echo "================================================"

mkdir -p ~/.kube
echo "${KUBECONFIG_CONTENT}" > ~/.kube/config
chmod 600 ~/.kube/config

helm repo add catalyst-helm https://raw.githubusercontent.com/catalystcommunity/charts/main
helm repo update

kubectl create namespace "${K8S_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret docker-registry regcred \
    --namespace "${K8S_NAMESPACE}" \
    --save-config \
    --dry-run=client \
    --docker-server="${REGISTRY_INTERNAL}" \
    --docker-username="${REGISTRY_USER:-}" \
    --docker-password="${REGISTRY_PASSWORD:-}" \
    -o yaml | kubectl apply -f -

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
