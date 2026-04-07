#!/usr/bin/env bash
set -euo pipefail

echo "================================================"
echo "LinkKeys Deploy"
echo "================================================"

cd "${REACTORCIDE_REPOROOT:-/job/src}"

if [[ -z "${K8S_NAMESPACE:-}" ]]; then
    echo "ERROR: K8S_NAMESPACE must be set via overlay"
    exit 1
fi
if [[ -z "${HELM_RELEASE:-}" ]]; then
    echo "ERROR: HELM_RELEASE must be set via overlay"
    exit 1
fi
if [[ -z "${HELM_VALUES_FILE:-}" ]]; then
    echo "ERROR: HELM_VALUES_FILE must be set via overlay"
    exit 1
fi

echo "Namespace:  ${K8S_NAMESPACE}"
echo "Release:    ${HELM_RELEASE}"
echo "Values:     ${HELM_VALUES_FILE}"
echo "Image tag:  ${IMAGE_TAG:-latest}"

# ================================================
# Setup tools
# ================================================
export HOME="${HOME:-/root}"
LOCAL_BIN="$HOME/.local/bin"
mkdir -p "$LOCAL_BIN"
export PATH="$LOCAL_BIN:$PATH"

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
# Configure kubectl
# ================================================
mkdir -p ~/.kube
echo "${KUBECONFIG_CONTENT}" > ~/.kube/config
chmod 600 ~/.kube/config

# ================================================
# Create namespace and registry secret
# ================================================
kubectl create namespace "${K8S_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

if [[ -n "${REGISTRY_USER:-}" ]] && [[ -n "${REGISTRY_PASSWORD:-}" ]]; then
    kubectl create secret docker-registry regcred \
        --namespace "${K8S_NAMESPACE}" \
        --save-config \
        --dry-run=client \
        --docker-server="10.16.0.1:5000" \
        --docker-username="${REGISTRY_USER}" \
        --docker-password="${REGISTRY_PASSWORD}" \
        -o yaml | kubectl apply -f -
fi

# ================================================
# Generate passphrase if not provided
# ================================================
PASSPHRASE="${DOMAIN_KEY_PASSPHRASE:-}"
if [[ -z "${PASSPHRASE}" ]]; then
    # Check if a passphrase secret already exists in the namespace
    EXISTING=$(kubectl -n "${K8S_NAMESPACE}" get secret "${HELM_RELEASE}" -o jsonpath='{.data.DOMAIN_KEY_PASSPHRASE}' 2>/dev/null || echo "")
    if [[ -n "${EXISTING}" ]]; then
        echo "Using existing passphrase from secret"
        PASSPHRASE=$(echo "${EXISTING}" | base64 -d)
    else
        echo "Generating new random passphrase"
        PASSPHRASE=$(openssl rand -base64 32)
    fi
fi

# ================================================
# Deploy with Helm
# ================================================
echo ""
echo "================================================"
echo "Deploying with Helm"
echo "================================================"

# Write runtime overrides to a temp values file (no --set needed)
RUNTIME_VALUES="/tmp/runtime-values.yaml"
cat > "${RUNTIME_VALUES}" <<VALS
image:
  tag: "${IMAGE_TAG:-latest}"
server:
  domainKeyPassphrase: "${PASSPHRASE}"
VALS

helm upgrade \
    --install \
    --create-namespace \
    --namespace "${K8S_NAMESPACE}" \
    "${HELM_RELEASE}" \
    ./helm_chart \
    -f "${HELM_VALUES_FILE}" \
    -f "${RUNTIME_VALUES}"

rm -f "${RUNTIME_VALUES}"

echo ""
echo "================================================"
echo "Deployment complete!"
echo "Namespace: ${K8S_NAMESPACE}"
echo "Release:   ${HELM_RELEASE}"
echo "================================================"
