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
echo "Image tag:  ${IMAGE_TAG:-(chart appVersion)}"

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
        --docker-server="containers.catalystsquad.com" \
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
# Wait for the server image to be published
# ================================================
# This job may be triggered by the same version bump that builds the image, and
# reactorcide has no cross-job ordering — so poll the registry for the target
# tag before deploying. Otherwise the new pod ImagePullBackOffs until the build
# finishes. Skipped entirely when WAIT_FOR_IMAGE_REPO is unset (manual deploys
# of an already-published tag don't need it).
if [[ -n "${WAIT_FOR_IMAGE_REPO:-}" ]]; then
    WAIT_TAG="${IMAGE_TAG:-$(cat version/VERSION.txt)}"
    WAIT_HOST="${WAIT_FOR_IMAGE_REPO%%/*}"
    WAIT_PATH="${WAIT_FOR_IMAGE_REPO#*/}"
    MANIFEST_URL="https://${WAIT_HOST}/v2/${WAIT_PATH}/manifests/${WAIT_TAG}"

    CURL_AUTH=()
    if [[ -n "${REGISTRY_USER:-}" ]] && [[ -n "${REGISTRY_PASSWORD:-}" ]]; then
        CURL_AUTH=(-u "${REGISTRY_USER}:${REGISTRY_PASSWORD}")
    fi

    echo "Waiting for image ${WAIT_FOR_IMAGE_REPO}:${WAIT_TAG} ..."
    DEADLINE=$(( $(date +%s) + ${WAIT_FOR_IMAGE_TIMEOUT:-1500} ))
    until curl -fsS -o /dev/null "${CURL_AUTH[@]}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        -H "Accept: application/vnd.oci.image.index.v1+json" \
        "${MANIFEST_URL}"; do
        if [[ $(date +%s) -ge ${DEADLINE} ]]; then
            echo "ERROR: image ${WAIT_FOR_IMAGE_REPO}:${WAIT_TAG} not published within timeout"
            exit 1
        fi
        echo "  not yet available; retrying in 15s..."
        sleep 15
    done
    echo "Image is available."
fi

# ================================================
# Deploy with Helm
# ================================================
echo ""
echo "================================================"
echo "Deploying with Helm"
echo "================================================"

# Write runtime overrides to a temp values file (no --set needed).
# IMAGE_TAG defaults to empty so the chart's
# {{ .Values.image.tag | default .Chart.AppVersion }} fallback picks
# the released version. Overlays may set IMAGE_TAG explicitly to pin
# a specific tag (e.g. for rollback).
RUNTIME_VALUES="/tmp/runtime-values.yaml"
cat > "${RUNTIME_VALUES}" <<VALS
image:
  tag: "${IMAGE_TAG:-}"
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
