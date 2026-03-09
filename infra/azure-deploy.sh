#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Azure Deployment Script for TideWarden
# Builds the Docker image, pushes to ACR, and updates the Container App.
# Run azure-infra.sh first to provision the infrastructure.
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/azure-config.sh"

# ── Colours / helpers ───────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[deploy]${NC} $1"; }
ok()   { echo -e "${GREEN}[deploy]${NC} $1"; }
warn() { echo -e "${YELLOW}[deploy]${NC} $1"; }
err()  { echo -e "${RED}[deploy]${NC} $1"; exit 1; }

# ── Parse arguments ────────────────────────────────────────────────────────
IMAGE_TAG="${1:-latest}"
TIDEWARDEN_IMAGE="${ACR_NAME}.azurecr.io/${PROJECT_NAME}:${IMAGE_TAG}"

usage() {
    echo "Usage: $0 [IMAGE_TAG]"
    echo ""
    echo "  IMAGE_TAG   Docker image tag (default: latest)"
    echo ""
    echo "Examples:"
    echo "  $0              # builds and deploys with :latest tag"
    echo "  $0 v1.2.3       # builds and deploys with :v1.2.3 tag"
    echo "  $0 \$(git rev-parse --short HEAD)  # tag with git SHA"
    exit 0
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

# ── Pre-flight checks ──────────────────────────────────────────────────────
command -v az &>/dev/null || err "Azure CLI (az) is not installed."
command -v docker &>/dev/null || err "Docker is not installed."
az account show &>/dev/null || err "Not logged in. Run: az login"

# Verify infrastructure exists
az group show --name "${RESOURCE_GROUP}" &>/dev/null \
    || err "Resource group '${RESOURCE_GROUP}' not found. Run azure-infra.sh first."

az acr show --name "${ACR_NAME}" --resource-group "${RESOURCE_GROUP}" &>/dev/null \
    || err "ACR '${ACR_NAME}' not found. Run azure-infra.sh first."

az containerapp show --name "${TIDEWARDEN_APP_NAME}" --resource-group "${RESOURCE_GROUP}" &>/dev/null \
    || err "Container App '${TIDEWARDEN_APP_NAME}' not found. Run azure-infra.sh first."

echo ""
log "Deployment Configuration:"
log "  Image:          ${TIDEWARDEN_IMAGE}"
log "  Resource Group: ${RESOURCE_GROUP}"
log "  Container App:  ${TIDEWARDEN_APP_NAME}"
echo ""

# ── 1. Login to ACR ────────────────────────────────────────────────────────
log "Logging into Azure Container Registry..."
az acr login --name "${ACR_NAME}"
ok "ACR login successful"

# ── 2. Build Docker image ──────────────────────────────────────────────────
log "Building Docker image..."

# Determine which Dockerfile to use
DOCKERFILE="${ROOT_DIR}/docker/Dockerfile.debian"
if [[ ! -f "${DOCKERFILE}" ]]; then
    err "Dockerfile not found at ${DOCKERFILE}"
fi

docker build \
    -t "${TIDEWARDEN_IMAGE}" \
    -f "${DOCKERFILE}" \
    --build-arg DB=postgresql \
    --build-arg CARGO_PROFILE=release \
    --platform linux/amd64 \
    "${ROOT_DIR}"

ok "Image built: ${TIDEWARDEN_IMAGE}"

# ── 3. Push to ACR ─────────────────────────────────────────────────────────
log "Pushing image to ACR..."
docker push "${TIDEWARDEN_IMAGE}"
ok "Image pushed: ${TIDEWARDEN_IMAGE}"

# Also tag and push as latest if a specific tag was given
if [[ "${IMAGE_TAG}" != "latest" ]]; then
    LATEST_IMAGE="${ACR_NAME}.azurecr.io/${PROJECT_NAME}:latest"
    docker tag "${TIDEWARDEN_IMAGE}" "${LATEST_IMAGE}"
    docker push "${LATEST_IMAGE}"
    ok "Also pushed: ${LATEST_IMAGE}"
fi

# ── 4. Update Container App ────────────────────────────────────────────────
log "Updating Container App with new image..."
az containerapp update \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --image "${TIDEWARDEN_IMAGE}" \
    --output none
ok "Container App updated"

# ── 5. Wait for deployment ─────────────────────────────────────────────────
log "Waiting for new revision to become active..."

# Give a few seconds for the revision to begin provisioning
sleep 5

LATEST_REVISION=$(az containerapp revision list \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query "[0].name" -o tsv)

RETRIES=0
MAX_RETRIES=30
while [[ ${RETRIES} -lt ${MAX_RETRIES} ]]; do
    STATUS=$(az containerapp revision show \
        --name "${TIDEWARDEN_APP_NAME}" \
        --resource-group "${RESOURCE_GROUP}" \
        --revision "${LATEST_REVISION}" \
        --query "properties.runningState" -o tsv 2>/dev/null || echo "Unknown")

    if [[ "${STATUS}" == "Running" ]]; then
        ok "Revision ${LATEST_REVISION} is running"
        break
    fi

    if [[ "${STATUS}" == "Failed" ]]; then
        err "Revision ${LATEST_REVISION} failed to start. Check logs: az containerapp logs show --name ${TIDEWARDEN_APP_NAME} --resource-group ${RESOURCE_GROUP}"
    fi

    RETRIES=$((RETRIES + 1))
    log "Waiting for revision... (${STATUS}) [${RETRIES}/${MAX_RETRIES}]"
    sleep 10
done

if [[ ${RETRIES} -ge ${MAX_RETRIES} ]]; then
    warn "Timed out waiting for revision. Check manually:"
    warn "  az containerapp revision list --name ${TIDEWARDEN_APP_NAME} --resource-group ${RESOURCE_GROUP}"
fi

# ── 6. Show deployed URL ───────────────────────────────────────────────────
TIDEWARDEN_FQDN=$(az containerapp show \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query properties.configuration.ingress.fqdn -o tsv)

echo ""
echo "============================================="
echo "  Deployment Complete"
echo "============================================="
echo ""
echo "  Image:    ${TIDEWARDEN_IMAGE}"
echo "  Revision: ${LATEST_REVISION}"
echo "  URL:      https://${TIDEWARDEN_FQDN}"
echo ""
echo "  View logs:"
echo "    az containerapp logs show \\"
echo "      --name ${TIDEWARDEN_APP_NAME} \\"
echo "      --resource-group ${RESOURCE_GROUP} \\"
echo "      --follow"
echo "============================================="
