#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Azure Deployment Script for TideWarden
# Updates the Container App to a new image tag from Docker Hub.
# Run azure-infra.sh first to provision the infrastructure.
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/azure-config.sh"

# ── Colours / helpers ───────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[deploy]${NC} $1"; }
ok()   { echo -e "${GREEN}[deploy]${NC} $1"; }
warn() { echo -e "${YELLOW}[deploy]${NC} $1"; }
err()  { echo -e "${RED}[deploy]${NC} $1"; exit 1; }

# ── Parse arguments ────────────────────────────────────────────────────────
DEPLOY_TAG="${1:-${IMAGE_TAG}}"
FULL_IMAGE="${DOCKER_IMAGE}:${DEPLOY_TAG}"

usage() {
    echo "Usage: $0 [IMAGE_TAG]"
    echo ""
    echo "  IMAGE_TAG   Docker Hub image tag (default: ${IMAGE_TAG})"
    echo ""
    echo "Examples:"
    echo "  $0              # deploys ${DOCKER_IMAGE}:${IMAGE_TAG}"
    echo "  $0 v1.2.3       # deploys ${DOCKER_IMAGE}:v1.2.3"
    echo "  $0 sha-abc1234  # deploys ${DOCKER_IMAGE}:sha-abc1234"
    exit 0
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

# ── Pre-flight checks ──────────────────────────────────────────────────────
command -v az &>/dev/null || err "Azure CLI (az) is not installed."
az account show &>/dev/null || err "Not logged in. Run: az login"

az containerapp show --name "${TIDEWARDEN_APP_NAME}" --resource-group "${RESOURCE_GROUP}" &>/dev/null \
    || err "Container App '${TIDEWARDEN_APP_NAME}' not found. Run azure-infra.sh first."

echo ""
log "Deployment Configuration:"
log "  Image:          ${FULL_IMAGE}"
log "  Resource Group: ${RESOURCE_GROUP}"
log "  Container App:  ${TIDEWARDEN_APP_NAME}"
echo ""

# ── 1. Update Container App ────────────────────────────────────────────────
log "Updating Container App with image: ${FULL_IMAGE}..."
az containerapp update \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --image "${FULL_IMAGE}" \
    --output none
ok "Container App updated"

# ── 2. Wait for deployment ─────────────────────────────────────────────────
log "Waiting for new revision to become active..."

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

# ── 3. Show deployed URL ───────────────────────────────────────────────────
TIDEWARDEN_FQDN=$(az containerapp show \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query properties.configuration.ingress.fqdn -o tsv)

echo ""
echo "============================================="
echo "  Deployment Complete"
echo "============================================="
echo ""
echo "  Image:    ${FULL_IMAGE}"
echo "  Revision: ${LATEST_REVISION}"
echo "  URL:      https://${TIDEWARDEN_FQDN}"
echo ""
echo "  View logs:"
echo "    az containerapp logs show \\"
echo "      --name ${TIDEWARDEN_APP_NAME} \\"
echo "      --resource-group ${RESOURCE_GROUP} \\"
echo "      --follow"
echo "============================================="
