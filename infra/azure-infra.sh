#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Azure Infrastructure Provisioning for TideWarden
# Creates: Resource Group, ACR, Log Analytics, Container Apps Environment,
#          PostgreSQL Flexible Server, TideWarden Container App
# Note: TideCloak is hosted externally — set TIDECLOAK_URL in azure-config.sh
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/azure-config.sh"

# ── Colours / helpers ───────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[infra]${NC} $1"; }
ok()   { echo -e "${GREEN}[infra]${NC} $1"; }
warn() { echo -e "${YELLOW}[infra]${NC} $1"; }
err()  { echo -e "${RED}[infra]${NC} $1"; exit 1; }

# ── Pre-flight checks ──────────────────────────────────────────────────────
command -v az &>/dev/null || err "Azure CLI (az) is not installed. https://aka.ms/install-azure-cli"

az account show &>/dev/null || err "Not logged in. Run: az login"

log "Subscription: $(az account show --query '{name:name, id:id}' -o tsv)"

# Prompt for PostgreSQL password if not set
if [[ -z "${PG_ADMIN_PASSWORD}" ]]; then
    echo -ne "${YELLOW}Enter PostgreSQL admin password: ${NC}"
    read -rs PG_ADMIN_PASSWORD
    echo
    [[ -z "${PG_ADMIN_PASSWORD}" ]] && err "PostgreSQL password is required"
    export PG_ADMIN_PASSWORD
fi

echo ""
log "Configuration:"
log "  Environment:    ${ENVIRONMENT}"
log "  Location:       ${LOCATION}"
log "  Resource Group: ${RESOURCE_GROUP}"
log "  ACR:            ${ACR_NAME}"
log "  PostgreSQL:     ${PG_SERVER_NAME}"
log "  TideCloak:      ${TIDECLOAK_URL} (external)"
log "  TideWarden App: ${TIDEWARDEN_APP_NAME}"
echo ""

# ── 1. Resource Group ───────────────────────────────────────────────────────
log "Creating Resource Group..."
az group create \
    --name "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --output none
ok "Resource Group: ${RESOURCE_GROUP}"

# ── 2. Azure Container Registry ────────────────────────────────────────────
log "Creating Azure Container Registry..."
az acr create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${ACR_NAME}" \
    --sku Basic \
    --admin-enabled true \
    --output none
ok "ACR: ${ACR_NAME}.azurecr.io"

# ── 3. Log Analytics Workspace ─────────────────────────────────────────────
log "Creating Log Analytics Workspace..."
az monitor log-analytics workspace create \
    --resource-group "${RESOURCE_GROUP}" \
    --workspace-name "${LOG_ANALYTICS_WORKSPACE}" \
    --location "${LOCATION}" \
    --output none

LOG_ANALYTICS_ID=$(az monitor log-analytics workspace show \
    --resource-group "${RESOURCE_GROUP}" \
    --workspace-name "${LOG_ANALYTICS_WORKSPACE}" \
    --query customerId -o tsv | tr -d '[:space:]')

LOG_ANALYTICS_KEY=$(az monitor log-analytics workspace get-shared-keys \
    --resource-group "${RESOURCE_GROUP}" \
    --workspace-name "${LOG_ANALYTICS_WORKSPACE}" \
    --query primarySharedKey -o tsv | tr -d '\r\n')

ok "Log Analytics: ${LOG_ANALYTICS_WORKSPACE}"

# ── 4. Container Apps Environment ──────────────────────────────────────────
log "Creating Container Apps Environment..."
az containerapp env create \
    --name "${CONTAINER_ENV_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --location "${LOCATION}" \
    --logs-workspace-id "${LOG_ANALYTICS_ID}" \
    --logs-workspace-key "${LOG_ANALYTICS_KEY}" \
    --output none
ok "Container Apps Environment: ${CONTAINER_ENV_NAME}"

# ── 5. PostgreSQL Flexible Server ──────────────────────────────────────────
log "Creating PostgreSQL Flexible Server..."
az postgres flexible-server create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${PG_SERVER_NAME}" \
    --location "${LOCATION}" \
    --admin-user "${PG_ADMIN_USER}" \
    --admin-password "${PG_ADMIN_PASSWORD}" \
    --tier "${PG_TIER}" \
    --sku-name "${PG_SKU}" \
    --storage-size "${PG_STORAGE_SIZE}" \
    --version "${PG_VERSION}" \
    --yes \
    --output none

ok "PostgreSQL: ${PG_SERVER_NAME}"

# Create the database
log "Creating database '${PG_DB_NAME}'..."
az postgres flexible-server db create \
    --resource-group "${RESOURCE_GROUP}" \
    --server-name "${PG_SERVER_NAME}" \
    --database-name "${PG_DB_NAME}" \
    --output none
ok "Database: ${PG_DB_NAME}"

# Allow Azure services to connect (Container Apps -> PostgreSQL)
log "Configuring PostgreSQL firewall for Azure services..."
az postgres flexible-server firewall-rule create \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${PG_SERVER_NAME}" \
    --rule-name "AllowAzureServices" \
    --start-ip-address 0.0.0.0 \
    --end-ip-address 0.0.0.0 \
    --output none
ok "PostgreSQL firewall rule configured"

# Build the connection string
PG_FQDN=$(az postgres flexible-server show \
    --resource-group "${RESOURCE_GROUP}" \
    --name "${PG_SERVER_NAME}" \
    --query fullyQualifiedDomainName -o tsv)

DATABASE_URL="postgresql://${PG_ADMIN_USER}:${PG_ADMIN_PASSWORD}@${PG_FQDN}:5432/${PG_DB_NAME}?sslmode=require"

# ── 6. TideWarden Container App ────────────────────────────────────────────
log "Creating TideWarden Container App..."

# Get the Container Apps Environment default domain
CAE_DOMAIN=$(az containerapp env show \
    --name "${CONTAINER_ENV_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query properties.defaultDomain -o tsv)

# Use a placeholder image initially; azure-deploy.sh will update it
# Create the app first with a public placeholder (no ACR auth needed yet)
az containerapp create \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --environment "${CONTAINER_ENV_NAME}" \
    --image "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest" \
    --target-port 80 \
    --ingress external \
    --min-replicas "${TIDEWARDEN_MIN_REPLICAS}" \
    --max-replicas "${TIDEWARDEN_MAX_REPLICAS}" \
    --cpu "${TIDEWARDEN_CPU}" \
    --memory "${TIDEWARDEN_MEMORY}" \
    --env-vars \
        "ROCKET_ADDRESS=0.0.0.0" \
        "ROCKET_PORT=80" \
        "DATABASE_URL=${DATABASE_URL}" \
        "WEB_VAULT_ENABLED=true" \
        "SSO_ENABLED=true" \
        "SSO_ONLY=true" \
        "SSO_PKCE=true" \
        "TIDECLOAK_LOCAL_URL=${TIDECLOAK_URL}" \
        "DOMAIN=https://${TIDEWARDEN_APP_NAME}.${CAE_DOMAIN}" \
        "SIGNUPS_ALLOWED=true" \
        "LOG_LEVEL=info" \
    --output none

TIDEWARDEN_FQDN=$(az containerapp show \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query properties.configuration.ingress.fqdn -o tsv)

ok "TideWarden: https://${TIDEWARDEN_FQDN}"

# Assign system-managed identity and grant AcrPull so deploy can swap to ACR images
log "Configuring managed identity for ACR pull..."
az containerapp identity assign \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --system-assigned \
    --output none

IDENTITY_PRINCIPAL=$(az containerapp identity show \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query principalId -o tsv | tr -d '[:space:]')

ACR_ID=$(az acr show --name "${ACR_NAME}" --resource-group "${RESOURCE_GROUP}" --query id -o tsv | tr -d '[:space:]')

az role assignment create \
    --assignee "${IDENTITY_PRINCIPAL}" \
    --role AcrPull \
    --scope "${ACR_ID}" \
    --output none

# Register the ACR with managed identity on the container app
az containerapp registry set \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --server "${ACR_NAME}.azurecr.io" \
    --identity system \
    --output none

ok "Managed identity configured for ACR pull"

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo "  Infrastructure Provisioning Complete"
echo "============================================="
echo ""
echo "  Resource Group:  ${RESOURCE_GROUP}"
echo "  ACR:             ${ACR_NAME}.azurecr.io"
echo "  PostgreSQL:      ${PG_FQDN}"
echo "  Database:        ${PG_DB_NAME}"
echo ""
echo "  TideCloak:       ${TIDECLOAK_URL} (external)"
echo "  TideWarden URL:  https://${TIDEWARDEN_FQDN}"
echo ""
echo "  Next step: Run azure-deploy.sh to build and"
echo "  deploy the TideWarden container image."
echo "============================================="
