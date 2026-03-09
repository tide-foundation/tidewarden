#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Azure Infrastructure Provisioning for TideWarden
# Creates: Resource Group, ACR, Log Analytics, Container Apps Environment,
#          PostgreSQL Flexible Server, TideCloak Container App,
#          TideWarden Container App
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

# Prompt for passwords if not set
if [[ -z "${PG_ADMIN_PASSWORD}" ]]; then
    echo -ne "${YELLOW}Enter PostgreSQL admin password: ${NC}"
    read -rs PG_ADMIN_PASSWORD
    echo
    [[ -z "${PG_ADMIN_PASSWORD}" ]] && err "PostgreSQL password is required"
    export PG_ADMIN_PASSWORD
fi

if [[ -z "${KC_ADMIN_PASSWORD}" ]]; then
    echo -ne "${YELLOW}Enter TideCloak admin password: ${NC}"
    read -rs KC_ADMIN_PASSWORD
    echo
    [[ -z "${KC_ADMIN_PASSWORD}" ]] && err "TideCloak admin password is required"
    export KC_ADMIN_PASSWORD
fi

echo ""
log "Configuration:"
log "  Environment:    ${ENVIRONMENT}"
log "  Location:       ${LOCATION}"
log "  Resource Group: ${RESOURCE_GROUP}"
log "  ACR:            ${ACR_NAME}"
log "  PostgreSQL:     ${PG_SERVER_NAME}"
log "  TideCloak App:  ${TIDECLOAK_APP_NAME}"
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
    --query customerId -o tsv)

LOG_ANALYTICS_KEY=$(az monitor log-analytics workspace get-shared-keys \
    --resource-group "${RESOURCE_GROUP}" \
    --workspace-name "${LOG_ANALYTICS_WORKSPACE}" \
    --query primarySharedKey -o tsv)

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

# ── 6. TideCloak Container App ─────────────────────────────────────────────
log "Creating TideCloak Container App..."

# Get the Container Apps Environment default domain for internal URLs
CAE_DOMAIN=$(az containerapp env show \
    --name "${CONTAINER_ENV_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query properties.defaultDomain -o tsv)

az containerapp create \
    --name "${TIDECLOAK_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --environment "${CONTAINER_ENV_NAME}" \
    --image "${TIDECLOAK_IMAGE}" \
    --target-port 8080 \
    --ingress external \
    --min-replicas "${TIDECLOAK_MIN_REPLICAS}" \
    --max-replicas "${TIDECLOAK_MAX_REPLICAS}" \
    --cpu "${TIDECLOAK_CPU}" \
    --memory "${TIDECLOAK_MEMORY}" \
    --env-vars \
        "KC_BOOTSTRAP_ADMIN_USERNAME=${KC_ADMIN_USER}" \
        "KC_BOOTSTRAP_ADMIN_PASSWORD=${KC_ADMIN_PASSWORD}" \
        "KC_HOSTNAME=https://${TIDECLOAK_APP_NAME}.${CAE_DOMAIN}" \
        "SYSTEM_HOME_ORK=https://sork1.tideprotocol.com" \
        "USER_HOME_ORK=https://sork1.tideprotocol.com" \
        "THRESHOLD_T=3" \
        "THRESHOLD_N=5" \
    --output none

TIDECLOAK_FQDN=$(az containerapp show \
    --name "${TIDECLOAK_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query properties.configuration.ingress.fqdn -o tsv)

ok "TideCloak: https://${TIDECLOAK_FQDN}"

# ── 7. TideWarden Container App ────────────────────────────────────────────
log "Creating TideWarden Container App..."

# Get ACR credentials for Container App to pull images
ACR_USERNAME=$(az acr credential show --name "${ACR_NAME}" --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name "${ACR_NAME}" --query "passwords[0].value" -o tsv)

# Use a placeholder image initially; azure-deploy.sh will update it
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
    --registry-server "${ACR_NAME}.azurecr.io" \
    --registry-username "${ACR_USERNAME}" \
    --registry-password "${ACR_PASSWORD}" \
    --env-vars \
        "ROCKET_ADDRESS=0.0.0.0" \
        "ROCKET_PORT=80" \
        "DATABASE_URL=${DATABASE_URL}" \
        "WEB_VAULT_ENABLED=true" \
        "SSO_ENABLED=true" \
        "SSO_ONLY=true" \
        "SSO_PKCE=true" \
        "TIDECLOAK_LOCAL_URL=https://${TIDECLOAK_FQDN}" \
        "DOMAIN=https://${TIDEWARDEN_APP_NAME}.${CAE_DOMAIN}" \
        "SIGNUPS_ALLOWED=true" \
        "LOG_LEVEL=info" \
    --output none

TIDEWARDEN_FQDN=$(az containerapp show \
    --name "${TIDEWARDEN_APP_NAME}" \
    --resource-group "${RESOURCE_GROUP}" \
    --query properties.configuration.ingress.fqdn -o tsv)

ok "TideWarden: https://${TIDEWARDEN_FQDN}"

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
echo "  TideCloak URL:   https://${TIDECLOAK_FQDN}"
echo "  TideWarden URL:  https://${TIDEWARDEN_FQDN}"
echo ""
echo "  Next step: Run azure-deploy.sh to build and"
echo "  deploy the TideWarden container image."
echo "============================================="
