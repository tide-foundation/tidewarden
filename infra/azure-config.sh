#!/usr/bin/env bash
# Shared Azure configuration for TideWarden infrastructure and deployment.
# Source this file from azure-infra.sh and azure-deploy.sh.

# ── Naming ──────────────────────────────────────────────────────────────────
export PROJECT_NAME="${PROJECT_NAME:-tidewarden}"
export ENVIRONMENT="${ENVIRONMENT:-prod}"         # prod, staging, dev
export LOCATION="${LOCATION:-eastus}"

# Derived resource names (override any individually if needed)
export RESOURCE_GROUP="${RESOURCE_GROUP:-rg-${PROJECT_NAME}-${ENVIRONMENT}}"
export ACR_NAME="${ACR_NAME:-acr${PROJECT_NAME}${ENVIRONMENT}}"          # must be alphanumeric
export LOG_ANALYTICS_WORKSPACE="${LOG_ANALYTICS_WORKSPACE:-law-${PROJECT_NAME}-${ENVIRONMENT}}"
export CONTAINER_ENV_NAME="${CONTAINER_ENV_NAME:-cae-${PROJECT_NAME}-${ENVIRONMENT}}"

# ── Container Apps ──────────────────────────────────────────────────────────
export TIDEWARDEN_APP_NAME="${TIDEWARDEN_APP_NAME:-ca-${PROJECT_NAME}-${ENVIRONMENT}}"
export TIDECLOAK_APP_NAME="${TIDECLOAK_APP_NAME:-ca-tidecloak-${ENVIRONMENT}}"

export TIDEWARDEN_IMAGE="${TIDEWARDEN_IMAGE:-${ACR_NAME}.azurecr.io/${PROJECT_NAME}:latest}"
export TIDECLOAK_IMAGE="${TIDECLOAK_IMAGE:-tideorg/tidecloak-stg-dev:latest}"

export TIDEWARDEN_CPU="${TIDEWARDEN_CPU:-1.0}"
export TIDEWARDEN_MEMORY="${TIDEWARDEN_MEMORY:-2.0Gi}"
export TIDECLOAK_CPU="${TIDECLOAK_CPU:-1.0}"
export TIDECLOAK_MEMORY="${TIDECLOAK_MEMORY:-2.0Gi}"

export TIDEWARDEN_MIN_REPLICAS="${TIDEWARDEN_MIN_REPLICAS:-1}"
export TIDEWARDEN_MAX_REPLICAS="${TIDEWARDEN_MAX_REPLICAS:-3}"
export TIDECLOAK_MIN_REPLICAS="${TIDECLOAK_MIN_REPLICAS:-1}"
export TIDECLOAK_MAX_REPLICAS="${TIDECLOAK_MAX_REPLICAS:-1}"

# ── PostgreSQL ──────────────────────────────────────────────────────────────
export PG_SERVER_NAME="${PG_SERVER_NAME:-psql-${PROJECT_NAME}-${ENVIRONMENT}}"
export PG_ADMIN_USER="${PG_ADMIN_USER:-twadmin}"
export PG_ADMIN_PASSWORD="${PG_ADMIN_PASSWORD:-}"   # MUST be set externally or prompted
export PG_SKU="${PG_SKU:-B_Standard_B1ms}"
export PG_STORAGE_SIZE="${PG_STORAGE_SIZE:-32}"      # GiB
export PG_VERSION="${PG_VERSION:-16}"
export PG_DB_NAME="${PG_DB_NAME:-tidewarden}"

# ── TideCloak defaults ──────────────────────────────────────────────────────
export KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
export KC_ADMIN_PASSWORD="${KC_ADMIN_PASSWORD:-}"    # MUST be set externally or prompted
