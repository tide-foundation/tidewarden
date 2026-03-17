#!/usr/bin/env bash
# Shared Azure configuration for TideWarden infrastructure and deployment.
# Source this file from azure-infra.sh and azure-deploy.sh.

# ── Naming ──────────────────────────────────────────────────────────────────
export PROJECT_NAME="${PROJECT_NAME:-tidewarden}"
export ENVIRONMENT="${ENVIRONMENT:-prod}"         # prod, staging, dev
export LOCATION="${LOCATION:-australiaeast}"

# Derived resource names (override any individually if needed)
export RESOURCE_GROUP="${RESOURCE_GROUP:-TideWarden}"
export LOG_ANALYTICS_WORKSPACE="${LOG_ANALYTICS_WORKSPACE:-law-${PROJECT_NAME}-${ENVIRONMENT}}"
export CONTAINER_ENV_NAME="${CONTAINER_ENV_NAME:-cae-${PROJECT_NAME}-${ENVIRONMENT}}"

# ── Container Image (Docker Hub) ──────────────────────────────────────────
export DOCKER_IMAGE="${DOCKER_IMAGE:-tideorg/tidewarden}"
export IMAGE_TAG="${IMAGE_TAG:-latest}"

# ── Container App ─────────────────────────────────────────────────────────
export TIDEWARDEN_APP_NAME="${TIDEWARDEN_APP_NAME:-ca-${PROJECT_NAME}-${ENVIRONMENT}}"
export TIDEWARDEN_DOMAIN="${TIDEWARDEN_DOMAIN:-https://tidewarden.tide.org}"

export TIDEWARDEN_CPU="${TIDEWARDEN_CPU:-1.0}"
export TIDEWARDEN_MEMORY="${TIDEWARDEN_MEMORY:-2.0Gi}"
export TIDEWARDEN_MIN_REPLICAS="${TIDEWARDEN_MIN_REPLICAS:-1}"
export TIDEWARDEN_MAX_REPLICAS="${TIDEWARDEN_MAX_REPLICAS:-3}"

# ── PostgreSQL ──────────────────────────────────────────────────────────────
export PG_SERVER_NAME="${PG_SERVER_NAME:-psql-tidewarden}"
export PG_ADMIN_USER="${PG_ADMIN_USER:-twadmin}"
export PG_ADMIN_PASSWORD="${PG_ADMIN_PASSWORD:-}"   # MUST be set externally or prompted
export PG_TIER="${PG_TIER:-Burstable}"
export PG_SKU="${PG_SKU:-Standard_B1ms}"
export PG_STORAGE_SIZE="${PG_STORAGE_SIZE:-32}"      # GiB
export PG_VERSION="${PG_VERSION:-16}"
export PG_DB_NAME="${PG_DB_NAME:-tidewarden}"

# ── Persistent Storage (Azure File Share for /data) ──────────────────────
export STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_NAME:-sttidewarden}"
export STORAGE_SHARE_NAME="${STORAGE_SHARE_NAME:-tidewarden-data}"
export STORAGE_MOUNT_NAME="${STORAGE_MOUNT_NAME:-tidewardendata}"

# ── External TideCloak ─────────────────────────────────────────────────────
# TideCloak is hosted externally. Set this to your existing instance URL.
export TIDECLOAK_URL="${TIDECLOAK_URL:-https://login.dauth.me}"
