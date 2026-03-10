#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Build and push TideWarden Docker image to Docker Hub
# Usage: ./docker-build-push.sh [IMAGE_TAG]
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
source "${SCRIPT_DIR}/azure-config.sh"

# ── Colours / helpers ───────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[build]${NC} $1"; }
ok()   { echo -e "${GREEN}[build]${NC} $1"; }
err()  { echo -e "${RED}[build]${NC} $1"; exit 1; }

# ── Parse arguments ────────────────────────────────────────────────────────
BUILD_TAG="${1:-${IMAGE_TAG}}"
FULL_IMAGE="${DOCKER_IMAGE}:${BUILD_TAG}"

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && {
    echo "Usage: $0 [IMAGE_TAG]"
    echo ""
    echo "  IMAGE_TAG   Docker image tag (default: ${IMAGE_TAG})"
    echo ""
    echo "Examples:"
    echo "  $0              # builds and pushes ${DOCKER_IMAGE}:${IMAGE_TAG}"
    echo "  $0 v1.2.3       # builds and pushes ${DOCKER_IMAGE}:v1.2.3"
    exit 0
}

# ── Pre-flight checks ──────────────────────────────────────────────────────
command -v docker &>/dev/null || err "Docker is not installed."

DOCKERFILE="${ROOT_DIR}/docker/Dockerfile.debian"
[[ -f "${DOCKERFILE}" ]] || err "Dockerfile not found at ${DOCKERFILE}"

echo ""
log "Build Configuration:"
log "  Image:      ${FULL_IMAGE}"
log "  Dockerfile: ${DOCKERFILE}"
log "  DB:         postgresql"
echo ""

# ── 1. Login to Docker Hub ─────────────────────────────────────────────────
log "Logging into Docker Hub..."
docker login || err "Docker Hub login failed"
ok "Docker Hub login successful"

# ── 2. Ensure buildx is available (needed for BuildKit / $BUILDPLATFORM) ──
if ! docker buildx version &>/dev/null; then
    log "Installing docker-buildx plugin..."
    sudo apt-get update -qq && sudo apt-get install -y -qq docker-buildx >/dev/null 2>&1 \
        || err "Failed to install docker-buildx. Install manually: sudo apt-get install docker-buildx"
    ok "docker-buildx installed"
fi

# ── 3. Build ───────────────────────────────────────────────────────────────
log "Building image (this will take a while for a Rust release build)..."
docker buildx build \
    -t "${FULL_IMAGE}" \
    -f "${DOCKERFILE}" \
    --build-arg DB=postgresql \
    --build-arg CARGO_PROFILE=release \
    --load \
    "${ROOT_DIR}"

ok "Image built: ${FULL_IMAGE}"

# ── 4. Push ────────────────────────────────────────────────────────────────
log "Pushing to Docker Hub..."
docker push "${FULL_IMAGE}"
ok "Pushed: ${FULL_IMAGE}"

# Also tag and push as latest if a specific tag was given
if [[ "${BUILD_TAG}" != "latest" ]]; then
    docker tag "${FULL_IMAGE}" "${DOCKER_IMAGE}:latest"
    docker push "${DOCKER_IMAGE}:latest"
    ok "Also pushed: ${DOCKER_IMAGE}:latest"
fi

echo ""
echo "============================================="
echo "  Build & Push Complete"
echo "============================================="
echo ""
echo "  Image: ${FULL_IMAGE}"
echo ""
echo "  To deploy to Azure Container Apps:"
echo "    ./azure-deploy.sh ${BUILD_TAG}"
echo "============================================="
