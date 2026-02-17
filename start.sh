#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENTS_DIR="$ROOT_DIR/clients"
WEB_VAULT_DIR="$ROOT_DIR/web-vault"
BROWSER_BUILD_DIR="$CLIENTS_DIR/apps/browser/build"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[tidewarden]${NC} $1"; }
ok()   { echo -e "${GREEN}[tidewarden]${NC} $1"; }
warn() { echo -e "${YELLOW}[tidewarden]${NC} $1"; }
err()  { echo -e "${RED}[tidewarden]${NC} $1"; }

usage() {
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  --skip-build       Skip building server and clients"
  echo "  --server-only      Build and run server only"
  echo "  --clients-only     Build clients only (no server)"
  echo "  --web-only         Build web vault only (no browser extension)"
  echo "  --browser-only     Build browser extension only (no web vault)"
  echo "  --release          Build server in release mode"
  echo "  -h, --help         Show this help"
  exit 0
}

# Defaults
SKIP_BUILD=false
SERVER=true
WEB=true
BROWSER=true
CARGO_PROFILE=""

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --skip-build)    SKIP_BUILD=true; shift ;;
    --server-only)   WEB=false; BROWSER=false; shift ;;
    --clients-only)  SERVER=false; shift ;;
    --web-only)      BROWSER=false; shift ;;
    --browser-only)  WEB=false; shift ;;
    --release)       CARGO_PROFILE="--release"; shift ;;
    -h|--help)       usage ;;
    *) err "Unknown option: $1"; usage ;;
  esac
done

# Source rust toolchain
if [[ -f "$HOME/.cargo/env" ]]; then
  source "$HOME/.cargo/env"
fi

# ─── Prerequisite checks ───

check_cmd() {
  if ! command -v "$1" &>/dev/null; then
    err "Missing required command: $1"
    [[ -n "${2:-}" ]] && echo -e "       Install: ${CYAN}$2${NC}"
    return 1
  fi
}

MISSING=0

if $SERVER; then
  check_cmd cargo  "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"  || MISSING=1
  check_cmd cc     "sudo apt install build-essential"                                   || MISSING=1

  # Check for libssl-dev (needed by openssl-sys crate)
  if ! pkg-config --exists openssl 2>/dev/null; then
    err "Missing library: libssl-dev (openssl development headers)"
    echo -e "       Install: ${CYAN}sudo apt install libssl-dev pkg-config${NC}"
    MISSING=1
  fi
fi

if $WEB || $BROWSER; then
  check_cmd node "https://nodejs.org/ or: curl -fsSL https://fnm.vercel.app/install | bash && fnm install --lts" || MISSING=1
  check_cmd npm  "(bundled with node)"                                                                            || MISSING=1

  # Check node version >= 18
  NODE_VER=$(node -v | sed 's/v//' | cut -d. -f1)
  if [[ "$NODE_VER" -lt 18 ]]; then
    err "Node.js >= 18 required (found v$(node -v | sed 's/v//'))"
    MISSING=1
  fi

  # Check clients submodule is initialized
  if [[ ! -f "$CLIENTS_DIR/package.json" ]]; then
    err "Clients submodule not initialized."
    echo -e "       Run: ${CYAN}git submodule update --init --recursive${NC}"
    MISSING=1
  fi
fi

if $SERVER; then
  # Check .env exists
  if [[ ! -f "$ROOT_DIR/.env" ]]; then
    warn "No .env file found. Copying from .env.template..."
    if [[ -f "$ROOT_DIR/.env.template" ]]; then
      cp "$ROOT_DIR/.env.template" "$ROOT_DIR/.env"
      ok "Created .env from template. Edit it before running."
    else
      warn "No .env.template found either. Server may fail to start without configuration."
    fi
  fi
fi

if [[ "$MISSING" -ne 0 ]]; then
  err "Fix the above issues and re-run."
  exit 1
fi

ok "All prerequisites satisfied."

# --- Build server ---
if $SERVER && ! $SKIP_BUILD; then
  log "Building vaultwarden server..."
  cd "$ROOT_DIR"
  cargo build --features sqlite $CARGO_PROFILE
  ok "Server build complete."
fi

# --- Build clients ---
if ($WEB || $BROWSER) && ! $SKIP_BUILD; then
  if [[ ! -d "$CLIENTS_DIR/node_modules" ]]; then
    log "Installing client dependencies..."
    cd "$CLIENTS_DIR"
    npm install
    ok "Dependencies installed."
  fi
fi

if $WEB && ! $SKIP_BUILD; then
  log "Building web vault..."
  cd "$CLIENTS_DIR/apps/web"
  ENV=selfhosted npx webpack --mode development 2>&1 | tail -5
  log "Copying web vault to $WEB_VAULT_DIR..."
  rm -rf "$WEB_VAULT_DIR"
  mv build "$WEB_VAULT_DIR"
  ok "Web vault ready."
fi

if $BROWSER && ! $SKIP_BUILD; then
  log "Building browser extension (MV3)..."
  cd "$CLIENTS_DIR/apps/browser"
  MANIFEST_VERSION=3 npx webpack --config webpack.config.js --mode development 2>&1 | tail -5
  ok "Browser extension ready at: $BROWSER_BUILD_DIR"
fi

# --- Start server ---
if $SERVER; then
  # Kill any existing instance on port 8000
  existing_pid=$(lsof -ti :8000 2>/dev/null || true)
  if [[ -n "$existing_pid" ]]; then
    warn "Killing existing process on port 8000 (PID: $existing_pid)"
    kill "$existing_pid" 2>/dev/null || true
    sleep 1
  fi

  cd "$ROOT_DIR"
  BINARY="./target/debug/vaultwarden"
  if [[ -n "$CARGO_PROFILE" ]]; then
    BINARY="./target/release/vaultwarden"
  fi

  log "Starting vaultwarden on http://localhost:8000 ..."
  exec "$BINARY"
fi
