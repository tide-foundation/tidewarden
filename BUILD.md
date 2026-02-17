# TideWarden Build & Run Guide

## Prerequisites

- **Rust**: `~/.cargo/env` (source it before building)
- **Node.js**: >= 22.12.0, npm ~10
- **System packages**: `libssl-dev`, `pkg-config`
- **SQLite**: used as the database backend

## Directory Layout

```
password-manager/
├── vaultwarden/          # Rust server (port 8000)
├── clients/              # Bitwarden clients monorepo
│   ├── apps/
│   │   ├── web/          # Web vault (served by vaultwarden)
│   │   └── browser/      # Browser extension (Chrome MV3)
│   └── libs/             # Shared libraries
├── mediquil/
│   └── tidecloak-js/     # @tidecloak/js package (local dependency)
└── BUILD.md              # This file
```

## 1. Server (Vaultwarden)

```bash
cd ~/password-manager/vaultwarden

# Build
source ~/.cargo/env
cargo build --features sqlite

# Run (serves on http://localhost:8000)
cargo run --features sqlite
```

Configuration is in `.env`:
- `ROCKET_PORT=8000` — server port
- `WEB_VAULT_ENABLED=true` — serves the web vault from `web-vault/`
- `SSO_ENABLED=true` — TideCloak SSO via OIDC
- `TIDE_ENABLED=true` — ORK field encryption

## 2. Web Vault

```bash
cd ~/password-manager/clients

# Install dependencies (first time or after package.json changes)
npm install

# Build
cd apps/web
npm run build:oss

# Copy build output to vaultwarden
rm -rf ~/password-manager/vaultwarden/web-vault/*
cp -r build/* ~/password-manager/vaultwarden/web-vault/
```

The web vault is served by vaultwarden at http://localhost:8000.

For **dev mode with hot reload**:
```bash
cd ~/password-manager/clients/apps/web
npm run build:oss:selfhost:watch
```
(Note: dev mode serves on its own port, not through vaultwarden)

## 3. Browser Extension (Chrome)

```bash
cd ~/password-manager/clients/apps/browser

# Build for Chrome MV3
npm run build

# Output: build/ directory
```

To load in Chrome:
1. Go to `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select `~/password-manager/clients/apps/browser/build`

For **watch mode** (auto-rebuild on changes):
```bash
npm run build:watch
```

Other browsers:
```bash
npm run build:firefox
npm run build:edge
npm run build:safari
```

## 4. TideCloak Dependencies

If you modify `@tidecloak/js` (heimdall-tide wrapper):

```bash
# Rebuild heimdall
cd ~/heimdall
npm run build

# Rebuild @tidecloak/js
cd ~/mediquil/tidecloak-js/packages/tidecloak-js
npm run build

# Then rebuild whichever client uses it (web or browser)
```

## Quick: Build & Run Everything

```bash
# Terminal 1: Server
cd ~/password-manager/vaultwarden
source ~/.cargo/env
cargo run --features sqlite

# Terminal 2: Web vault
cd ~/password-manager/clients/apps/web
npm run build:oss
rm -rf ~/password-manager/vaultwarden/web-vault/*
cp -r build/* ~/password-manager/vaultwarden/web-vault/

# Terminal 3: Browser extension
cd ~/password-manager/clients/apps/browser
npm run build
```

Then open http://localhost:8000 for the web vault, or load the browser extension from `clients/apps/browser/build`.
