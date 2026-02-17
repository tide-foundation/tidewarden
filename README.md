![TideWarden Logo](./resources/tidewarden-logo-auto.svg)

A fork of [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (server) and [Bitwarden Clients](https://github.com/bitwarden/clients) (web vault & browser extension) with integrated [TideCloak](https://tide.org/tidecloak) support for decentralized key management and zero-knowledge, end-to-end per-field encryption.

---

## Why TideWarden?

Traditional password managers force a choice between convenience and security. Most opt for convenience, filling the gap with promises that often [prove unfounded](https://www.itnews.com.au/news/researchers-find-critical-vulnerabilities-in-cloud-based-password-managers-623661). TideWarden offers a different approach, built on two assumptions: that servers should be treated as potentially hostile, and that users shouldn't be burdened with key management. By integrating with Tide's Cybersecurity Fabric, cryptographic keys (used to authenticate the user and encrypt their passwords) are generated and operated across a decentralized network, never materializing anywhere in full or trusted to anyone. A compromised server cannot expose secrets or elevate privileges. Users never need to remember, store, or safeguard a master key.

**Key differences from Vaultwarden / Bitwarden:**

- **True cryptographic keys, not password-derived encryption.** Traditional password managers derive encryption keys from your master password, which means attackers can brute-force stolen vaults offline. TideWarden uses proper cryptographic keys generated through Tide's Cybersecurity Fabric, giving you fully encrypted data, without risk of exposing the key
- **No key to steal, manage, or trust to a vendor.** The cryptographic key that protects your vault never exists in complete form anywhere. It's generated across a decentralized network. You don't have to remember it, back it up, or trust anyone to safeguard it
- **Stolen database is useless.** Without the decentralized network cooperating in real-time with your authenticated browser, encrypted vault data cannot be decrypted
- **On-demand decryption.** Only the exact field you are viewing is decrypted, just-in-time, and only on the device you successfully authenticated from by binding with an ephemeral session key that only lives on your device TPM.
- **TideCloak SSO.** Authentication through TideCloak's Zero-Knowledge mechanism (a Keycloak fork with Tide integration) instead of brute-force-susceptible passwords
- **Chrome MV3** — Browser extension built with Manifest V3

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Browser    │     │  TideWarden  │     │  TideCloak   │
│  Extension   │────>│    Server    │────>│   (IiAM)     │
│  / Web Vault │     │ (Rust/Rocket)│     │              │
└──────┬───────┘     └──────────────┘     └──────┬───────┘
       │                                         │
       │  encrypt/decrypt                        │ ZK-Auth
       ▼                                         │
┌──────────────┐                                 │
│ Tide Fabric  │                                 │
│  (Threshold  │ <───────────────────────────────┘
│   Crypto)    │
└──────────────┘
```

- **Server**: Fork of [Vaultwarden](https://github.com/dani-garcia/vaultwarden) — Rust, Rocket framework, SQLite/MySQL/PostgreSQL
- **Clients**: Fork of [Bitwarden Clients](https://github.com/bitwarden/clients) — Angular web vault + browser extension (included as a git submodule at `clients/`)

## Features

Everything from Vaultwarden, plus:

- TideCloak SSO login (OIDC with vendor_data exchange)
- Tide-encrypted vault fields (login credentials, notes, card details, identity fields)
- Doken-based authorization for Tide Fabric operations
- On-demand decryption (bulk vault loads, individual items decrypt on view)
- Browser extension with MV3 manifest
- Configurable via environment variables (`TIDE_ENABLED`, `TIDE_HOME_ORK_URL`, etc.)

## Prerequisites

- **Rust** toolchain (stable)
- **Node.js** >= 18 and npm
- **System packages**: `libssl-dev`, `pkg-config`, `build-essential`
- A running **TideCloak** instance configured with your realm and vendor

## Quick Start

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/sashyo/vaultwarden.git
cd vaultwarden

# Copy and edit environment config
cp .env.template .env
# Edit .env — set TIDE_ENABLED=true, SSO_*, TIDE_* variables

# Build everything and start
./start.sh
```

The start script builds the server, web vault, and browser extension, then starts vaultwarden on `http://localhost:8000`.

### Script options

```
./start.sh                 # Build all + start server
./start.sh --skip-build    # Start server without building
./start.sh --server-only   # Build + run server only
./start.sh --clients-only  # Build web vault + browser extension only
./start.sh --web-only      # Build web vault only
./start.sh --browser-only  # Build browser extension (MV3) only
./start.sh --release       # Cargo release build
```

### Loading the browser extension

After building, load the extension from `clients/apps/browser/build/` in Chrome/Edge:

1. Go to `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `build/` directory

## Configuration

Copy `.env.template` to `.env` and set the following variables. All of these are **required** for TideWarden to work:

```env
# Server
DOMAIN=http://localhost:8000
ROCKET_PORT=8000
WEB_VAULT_ENABLED=true
# SSO (public client, no secret needed)
SSO_ENABLED=true
SSO_AUTHORITY=https://your-tidecloak-host/realms/your-realm
SSO_CLIENT_ID=your-client-id
SSO_PKCE=true
SSO_ONLY=true
# TideCloak
TIDE_ENABLED=true
TIDE_VENDOR_ID=your-vendor-id
TIDE_HOME_ORK_URL=https://your-ork-endpoint
TIDE_CLIENT_ORIGIN_AUTH=your-base64-auth-key
TIDE_CLIENT_ORIGIN_AUTH_BROWSER=your-base64-browser-auth-key
```

Optional debugging settings:

```env
SSO_DEBUG_TOKENS=true
LOG_LEVEL=debug
```

### Variable reference

| Variable                            | Required | Description                                                                                  |
| ----------------------------------- | -------- | -------------------------------------------------------------------------------------------- |
| `DOMAIN`                          | Yes      | Full URL including port where TideWarden is hosted                                           |
| `SSO_ENABLED`                     | Yes      | Must be `true` to enable SSO login                                                         |
| `SSO_AUTHORITY`                   | Yes      | TideCloak OIDC discovery base URL (`{url}/.well-known/openid-configuration` must be valid) |
| `SSO_CLIENT_ID`                   | Yes      | OIDC client ID configured in TideCloak                                                       |
| `SSO_PKCE`                        | Yes      | Enable PKCE for the auth code flow (recommended `true`)                                    |
| `SSO_ONLY`                        | Yes      | Disable email+password login, require SSO                                                    |
| `TIDE_ENABLED`                    | Yes      | Enable TideCloak integration                                                                 |
| `TIDE_VENDOR_ID`                  | Yes      | Vendor ID for ORK operations                                                                 |
| `TIDE_HOME_ORK_URL`               | Yes      | Home ORK endpoint URL                                                                        |
| `TIDE_CLIENT_ORIGIN_AUTH`         | Yes      | Base64-encoded client origin auth key (server-side)                                          |
| `TIDE_CLIENT_ORIGIN_AUTH_BROWSER` | Yes      | Base64-encoded client origin auth key (browser-side)                                         |

## Upstream

- Server: [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden)
- Clients: [bitwarden/clients](https://github.com/bitwarden/clients)
- TideCloak: [tidecloak website](https://tide.org/tidecloak)

## License

This project inherits the [AGPL-3.0 license](LICENSE.txt) from Vaultwarden.

**This project is not associated with [Bitwarden](https://bitwarden.com/) or Bitwarden, Inc., nor with [Vaultwarden](https://github.com/dani-garcia/vaultwarden).**
