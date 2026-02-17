![TideWarden Logo](./resources/tidewarden-logo-auto.svg)

A fork of [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (server) and [Bitwarden Clients](https://github.com/bitwarden/clients) (web vault & browser extension) with integrated [TideCloak](https://www.tideprotocol.com/) support for decentralized key management and ORK-based field encryption.

---

## Why TideWarden?

The fundamental flaw in current password managers is that they function like a physical safe: if thieves steal the database, they can take it offline and use infinite computing power to drill the lock until it breaks. Integrating Tide fundamentally alters this reality by ensuring the master key to that safe never actually exists to be stolen. Instead, Tide transforms your specific browser into a temporary, ephemeral key that decrypts only the exact password you need, strictly for the moment you are using it, while the rest of the vault remains mathematically sealed. This renders a stolen database useless: because the "key" is generated physically on your device and vanishes when you leave, an attacker cannot drag the vault away to crack it, nor can they unlock the full contents even if they compromise the server.

**Key differences from Vaultwarden / Bitwarden:**

- **No master password** — There is no master key to steal. Keys are generated ephemerally on your device through the ORK threshold network and never persist
- **Stolen database is useless** — Without the ORK network cooperating in real-time with your authenticated browser, encrypted vault data cannot be decrypted offline
- **On-demand decryption** — Only the exact field you are viewing is decrypted, only for the moment you need it. The rest of the vault remains sealed
- **TideCloak SSO** — Authentication through TideCloak (a Keycloak fork with Tide Protocol integration) instead of email/password
- **ORK field encryption** — Vault fields are encrypted via the ORK network using `EncryptionType 100`, not local AES
- **Chrome MV3** — Browser extension built with Manifest V3

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Browser    │     │  TideWarden  │     │  TideCloak   │
│  Extension   │────▶│    Server    │────▶│   (IdP)      │
│  / Web Vault │     │ (Rust/Rocket)│     │              │
└──────┬───────┘     └──────────────┘     └──────────────┘
       │
       │  encrypt/decrypt
       ▼
┌──────────────┐
│  ORK Network │
│  (Threshold  │
│   Crypto)    │
└──────────────┘
```

- **Server**: Fork of [Vaultwarden](https://github.com/dani-garcia/vaultwarden) — Rust, Rocket framework, SQLite/MySQL/PostgreSQL
- **Clients**: Fork of [Bitwarden Clients](https://github.com/bitwarden/clients) — Angular web vault + browser extension (included as a git submodule at `clients/`)

## Features

Everything from Vaultwarden, plus:

- TideCloak SSO login (OIDC with vendor_data exchange)
- ORK-encrypted vault fields (login credentials, notes, card details, identity fields)
- Doken-based authorization for ORK operations
- On-demand decryption (bulk vault loads skip ORK, individual items decrypt on view)
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

TideCloak-specific environment variables (set in `.env`):

| Variable | Description |
|----------|-------------|
| `TIDE_ENABLED` | Enable TideCloak integration (`true`/`false`) |
| `SSO_ENABLED` | Enable SSO (`true`) |
| `SSO_AUTHORITY` | TideCloak base URL |
| `SSO_CLIENT_ID` | OIDC client ID |
| `SSO_CLIENT_SECRET` | OIDC client secret |
| `TIDE_HOME_ORK_URL` | Home ORK endpoint URL |
| `TIDE_VOUCHER_PATH` | Voucher endpoint path |
| `TIDE_REALM` | TideCloak realm name |
| `TIDE_VENDOR_ID` | Vendor ID for ORK operations |

## Upstream

- Server: [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden)
- Clients: [bitwarden/clients](https://github.com/bitwarden/clients)
- Tide Protocol: [tide-foundation](https://www.tideprotocol.com/)

## License

This project inherits the [AGPL-3.0 license](LICENSE.txt) from Vaultwarden.

**This project is not associated with [Bitwarden](https://bitwarden.com/) or Bitwarden, Inc., nor with [Vaultwarden](https://github.com/dani-garcia/vaultwarden).**
