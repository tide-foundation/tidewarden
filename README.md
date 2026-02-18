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

## Prerequisites

- **Rust** toolchain (stable)
- **Node.js** >= 18 and npm
- **System packages**: `libssl-dev`, `pkg-config`, `build-essential`
- A running **TideCloak** instance configured with your realm and vendor

## Quick Start

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/sashyo/tidewarden.git
cd tidewarden/scripts

# Build everything and start
./start.sh
```

The start script builds the server, web vault, and browser extension, then starts vaultwarden on `http://localhost:8000`.

## Upstream

- Server: [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden)
- Clients: [bitwarden/clients](https://github.com/bitwarden/clients)
- TideCloak: [tidecloak website](https://tide.org/tidecloak)

## License

This project inherits the [AGPL-3.0 license](LICENSE.txt) from Vaultwarden.

**This project is not associated with [Bitwarden](https://bitwarden.com/) or Bitwarden, Inc., nor with [Vaultwarden](https://github.com/dani-garcia/vaultwarden).**
