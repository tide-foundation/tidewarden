<img src="./resources/tidewarden-logo-auto.svg" alt="TideWarden Logo" width="600" />

![Status](https://img.shields.io/badge/status-proof--of--concept-orange)

An open-source "trustless password manager" proof-of-concept prompted by [ETH Zurich&#39;s research](https://ethz.ch/en/news-and-events/eth-news/news/2026/02/password-managers-less-secure-than-promised.html), which documented 25 vulnerabilities showing how a compromised password manager server can silently steal your credentials. Built to demonstrate that the architecture can be redesigned so a compromised server simply can't. Using a fork of [Vaultwarden](https://github.com/dani-garcia/vaultwarden) (server) and [Bitwarden Clients](https://github.com/bitwarden/clients) (web vault & browser extension) wired to [TideCloak](https://docs.tidecloak.com/) for decentralized key management and zero-knowledge, end-to-end per-field encryption.

---

## What this PoC demonstrates

Traditional password managers face a choice between offering better security or convenience. Most opt for convenience by acting as a trusted intermediary that manages keys and encryption on the user's behalf, making themselves a blindly trusted cog accompanied by security promises ETH Zurich's research proved are often unfounded.

By wiring Vaultwarden to TideCloak, cryptographic keys, used to authenticate users and encrypt data, are generated and operated across a decentralized network, never materializing in full anywhere, and never trusted to any single party. A compromised server cannot expose vault contents or elevate its own privileges, because no one ever holds the keys needed to do either.

**Specifically:**

- **Keys cannot be brute-forced.** Traditional managers derive encryption keys from your master password, making stolen vaults crackable offline. Here, data is locked with 256-bit elliptic curve keys.
- **There's no key to steal from the server.** Those keys never exist in complete form on any single machine. A server breach yields encrypted data with no path to decryption.
- **Decryption requires live network consensus.** Even with the entire encrypted database in hand, decryption requires the decentralized network cooperating in real-time with an authenticated session. Exfiltrated data alone gets you nowhere.
- **Decryption is scoped to exactly what you're viewing.** Only the specific data in use is decrypted, just-in-time, bound to an ephemeral session key on the authenticated user's device (TPM).
- **Authentication doesn't rely on brute-force-susceptible passwords.** Login goes through TideCloak's zero-knowledge mechanism rather than a traditional master password.

Note: This is a research prototype, not a hardened production deployment.

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
- Doken-based authorization for decentralized cryptographic operations
- On-demand decryption (bulk vault loads, individual items decrypt on view)
- Browser extension with MV3 manifest

## Prerequisites

- **Rust** toolchain (stable)
- **Node.js** >= 18 and npm
- **System packages**: `libssl-dev`, `pkg-config`, `build-essential`
- A running **TideCloak** instance configured with your realm and vendor

## Try it yourself

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
- TideCloak: [docs.tidecloak.com](https://docs.tidecloak.com/)

## License

This project inherits the [AGPL-3.0 license](LICENSE.txt) from Vaultwarden.

**This project is not associated with [Bitwarden](https://bitwarden.com/) or Bitwarden, Inc., nor with [Vaultwarden](https://github.com/dani-garcia/vaultwarden).**
