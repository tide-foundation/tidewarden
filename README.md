<img src="./resources/tidewarden-logo-auto.svg" alt="TideWarden Logo" width="600" />

![Status](https://img.shields.io/badge/status-proof--of--concept-orange)

An open-source proof-of-concept exploring a new password manager architecture. One where users get the convenience of a centralised vault without the catastrophic risk that comes with it.

Password managers are useful because they centralise credentials. The problem is that centralisation also creates a single point of failure in vendors, channels, and anyone positioned between the user and their data. ETH Zurich's [recently published](https://ethz.ch/en/news-and-events/eth-news/news/2026/02/password-managers-less-secure-than-promised.html) research documented 25 ways the security promises covering that risk break down in practice, and users have no way to verify any of them independently.

The project uses a fork of [Vaultwarden](https://github.com/dani-garcia/vaultwarden) and [Bitwarden Clients](https://github.com/bitwarden/clients) wired to [TideCloak](https://docs.tidecloak.com/) for decentralized key management and zero-knowledge, end-to-end per-field encryption.

---

## What this PoC demonstrates

The goal is simple: a user's credentials should only ever be accessible to that user, on a device they successfully authenticated from, with no viable path for a vendor, server operator, or man-in-the-middle to access them, even acting with full malicious intent.

In conventional architectures that guarantee is a promise. Most vendors claim zero-knowledge cryptography, and some may genuinely attempt it. But the trusted role they play in brokering authentication and key operations means a compromised or complicit vendor can quietly step into the user's shoes without ever being detected. Here, keys are generated and operated across a decentralized network and never materialise in complete form on any single machine. No single party, including the platform operator, is ever in a position to broker that privilege unilaterally. The guarantee is structural, not asserted.

**Specifically:**

- **Keys cannot be brute-forced.** Traditional managers derive encryption keys from your master password, making stolen vaults crackable offline. Here, data is locked with 256-bit elliptic curve keys.
- **A server breach yields nothing usable.** Keys never exist in complete form on any single machine, so encrypted data has no viable path to decryption.
- **Decryption requires live network consensus.** A full database dump is inert without the decentralized network cooperating in real-time with an authenticated session.
- **Decryption is scoped to exactly what you're viewing.** Only the specific data in use is decrypted, just-in-time, bound to an ephemeral session key on the authenticated user's device (TPM).
- **Authentication without a brute-force surface.** Login goes through TideCloak's zero-knowledge mechanism rather than a traditional master password.

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
