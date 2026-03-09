# Get Started with TideWarden Browser Extension

> **Your passwords, protected by the tide.** Zero-knowledge encryption powered by the Tide Protocol — no single point of compromise, ever.

---

## Set up TideWarden in 3 easy steps

### Step 1: Install & Pin the Extension

<details>
<summary><strong>Chrome / Edge / Brave</strong></summary>

1. Install TideWarden from the Chrome Web Store
2. Click the **puzzle piece** icon (Extensions) in the toolbar
3. Find **TideWarden** and click the **pin** icon

</details>

<details>
<summary><strong>Firefox</strong></summary>

1. Install TideWarden from Firefox Add-ons
2. Click the **puzzle piece** icon (Extensions) in the toolbar
3. Click the **gear** next to TideWarden and select **Pin to Toolbar**

</details>

Once pinned, the TideWarden icon appears in your toolbar:

| Icon State | Meaning |
|:---:|:---|
| **Grey shield** | Logged out |
| **Blue shield** | Logged in — vault locked |
| **Green shield** | Logged in — vault unlocked |

> **Tip:** Pinning the extension gives you one-click access to autofill, generate passwords, and manage your vault.

---

### Step 2: Create Your Account or Log In

#### New to TideWarden?

1. Click the TideWarden icon in your toolbar
2. Select **Create Account**
3. Enter your **email** and choose a **master password**
4. Your account is secured with the **Tide Protocol** — your master password is never stored or transmitted. Instead, it's split across a decentralized network of ORK nodes so no single party can access it.

#### Already have an account?

1. Click the TideWarden icon
2. Enter your **email** and **master password**
3. If your organization uses **SSO**, select *Enterprise Single Sign-On* and enter your org identifier

> **Using a self-hosted server?** Before logging in, tap the **gear** icon on the login screen and enter your server URL.

---

### Step 3: Start Securing Your Digital Life

Once logged in, TideWarden works seamlessly in your browser:

#### Autofill Passwords
TideWarden detects login forms and offers to autofill your saved credentials. Look for the TideWarden overlay or use the keyboard shortcut:

| Platform | Shortcut |
|:---|:---|
| **Windows / Linux** | `Ctrl + Shift + L` |
| **macOS** | `Cmd + Shift + L` |

#### Save New Logins
When you sign up or log into a site for the first time, TideWarden prompts you to **save** the credentials to your vault.

#### Generate Strong Passwords
Click the TideWarden icon and select **Generator** to create strong, unique passwords on the fly. Configure length, complexity, and passphrase options.

---

## What Makes TideWarden Different?

<table>
<tr>
<td width="50%">

### Zero-Knowledge Architecture
Your vault data is encrypted **before** it leaves your device. TideWarden never has access to your master password or unencrypted data.

</td>
<td width="50%">

### Decentralized Key Protection
Powered by the **Tide Protocol**, your encryption keys are split across independent ORK (Orchestrated Recluder of Keys) nodes. No single node — and no single company — can reconstruct your key.

</td>
</tr>
<tr>
<td>

### Threshold Cryptography
Operations like signing and decryption require a **threshold** of ORK nodes to cooperate. Even if some nodes are compromised, your data stays safe.

</td>
<td>

### Policy-Governed Access
Organization admins define **Forseti policies** — smart contracts that enforce who can grant roles, approve changes, and access resources, all validated cryptographically at the ORK level.

</td>
</tr>
</table>

---

## Quick Actions from the Extension

| Action | How |
|:---|:---|
| **Search vault** | `Ctrl/Cmd + Shift + L` or click the icon and type |
| **Add a login** | Click **+** in the extension popup |
| **Generate a password** | Extension popup > **Generator** tab |
| **Open web vault** | Extension popup > **Settings** > **Open Web Vault** |
| **Lock vault** | Extension popup > **Lock** (or set auto-lock timeout) |
| **Send encrypted text/file** | Extension popup > **Send** tab |

---

## Importing from Another Password Manager

Already using another password manager? Migrate in minutes:

1. **Export** your data from your current manager (CSV or JSON)
2. Open the **TideWarden Web Vault**
3. Go to **Tools** > **Import Data**
4. Select your previous manager from the dropdown
5. Upload your export file

TideWarden supports imports from **LastPass, 1Password, Dashlane, KeePass, Chrome, Firefox**, and [many more](https://bitwarden.com/help/import-data/).

> **Security reminder:** Delete the exported file from your device after importing.

---

## Organization & Team Features

Using TideWarden with your team? Your admin can:

- **Manage collections** — group credentials by team, project, or department
- **Set access policies** — Forseti-powered policies enforce role-based access at the cryptographic layer
- **Onboard members** — invite users and assign roles with change-set approvals
- **Audit activity** — review policy logs and approval history

---

## Need Help?

- **Keyboard shortcuts:** `Ctrl/Cmd + Shift + L` to autofill, `Ctrl/Cmd + Shift + 9` to generate
- **Vault timeout:** Configure auto-lock under **Settings** > **Vault Timeout**
- **Biometric unlock:** Enable fingerprint/face unlock under **Settings** (desktop required)
- **Troubleshooting:** Clear the extension cache via **Settings** > **Clear Clipboard**

---

<p align="center">
  <strong>TideWarden</strong> — Open-source password management, hardened by the Tide Protocol.<br/>
  <em>Your keys. Your rules. No single point of compromise.</em>
</p>
