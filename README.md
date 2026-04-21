# Winstack

**Files that prove themselves.**

Create a cryptographic proof for any file. Share the file and its proof together. Anyone can verify the file has not changed — offline, without accounts, without trusting a server.

---

## How it works

1. **Create a proof** — drop a file into Winstack. A `.proof.json` file is saved next to it.
2. **Share both** — send the file and its proof together.
3. **Verify anywhere** — drop the file and proof into any Winstack verifier. Get one of three answers:

| Result | Meaning |
|---|---|
| **Verified** | This file has not changed since it was sealed. |
| **Tampered** | This file does not match the proof. It was modified or the wrong file was selected. |
| **Invalid proof** | The proof is broken or cannot be used to verify this file. |

No fourth state. No ambiguity.

---

## Try it now

**Verify without installing anything:**
Open [winstack.dev](https://wise-est-systems.github.io/winstack-network/) in your browser. Drop a `.win` file. Everything runs locally — nothing is uploaded.

**Desktop app (macOS):**
[Download the latest release](https://github.com/Wise-Est-Systems/winstack-network/releases/latest) — open the app, drop a file to seal it, drop a `.win` to verify it.

**CLI:**
```bash
cargo build --release
./target/release/winstack seal document.pdf        # creates document.pdf.win
./target/release/winstack verify document.pdf.win  # VERIFIED / TAMPERED / INVALID
./target/release/winstack open document.pdf.win    # extracts original file
```

---

## What the proof contains

- SHA-256 hash of the file (not the file itself)
- Ed25519 digital signatures
- Timestamps (local or externally anchored via RFC 3161)
- Creator public key
- Chain/history metadata (if part of a version chain)
- Protocol version (`V1`)

## What the proof does NOT contain

- File contents
- File paths
- Usernames or account information
- Machine identifiers
- Any data that identifies your computer or location

The proof is safe to share publicly.

---

## How Winstack spreads

The product is not the app. The product is the proof attached to the file.

- You create a proof for a file
- The file and proof travel together
- Anyone verifies using any Winstack verifier
- The app is a creator tool and a verifier — not a platform

Three verification paths, same result:
1. **Browser** — `check.html`, zero install, runs in-browser
2. **Desktop app** — full offline verification with proof creation
3. **CLI** — `winstack verify file proof.json`

---

## Comparison

| | Winstack | Traditional hash | Blockchain notary | Cloud signing |
|---|---|---|---|---|
| Works offline | Yes | Yes | No | No |
| Requires server trust | No | No | Yes | Yes |
| Any file type | Yes | Yes | Varies | Varies |
| Proof travels with file | Yes | Manual | No | No |
| Version history | Yes (chains) | No | Varies | Varies |
| Key rotation | Yes (delegation) | No | Varies | Varies |
| Accounts required | No | No | Yes | Yes |
| External timestamps | Optional | No | Built-in | Built-in |

Winstack is not a blockchain, a certificate authority, or a cloud service. It is a local proof system. Proofs are self-contained. Verification contacts nothing.

---

## What Winstack proves

- A specific file existed at a specific time
- It has not been modified since
- It was signed by a specific key
- It may be part of a verifiable version chain

## What Winstack does NOT prove

- That the file content is true or accurate
- The real-world identity of the signer (only key continuity)
- That this is the first copy in the world (only first in this lineage)
- That the timestamp is absolute (local time is from the device clock; external time is from a specific TSA)

---

## Architecture

13 crates. 77 tests. Fail-closed everywhere.

```
canon-types       domain primitives
crypto            Ed25519 + SHA-256
identity-core     identity + module registry
time-core         time chain + RFC 3161 TSA
policy-core       policy evaluation
object-store      immutable store
graph-index       SQLite lineage DAG
verifier          deterministic verifier + chain walker
registry-core     10-step sealing pipeline
module-import     import assembly
module-ai         AI generation assembly
window-api        Axum API
cli               win + winstack binaries
```

Desktop app built with Tauri 2. Browser verifier uses SubtleCrypto (SHA-256 + Ed25519).

---

## Downloads

[Latest release](https://github.com/Wise-Est-Systems/winstack-network/releases/latest)

- **Winstack.dmg** — macOS Apple Silicon
- **Winstack.zip** — macOS Apple Silicon (alternative)

> macOS may show a developer warning on first launch (the app is not yet code-signed). Right-click → Open → Open to bypass.

---

## Build from source

```bash
# CLI tools
cargo build --release
./target/release/winstack prove file.pdf
./target/release/winstack verify file.pdf file.pdf.proof.json

# Desktop app
cargo install tauri-cli --version "^2"
cd desktop && cargo tauri build
```

---

## License

[MIT](LICENSE) — Wise.Est Systems
