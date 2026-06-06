# WIN — Wise Independent Network

[![CI](https://github.com/Wise-Est-Systems/winstack-network/actions/workflows/ci.yml/badge.svg)](https://github.com/Wise-Est-Systems/winstack-network/actions/workflows/ci.yml)
[![WASM](https://github.com/Wise-Est-Systems/winstack-network/actions/workflows/wasm.yml/badge.svg)](https://github.com/Wise-Est-Systems/winstack-network/actions/workflows/wasm.yml)
[![Audit](https://github.com/Wise-Est-Systems/winstack-network/actions/workflows/audit.yml/badge.svg)](https://github.com/Wise-Est-Systems/winstack-network/actions/workflows/audit.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.82-orange.svg)](rust-toolchain.toml)

**Files that prove themselves. Drop a file. Get the truth.**

WIN gives every file a *win tag* — a small portable record that
travels with it. The win tag says when the file was sealed, the key
that sealed it, and whether the file is unchanged since. Receivers
read it offline, without accounts, without trusting any server.

There is one public file type: `.win`. The proof and the change-map
live inside it. A file without a win tag is *untagged*: neutral, not
dangerous.

WIN (Wise Independent Network) is a Wise.Est Systems product.

---

## What a `.win` proves

A `.win` proves:
- the file inside matches the proof inside
- the file has not changed since it was sealed
- the sealing key signed that proof
- the proof travels with the file

A verified `.win` proves the file is **unchanged since it was sealed by
some key.** It does **not** prove who that key belongs to. Specifically,
a `.win` does **not** prove:
- the real-world person, company, or organization behind the key
- that the signer told the truth
- that the file content is factually correct
- that Wise.Est Systems signed it
- that it was the first copy ever made

That is why WIN separates **file integrity** from **human trust**.
The verifier returns one of three states for the file integrity check
(Verified / Tampered / Invalid). Alongside it, the verifier surfaces a
**receiver-local label** for the signing key — a hint about whether
*you* have seen this key before, not a claim the protocol enforces:

| Label | What it means |
|-------|---------------|
| **Local** | Signed by a key generated on a device. Verification proves the file still matches what that key sealed; it does not prove a real-world identity behind the key. |
| **Unknown** | Valid signature, but the signer is not on any list you maintain locally. |

These labels are decided by the receiver's own machine. The protocol
does **not** cryptographically prove real-world identity, and there is
no notion of an "official" identity enforced by `verify_object` today.
That is the paid roadmap — official witnessing and attestation — not a
claim we make now.

There is no central Wise.Est Systems signing key in the protocol. Any
`.win` is signed by whichever key sealed it — by default, a key
generated on the sealer's own device.

---

## Status

| Surface              | Status                                                  |
|----------------------|---------------------------------------------------------|
| Verifier (Rust)      | Stable. 189 tests, `#![forbid(unsafe_code)]`            |
| Verifier (WASM)      | Stable. ≤ 1 MB compressed budget enforced in CI         |
| `.win` container v1  | Stable. Backwards-compatibility contract in CONTRIBUTING |
| CLI                  | `win` — Linux / macOS / Windows                          |
| Desktop app          | macOS Apple Silicon shipping; Linux / Windows in CI     |
| URL verifier         | `truth.systems/v/<hash>` — share-anywhere static page    |

See [`CHANGELOG.md`](CHANGELOG.md) for what changed in each release.

---

## How it works

1. **Witness seals a file** — `win seal report.pdf` produces
   `report.pdf.win`, a single portable container holding the file plus its
   win tag.
2. **The file travels** — email, Slack, Drive, S3. The win tag travels
   inside the container; nothing strips it.
3. **Receiver verifies it** — drops the `.win` into any verifier
   (browser, desktop, CLI, WASM). The verifier returns one of three
   states.

| State        | Meaning                                                                              |
|--------------|--------------------------------------------------------------------------------------|
| **Verified** | The win tag matches the file. Unchanged since it was sealed.                         |
| **Tampered** | Was sealed once. Has been changed since. The original is gone.                       |
| **Invalid**  | We can't verify this win tag. Wrong tag, unreadable signature, or malformed container. |

Three states. No fourth. See [ADR 0002](docs/adr/0002-three-state-grammar.md).

---

## Try it

**Without installing anything** — open [truth.systems](https://truth.systems/),
drop a `.win`. Verification runs locally in the browser; nothing is
uploaded.

**Plain-English intro** — [proofs.systems](https://proofs.systems/)
explains what a `.win` is, what the three results mean, and what it
does not prove.

**CLI** —

```bash
cargo build --release

./target/release/win seal   report.pdf          # → report.pdf.win
./target/release/win verify report.pdf.win      # Verified / Tampered / Invalid
./target/release/win open   report.pdf.win      # → restores report.pdf
./target/release/win publish report.pdf.win     # → public/v/<hash>.json
```

---

## What the win tag contains

- SHA-256 of the file (not the file)
- Ed25519 signature over the canonical object payload
- Witness public key
- Creation date — local clock, or RFC 3161 anchored
- Lineage metadata (parents, generation, optional delegation chain)
- Protocol version (`V1`)

It does **not** contain the file contents, file paths, account info,
machine identifiers, or anything that identifies the witness's location.
The win tag is safe to share publicly.

---

## How WIN spreads

The product is not the app. **The product is the win tag attached to
the file.**

- A witness seals a file. The file and win tag travel together.
- A receiver verifies using any WIN verifier. No coordination.
- The app and CLI are creator tools and verifiers — not a platform.

WIN is **designed** so a `.win` verifies anywhere, offline, with no
account. (Cross-machine, cross-OS verification is the design intent; a
frozen golden-artifact cross-OS test is on the roadmap, not yet a proven
guarantee.)

Three verification paths, same result:

1. **URL** — `truth.systems/v/<hash>` resolves to the static win tag.
2. **Browser** — drop a `.win` into the verifier; runs in-browser.
3. **Desktop app** — full offline verification with name-tag creation.
4. **CLI / library** — `win verify`, or call the `verifier-wasm`
   exports from any browser-adjacent surface.

---

## Comparison

|                              | WIN            | Traditional hash | Blockchain notary | Cloud signing |
|------------------------------|----------------|------------------|-------------------|---------------|
| Works offline                | Yes            | Yes              | No                | No            |
| Requires server trust        | No             | No               | Yes               | Yes           |
| Any file type                | Yes            | Yes              | Varies            | Varies        |
| Win tag travels with file    | Yes            | Manual           | No                | No            |
| Version history (lineage)    | Yes            | No               | Varies            | Varies        |
| Key rotation (delegation)    | Yes            | No               | Varies            | Varies        |
| Accounts required            | No             | No               | Yes               | Yes           |
| External timestamps          | Optional       | No               | Built-in          | Built-in      |

WIN is not a blockchain, a certificate authority, or a cloud
service. It is a local proof system. Win tags are self-contained;
verification contacts nothing.

---

## What WIN proves

- A specific file existed at a specific time (local device clock, or
  anchored via RFC 3161).
- It has not been modified since it was sealed.
- It was sealed by a specific key (the key — not a verified real-world
  identity).
- It may be part of a verifiable lineage.

## What WIN does NOT prove

- That the file content is true or accurate.
- The real-world identity of the witness (only key continuity).
- That this is the first copy in the world (only first in this lineage).
- That a local timestamp is globally authoritative — only anchored
  timestamps are independently verifiable.

---

## Architecture

12 Rust crates plus a Tauri desktop app and zero-dep browser verifier.
The `verifier-wasm` crate compiles to a single `.wasm` artifact that
powers every browser-adjacent receiver surface (URL verifier, planned
extensions, planned chat-app integrations).

```
canon-types       Domain primitives. The three-state grammar lives here.
crypto            SHA-256 + Ed25519. Constant-time guarantees inherited.
identity-core     Identities, key delegation, module registry.
time-core         Time chain + RFC 3161 TSA validation.
policy-core       Permit/Deny decisions and proofs.
object-store      Content-addressed object storage (SQLite).
graph-index       Lineage DAG.
verifier          Pure-function verifier. No I/O. 12-step pipeline.
verifier-wasm     wasm-bindgen export. Same logic, JS-callable.
win-format        The .win container. Zero workspace dependencies.
registry-core     10-step sealing pipeline. Fail-closed on persistence.
window-api        Axum HTTP API used by the desktop app.
cli               win binary.
desktop           Tauri 2 frontend.
```

Read [`docs/architecture.md`](docs/architecture.md) for the long form,
and [`docs/adr/`](docs/adr/) for the rationales behind the
non-obvious decisions.

The cultural and product constitution lives in
[`spec/grammar.md`](spec/grammar.md). Read it before proposing
features.

---

## Build from source

```bash
# Prereqs
rustup toolchain install stable
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.117

# CLI
cargo build --workspace --release

# WASM verifier
./scripts/build-wasm.sh           # → public/wasm/

# Desktop app
cargo install tauri-cli --version "^2"
cd desktop && cargo tauri build
```

The four checks every PR must pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/build-wasm.sh           # if WASM-touching changes
```

CI runs these on Linux, macOS, and Windows.

---

## Project documents

| Document                                                | Purpose                                          |
|---------------------------------------------------------|--------------------------------------------------|
| [`spec/grammar.md`](spec/grammar.md)                     | Cultural and product constitution                |
| [`spec/PROOF-SPEC.md`](spec/PROOF-SPEC.md)               | Wire format and verification rules               |
| [`docs/architecture.md`](docs/architecture.md)           | Crate layout, pipelines, surfaces                |
| [`docs/adr/`](docs/adr/)                                 | Architecture Decision Records                    |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                     | How to contribute                                |
| [`SECURITY.md`](SECURITY.md)                             | Vulnerability disclosure                         |
| [`CHANGELOG.md`](CHANGELOG.md)                           | What changed in each release                     |
| [`ROADMAP.md`](ROADMAP.md)                               | Where the project is heading                     |

---

## Downloads

[Latest release](https://github.com/Wise-Est-Systems/winstack-network/releases/latest)

- **WIN.dmg** — macOS Apple Silicon
- **WIN.zip** — macOS Apple Silicon (alternative archive)

> macOS may show a developer warning on first launch (the app is not yet
> code-signed). Right-click → Open → Open to bypass.

Linux and Windows release artifacts are produced by CI; promotion to
shipped releases is tracked in [`ROADMAP.md`](ROADMAP.md).

---

## License

[MIT](LICENSE) — Wise.Est Systems
