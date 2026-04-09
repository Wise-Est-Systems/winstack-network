# Winstack

**Deterministic artifact verification for sovereign local-first systems.**

Winstack seals files with cryptographic proofs and re-verifies them deterministically — offline, without a server, without probabilistic trust. A sealed object is either `VERIFIED` or `INVALID`. There is no third state.

---

## What it does

You give Winstack a file. It produces a self-contained proof bundle that records:

- **Who** sealed it (Ed25519 creator identity, verified chain)
- **What** it is (SHA-256 content hash, byte-exact)
- **When** it was sealed (signed time chain, monotonic, no client clock trust)
- **Why** it was permitted (signed policy proof, evaluator identity)
- **Whether** any of those claims are still true right now

Any party with the file and its proof bundle can independently verify every claim without contacting any server.

---

## Architecture

13 crates, strict dependency order, no circular imports:

```
canon-types          domain primitives, zero logic
crypto               Ed25519 + SHA-256, deterministic
identity-core        signed identity chains, module registry
time-core            chained time events, monotonic
policy-core          policy evaluation, signed proofs
object-store         content-addressed, immutable, fsync-safe
graph-index          SQLite lineage DAG, rebuildable
verifier             deterministic re-verification, fail-closed
registry-core        sole write authority, 10-step sealing pipeline
module-import        sealed import assembly
module-ai            AI generation assembly
window-api           read-only inspection API (Axum)
cli                  two binaries: win + winstack
```

**Core law:** only objects born through the sealing pipeline carry native trust. Every other claim is rejected or classified `FOREIGN`.

---

## Sealing pipeline (registry-core)

Every object passes 10 steps before being written to disk:

1. Structural validation (no orphan parents, content hash check)
2. Creator identity — chain validation, active status, eligible kind
3. Module validation — registered, binary hash match, scope check
4. Lineage — cycle detection, parent existence
5. Policy evaluation — deterministic permit/deny
6. Time attestation — signed, chained, monotonic
7. Object assembly — all records signed by creator key
8. Final verification — the full verifier runs before any write
9. Atomic persistence — fsync-safe writes, commit marker last
10. Audit event — written last; its presence is the commit signal

If step 8 fails, nothing is written. If any step fails, the whole proposal is rejected with an exact `RejectCode`.

---

## Verification pipeline (verifier)

Re-verification is deterministic and stateless. Given a complete input bundle it checks:

- Content hash matches artifact bytes
- Creator identity chain is valid and active
- Module registration matches scope
- Time event signature is valid; chain linkage is present
- Policy proof signature is valid; decision is `Permit`
- Lineage is acyclic; all declared parents load and verify
- All cross-record fields are consistent (object / origin record)

The result is `VERIFIED` or `INVALID` with every failing rule listed by exact `FailureCode`.

---

## Binaries

### `winstack` — user-facing proof CLI

```bash
# Seal a file (initialises node on first run)
winstack prove document.pdf
# -> document.pdf.proof.json

# Verify the file against its proof bundle
winstack verify document.pdf document.pdf.proof.json
```

**Proof bundles are self-contained.** Verification requires no network access and no node state.

Exit codes: `0` verified, `1` invalid/tampered, `2` error

### `win` — internal inspection CLI

```bash
win verify  <object-id>
win inspect <object-id>
win export  <object-id> <output.json>
win serve   --addr 0.0.0.0:3000
```

---

## Inspection API (window-api)

HTTP API over the object store. Every request re-runs the full verifier. No cached status is ever served.

```
GET /objects/:id          full inspection response
```

`trust_class` is always `NATIVE` or `FOREIGN`. If a required record is missing, the response is `INVALID` with the exact failure code.

---

## Browser UI (window/index.html)

Single static HTML page. No build step.

```bash
python3 -m http.server 8080 --directory window/
open http://localhost:8080
```

Set the API base URL via `window.WINSTACK_API_BASE` or edit the constant at the top of the script. Accepts `?id=<uuid>` for direct linking.

---

## Build

**Requirements:** Rust stable via [rustup](https://rustup.rs)

```bash
cargo build --release

./target/release/win
./target/release/winstack
```

---

## Test

```bash
cargo test
```

---

## Object classes

| Class | Trust | Description |
|---|---|---|
| `NATIVE` | Native | Born on this node through the sealing pipeline |
| `AI_GENERATED` | Native | AI output sealed through the generation pipeline |
| `SEALED_IMPORT` | **Foreign** | External artifact brought in under a signed declaration |

Sealed imports never become native. Their `trust_class` is always `FOREIGN`.

---

## Structure

```
Cargo.toml
rust-toolchain.toml
README.md
window/
  index.html            browser inspection UI
crates/
  canon-types/          domain types, zero logic
  crypto/               Ed25519, SHA-256
  identity-core/        IdentityStore, ModuleRegistry
  time-core/            ChainedTimeEvent, attest_time
  policy-core/          evaluate_*, issue_policy_proof
  object-store/         ObjectStore, atomic writes
  graph-index/          GraphIndex, SQLite DAG
  verifier/             verify_any_object, FailureCode
  registry-core/        Registry, sealing pipeline, tests
  module-import/        ImportBirthProposal assembly
  module-ai/            AiBirthProposal assembly
  window-api/           Axum inspection API
  cli/
    src/main.rs         win binary
    src/bin/winstack.rs winstack binary
```
