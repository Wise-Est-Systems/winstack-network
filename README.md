# Winstack

**Deterministic artifact verification for sovereign local-first systems.**

Winstack seals files with cryptographic proofs and re-verifies them deterministically — offline, without a server, without probabilistic trust.

A sealed object is one of exactly three states:

- `VERIFIED` — file matches proof and proof verifies
- `TAMPERED` — file does not match proof
- `INVALID` — proof is broken or unusable

---

## What it does

You give Winstack a file. It produces a self-contained proof bundle that records:

- **Who** sealed it (Ed25519 creator identity)
- **What** it is (SHA-256 content hash, byte-exact)
- **When** it was sealed (signed time chain + optional RFC 3161 external timestamp)
- **Why** it was permitted (signed policy proof)
- **Whether** any of those claims are still true right now

Any party with the file and its proof bundle can independently verify every claim without contacting any server.

---

## Quick start

```bash
# Build
cargo build --release

# Seal a file
./target/release/winstack prove document.pdf

# Verify it
./target/release/winstack verify document.pdf document.pdf.proof.json

# Seal with external timestamp (optional)
./target/release/winstack prove document.pdf --tsa-url https://freetsa.org/tsr

# Verify with pinned TSA trust (optional)
./target/release/winstack verify document.pdf document.pdf.proof.json \
  --tsa-root <sha256-fingerprint-of-trusted-root-cert>
```

**Proof bundles are self-contained.** Verification requires no network access and no node state.

Exit codes: `0` verified, `1` invalid/tampered, `2` error

---

## Browser verification UI

```bash
# Start the API
./target/release/win serve

# Serve the UI
python3 -m http.server 8080 --directory window/

# Open
open http://localhost:8080/verify.html
```

Pick a file, pick its `.proof.json`, click VERIFY. No account, no login, no setup.

---

## Architecture

13 crates, strict dependency order, no circular imports:

```
canon-types          domain primitives, zero logic
crypto               Ed25519 + SHA-256, deterministic
identity-core        signed identity chains, module registry
time-core            chained time events, RFC 3161 TSA client
policy-core          policy evaluation, signed proofs
object-store         content-addressed, immutable, fsync-safe
graph-index          SQLite lineage DAG, rebuildable
verifier             deterministic re-verification, fail-closed
registry-core        sole write authority, 10-step sealing pipeline
module-import        sealed import assembly
module-ai            AI generation assembly
window-api           read-only inspection + verification API (Axum)
cli                  two binaries: win + winstack
```

---

## Verification pipeline

Re-verification is deterministic and stateless. Given a file and its proof bundle:

0. Protocol version gate (reject unknown versions)
1. Content hash matches artifact bytes
2. Object signature valid against creator key
3. Creator identity active, not session for native objects
4. Module kind matches object class
5. Time event signature valid; chain linkage present
6. If external time: RFC 3161 CMS signature verified, cert chain validated, trust store checked
7. Policy proof signature valid; decision is Permit; version matches current
8. Origin record consistent with object
9. AI generation / import declaration present where required
10. Lineage: parents exist, are older, no cycles

Result is `VERIFIED` or `INVALID` with every failing rule listed by exact `FailureCode`.

---

## Test

```bash
cargo test     # 64 tests
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

## Node state

`winstack prove` creates `.winstack/` containing identity keys and the object store. **Do not commit this directory.** It is gitignored by default.

---

## Protocol

All records carry `"protocol": "V1"`. Signing payloads use canonical JSON (serde_json). Ed25519 signatures. SHA-256 content hashes. See `spec/PROOF-SPEC.md` for the full specification.

---

## Structure

```
Cargo.toml
rust-toolchain.toml
README.md
.gitignore
spec/
  PROOF-SPEC.md           proof format specification
window/
  verify.html             browser verification UI
  index.html              object inspector UI
crates/
  canon-types/            domain types
  crypto/                 Ed25519, SHA-256
  identity-core/          identity + module registry
  time-core/              time chain + RFC 3161 TSA
  policy-core/            policy evaluation
  object-store/           immutable object store
  graph-index/            SQLite lineage DAG
  verifier/               deterministic verifier
  registry-core/          sealing pipeline + tests
  module-import/          import assembly
  module-ai/              AI generation assembly
  window-api/             Axum API + verify endpoint
  cli/                    win + winstack binaries
```
