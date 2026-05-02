# Architecture

A short tour for new contributors. Pair it with [`spec/grammar.md`](../spec/grammar.md)
(what the system *means*) and [`spec/PROOF-SPEC.md`](../spec/PROOF-SPEC.md) (the wire format).

## At a glance

```
┌──────────────────────────────────────────────────────────────────┐
│                     Witness                Receiver              │
│                       │                       │                  │
│                  winstack win           winstack verify         │
│                       │                       │                  │
│                       ▼                       ▼                  │
│                  ┌────────┐              ┌────────┐              │
│                  │ .win   │ ─ travels ─▶ │ .win   │              │
│                  └────────┘              └────────┘              │
│                       │                       │                  │
│                  winstack publish        Drop into verifier      │
│                       │                       │                  │
│                       ▼                       ▼                  │
│            public/v/<hash>.json    Browser / Desktop / WASM      │
│                       │                       │                  │
│                       └─── winstack.dev/v/<hash> ◀──── share URL │
└──────────────────────────────────────────────────────────────────┘
```

The witness produces a win tag. The receiver verifies it. The verifier
returns one of three states (`spec/grammar.md` § 3). Nothing about
verification routes through any service we operate.

## Crate layout

Strict dependency order. No cycles. Lower layers cannot depend on higher
layers; this is enforced by review and by the fact that the workspace
graph would not build otherwise.

```
canon-types        Domain primitives. The state and failure types live here.
                   Pure data; no I/O.
                       │
crypto              ─→ SHA-256 + Ed25519 wrappers. Constant-time guarantees
                       inherited from ed25519-dalek and sha2.
                       │
identity-core      ─→ Identity records, key delegation, module registry.
                       │
time-core          ─→ ChainedTimeEvent + RFC 3161 TSA token validation
                       (rsa, p256, p384, ecdsa, x509-cert, cms).
                       │
policy-core        ─→ Policy decisions and proofs. Permit/Deny.
                       │
object-store       ─→ Content-addressed object storage backed by SQLite.
graph-index        ─→ Lineage DAG over object IDs.
                       │
verifier           ─→ verify_object / verify_from_proof_bundle / verify_chain.
                       Pure function from input → VerificationResult. No I/O,
                       no network, no clock side effects.
                       │
verifier-wasm      ─→ wasm-bindgen exports. Same logic, JS-callable.
                       │
win-format         ─→ The .win container format. Zero non-std deps.
                       │
registry-core      ─→ The 10-step sealing pipeline. Wraps verifier on the
                       write path to fail-closed before persistence.
                       │
window-api         ─→ Axum HTTP API consumed by the desktop app.
                       │
cli                ─→ winstack / winopen binaries.
                       │
desktop            ─→ Tauri 2 desktop frontend.
```

## Surfaces

| Surface             | Crate / path                       | Purpose                                                    |
|---------------------|------------------------------------|------------------------------------------------------------|
| `winstack` CLI      | `crates/cli/src/bin/winstack.rs`   | seal / verify / inspect / open / publish / trust           |
| `winopen`           | `crates/cli/src/bin/winopen.rs`    | Double-click handler for `.win` files                      |
| Desktop app         | `desktop/`                         | Tauri 2 macOS app (Windows/Linux planned — see ROADMAP)    |
| Desktop verifier UI | `window/verify.html`               | The desktop app's window — talks to the embedded HTTP API  |
| URL verifier        | `public/index.html`                | Share-anywhere — `winstack.dev/v/<hash>` — uses WASM       |
| WASM verifier       | `crates/verifier-wasm`             | Canonical receiver-side library (see ADR 0005)             |
| HTTP API            | `crates/window-api`                | `/check`, `/verify`, `/seal`, `/save-and-open`             |

## The sealing pipeline

`registry-core` runs ten steps in order, fail-closed at every step:

1. Resolve creator identity.
2. Resolve module registration.
3. Hash payload (SHA-256).
4. Construct origin record.
5. Construct (or fetch + verify) RFC 3161 timestamp.
6. Construct policy proof.
7. Sign object payload.
8. Run `verifier::verify_object` on the freshly-built object.
9. Persist to `object-store` and `graph-index`.
10. Emit `SealedObject`.

Step 8 is the crucial gate: we never persist an object that does not
verify against itself. This catches bugs during development and prevents
ever shipping a win tag that recipients would refuse.

## The verification pipeline

`verifier::verify_object` is a pure function. The 12-step body:

```
0  Protocol version gate
1  Payload hash (file ↔ recorded hash)
1b Artifact size
2  Object signature (Ed25519)
3  Creator identity (active, matches origin)
4  Module validation (kind, scope, binary hash)
5  Origin record consistency
6  AI-generation record (if present)
7  Import declaration (if present)
8  Time event signature + chain linkage
9  Policy proof (decision = Permit, signature, version, context)
10 Lineage parent links + cycle detection
11 RFC 3161 token validation (if anchored, with optional trust store)
12 Proof chain linkage (if successor)
```

Failures accumulate into a `Vec<Failure>`. The final state is derived via
`VerificationStatus::from_failures(&failures)`:

- Empty → `Verified`
- Contains `PayloadHashMismatch` → `Tampered` (this beats other failures)
- Otherwise → `Invalid`

Container-parse failures (malformed `.win` bytes, unreadable proof JSON)
are surfaced by callers as `Invalid` with a `ContainerMalformed` failure
code.

## The grammar contract

Three states. No fourth. Engineering vocabulary (`HASH`, `SIGNATURE`,
`ATTESTATION`, etc.) is forbidden in user surfaces. The constitution
lives in [`spec/grammar.md`](../spec/grammar.md) — locked, with a
finality clause. A change that contradicts the grammar requires an ADR
amending the spec — not a quick PR.

See [ADR 0002](adr/0002-three-state-grammar.md) for the rationale.

## Test surfaces

- Unit tests in each crate (`src/` or `tests/`).
- Integration tests in `crates/registry-core/tests/integration.rs` exercise
  the full sealing → verification round trip plus all known adversarial
  inputs (signature tampering, time downgrade, policy forgery, lineage
  cycles, chain-link fabrication).
- Property tests landing under follow-up issues for fuzzing the `.win`
  parser and the proof-bundle deserializer.
- WASM build verified in CI but exercised manually in-browser; a
  Playwright suite is on the roadmap.

## Cross-platform stance

| Platform         | Status                                                |
|------------------|-------------------------------------------------------|
| macOS (arm64)    | Released — `Winstack.dmg` builds shipping             |
| macOS (x86_64)   | Builds pass CI; release artifacts not yet shipped     |
| Linux (x86_64)   | Builds pass CI; release artifacts not yet shipped     |
| Windows (x86_64) | Builds pass CI; release artifacts not yet shipped     |
| WASM             | First-class — see ADR 0005                            |

Platform-specific code is gated with `#[cfg(target_os = ...)]`. The
verifier and library crates are `#![forbid(unsafe_code)]`.

## What this document deliberately does not cover

- Specific function signatures and types — read the source.
- The `.win` wire format — see [`spec/PROOF-SPEC.md`](../spec/PROOF-SPEC.md).
- The cultural and product constitution — see [`spec/grammar.md`](../spec/grammar.md).
- Decision rationales — see [`docs/adr/`](adr/).
- Adoption strategy — internal; lives in private planning docs.
