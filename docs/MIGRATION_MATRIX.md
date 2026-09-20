# W.I.N. — Migration Matrix

What happened to each existing repository/component when the unified W.I.N.
product was built. Governing decision: **wrap, don't touch** — build on top of
proven work; do not edit frozen specs, vectors, schemas, or fingerprints; keep
existing `.win` artifacts verifiable. Nothing was deleted.

## Repositories (forensic inventory, 2026-07-29/30)

| Repo | What it is | Verified state | Disposition |
|---|---|---|---|
| `WinStack_Network_v1` | Production `.win` implementation: format, verifier, desktop shell, CLI, policy/identity seeds (Rust). | Compiled clean; **323 tests** green at start. | **Chosen as the spine.** Product built *inside* it. |
| `wuso` (WUSO-1) | Pure portable-proof core, offline verify (Rust). | `wuso-conformance` **44/44** pass. | **Reference core.** Not forked into the desktop; left intact. |
| `wiseorder-protocol` | Governance kernel canon: Python + Go + Rust verifiers, canonicalization, vectors, schemas. | Present; frozen zones. | **Untouched.** Governed-execution semantics reimplemented natively in Rust (`win-transition`) rather than depended on, to keep the app single-binary/offline. |
| `wop` (WISEATA) | Research implementation (Python). | Present. | **Untouched.** |
| `wiseorder` | Services/agents (Python). | Present. | **Untouched.** |
| `wisest` | Witnessed-substrate language / canon. | Present. | **Untouched.** |

## What was added inside the spine (`WinStack_Network_v1`)

| Path | Change | Kind |
|---|---|---|
| `crates/win-transition/` | New: the governed-transition engine + `.win` seal/verify + reference proposer + SDK example. | Added |
| `crates/win-conformance/` | New: 10 frozen vectors + manifest + runner + test. | Added |
| `crates/window-api/src/transition.rs` + 4 routes | Desktop backend: `/transition/{propose,summarize,publish,verify}`. | Added |
| `window/transition.html` | Desktop frontend workflow page; link added from `verify.html`. | Added / minimal edit |
| `crates/cli/src/bin/win.rs` | New `summarize` command; `verify` auto-detects transition artifacts. Existing behavior unchanged. | Extended |
| `demo/` | Reproducible accepted/refused/tampered artifacts + `DEMO_SCRIPT.md`. | Added |
| `docs/`, `specs/`, `FINAL_PRODUCT_REPORT.md` | This documentation set. | Added |

## What was NOT touched

- No edits to `spec/`, existing `README.md`, `SECURITY.md`, or any frozen
  fingerprint/vector/schema.
- No existing crate's behavior changed except purely additive extensions; all
  prior tests remained green (workspace grew from 323 → 350 passing).

## One behavior correction (additive, tested)

- `verify_transition` no longer requires a stored policy proof to be `Permit` on a
  **refused** transition (a policy-deny refusal is a valid record). This is
  strictly more correct and covered by a test + the `refused-policy-deny` vector.
