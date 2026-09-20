# W.I.N. — Final Product Report

Status of the W.I.N. governed-transition product built inside
`WinStack_Network_v1`. Every claim here is backed by a path, a command, or a test
result. Where something is not done, it says so.

## What was built

A local-first system that turns a proposed digital change into an accountable,
portable, independently verifiable record — delivered as a working desktop app, a
CLI, an SDK, a conformance suite, and a portable `.win` artifact format.

- **Engine** — `crates/win-transition`: the governed lifecycle
  (propose → authorize → verify → execute | refuse → record → seal → verify),
  scoped authority, bounded filesystem executor with signed receipts, first-class
  sealed refusals, policy gate, `.win` seal/independent-verify, honest matrix.
- **Desktop** — `wise-desktop` (Tauri "Wise"): the full workflow via
  `window/transition.html` + `window-api` `/transition/*` routes.
- **CLI** — `win summarize` / `win verify` (auto-detects transition artifacts).
- **Conformance** — `crates/win-conformance`: 10 frozen `.win` vectors + manifest
  + runner.
- **SDK example** — `crates/win-transition/examples/sdk.rs` incl. a custom executor.

## How to launch

- **Installed app:** open `target/release/bundle/dmg/Wise_0.2.0_aarch64.dmg`, drag
  **Wise** to Applications, launch. (Unsigned — first launch: right-click → Open.)
- **App bundle directly:** `open target/release/bundle/macos/Wise.app`
- **From source (release):** `cargo tauri build` then launch the bundle.
- **CLI:** `cargo run -p cli --bin win -- summarize <file>`

## What the user can do

Import a document → review the proposal, evidence, and required authority →
authorize local write → get the created summary + resulting identity → export a
`.win` → independently verify it → attempt an external publish and see it
**refused with no side effect** → export the refusal → detect tampering. For
non-text files the proposal is an honest object description, not gibberish.

## What a developer can build

Use `win-transition` to propose, authorize, verify, execute (filesystem or a
custom `Executor`), record, seal, and independently verify a transition without
the desktop. Implement new executors/proposers from documented interfaces. Prove
compatibility against the frozen conformance vectors. See
[docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md).

## Guarantees (what it proves)

Exact content identity, content integrity, key-custody signatures, causal
lineage, scoped authorization, execution receipts, recorded refusals, internal
consistency, tamper evidence — verifiable offline from an artifact's bytes alone.

## Limits (what it does NOT prove)

Factual correctness of content, or the quality of a proposer's summary. Identity
is an honest ladder: the CLI now supports a persistent authorizer key, self-asserted
names (`--as`), and `TRUSTED` via the recipient's trust list (`win trust add`) —
but `TRUSTED` means a key the recipient chose to trust (web of trust), not global
truth, and the desktop UI + external anchoring are not yet built. The app is
unsigned. Full detail: [docs/KNOWN_LIMITS.md](docs/KNOWN_LIMITS.md),
[docs/SECURITY_BOUNDARIES.md](docs/SECURITY_BOUNDARIES.md),
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Retained vs deprecated

- **Retained:** all existing WinStack functionality (`.win` seal/verify, desktop,
  CLI, WASM verifier) — behavior unchanged; all prior tests green.
- **Reference (not forked):** `wuso` (44/44 pure-proof core).
- **Untouched:** `wiseorder-protocol`, `wop`, `wiseorder`, `wisest`.
- **Deprecated / deleted:** none. See [docs/MIGRATION_MATRIX.md](docs/MIGRATION_MATRIX.md).

## Test results (run 2026-07-30)

| Suite | Command | Result |
|---|---|---|
| Full workspace | `cargo test --workspace` | **350 pass, 0 fail** |
| Engine | `cargo test -p win-transition` | 20 pass |
| Desktop API | `cargo test -p window-api` | 12 pass |
| CLI (incl. e2e) | `cargo test -p cli` | 95 pass |
| Conformance | `cargo run -p win-conformance --bin win-conformance` | 10 pass, 0 fail |
| Lint | `cargo clippy --all-targets -- -D warnings` | clean |
| Reference core | `cargo run -p wuso-conformance` (repo `wuso`) | 44/44 |

## Known security limitations

Design-level threat model only — **no external security audit has been
performed.** Out of scope: key ownership/impersonation, a malicious authorizer, a
compromised host, content truthfulness. See THREAT_MODEL and SECURITY_BOUNDARIES.

## Remaining work (real, not done)

- Desktop identity/trust UI (Phase 2) + external identity anchoring (SSO/OIDC/DNS/hardware, Rung 4).
- Code-signing + notarization for redistribution.
- Additional executors beyond filesystem in the product; a real model proposer.
- Deterministic re-seal conformance vectors (current vectors freeze verification).

## Exact paths

- App bundle: `target/release/bundle/macos/Wise.app`
- Installer: `target/release/bundle/dmg/Wise_0.2.0_aarch64.dmg`
- Engine: `crates/win-transition/` · SDK example: `crates/win-transition/examples/sdk.rs`
- Conformance: `crates/win-conformance/vectors/`
- Demo: `demo/` (+ `DEMO_SCRIPT.md`)
- Spec: `specs/WIN_UNIFIED_TRANSITION_PROTOCOL.md`
- Docs: `docs/PRODUCT.md`, `USER_GUIDE.md`, `DEVELOPER_GUIDE.md`, `OBJECT_RECORD.md`,
  `VERIFICATION_RESULTS.md`, `THREAT_MODEL.md`, `SECURITY_BOUNDARIES.md`,
  `MIGRATION_MATRIX.md`, `KNOWN_LIMITS.md`
