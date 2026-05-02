# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Cultural constitution: `spec/grammar.md` codifying the four-state grammar,
  six-death taxonomy, ten first principles, and explicit non-goals.
- Architecture Decision Records under `docs/adr/` (ADR 0001–0005).
- High-level architecture document at `docs/architecture.md`.
- WASM verifier crate `verifier-wasm`, building to a single
  `verifier_wasm_bg.wasm` artifact callable from any browser-adjacent surface
  (ADR 0005).
- URL verifier — `truth.systems/v/<hash>` static page that fetches a
  hash-indexed proof bundle and renders the four-state outcome.
- `win publish` CLI subcommand that extracts a name tag and writes it
  to a hash-indexed directory for static deployment.
- CI pipeline: format + clippy + test on Linux/macOS/Windows, MSRV check at
  Rust 1.82, doc build, WASM build with size budget, weekly cargo-deny.
- Workspace lints (curated; see `Cargo.toml`).
- Project hygiene: SECURITY.md, CODEOWNERS, PR/issue templates, dependabot,
  editorconfig, gitattributes.

### Changed
- `VerificationStatus` expanded from `{ Verified, Invalid }` to the
  four-state grammar `{ Alive, Wounded, Unrecognized, Dying }`. State is
  derived from failures via `VerificationStatus::from_failures()`. **Breaking**
  for downstream consumers of the public type.
- All user-facing strings across CLI, HTTP API, and browser verifier
  rewritten to the grammar voice. Engineering vocabulary remains in
  diagnostic chips and `FailureCode` values.
- Sealing pipeline check `result.status != Verified` replaced with
  `!result.status.is_alive()` to reflect the four-state model.

### Changed (continued)
- `win seal report.pdf` now produces `report.win` instead of
  `report.pdf.win`. Every named file is a `.win` — no extension chain.
  The container preserves the original filename internally, so
  `win open report.win` still restores `report.pdf`. If
  `<basename>.win` already exists in the parent directory, the new
  artifact is suffixed with the first 8 hex chars of the payload hash
  (e.g. `report-9fb93974.win`) to avoid silent overwrites.

### Removed
- `crates/module-import` and `crates/module-ai` — empty stubs with zero
  callers. The AI-provenance pipeline will be reintroduced as a working
  implementation when the wedge work begins; the import pipeline is
  unscheduled.
- `crates/cli/src/main.rs` — the `win` internal-inspection binary. Power
  users use `wise` (user-facing) and `winopen` (file association).
- `window/check.html` — superseded by `public/v.html` calling the WASM
  verifier; both surfaces previously duplicated the verification logic.
- `window/index.html` — the engineering-inspection view; out of scope for
  user surfaces and not referenced by any shipping flow.
- `docs/index.html` — orphan deploy artifact; not referenced.

### Fixed
- `WinError::is_container_damage` simplified to use `matches!` — fixes a
  clippy warning under the strict workspace lint set.
- Tauri `PageLoadEvent::Finished` pattern updated to its unit-variant form.

## [0.2.0] — 2026-04-19

### Added
- `.win` container format: file + proof in one portable artifact
  (`crates/win-format`).
- Tauri 2 desktop application with `.win` file association.
- 14-crate workspace structure with strict dependency ordering.
- Proof chaining and key delegation across full lineage.
- RFC 3161 external timestamp anchoring.
- Browser verifier running entirely in-browser via SubtleCrypto.
- Public macOS release: `Wise.dmg`, `Wise.zip` (Apple Silicon).

## [0.1.0] — 2026-04-04

### Added
- Initial CLI with `seal`, `verify`, `prove`, `inspect`, `open`.
- Sidecar proof format (`*.proof.json`).
- Core verification: SHA-256 hash check, Ed25519 signatures, identity and
  module validation, policy proofs.

[Unreleased]: https://github.com/Wise-Est-Systems/wise/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Wise-Est-Systems/wise/releases/tag/v0.2.0
[0.1.0]: https://github.com/Wise-Est-Systems/wise/releases/tag/v0.1.0
