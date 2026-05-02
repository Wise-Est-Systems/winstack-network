# Roadmap

## Shipping today

- [x] Four-state grammar verifier
- [x] `.win` container format
- [x] Proof chaining + key delegation
- [x] RFC 3161 anchored timestamps
- [x] Full chain-walk verification
- [x] Browser verifier (`public/v.html`, WASM-backed)
- [x] WASM verifier crate (`verifier-wasm`)
- [x] URL verifier (`winstack.dev/v/<hash>`)
- [x] Desktop app (macOS Apple Silicon)
- [x] Cross-platform CI (Linux + macOS + Windows)
- [x] Workspace lints, cargo-deny, weekly supply-chain audit

## Phase 0 → Phase 1 (next)

- [ ] Wire WASM into `public/v.html` (collapse the duplicate JS verifier)
- [ ] Demo video — 60-second seal → publish → recognize round trip
- [ ] Anchor-user outreach (Cursor / Substack / Notion / journalism CMS)
- [ ] Windows release artifacts (.msi)
- [ ] Linux release artifacts (.AppImage / .deb)
- [ ] macOS code signing + notarization

## Phase 2 — AI-lab pitch

- [ ] Reintroduce `module-ai` as a working AI-output sealing pipeline
- [ ] Demo: every model output sealed by the lab's key
- [ ] First major AI lab signed-on (Anthropic preferred per ADR 0004)

## Phase 3 — Receiver-side proliferation

- [ ] Chrome / Firefox / Safari extension
- [ ] Slack unfurl bot
- [ ] Gmail add-on
- [ ] Discord verifier bot
- [ ] CMS embed widget
- [ ] Lineage / family-tree view UI
- [ ] Witness notices system (orphaned / disowned / compromised)

## Later

- [ ] Independent security audit
- [ ] Resurrection ritual — re-name a Dying file
- [ ] Algorithm migration path (post-quantum)
- [ ] Witness directory federation

## Not planned

- Accounts or user registration
- Cloud storage or server-side verification
- Blockchain integration
- Subscription or payment model
- Per-language SDKs (the WASM verifier is the canonical receiver — see ADR 0005)
