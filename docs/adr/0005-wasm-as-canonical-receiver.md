# 0005 — WASM as the canonical receiver

- **Status:** Accepted
- **Date:** 2026-04-26
- **Crate:** [`crates/verifier-wasm/`](../../crates/verifier-wasm/)

## Context

Receiver-side surfaces will eventually include: the URL verifier page, a
Chrome extension, a Firefox extension, a Safari extension, a Slack app, a
Gmail add-on, a Discord bot, a Notion / Substack embed, native verifiers
in iMessage / WhatsApp link previews if the platforms cooperate, and
language-specific SDKs (Python / Go / Ruby / Java / Swift).

The naive expansion path is N implementations of the verifier in N
ecosystems. That path produces:

- N divergence vectors. The four-state grammar drifts to "verified vs not"
  in the first integration that values brevity over correctness.
- N timing-attack surfaces, N constant-time-comparison reviews, N
  cryptographic-library version bumps.
- N CVE response lanes when SHA-256 / Ed25519 / RFC 3161 needs migration.

## Decision

We compile the existing Rust `verifier` crate to WebAssembly via
`crates/verifier-wasm` and treat the produced `.wasm` artifact as the
canonical receiver. Every browser-adjacent surface (the eight listed
above except language SDKs) loads the same `.wasm` and calls the same
`recognize_win()` / `recognize_bundle()` functions.

For language SDKs (Python, Go, Ruby, Java, Swift): the WASM is callable
from each via the language's WASM runtime
(`wasmtime-py`, `wasmtime-go`, `wasm-rs` for Java, etc.). Per the spec's
non-goal "no multi-language SDKs," we do not maintain hand-written
bindings.

## Alternatives considered

1. **Hand-written per-language libraries.** *Rejected.* See N-divergence
   above; would consume the project's bandwidth indefinitely.
2. **Server-side verification API.** *Rejected.* Conflicts with P1 (name
   tags travel) and P9 (no accounts) — requires uploading the file to be
   verified.
3. **C++ / Rust shared library + per-language FFI shims.** *Rejected.*
   FFI brings ABI stability problems WASM does not have. WASM artifacts
   are content-addressable and do not break across host upgrades.

## Consequences

- One implementation, one CVE response lane, one constant-time-correctness
  review.
- The four-state grammar is enforced at the type system of every
  consumer because there is only one type system.
- Receivers pay a one-time ~300 KB compressed download. We hold this to a
  ≤ 1 MB compressed budget in CI (`.github/workflows/wasm.yml`).
- WASM cryptographic primitives must be constant-time. We rely on
  `ed25519-dalek` and `sha2`'s constant-time guarantees; any change away
  from these requires a follow-up ADR.
- Browsers that cannot load the WASM (extremely old or restricted
  environments) do not get receiver functionality. We accept this; the
  population is small and shrinking.
