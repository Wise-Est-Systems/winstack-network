# W.I.N. — Known Limits

Stated plainly. These are real limitations of the current implementation, not
future-work aspirations dressed up as done.

## Identity

- **Honest identity ladder (Phase 1 implemented).** The CLI `win summarize` uses a
  **persistent** authorizer key and can attach a self-asserted name (`--as`), so
  the matrix reports `CONSISTENT ACTOR`, `CLAIMED "…" (SELF-ASSERTED)`, or —
  when the recipient has run `win trust add` on the key — `TRUSTED "…"`. It never
  inflates a claim into a fact.
- **Not yet:** the **desktop app** does not yet expose identity/trust UI (Phase 2)
  — its transition endpoints still use session keys, so desktop artifacts read
  `NOT ESTABLISHED`. And there is **no external anchoring** (SSO/OIDC/DNS/hardware)
  — that is Rung 4, not implemented. `TRUSTED` means *a key the recipient chose to
  trust* (web of trust), not verification by any authority.
- The protocol proves **key custody** (these keys signed this record), never
  **key ownership** (who holds the key) — even at `TRUSTED`.

## What a PASS does not mean

- It does not mean the content is **true**. A summary can be sealed and verified
  while being a poor or wrong summary. `FACTUAL CLAIMS: NOT INDEPENDENTLY
  ESTABLISHED`.
- It does not mean a real person authorized anything — only that the named
  authorizer key signed a scoped grant.
- Cryptographic integrity is **not** truth.

## Proposer

- The shipping proposer (`win-local-extractive-proposer`) is a deterministic,
  offline heuristic: a lead line + statistics for text, or an honest object
  description (type/size/identity) for non-text. It is **not** an LLM and does
  not understand content. A real model proposer is not yet implemented.

## Executors

- Only `FilesystemExecutor` (bounded to `LocalWrite`, verb `create_file`) ships
  in the product. `ExternalPublish` / `NetworkSend` have **no** executor — they
  can only be refused. The `Executor` trait is open; see `examples/sdk.rs`.

## Distribution

- `Wise.app` and the `.dmg` are **unsigned and un-notarized**. Fine to run on the
  machine that built them. On another Mac, Gatekeeper will warn; real
  distribution requires an Apple Developer signing certificate and notarization.

## Determinism

- Conformance freezes **verification behavior** over fixed bytes. It does not yet
  freeze byte-identical **re-sealing** (sealing uses random keys and recorded
  timestamps), so two independent seals of the same input differ.

## Scope of this build

- Single-machine, local-first, offline. No network is required or used in the
  governed-transition path. There is no server, no account, no cloud dependency —
  by design, and also meaning there is no multi-party or cross-host trust
  mechanism here.
