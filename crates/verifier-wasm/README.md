# verifier-wasm

WASM bindings for the Winstack verifier. **One artifact, many surfaces.**

This is the canonical receiver-side verifier for every browser-adjacent
integration: the URL verifier page, browser extensions, Slack/Gmail/Discord
unfurl bots, CMS embed widgets. All of them load `verifier_wasm.js` and call
`recognize_win()` or `recognize_bundle()` — no per-language SDK required.

See `spec/grammar.md` § 3 for the four states this returns.

## API

```js
import init, { recognize_win, recognize_bundle } from '/wasm/verifier_wasm.js';
await init();

// Mode 1: a .win container in one call
const reading = recognize_win(winFileBytes);

// Mode 2: name tag arrives separately from the file
const reading = recognize_bundle(proofJsonString, fileBytes);
```

A `Reading` is a plain object:

```ts
{
  status:       "Verified" | "Tampered" | "Invalid" | "Dying",
  witness:      { public_key_hex: string, trust_class: string } | null,
  born:         string | null,    // ISO-8601 timestamp
  anchored:     boolean,           // true for RFC 3161 anchored birthdays
  lineage:      "Standalone" | "Origin" | "Successor" | "Unknown",
  payload_hash: string | null,
  size_bytes:   number | null,
  failures:     { code: string, reason: string }[],
  message:      string             // ready-to-display sentence in grammar voice
}
```

## Building

One-time setup:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.117  # match Cargo.lock
```

Build:

```bash
./scripts/build-wasm.sh
```

This emits to `public/wasm/`:

- `verifier_wasm_bg.wasm` — the WebAssembly binary
- `verifier_wasm.js` — JS glue
- `verifier_wasm.d.ts` — TypeScript types

If `wasm-opt` is on PATH, the script also runs `-Oz` size optimization
(typically halves the wasm size).

## Why this lives outside the workspace's default native build

The crate is in workspace members and *does* compile under
`cargo build --workspace` (as a native `rlib`). The `cdylib` artifact is
only produced when targeting `wasm32-unknown-unknown`. The native rlib path
keeps it in the same compilation unit as the rest of the verifier so changes
to `canon-types` can't drift the WASM API silently.

## What's NOT here

- **Browser extension scaffolding** — separate, downstream of this crate.
- **npm publication** — when there's an audience.
- **Witness notice fetching** — § 5b of the grammar; separate unit.
- **TSA cert verification at recognize-time** — `verify_from_proof_bundle`
  passes `None` for the trust store. RFC 3161 anchored timestamps are flagged
  as "Anchored" but the receiver-side WASM does not re-verify the TSA chain.
  That's a `verifier-wasm-tsa` extension when the witness-notice system lands.
