---
canonical-name: winstack-network
layer: implementation
parent: Wise-Est-Systems
license: MIT
canon: https://github.com/Wise-Est-Systems/wiseorder-protocol/blob/main/STRUCTURE.md
---

# Role: `.win` Implementation

`winstack-network` is the **production implementation** of the `.win` tag — portable cryptographic proofs that files can carry to verify themselves offline.

## What this repo IS

- A Rust workspace producing the `.win` file format, the crypto layer, the native verifier, the WASM verifier, the desktop drop-target, and the CLI.
- Thirteen crates: `canon-types`, `cli`, `crypto`, `graph-index`, `identity-core`, `object-store`, `policy-core`, `registry-core`, `time-core`, `verifier`, `verifier-wasm`, `win-format`, `window-api`.
- An offline verifier — any recipient can confirm a `.win` artifact's integrity without contacting Wise.Est Systems. The verifier continues to function if Wise.Est Systems no longer exists.

## What this repo IS NOT

- The governance kernel. That is `wiseorder-protocol`.
- A hosted service. Verification is local and byte-by-byte, with no servers in the trust path.
- A general identity system. The identity layer is scoped to artifact signing within the protocol.
- A finished product. Crates under construction are documented in `ROADMAP.md`.

## Drift policy

Any change to this file MUST be accompanied by an update to the `winstack-network` row in [`wiseorder-protocol/STRUCTURE.md`](https://github.com/Wise-Est-Systems/wiseorder-protocol/blob/main/STRUCTURE.md). CI verifies the fingerprint on every push.
