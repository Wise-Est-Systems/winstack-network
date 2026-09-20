# W.I.N. Desktop — User Guide

No terminal, no accounts, no network. Everything below happens on your machine.

## Install / launch

- **From the build:** open `target/release/bundle/dmg/Wise_0.2.0_aarch64.dmg` and
  drag **Wise** to Applications, then launch it. (The app is unsigned — on a Mac
  that did not build it, right-click → **Open** the first time to get past
  Gatekeeper. See KNOWN_LIMITS.)
- **From source (dev):** `cargo run -p wise-desktop`. A debug run loads its
  frontend from `http://localhost:8080`, so first run a static server for the
  `window/` folder; a release build (`cargo tauri build`) has the pages baked in
  and needs no server.

## The two screens

The app opens on **Drop a file** (verify/seal). Click **"Governed actions →"** in
the footer for the workflow below.

## Governed document workflow

1. **Bring a document in.** Drop a file (or click to choose) on the Governed
   actions page.
2. **Review the proposed action.** Nothing has been created yet. You see: the
   proposed action, the source and its content identity, the proposer, the
   authority required (`LocalWrite`), external actions (`None`), the claims, and a
   preview of the proposed summary. For a non-text file (image, PDF, …) the
   proposal is an honest object description, not a fake text summary.
3. **Authorize or cancel.** Click **Authorize local write** to permit exactly the
   local file creation — nothing more.
4. **See the result.** "Summary created", the resulting identity, and the full
   verification matrix.
5. **Export .win.** Save the portable proof anywhere.
6. **Verify this .win.** Re-check the artifact you just made.
7. **Try to publish it.** This requests an *external* action your authorization
   does not cover. It is **refused** — no network call, no file — and the refusal
   is sealed as its own proof you can export.

## Reading the result

See [OBJECT_RECORD](OBJECT_RECORD.md) and
[VERIFICATION_RESULTS](VERIFICATION_RESULTS.md). Key honest lines you will always
see: `REAL-WORLD IDENTITY: NOT ESTABLISHED` and `FACTUAL CLAIMS: NOT
INDEPENDENTLY ESTABLISHED` — the app never overstates what a check proves.

## Verifying a `.win` from someone else

On the **Drop a file** screen, drop any `.win`. A transition artifact shows the
matrix; a classic sealed-file `.win` shows its verification. Both work offline.
