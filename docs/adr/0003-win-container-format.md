# 0003 — Custom .win container format

- **Status:** Accepted
- **Date:** 2026-04-26
- **Spec:** [`spec/PROOF-SPEC.md`](../../spec/PROOF-SPEC.md)

## Context

A named file and its name tag must travel together. Two off-the-shelf
options exist:

1. **Sidecar file** (`document.pdf` + `document.pdf.proof.json`). Standard
   in the GPG world.
2. **Container** (zip, tar, custom) bundling the file and proof.

Sidecars are routinely stripped by Slack, Gmail, iMessage, and most email
gateways — the proof gets lost at the first relay. Bundled containers
survive because they are a single artifact.

## Decision

We ship a custom container format with the magic bytes `WIN\x01`, a
length-prefixed filename, a length-prefixed file body, and a trailing JSON
proof bundle. The format is specified in `spec/PROOF-SPEC.md` and
implemented by `crates/win-format`.

The container is **not encrypted**. Name tags are visible and addressable
(`spec/grammar.md` § 11). Confidentiality is out of scope; recognition is
the only goal.

We continue to support the sidecar format (`*.proof.json`) for compatibility
with pre-`.win` proofs and for surfaces that prefer separate transport.

## Alternatives considered

1. **Zip with manifest.** *Rejected.* The format is then ambiguous (which
   file is the artifact?), zip is mutable in subtle ways that break
   reproducible signing, and the format invites recipients to "extract and
   modify."
2. **PGP detached signatures.** *Rejected.* Requires pre-existing key
   exchange that 99% of recipients lack; the standard has 30 years of
   adoption failure as evidence.
3. **C2PA.** *Rejected for v1.* C2PA is image-and-video-shaped; the
   metadata model does not extend cleanly to arbitrary files. Re-evaluated
   when the standard expands.
4. **PDF-with-signature embedding.** *Rejected.* File-type-specific.
5. **TAR.** *Rejected.* Wrong wire format for short payloads; oversized
   parser surface for the receiver-side WASM.

## Consequences

- Recipients receive a single file. Forwarders cannot accidentally drop
  the proof.
- The format is small and parseable in ~50 lines of JavaScript (see
  `public/v.html`'s `parseWin`).
- The `.win` extension does not currently have a registered MIME type.
  We treat it as `application/octet-stream` and recommend
  `application/vnd.wise.win+zip` once registration is feasible.
- Containers larger than 2 GB are not supported (uint32 file length).
  Larger files use the sidecar form. A future v2 of the format may extend.
