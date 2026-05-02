<!--
Title format: <area>: <imperative summary>
Examples:
  verifier: tighten Wounded vs Unrecognized routing for chain failures
  cli: add publish subcommand for hash-indexed name tag publishing
  spec: amend grammar.md § 4 to extend lexicon

Keep PRs small. One logical change per PR.
-->

## What

<!-- 1–3 sentences. The change itself. -->

## Why

<!-- The motivation. Link issues, ADRs, or grammar sections. -->

## How it was tested

<!--
- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo fmt --all --check`
- [ ] WASM build succeeded (if `crates/verifier-wasm/` or its deps changed)
- [ ] Manual UI walkthrough (if any user-facing string changed)
-->

## Grammar contract

<!--
If this PR touches user-facing strings, confirm:
- [ ] Reads in the four-state grammar (Alive / Wounded / Unrecognized / Dying)
- [ ] No prohibited engineering vocabulary in user surfaces (see spec/grammar.md § 4)
- [ ] No fifth state introduced
-->

## Backwards compatibility

<!--
If this PR touches signed payloads, the wire format, or the verifier:
- [ ] Existing proofs still verify
- [ ] Protocol version bumped if semantics changed
- [ ] Migration path documented
-->
