# Contributing

Thanks for considering a contribution. This document covers what we expect
from PRs, how the project is structured, and the few rules that are
non-negotiable.

## Before you start

Two documents define what this project is and is not. Read them before
opening a non-trivial PR:

- [`spec/grammar.md`](spec/grammar.md) — the cultural and product
  constitution. Four states, ten principles, explicit non-goals.
- [`docs/architecture.md`](docs/architecture.md) — crate layout, sealing
  and verification pipelines, surfaces.

If your change conflicts with the constitution, the right next step is an
**ADR amending the spec** before a code PR — see [`docs/adr/`](docs/adr/).

## Local development

### One-time setup

```bash
rustup toolchain install stable
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.117  # match Cargo.lock
cargo install cargo-deny --locked                 # supply-chain checks
```

### The four checks

Every PR must pass these locally before review:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/build-wasm.sh    # if WASM-touching changes
```

CI runs the same on Linux + macOS + Windows. Don't push code that you
haven't verified passes locally on at least one of these.

### Useful one-liners

```bash
cargo test -p verifier                           # one crate
cargo test --workspace -- verify_chain           # one test pattern
cargo doc --workspace --no-deps --open           # browse the API surface
cargo deny check                                 # licenses, advisories, bans
```

## Branch and commit conventions

- Branch names: `area/short-summary` — e.g. `verifier/wounded-vs-unrecognized`,
  `cli/publish-subcommand`, `spec/lexicon-extension`.
- Commit subjects: `<area>: imperative summary` under 72 chars.
  - Good: `cli: add publish subcommand for hash-indexed name tags`
  - Bad: `Updated some files`
- Commit bodies are welcome and useful. Lead with the why, not the what.
- Keep history clean. Squash WIP commits before review.

## Pull request rules

- One logical change per PR. Mixed concerns get split.
- Include test coverage for new behavior. Both positive and negative cases
  for verifier-affecting changes.
- Update [`CHANGELOG.md`](CHANGELOG.md) under `[Unreleased]` for any
  user-visible change.
- Update [`spec/grammar.md`](spec/grammar.md) only via ADR.
- Update [`spec/PROOF-SPEC.md`](spec/PROOF-SPEC.md) only with a protocol
  version bump and a migration story.

## Code layering

Crate dependency order is strict and one-directional. Lower must not
depend on higher.

```
canon-types → crypto → identity-core → time-core → policy-core
  → object-store → graph-index → verifier → verifier-wasm
  → registry-core → window-api → cli → desktop
```

`win-format` is a leaf — it depends on nothing else in the workspace,
deliberately, to keep the parser surface small.

## Backwards compatibility

The protocol is `V1`. Existing proofs **must continue to verify** under
any change to:

- Signed payload structures (`canon-types`)
- Verification logic (`verifier`)
- Container format (`win-format`)

Any structural change requires:

1. `serde(default)` and `skip_serializing_if` annotations to round-trip
   older proofs.
2. Tests proving prior-version proofs still verify.
3. A protocol version bump if recipient semantics change.
4. An ADR documenting the migration story.

## Testing

- Unit tests live next to the code they test.
- Integration tests live in `crates/registry-core/tests/integration.rs`
  and cover the full sealing → verification round trip plus adversarial
  inputs.
- Browser tests are manual today. A Playwright harness for `public/index.html`
  is planned. The CLI binary is covered by 21 e2e tests in
  `crates/cli/tests/cli_e2e.rs` and 5 property tests
  (~320 generated cases) in `crates/cli/tests/cli_proptest.rs`.
- WASM is exercised by the Rust unit tests indirectly (the wasm crate is
  a thin wrapper) and by deploy verification of the produced artifact.

When adding a verification check, test:

1. The positive case (an honest input passes).
2. The exact failure code that fires on a malicious input.
3. The three-state outcome (Verified / Tampered / Invalid) via the
   `from_failures` mapping.

## Security

Do **not** open public issues for vulnerabilities. See [`SECURITY.md`](SECURITY.md)
for the disclosure process. The default coordinated-disclosure window is
90 days.

The verifier is `#![forbid(unsafe_code)]`. Library crates avoid `unwrap`
in non-test paths; CLI binaries may panic on operator errors.

## Browser surfaces

`window/verify.html` (Tauri-embedded) and `public/index.html` (browser) must work:

- Opened directly from disk (no server)
- Hosted on any static server
- Without external JavaScript dependencies

Test manually: seal a file with the CLI, verify it in each surface.

## Releases

Releases are tagged from `main`:

```bash
# 1. Update CHANGELOG.md — move Unreleased → version section, set date.
# 2. Update workspace.package.version in Cargo.toml.
# 3. cargo test --workspace
# 4. git commit -am "release: vX.Y.Z"
# 5. git tag -s vX.Y.Z -m "vX.Y.Z"
# 6. git push origin main vX.Y.Z
# 7. GitHub Actions builds artifacts; create the GH Release with notes.
```

## Code of conduct

Be technically rigorous. Be kind to humans. Disagree about ideas, not
people. Reviewers expect short, specific feedback; authors are expected
to address it without escalation.

## License

By contributing you agree that your contributions are licensed under the
terms of the [MIT license](LICENSE).
