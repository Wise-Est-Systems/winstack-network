# Evidence packet — WinStack_Network_v1 — 2026-06-07

Produced by the Credibility engine (test/use/break/capture/report). No product
code was edited. No frozen artifact (spec/**, vectors/**, schemas/**, golden
`.win` fixture, frozen reports) was touched. This packet records the real
output of running the repository's own test gate.

## Repo state at time of run

- Branch: `main` (up to date with `origin/main`)
- HEAD commit: `45aa999eeec6701e762ce8e6dc3b5df6179bf52f`
  ("site: unify three doors into one story (consistent footer nav)")
- Working tree before run: clean except untracked `docs/adoption-proposal-2026-06-07.md`
- Toolchain: `rust-toolchain.toml` → channel `stable`
- `cargo 1.94.1 (29ea6fb6a 2026-03-24)`
- `rustc 1.94.1 (e408947bf 2026-03-25)`
- Platform: macOS (darwin 25.5.0), single developer machine

## Claim under test

The repository's own test gate — the same `cargo test` invocation defined in
`.github/workflows/ci.yml` (the macOS matrix row uses
`--workspace --all-features`) — passes locally with zero failures, exercising
the verifier, CLI, `.win` format, crypto, and the adversarial / tamper test
suites that back the protocol's "Verified / Tampered / Invalid" claim.

## Commands run (verbatim)

Narrow gate first (core trust crate):

```
cargo test -p verifier --all-features
```

Broad gate (matches CI macOS matrix row `--workspace --all-features`, plus the
CI `--no-fail-fast` flag so every binary reports even if one fails):

```
cargo test --workspace --all-features --no-fail-fast
```

## Output (verbatim, trimmed only at compile noise)

### Narrow gate — `cargo test -p verifier --all-features`

```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 3.56s
     Running unittests src/lib.rs (target/debug/deps/verifier-60ea2885568072c6)

running 1 test
test tests::empty_input_detects_failures ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests verifier

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Broad gate — `cargo test --workspace --all-features --no-fail-fast`

Process exit code: `0`.

Per-binary `test result:` lines (all 37, verbatim aggregation):

```
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 120 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 30 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out   (× 13 doc-test binaries with 0 tests)
```

Aggregate (sum of all `test result:` lines):

```
passed=323 failed=0 ignored=0
```

Filter for real failure signals (`error[`, `panicked`, `FAILED`, `warning:`):
no matches other than the literal "0 failed" substring inside passing result
lines. No compiler errors, no panics, no test failures, no warnings.

### Test binaries that back the protocol claim (from the binary list)

These named integration-test binaries ran and passed (counts from their
respective `test result:` lines above):

- `crates/cli/tests/e2e_state_matrix.rs` — end-to-end state matrix (30 passed)
- `crates/cli/tests/cli_e2e.rs` — CLI end-to-end (21 passed)
- `crates/cli/tests/cli_proptest.rs` — property tests (7 passed)
- `crates/registry-core/tests/golden_win.rs` — golden `.win` regression (2 passed)
- `crates/registry-core/tests/integration.rs` — registry integration (120 passed)
- `crates/win-format/tests/adversarial_corpus.rs` — adversarial corpus (25 passed)
- `crates/win-format/tests/tamper_grid.rs` — tamper grid (30 passed)
- `crates/window-api/tests/check_endpoint_states.rs` — Verified / Tampered /
  Invalid / Damaged endpoint states (8 passed), including:
  `check_valid_win_returns_verified`,
  `check_payload_tampered_win_returns_tampered`,
  `check_proof_signature_tampered_win_returns_invalid`,
  `check_too_short_container_returns_damaged`.

## Verdict

VERIFIED

The repository's own test gate (matching the CI macOS matrix invocation) ran to
a clean exit on this machine: 323 tests passed, 0 failed, 0 ignored, exit
code 0.

## What is now real

- On this machine, at commit `45aa999`, with stable rustc 1.94.1, the full
  workspace test suite (`--workspace --all-features`) compiles and passes with
  zero failures.
- The "three results" behavior the public `proofs` page describes is backed by
  passing tests: a valid `.win` returns Verified, a payload-tampered `.win`
  returns Tampered, a signature-tampered `.win` returns Invalid, and a
  too-short / truncated container returns Damaged
  (`crates/window-api/tests/check_endpoint_states.rs`).
- Adversarial and tamper-grid suites (`adversarial_corpus.rs`, `tamper_grid.rs`)
  pass, meaning the format rejects the corpus of malformed/tampered inputs
  they encode.
- The golden `.win` regression fixture
  (`crates/registry-core/tests/vectors/golden/golden.win`) still verifies
  against current code (`golden_win.rs`, 2 passed) — frozen fixture, not
  modified by this packet.

## What remains unproven

- This is a single-machine, single-run result on macOS. It does NOT prove the
  Ubuntu/Windows CI matrix rows, MSRV (1.82) check, `cargo fmt --check`,
  `cargo clippy -D warnings`, or `cargo doc` — those CI jobs were not run here.
- It is first-party verification: the author's own tests run by the author's
  agent. No external/third-party reviewer has run or audited this.
- It does not prove cryptographic soundness, performance, or any real-world
  adversary resistance beyond the specific inputs encoded in the test corpus.
- Test count (323) reflects current suite breadth, not coverage; no coverage
  metric was measured in this run.

## Strongest defensible claim this packet supports

> On a clean checkout of commit `45aa999` with Rust 1.94.1 on macOS, WinStack's
> own workspace test suite (`cargo test --workspace --all-features`) passes with
> 323 tests, 0 failures — including the integration tests that assert a valid
> `.win` verifies, a tampered payload reports Tampered, and a tampered signature
> reports Invalid.

This is a first-party, single-machine result. It is not external validation and
does not cover the cross-platform CI matrix, lint, format, or MSRV gates.
