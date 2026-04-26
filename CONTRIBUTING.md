# Contributing to Winstack

## Quick start

```bash
cargo build
cargo test        # 77 tests
cargo clippy --all-targets
cargo fmt --check
```

All four must pass before submitting changes.

## Code layering

Crates have strict dependency order. No circular imports.

```
canon-types → crypto → identity-core → time-core → policy-core
  → object-store → graph-index → verifier → registry-core
  → module-import, module-ai → window-api → cli → desktop
```

Lower layers must not depend on higher layers.

## Protocol compatibility

**Do not break existing proofs.** Any change to signed payload structures, verification logic, or proof format must:

1. Preserve backward compatibility via `serde(default)` and `skip_serializing_if`
2. Include tests proving old proofs still verify
3. Bump protocol version if semantics change

The four result states are immutable:
- `Alive` = file matches its name tag and the witness's signature is intact
- `Wounded` = file has been changed since it was named
- `Unrecognized` = name tag doesn't fit this file, or the witness's signature can't be read
- `Dying` = the name tag itself is decomposing (container malformed)

## Testing

- Unit tests live in each crate's `src/` or `tests/`
- Integration tests are in `crates/registry-core/tests/integration.rs`
- Security regression tests cover: signature tampering, time downgrade, policy forgery, chain tampering
- Chain walk and key delegation tests cover full lineage verification

When adding verification checks, test both the positive case (passes) and negative case (exact failure code).

## Browser verifier

`window/check.html` must work:
- Opened directly from disk (no server)
- Hosted on any static server
- Without any external JavaScript dependencies

Test manually: create a proof with the CLI, then verify it in `check.html`.

## Pull requests

- One logical change per PR
- Include test coverage for new behavior
- Run `cargo fmt` and `cargo clippy --all-targets` before submitting
- Describe what changed and why in the PR description
