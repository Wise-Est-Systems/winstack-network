# W.I.N. — Developer Guide

Build on the governed-transition engine without the desktop app.

## Crates

| Crate | Role |
|---|---|
| `win-transition` | The engine: types, roles, `govern`, `.win` seal/verify. The SDK. |
| `win-format` | The `.win` container (pack/unpack). |
| `policy-core`, `wise-crypto`, `canon-types` | Policy proofs, Ed25519/SHA-256, shared types. |
| `win-conformance` | Frozen vectors + runner. |

## The lifecycle in code

See `crates/win-transition/examples/sdk.rs` for a runnable walkthrough:

```
cargo run -p win-transition --example sdk
```

Shape (types from `win_transition`):

```rust
// 1. PROPOSE — a proposer suggests an action; holds no authority.
let action = RequestedAction::new("create_file", &subject, target, Authority::LocalWrite);

// 2. AUTHORIZE — a different party issues a scoped, signed grant.
let grant = authorizer.issue_grant(Authority::LocalWrite, &subject);

// 3. VERIFY — check the grant's signature.
verify_authorization(&grant, &authorizer.public_key_hex())?;

// 4-5. EXECUTE | REFUSE + RECORD — the safe orchestrator.
let transition = govern(GovernRequest { /* … */ }, &executor, &recorder);

// 6. SEAL — portable .win.
let win = seal_win(&PortableProof::new(transition, keys), "out.win", content);

// 7. INDEPENDENTLY VERIFY — from bytes alone.
let v = verify_win(&win)?;
assert!(v.all_checks_pass());
```

`govern` deliberately has no unsafe one-shot: authority is always a separately
issued, separately keyed grant, and the role separations are enforced inside it.

## Implementing an executor

Implement the `Executor` trait (`identity_id`, `public_key_hex`,
`bound_authority`, `settle`). `settle` must honor the upstream `precheck`, verify
the grant covers the action and matches the subject, then either perform its
bounded side effect and return a signed `ExecutionReceipt`, or return a signed
`Refusal`. `examples/sdk.rs` implements a non-filesystem `InMemoryExecutor`.

## Implementing a proposer

A proposer is any code that produces a `RequestedAction` (and the content). The
reference `win_transition::proposers::propose_summary(&[u8])` adapts to text vs
binary. A proposer holds no authority.

## Policy

Supply a `canon_types::PolicyProof` (from `policy_core::PolicyEvaluator`) to
`GovernRequest.policy`. A `Deny` refuses the action; a refusal caused by a deny is
itself a valid, verifiable record.

## Identity (the honest ladder)

Attach a self-signed identity claim to a key and verify against a recipient's
trust list:

```rust
let ident = assert_identity(&key, Some("Acme Ops".into()), None, Persistence::Persistent);
let proof = PortableProof::new(transition, keys).with_identities(vec![ident]);

// Verify with a recipient trust list (any `TrustLookup`):
let v = verify_win_with_trust(&win_bytes, &my_trust_store)?;
// v.authorizer_identity: NotEstablished | ConsistentActor | SelfAsserted | Trusted
```

`verify_win` (no trust) reaches at most `SelfAsserted`. `Trusted` requires the
recipient's `TrustLookup` to vouch for the key — web of trust, no central
authority. Assertions are self-signed: an attacker cannot forge identity for a key
they don't hold, and stripping assertions only downgrades (fail-safe).

CLI: `win summarize <file> --as "Acme Ops" --context "acme.co"` attaches the claim;
`win trust add <key> --label "..."` makes a later `win verify` read `TRUSTED`.

## Conformance

```
cargo run -p win-conformance --bin win-conformance          # human table
cargo run -p win-conformance --bin win-conformance -- --json
```

Point your own verifier at `crates/win-conformance/vectors/vectors.json` and
match every `expect` field to claim compatibility.
