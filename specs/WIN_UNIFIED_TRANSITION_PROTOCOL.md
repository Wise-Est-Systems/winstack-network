# W.I.N. Unified Transition Protocol (WIN-UTP/0.1)

This document describes the protocol **as implemented** in `crates/win-transition`
and `crates/win-conformance`. It does not describe planned behavior. Where a
behavior is not implemented, it says so.

- Protocol tag: `WIN-UTP/0.1` (`win_transition::PROTOCOL`)
- Artifact format tag: `WIN-UTP-ARTIFACT/0.1` (`win_transition::ARTIFACT_FORMAT`)
- Reference implementation: `crates/win-transition` (Rust)
- Conformance vectors: `crates/win-conformance/vectors/`

## 1. Purpose

A *governed transition* turns a proposed digital change into an accountable,
portable, independently verifiable record of: what was proposed, which authority
permitted or refused it, what actually happened, and what state resulted.

## 2. Roles and separation

The protocol separates five logical roles. They may run on one machine, but each
holds a distinct key and a distinct responsibility:

| Role | Responsibility | Type |
|---|---|---|
| Proposer | Suggests a change. Holds no authority. May be an AI. | `proposer_identity_id` (+ optional `AiModelInfo`) |
| Authorizer | Issues a scoped, signed grant. | `Authorizer` |
| Verifier | Checks the grant's signature. | `verify_authorization` |
| Executor | Performs the permitted side effect, or refuses. | `Executor` trait |
| Recorder | Seals the finished transition. | `Recorder` |

Enforced invariants (each has a conformance vector and/or unit test):

1. **AI is never the authority.** If `proposer_identity_id == authorizer_identity_id`,
   the action is refused (`SelfApproval`).
2. **The executor never approves itself.** If `executor.identity_id() ==
   authorizer_identity_id`, the action is refused (`SelfApproval`).
3. **A refusal is never discarded.** Every refusal becomes a signed `Refusal`
   inside the transition, with `side_effect_occurred = false`.

## 3. Authority vocabulary

`Authority` is a closed enum of scoped capabilities:

`LocalRead`, `LocalWrite`, `ExternalPublish`, `NetworkSend`.

Coverage is **exact match**: a `LocalWrite` grant covers only `LocalWrite`
actions. There is no implicit widening (write does not imply read). A grant is
bound to one subject (`subject_content_id`), preventing replay against a
different object.

## 4. Lifecycle

```
INPUT → PROPOSAL → VERIFICATION (grant authentic?)
      → SEPARATION CHECKS (proposer≠authorizer, executor≠authorizer)
      → POLICY EVALUATION (if a policy proof is supplied)
      → EXECUTION | REFUSAL → STATE COMMITMENT → RECORD (seal)
```

`win_transition::govern` orchestrates this. It never performs a side effect
itself; only an `Executor` can, and only after every gate passes. Any gate
failure produces a signed `Refusal` (not an executed action).

## 5. The central object: `Transition`

A `Transition` binds (see `crates/win-transition/src/lib.rs`):

`protocol`, `transition_id`, `prior_state_id`, `subject_content_id`,
`proposer_identity_id`, `proposer_model`, `action` (`RequestedAction`),
`policy` (optional `PolicyProof`), `authorization` (`AuthorizationGrant`),
`outcome` (`Executed(ExecutionReceipt)` | `Refused(Refusal)`),
`resulting_state_id`, `recorder_identity_id`, `recorded_at`, `signature`.

## 6. Cryptography and determinism

- Digest: SHA-256. Signatures: Ed25519 (via `wise-crypto`).
- Every signed object is a fixed-field struct signed over its
  declaration-ordered JSON (`sign_json`). Signed payloads contain no maps, so
  bytes reproduce across machines and signatures verify offline.
- No wall clock is required to verify. Timestamps are recorded strings, not a
  trust input.

## 7. Content identity

An object's identity is `sha256:<hex>` of its exact bytes. The executor's
`ExecutionReceipt.output_content_id` is the identity of what it produced;
`resulting_state_id` mirrors it on success.

## 8. Portable artifact (`.win`)

`seal_win` packs, via the `win-format` container (`WIN\x01` magic):
- the produced **content** (bytes; empty for a refusal), and
- a **proof JSON** = `PortableProof { format, transition, keys }`, where `keys`
  are the public keys needed to verify every embedded signature.

`open_win` / `verify_win` reconstruct all checks from the bytes alone.

## 9. Verification dimensions

`verify_win` returns a `VerifiedArtifact` reporting, per dimension:

- `container_structure_valid` — the container unpacked.
- `content_integrity` — `Valid` / `Mismatch` / `NotApplicable` (carried content
  hash vs the sealed `output_content_id`).
- `transition_valid` — every embedded signature verified and the record is
  internally consistent (subject binding; executed output matches resulting
  state; a refusal proves no side effect).
- Outcome, refusal reason, granted authority, policy-evaluated, receipt-present.

A stored policy proof is required to be `Permit` **only** when the transition
executed. On a refused transition the proof may be a `Deny` (the reason for
refusal); the recorder signature still guarantees it was not tampered with.

## 10. What the protocol does NOT establish

Per the honesty requirement, a passing verification proves internal consistency,
content integrity, and key-custody signatures — and nothing more. It does **not**
establish factual correctness of content or that a proposer's summary is accurate.

Identity is an honest ladder (`IdentityStatus`), reported per actor:
`NotEstablished` → `ConsistentActor` (persistent key) → `SelfAsserted` (a signed
name-claim, not proof) → `Trusted` (the *recipient's* trust list vouches for the
key, via `resolve_identity` + a `TrustLookup`). `Trusted` means a key the recipient
chose to trust — web of trust, not a central authority — never global truth.
Identity assertions ride in an additive, self-signed envelope
(`PortableProof.identities`): an attacker cannot forge an identity for a key whose
private half they lack, and stripping assertions only downgrades the reported rung
(fail-safe).

## 11. Conformance

An independent implementation is conformant if, for every vector in
`crates/win-conformance/vectors/vectors.json`, its verifier reproduces the
declared `expect` fields. The reference runner is `win-conformance` (10 vectors,
all passing).

## 12. Not implemented at this version

- Desktop identity/trust UI (Phase 2). The CLI has persistent authorizer identity
  + self-asserted names + trust-list verification; the desktop endpoints still use
  session keys. External anchoring (SSO/OIDC/DNS/hardware) — Rung 4 — is not
  implemented.
- Executors beyond `FilesystemExecutor` in the shipping product (the `Executor`
  trait is open; `examples/sdk.rs` shows a custom one).
- Cross-machine deterministic *sealing* vectors (conformance freezes verification
  behavior over fixed bytes, not byte-identical re-sealing).
