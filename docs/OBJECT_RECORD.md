# W.I.N. — The Object Record

Every governed transition produces a record with the sections below. In the
desktop app this is the result screen + verification matrix; in code it is the
`Transition` and the `VerifiedArtifact` from `verify_win`.

## Object

- Filename / title, media or artifact type.
- Content identity — `sha256:<hex>` of the exact bytes (the *subject*).
- Whether content is embedded in the `.win` (executed) or absent (refusal).

## Integrity

- **Container structure** — did the `.win` unpack.
- **Content integrity** — carried content hash vs the sealed `output_content_id`:
  `Valid` / `Mismatch` / `NotApplicable`.

## Lineage

- `prior_state_id` → this transition → `resulting_state_id`. In the app, the
  human-readable chain (e.g. `Contract.txt → governed summary → Summary.txt`).

## Claims

- Stated by the proposer, with their status. The reference proposer always
  attaches: *"derived from the identified source"* and *"no claim of independent
  factual validation."* Status of factual claims: **NOT INDEPENDENTLY
  ESTABLISHED**.

## Authority

- The action's `required_authority`, the scoped `granted_authority`, the
  authorizing key, and whether authorization was valid for the action. An action
  exceeding scope appears here as the reason it was refused.

## Execution

- `ExecutionReceipt`: requested vs actual operation, destination, output content
  identity, result (`Completed`/`Failed`/`Partial`), whether a side effect
  occurred, executor key. Absent on a refusal.

## Refusals

- `Refusal`: what was requested, the permitted authority, the reason
  (`AuthorizationScopeExceeded`, `SelfApproval`, `PolicyDenied`, `SubjectMismatch`,
  …), confirmation `side_effect_occurred = false`, and that it was recorded.

## Verification

- The full matrix (see [VERIFICATION_RESULTS](VERIFICATION_RESULTS.md)), including
  the `REAL-WORLD IDENTITY` row, which reports the honest identity rung reached:
  `NOT ESTABLISHED` / `CONSISTENT ACTOR` / `CLAIMED "…" (SELF-ASSERTED)` /
  `TRUSTED "…"`.

## Portable proof

- The whole record + the public keys, sealed into one `.win` that verifies from
  its bytes alone.
