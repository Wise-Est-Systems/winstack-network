# W.I.N. — Security Boundaries

What the design treats as a boundary, what it trusts, and where the boundary
ends. Grounded in `crates/win-transition`.

## Logical security boundaries (enforced in code)

These separations are enforced even though all roles can run on one machine:

- `PROPOSER ≠ AUTHORIZER` — a proposer (including an AI) cannot authorize its own
  request. Violation → `Refusal(SelfApproval)`.
- `AUTHORIZER ≠ EXECUTOR` — the executor cannot approve itself. Violation →
  `Refusal(SelfApproval)`.
- `AUTHORIZER` scope is explicit and exact — an action requiring `ExternalPublish`
  is refused under a `LocalWrite` grant (`AuthorizationScopeExceeded`), with no
  side effect.
- `GRANT ↔ SUBJECT` binding — a grant issued for one subject cannot authorize an
  action on another (`SubjectMismatch`).
- `REFUSAL` is durable — refusals are signed and recorded, never dropped.

Each boundary above has a conformance vector in `crates/win-conformance`.

## Integrity boundary

- The **recorder signature** covers the entire transition (proposal, policy,
  authorization, outcome, resulting state). Tampering any field breaks it →
  `transition_valid = false`.
- **Content integrity** is separate: the carried file's hash is checked against
  the sealed `output_content_id`. Altering the file yields `content_integrity =
  Mismatch` while signatures may still be valid — deliberately distinguishing
  *"the file was changed"* from *"the record was forged."*
- **Container damage** (truncation, bad magic) is reported distinctly from a
  forged proof, so a broken transfer is not mistaken for an attack.

## Trust assumptions (what is NOT protected)

- **Key ownership is out of scope.** The signing keys travel inside the artifact
  and are self-attested. Verification proves those keys signed the record; it
  does not prove who holds them. `REAL-WORLD IDENTITY: NOT ESTABLISHED`.
- **A malicious authorizer is out of scope.** If the party holding the authorizer
  key chooses to grant `ExternalPublish`, the protocol will treat a resulting
  publish as authorized. The protocol governs *whether an action is within a
  granted scope*, not *whether the grant was wise or honest*.
- **A compromised host is out of scope.** If the machine running all roles is
  compromised, an attacker with the keys can produce valid records. Local-first
  means the host is in the trusted computing base.
- **Content truth is out of scope.** See KNOWN_LIMITS.

## Cryptography

- SHA-256 for identity/integrity; Ed25519 for signatures (`wise-crypto`).
- Signed payloads are fixed-field, map-free, signed over declaration-ordered JSON
  so bytes and signatures reproduce across machines. Offline verification needs
  no clock and no network.

## Distribution boundary

- The desktop bundle is unsigned/un-notarized (see KNOWN_LIMITS). macOS Gatekeeper
  is the OS-level boundary for redistribution; this project does not yet cross it.
