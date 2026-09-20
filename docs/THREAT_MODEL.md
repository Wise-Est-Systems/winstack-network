# W.I.N. — Threat Model

Scoped to the governed-transition layer (`crates/win-transition`) and the `.win`
transition artifact. Each "defended" row maps to a conformance vector or test.

## Assets

- The **transition record** (proposal, authority, outcome, resulting state).
- The **carried content** (the file a transition produced).
- The **scope of authority** (what an action was permitted to do).

## Adversary capabilities considered

An adversary who can obtain and modify a `.win` artifact in transit, and can
craft their own artifacts. The adversary does **not** hold the legitimate signing
keys.

## Threats and outcomes

| # | Threat | Result | Evidence |
|---|---|---|---|
| T1 | Alter the carried content after sealing | `content_integrity = Mismatch`, overall FAIL | vector `tampered-content` |
| T2 | Forge/replace a signature in the record | `transition_valid = false`, overall FAIL | vector `forged-recorder-signature` |
| T3 | Name a different (attacker) key as the signer | signature fails under that key → `transition_valid = false` | vector `wrong-embedded-recorder-key` |
| T4 | Truncate / corrupt the container | reported as **damage**, not forgery | vector `container-damaged` |
| T5 | Escalate a local grant into an external publish | `Refusal(AuthorizationScopeExceeded)`, no side effect | vector `refused-publish-scope` |
| T6 | Replay a grant against a different subject | `Refusal(SubjectMismatch)` | vector `refused-subject-mismatch` |
| T7 | Have the AI/proposer authorize its own action | `Refusal(SelfApproval)` | vector `refused-self-approval` |
| T8 | Present a policy-denied action as executed | refused; refusal record verifies | vector `refused-policy-deny` |

## Out of scope (NOT defended)

- **O1 — Key ownership / impersonation.** The protocol cannot tell whether the
  signing key belongs to who a recipient thinks it does. It proves key custody,
  not identity. Mitigation is external (out-of-band key trust; not implemented in
  this layer).
- **O2 — Malicious/negligent authorizer.** A legitimate authorizer that grants
  broad scope is honored. The protocol enforces scope, not judgment.
- **O3 — Compromised host.** With the keys, an attacker on the local machine can
  produce valid records. The host is trusted.
- **O4 — Content truthfulness.** A valid record can carry a false statement. The
  protocol proves integrity and provenance-by-key, not facts.
- **O5 — Metadata/timing side channels, denial of service.** Not analyzed.

## Non-claims

This is a design-level threat model written by the implementer. It is **not** an
external security audit, and no such audit has been performed. See SECURITY.md for
reporting.
