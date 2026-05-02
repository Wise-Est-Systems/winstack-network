# 0004 — Witnesses bring their own keys

- **Status:** Accepted
- **Date:** 2026-04-26
- **Spec section:** [`spec/grammar.md` § 11 (P9)](../../spec/grammar.md#2-first-principles)

## Context

The traditional cryptographic-notarization product is a hosted service: the
user creates an account, the service holds a key, the service signs on the
user's behalf, the service's domain becomes the trust anchor. Examples:
DocuSign, every blockchain notary, every cloud signing CA.

That model fails the spec's first principle (P1, name tags travel with the
file) the moment the user wants to verify offline, fails P9 (no accounts)
by definition, and creates an ongoing operational liability for us as a
service provider that we are not equipped to discharge.

## Decision

Witnesses generate and hold their own signing keys. We do not store keys.
We do not run an account system. Verification reads the witness's public
key from the name tag and checks the signature directly; nothing about
verification routes through any service we operate.

For larger witnesses (organizations, AI labs, CMSes) we expect — and the
container format supports — key delegation chains, so a witness can
rotate keys without invalidating prior name tags. Delegation is signed,
verifiable, and recorded in the lineage.

## Alternatives considered

1. **Hosted-key model (DocuSign-shaped).** *Rejected.* Disqualifies the
   product from offline use, creates a single point of failure, and
   conflicts with the spec's "no platform expansion" non-goal.
2. **Hybrid: optional hosted keys for convenience.** *Rejected.* The
   first-class path becomes hosted; offline becomes a niche. Spec's P10
   ("the grammar is not a skin") implies we cannot let a convenient
   default contradict the principle in practice.
3. **Threshold / shared keys** (Shamir, MPC). *Deferred.* Real product
   need; no demand yet. Reopen when an enterprise witness asks.

## Consequences

- Onboarding a witness is "generate a key" — a CLI command, no signup.
- We carry zero per-user state. The service surface is the static deploy +
  the public witness directory (per ADR 0007 when it lands).
- Key compromise is a witness's problem to disclose via a signed notice
  (see `spec/grammar.md` § 5b — "The Stolen Hand"). The verifier surfaces
  the compromise but does not act on the user's behalf.
- We cannot offer "recover my account" features. This is by design.
