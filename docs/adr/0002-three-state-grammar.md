# 0002 — Three-state grammar

- **Status:** Accepted (locked)
- **Date:** 2026-04-26 · revised and locked 2026-04-27
- **Spec section:** [`spec/grammar.md` § 3](../../spec/grammar.md#3-the-three-states)

## Context

The verifier must communicate one of a small set of outcomes to a
non-technical receiver. Standard cryptographic-tool vocabulary
(`VERIFIED`, `INVALID`, `TAMPERED`, `CORRUPT`, `UNTRUSTED`) carries
connotations of security alerts that recipients are trained to dismiss.
The product needs the *opposite* emotional register: a calm, unambiguous
report on a single file in front of the receiver.

An earlier draft of this ADR proposed four states (Alive / Wounded /
Unrecognized / Dying). That vocabulary was rejected on 2026-04-27: it
asked the receiver to memorize three different ways a tag can fail, when
operationally those three reduce to one — *we can't verify this win tag.*
The receiver gains nothing from the distinction; the engineer can still
inspect the typed `FailureCode` underneath.

## Decision

The verifier reduces every check to exactly three states:

| State       | Meaning                                                           |
|-------------|-------------------------------------------------------------------|
| `Verified`  | File matches its win tag; witness signature intact.               |
| `Tampered`  | File was sealed once; has been changed since.                     |
| `Invalid`   | We can't verify this win tag. Subsumes wrong-tag, unreadable signature, malformed container. |

States are defined as the public type `canon_types::VerificationStatus`
and derived from the verifier's failure list via
`from_failures(&[Failure])`.

The three are exhaustive. The grammar (see
[`spec/grammar.md` § 11](../../spec/grammar.md#11-the-non-goals))
explicitly forbids a fourth state. Edge cases either map onto the
existing three or layer in as engineering-only `FailureCode` values.

## Alternatives considered

1. **Binary success / failure.** *Rejected* — collapses the receiver-
   actionable distinction between *the file in your hand was changed*
   (Tampered) and *we just can't read the tag* (Invalid).
2. **Four-state with `Unrecognized` and `Dying` as separate user-facing
   buckets.** *Rejected* — receivers can't act differently on those two,
   so splitting them costs cognition without buying anything.
3. **Continuous trust score (0–100).** *Rejected* — explicitly non-goal
   in the spec; trust scores hide the underlying signal.

## Consequences

- The grammar is the contract. Any change to the three-state set is a
  breaking change to every receiver-side surface (URL verifier, browser
  extension, chat-app integrations, SDKs).
- Engineering vocabulary (`HASH`, `SIGNATURE`, `ATTESTATION`, etc.) is
  forbidden in user-facing surfaces — enforced by review, not by lints.
- Failures still carry typed `FailureCode` values. Power-user inspection
  views may surface them; primary user surfaces must not.
- The grammar is locked (`spec/grammar.md` § 14). A future amendment may
  refine § 6–13; § 1–5 and § 11 — including the three-state set — do not
  change.
