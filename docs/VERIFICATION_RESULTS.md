# W.I.N. — Verification Results

`verify_win` never returns a single vague "Verified." It returns a per-dimension
matrix. Example (accepted transition):

```
CONTAINER STRUCTURE       VALID
CONTENT INTEGRITY         VALID
SIGNATURES                VALID
SIGNING KEY (recorder)    key:…
REAL-WORLD IDENTITY       NOT ESTABLISHED
AUTHORIZATION             SCOPED TO LocalWrite
POLICY EVALUATION         NONE
EXECUTION RECEIPT         PRESENT
OUTCOME                   EXECUTED
FACTUAL CLAIMS            NOT INDEPENDENTLY ESTABLISHED
EXTERNAL DEPENDENCIES     NONE — verified offline
```

## What each row means

| Row | VALID / value means | A failure means |
|---|---|---|
| CONTAINER STRUCTURE | The `.win` unpacked cleanly | Truncated/corrupt transfer (**damage**, not forgery) |
| CONTENT INTEGRITY | Carried content matches the sealed hash | `MISMATCH` — the content was altered after sealing |
| SIGNATURES | Every embedded signature verified + record internally consistent | `INVALID` — a signature was forged or a field tampered |
| SIGNING KEY | The recorder public key that signed | — |
| REAL-WORLD IDENTITY | The identity rung reached (see ladder) | Key custody is always proven; higher rungs add a *claim* or *your* trust, never global truth |
| AUTHORIZATION | The scope the action was granted | — |
| POLICY EVALUATION | `PASSED` if a Permit proof was checked, else `NONE` | — |
| EXECUTION RECEIPT | `PRESENT` if a side effect was attempted | `NONE` on a refusal |
| OUTCOME | `EXECUTED` or `REFUSED — <reason>` | — |
| FACTUAL CLAIMS | Always `NOT INDEPENDENTLY ESTABLISHED` | Integrity ≠ truth |
| EXTERNAL DEPENDENCIES | `NONE` — checked with no network | — |

## Overall

`all_checks_pass()` is true only when the container is intact, content integrity
is not `Mismatch`, and signatures are valid. A **refusal** artifact passes — it is
a valid signed record that an action was refused with no side effect.

## The three failure classes, kept distinct

- **Damaged** — the container itself is unreadable. Not an attack signal.
- **Mismatch** — the content changed but the record is intact ("file changed").
- **Invalid signature** — the record was forged ("record forged").

Keeping these apart is deliberate: a broken download must not read as tampering.

## The identity ladder

`REAL-WORLD IDENTITY` reports the highest rung the evidence supports, and labels
it honestly — it never inflates a claim into a fact:

| Rung | Shown as | Means |
|---|---|---|
| 0 | `NOT ESTABLISHED` | a throwaway key signed it |
| 1 | `CONSISTENT ACTOR (persistent key, no name)` | same signer across history, no name |
| 2 | `CLAIMED "…" — SELF-ASSERTED, NOT VERIFIED` | the key *claims* a name; a claim, not proof |
| 3 | `TRUSTED "…" (via your trust list)` | *you* chose to trust this key (`win trust add`) |

Rung 3 is web-of-trust: the recipient decides whom to trust; there is no central
authority. It means "a key you trust," not "verified by the world." External
anchoring (SSO/DNS/hardware) is a future rung, not yet implemented.

## Honest ceiling

A full PASS proves integrity, provenance-by-key, and internal consistency. Even at
`TRUSTED`, identity means *a key the recipient chose to trust* — not global truth,
and never factual correctness of content. See [KNOWN_LIMITS](KNOWN_LIMITS.md).
