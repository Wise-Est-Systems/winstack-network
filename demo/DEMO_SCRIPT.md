# W.I.N. governed-transition demo

This demo runs the full W.I.N. lifecycle end to end and produces artifacts you
can inspect and independently verify. Everything is offline — no network, no
clock, no external service.

## Reproduce

From the repository root:

```sh
cargo run -p win-transition --example demo -- demo
```

This writes, into `demo/`:

| File | What it is |
|---|---|
| `Contract.txt` | the sample source document that gets imported |
| `Summary.txt` | the file the governed transition actually created |
| `accepted-transition.win` | a sealed, portable proof of the **accepted** transition |
| `refused-transition.win` | a sealed proof of a **refused** external-publish attempt |
| `tampered-example.win` | the accepted artifact with one content byte flipped |
| `expected-verification-results.txt` | the verification matrix printed for all three |

## What happens, step by step

1. **Import** — the source document is read and given a content identity
   (`sha256:…` of its bytes). That hash is the *subject* every later step binds to.
2. **Propose** — a local, deterministic proposer (`win-local-extractive-proposer`)
   suggests a summary. It is **not** an LLM and makes no claim to have understood
   the document. It can only propose; it holds no authority.
3. **Authorize** — a *separate* authorizer issues a grant scoped to exactly
   `LocalWrite`, bound to that subject hash.
4. **Execute** — a *separate* filesystem executor creates `Summary.txt` and
   returns a signed receipt (what was requested, what happened, the output hash).
5. **Record + seal** — a *separate* recorder seals the whole transition into
   `accepted-transition.win`.
6. **Refuse** — the proposer then asks to *publish* the summary externally. The
   grant only covers local writing, so the executor **refuses**: no network call,
   no file, and the refusal itself is signed and sealed into
   `refused-transition.win`. A refusal is a record, not a discarded error.
7. **Verify** — each `.win` is reopened *from its bytes alone* and checked.

## Expected results

```text
ACCEPTED  → OVERALL: PASS   (container VALID, content VALID, signatures VALID, receipt PRESENT)
REFUSED   → OVERALL: PASS   (a valid signed record of AuthorizationScopeExceeded; no side effect)
TAMPERED  → OVERALL: FAIL   (CONTENT INTEGRITY: MISMATCH — content altered after sealing)
```

Note the tampered case: the **signatures are still VALID** but **content
integrity is MISMATCH**. That distinction is deliberate — it separates *"someone
changed the file"* from *"someone forged the record."*

## Honest limits (what a PASS does and does not mean)

A `PASS` proves: the container is intact, the carried content matches the hash
the transition sealed, and every signature was made by the keys named inside the
artifact. It does **not** prove **who owns those keys** — the matrix says
`REAL-WORLD IDENTITY: NOT ESTABLISHED`. It also does not validate the *factual*
correctness of the summary (`FACTUAL CLAIMS: NOT INDEPENDENTLY ESTABLISHED`).

The signing keys are freshly generated on each run, so the `SIGNING KEY` line
will differ run to run; the content hashes are deterministic and will not.
