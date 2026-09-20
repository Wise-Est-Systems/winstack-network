# W.I.N. — Product Overview

W.I.N. gives digital objects and digital actions an independently inspectable
record of identity, evidence, authority, execution, and resulting state.

Bring an important digital object into W.I.N., and it preserves an independently
inspectable record of what it is, what happened to it, why each change was
permitted or refused, and whether the complete record remains intact.

## Surfaces

| Surface | What it is | Where |
|---|---|---|
| **W.I.N. Desktop** | The primary app. Import → review → authorize → execute → refuse → export → verify. | `Wise.app` (Tauri), `window/transition.html` + `window-api` |
| **W.I.N. CLI** | `win summarize <file>`, `win verify <file.win>`. | `crates/cli` (binary `win`) |
| **W.I.N. SDK** | The governed-transition engine as a library. | `crates/win-transition` |
| **W.I.N. Conformance** | Frozen vectors an independent implementation checks against. | `crates/win-conformance` |
| **`.win` artifact** | The portable, self-verifying proof. | `win-format` container + `WIN-UTP-ARTIFACT/0.1` proof |

## The core promise (technically true today)

A person can:
1. bring a document into W.I.N.,
2. let a local proposer suggest a change,
3. inspect the proposal, evidence, and required authority,
4. grant narrowly scoped authority,
5. watch it execute and see the resulting identity,
6. export a portable `.win` proof,
7. independently verify it, and
8. see an unauthorized action (external publish) refused with **no side effect**.

Every step is real and covered by tests (workspace: 350 passing; conformance: 10
vectors).

## What it proves — and does not

It establishes: exact content identity, content integrity, key-custody
signatures, causal lineage, scoped authorization, execution receipts, recorded
refusals, internal consistency, and tamper evidence.

It does **not** establish: real-world identity of a key holder, factual
correctness of content, or that a proposer's summary is right. See
[VERIFICATION_RESULTS](VERIFICATION_RESULTS.md) and [KNOWN_LIMITS](KNOWN_LIMITS.md).

## Design law

The surface always answers: *what is changing, why is it allowed or refused, what
actually happened, can I verify it* — with the technical detail inspectable
beneath, never hidden behind a vague green check.
