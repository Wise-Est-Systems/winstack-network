# The Wise Grammar

> The cultural and product constitution. Every line of code, error message,
> animation, blog post, and pitch derives from this document. If a future
> contributor asks *"can we add X?"*, the answer is whatever this document
> implies. If the document is silent, debate it here — not in the codebase.

`PROOF-SPEC.md` is how the system works. This document is what the system
*means*.

---

## 1. What Wise Is

**One sentence:** Wise gives every file a *win tag* — a small portable
record that travels with the file so receivers can check it offline.

**One paragraph:** A win tag carries a witness, a creation date, and a
fingerprint of the file. Receivers read it without accounts, without
trusting any server. A file without a win tag is *untagged* — neutral,
not dangerous. As more files wear win tags, untagged files start to feel
less complete.

**The format:** `.win` stands for **Wise Independent Network** — three
words that compress the doctrine. *Wise* (the family). *Independent* (no
organizational dependency for verification). *Network* (no central
operator). The file extension carries its own meaning; nothing in the
verification path needs to know who built it.

The thing is verification. Mechanism is mechanism.

---

## 2. First Principles

Foundational rules. If a feature violates one, the feature is wrong.

- **P1 — The win tag travels with the file.** Anything that requires the
  file to come "back to Wise" to be understood is broken.
- **P2 — Decorate sealed files, not untagged ones.** Sealed files wear win
  tags. Untagged files wear nothing. We never paint warnings on untagged
  files; the absence is the signal.
- **P3 — Three states, no fourth.** *Verified, Tampered, Invalid.* Every
  receiver-side surface returns exactly one of these.
- **P4 — Witnesses are people, not keys.** Every win tag shows a face,
  avatar, or logo wherever space allows. Hex strings are debug info.
- **P5 — Tampered is past tense.** When a file disagrees with its win
  tag, we say what was lost in plain words, not error codes.
- **P6 — Distribution is the product.** Wise exists so win tags
  appear on files everywhere. Any feature that pulls users into a
  Wise-branded surface to use their own files is the wrong direction.
- **P7 — Files have lineage.** A file is a generation, not a version.
  Parents, children, descendants. Lineage is core, not optional.
- **P8 — One artifact, many surfaces.** The same `.win`, the same
  `truth.systems/v/<hash>` URL, the same win tag — desktop, browser,
  Gmail, Slack, court filing. We do not build per-surface formats.
- **P9 — No accounts, ever.** Verifying a win tag never requires a
  Wise login. Witnesses bring their own keys. Receivers bring their
  own eyes.
- **P10 — The grammar is not a skin.** The vocabulary in this document
  is the product's interior, not marketing copy on top of a security
  tool. Engineers, code, error messages, and log lines all use it.
- **P11 — Drop is the only ritual.** On browser and app surfaces, the
  user does nothing but drop a file. No clicks before the verdict. No
  menus. No save buttons gating the outcome. If a flow requires a
  second action from the user, the flow is wrong and we redesign it.
- **P12 — The win tag verifies itself.** A receiver reaches a verdict
  from a `.win` file plus any compliant verifier — without contacting a
  Wise server, without trusting a Wise key, and without
  consulting any Wise-controlled registry. The only verification
  gates are: witness signature, file-vs-tag hash, time signature, and
  (optional) RFC 3161 anchor. Anything else — module registrations,
  policy proofs, organizational metadata — rides along as informational
  annotations and never fails a file. If Wise.Est Systems disappears
  tomorrow, every `.win` ever produced still verifies.

---

## 3. The Three States

Canonical names. The *only* terms used in user-facing surfaces.

| State | Meaning | Triggered by |
|---|---|---|
| **Verified** | The win tag matches the file. The witness's signature is intact. The file is unchanged since it was sealed. | Default success. |
| **Tampered** | The file was sealed once, but it has been changed since. The original is gone. | File-vs-tag hash mismatch. |
| **Invalid** | We can't verify this win tag. The signature won't read, the container is malformed, or the tag does not fit the file. | Any failure other than tampering. |

**Three states. No fourth. Ever.** New edge cases map onto the existing
three or layer in as engineering-only failure codes (see § 11). Adding a
fourth state breaks every receiver surface. Don't.

**Why "Invalid" subsumes the rest.** The receiver gains nothing from
distinguishing "wrong tag," "unreadable signature," and "broken
container" — operationally they all mean *we can't tell you who sealed
this.* Power-user inspection panels may surface the underlying
`FailureCode`; primary user surfaces must not.

---

## 4. The Lexicon

Vocabulary with meaning, not substitutions.

- **Win tag** — the `.win` container or the `truth.systems/v/<hash>` URL.
  The portable artifact. *Anchor noun.* Plain on purpose; the smallness
  is the point.
- **Witness** — the holder of the signing key. Primary noun for the
  signer. Can be a person, an org (Anthropic), or a process (CI pipeline).
- **Seal** — the verb for giving a file a win tag. *"I sealed this file."*
  The CLI is `wise win <file>`; the file extension is `.win`; the act
  is *sealing*. Brand cohesion: every artifact and product name shares
  the `win` root.
- **Sealed** — past tense of *seal.* *"This file was sealed on 2026-04-26."*
- **Created on / Creation date** — the timestamp on the win tag. We do
  *not* say "born" or "birthday." Just *created.*
- **Anchored creation date** — a timestamp witnessed by an RFC 3161 TSA.
  Only anchored creation dates are independently verifiable.
- **Lineage** — the chain of related files.
- **Generation** — a node in a lineage.
- **Verify / Verification** — the act of checking a win tag.
- **Untagged** — a file with no win tag. Neutral.
- **Heir** — a successor key in a delegation chain.
- **Fingerprint** — the file hash. Internal/advanced UI only.

**Words we do not use in user surfaces:** *born, birthday, alive, wounded,
unrecognized, dying, recognize, recognition, hash, signature, key,
certificate, chain, attestation, integrity, cryptographic.* They live in
the engineering layer for precision; they never reach users.

---

## 5. The Sensory Grammar

Each state has one complete sensory definition. Identical across desktop,
browser, extension, embeds.

**Verified**
- Color: warm cream with a soft golden edge.
- Motion: a single calm settle, then still.
- Icon: filled circle with the witness avatar centered.
- Tone: present tense. *"Verified. Witnessed by Anthropic. Created on 2026-04-26."*

**Tampered**
- Color: bruise-blue (violet-grey undertone). *Never red.*
- Motion: one settle, then a single break across the icon.
- Icon: witness avatar with a thin fissure.
- Tone: past tense. *"This file was sealed by Anthropic on 2026-04-26 and changed sometime after."*

**Invalid**
- Color: flat grey, no warmth.
- Motion: none.
- Icon: faceless silhouette.
- Tone: plain, almost apologetic. *"Invalid. We can't verify this win tag."*

**Untagged file**
- Visually: identical to a normal file. No badge. No warning. *Nothing.*
- This is inviolable. (P2.)

---

## 6. The Artifacts

Complete inventory. Anything not on this list, we don't build.

- **The `.win` container** — file format carrying the win tag. Specced in
  `PROOF-SPEC.md`.
- **The `truth.systems/v/<hash>` URL** — share-anywhere form of the win
  tag. Survives Gmail/Slack/iMessage attachment-stripping. **Critical.**
- **The win tag (visual)** — rendered card: witness, creation date,
  state. Same design across all surfaces.
- **The lineage view** — graphical genealogy.
- **The verifier (offline)** — desktop, browser, extension, CLI, WASM.
  One core.
- **The witness key** — held by witnesses, never by Wise servers.
- **The press kit** — public assets ready for the viral-incident moment.

---

## 7. The Rituals

Four user actions. Every button in every Wise surface reduces to one
of these.

- **Sealing** — drop a file. The file gains a win tag. *"This file is
  sealed. Witnessed by you. Created today."*
- **Verifying** — drop a sealed file. The verifier returns one of
  Verified / Tampered / Invalid.
- **Inspecting** — open the details panel to see witness key, fingerprint,
  time source, lineage. Engineering vocabulary is permitted here only.
- **Sharing** — copy the `truth.systems/v/<hash>` URL. The receiver opens
  it and verifies in any browser, no install.

---

## 8. The Roles

- **Author** — creates the file content. May or may not be the witness.
- **Witness** — seals the file with their key. Person, organization, or
  process (CMS, CI pipeline, AI model).
- **Receiver** — gets the file, verifies the win tag.
- **Heir-witness** — successor key in a delegation chain.
- **Time anchor** — external RFC 3161 TSA that adds an anchored creation
  date.

A single file has one witness on its win tag. AI models can be witnesses
(Claude → Anthropic's key, Anthropic's logo).

---

## 9. The Receiver

The receiver is the cultural engine.

- Sealing is friction the witness bears; verification is value the
  receiver gets. We invest more in the receiver's surface than the
  witness's.
- The receiver never has to install anything. A URL alone is enough —
  that is what `truth.systems/v/<hash>` is for.
- The receiver's question is *"is it verified?"* — that is the phrase we
  want in cultural circulation.

---

## 10. The Voice

- **Calm.** Never urgent. Even Tampered is calm.
- **Tense carries meaning.** Present for verified, past for tampered.
  *"This file is verified."* / *"This file was sealed and changed since."*
- **Plain.** Words a 12-year-old understands. *"Unchanged since,"* not
  *"cryptographic integrity."*
- **Specific.** Always name the witness, the creation date, the lineage
  when known.
- **Quiet.** No exclamation points. No *Success!* No *Warning!* No emoji
  in core UI except witness avatars.
- **Honest.** When something is unknown, we say *"we can't tell,"* not
  *"ERROR."*

### Canonical messages

> *Verified. Witnessed by Anthropic. Created on 2026-04-26. Anchored.*

> *Tampered. This file was sealed by Anthropic on 2026-04-26 and changed
> sometime after. The original is gone.*

> *Invalid. We can't verify this win tag. The file may still be fine, but
> we can't tell you who sealed it.*

---

## 11. The Non-Goals

Explicit refusals.

- **No fourth state.** Three covers all cases.
- **No trust score.** A win tag tells you who, when, and intact-or-not. It
  does not tell you whether to *believe* the witness. That is the
  receiver's job.
- **No content moderation.** Sealing is not endorsement.
- **No accounts. No login. No SSO. No cloud-only mode.** Forever. (P9.)
- **No platform expansion** — not a CMS, sharing service, storage layer,
  or marketplace.
- **No encryption of content, no steganography, no hidden artifacts.** Win
  tags are visible and addressable.
- **No "premium" verifier.** Verification is free, for everyone, forever.
  Any monetization is on sealing-at-scale (witnesses), never on receivers.
- **No watermark.** Watermarks are hidden. Win tags are visible. We do
  the opposite of watermarking.
- **No multi-language SDKs.** One WASM verifier replaces per-language
  bindings.
- **No "born" or "birthday" language.** A file is *created.* That's it.

---

## 12. Success Conditions

In order of escalation.

- **Local win (12 months, by 2027-04-26):** one major AI lab seals
  outputs by default in some surface. *Adoption Plan kill criterion.*
- **Surface win (24 months):** four+ recipient surfaces (Gmail, Slack,
  Chrome, mobile preview) display win tags natively.
- **Linguistic win (36 months):** *"Is it verified?"* / *"Is it sealed?"*
  appears in tech writing, podcasts, and casual chat without prompting.
- **Cultural win (48 months):** the untagged file feels socially
  incomplete. People expect win tags the way they expect HTTPS locks.

### Anti-success — we have failed if:

- Wise becomes a SaaS product with logged-in-user counts as the
  primary metric.
- The grammar dilutes to *valid / invalid.*
- A fourth state is added.
- Receivers can't verify offline.

---

## 13. How This Document Is Used

This is the constitution. Every change in the codebase derives from it.

**Derivation order:**
1. Verifier UI strings.
2. URL verifier route (`truth.systems/v/<hash>`).
3. The `VerificationStatus` enum in `canon-types`.
4. Sensory grammar in CSS / animations.
5. WASM build of the `verifier` crate.
6. Lineage / family-tree view.
7. Browser extension and chat-app integrations (downstream of WASM).
8. AI-lab pitch deck.

If a contributor proposes a feature this document does not imply, they
propose it here first — as an amendment — before writing code.

---

## 14. Finality

**The core is locked.** *Verified, Tampered, Invalid* are the three
states. *Win tag* is the artifact. *Created* is the timestamp word.
*Untagged* is the no-tag noun. We will not revise these.

The principles list (§ 2) may **grow** — new principles can be added
when they capture commitments we discover by living with the product.
Existing principles cannot be retracted or weakened. The state grammar
(§ 3), lexicon (§ 4), sensory grammar (§ 5), and non-goals (§ 11) do not
change. If a proposal requires changing them, the answer is no.
