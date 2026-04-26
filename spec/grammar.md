# The Winstack Grammar

> The cultural and product constitution. Every line of code, animation, error
> message, blog post, and pitch derives from this document. If a future
> contributor asks *"can we add X?"*, the answer is whatever this document
> implies. If the document is silent, debate it here — not in the codebase.

`PROOF-SPEC.md` is how the system works. This document is what the system
*means*.

---

## 1. What Winstack Is

**One sentence:** Winstack gives files a name, a parent, and a birthday — so
receivers can recognize them.

**One paragraph:** Winstack is a system for naming files. A named file carries
a small, portable record — its *name tag* — that travels with it. The name
tag says who witnessed the file's birth, when, and whether the file is
unchanged since. Receivers read the name tag offline, without accounts,
without trusting any server. A file without a name tag is an *orphan*: not
dangerous, just nameless. As more files wear name tags, naked files start to
feel like strangers.

The words *proof, cryptographic, verify, hash* do not appear in the headline
definition. They are mechanism. The thing is recognition.

---

## 2. First Principles

Foundational rules. If a feature violates one, the feature is wrong.

- **P1 — The name tag travels with the file.** Anything that requires the
  file to come "back to Winstack" to be understood is broken.
- **P2 — Decorate life, not danger.** Sealed files wear name tags. Naked
  files wear nothing. We never paint warnings on naked files; the absence is
  the signal. Coloring naked files red turns them into dismissible security
  warnings.
- **P3 — Recognition, not authentication.** The verifier says hello, not
  "credentials accepted."
- **P4 — Witnesses are people, not keys.** Every name tag shows a face,
  avatar, or icon. Hex strings are debug info, never primary UI.
- **P5 — Tampering is grief, not error.** When a file disagrees with its
  name tag, we tell the user *what was lost.* No "ERROR 0x4F." A small
  mourning is more memorable than any warning.
- **P6 — Distribution is the product.** Winstack exists to make name tags
  exist on files everywhere. Any feature that pulls users into a
  Winstack-branded surface to use their files is the wrong direction.
- **P7 — Files have lineage.** A file is a generation, not a version.
  Parents, children, descendants. The lineage view is core, not optional.
- **P8 — One artifact, many surfaces.** The same `.win`, the same
  `winstack.dev/v/<hash>` URL, the same name tag — desktop, browser, Gmail,
  Slack, court filing. We do not build per-surface formats.
- **P9 — No accounts, ever.** Reading a name tag never requires a Winstack
  login. Witnesses bring their own keys. Receivers bring their own eyes.
- **P10 — The grammar is not a skin.** Life-vs-orphan language is the
  product's interior, not marketing copy on top of a security tool.
  Engineers, contracts, error messages, and log lines all speak it. If a
  developer reading server logs sees `VERIFIED` instead of `Alive`, we have
  failed at the level of culture.

---

## 3. The Four States

Canonical names. The *only* terms used in user-facing surfaces.

| State | Meaning | Triggered by |
|---|---|---|
| **Alive** | Unchanged since its naming. The witness's signature is intact. The name tag matches the file. | Default success. |
| **Wounded** | Was named once, but has been changed since. The original is gone. We can show who named it and when, but the file you have now is not that file. | File-vs-name-tag hash mismatch. |
| **Unrecognized** | This name tag does not belong to this file, or the witness's signature can't be read. We can't tell you who named this. | Signature failure / wrong proof. |
| **Dying** | The name tag itself is decomposing — container broken, truncated, malformed. The file underneath may still be alive; we just can't read its name. | `.win` container malformed. |

**No fifth state, ever.** New edge cases map onto the existing four. Scope
creep here destroys the grammar.

**Naming rationale.** *Wounded* is loaded — that is the point. Clinical
alternatives (*Altered*, *Changed*, *Broken*) are forgettable. Emotional grief
is the cultural payload. We keep *Wounded.*

---

## 4. The Lexicon

Vocabulary with meaning, not just substitutions.

- **Name tag** — the `.win` container or the `winstack.dev/v/<hash>` URL.
  The portable artifact. *Anchor noun.* Plain on purpose; smallness is the
  point.
- **Witness** — the holder of the signing key. Primary noun for the signer
  in single-file UI. Can be a person, an org (Anthropic), or a process (a CI
  pipeline).
- **Parent / Child** — used *only in lineage view*, where ancestry is the
  subject. Not used in single-file UI to describe the witness — that would
  be too strong for AI-lab signed files.
- **Naming** — the act of sealing. *"I named this PDF this morning."*
- **Born** — synonym for sealed. *"Born on April 26."*
- **Birthday** — the timestamp on the name tag.
- **Anchored birthday** — a timestamp witnessed by an RFC 3161 TSA. Only
  anchored birthdays are independently verifiable.
- **Lineage** — the chain of related files.
- **Generation** — a node in a lineage.
- **Recognition** — the act of verifying.
- **Naked** — a file with no name tag. Neutral, not pejorative.
- **Orphan** — a file whose name tag references an unknown or silent
  witness. Stronger than naked.
- **Stranger** — informal for the Unrecognized state.
- **Heir** — a successor key in a delegation chain.
- **Resurrection** — re-naming a Dying file.
- **Reincarnation** — the honest framing of resurrection: a new life with a
  new witness; the original is gone. (See § 5b.)
- **Inscription** — the data inside a name tag.
- **Hand** — informal for signing key. *"Signed by Anthropic's hand."*
- **Fingerprint** — the file hash. Internal/advanced UI only.
- **Family tree** — the lineage view UI.
- **Witness notice** — a public, signed statement from a witness about
  their key (dissolution, renunciation, compromise). See § 5b.

**Words we do not use in user surfaces:** *proof, hash, signature, key,
certificate, chain, verified, valid, invalid, tampered, error, warning,
encrypted, cryptographic, integrity, attestation.* They remain in the
engineering layer for precision; they never reach humans.

---

## 5. The Sensory Grammar

Every state has a complete sensory definition. Same across desktop, browser,
extension, embeds.

**Alive**
- Color: warm cream with soft golden edge
- Motion: slow steady pulse, ~60 BPM
- Sound (optional): a single soft recognition tone
- Icon: filled circle with witness avatar centered
- Behavior: lingers calmly, doesn't fade

**Wounded**
- Color: bruise-blue (violet-grey undertone) — *never red*
- Motion: heartbeat that pulses once, then flatlines
- Sound: a tone interrupted mid-note
- Icon: witness avatar with a small fissure
- Tense: past — *"was alive,"* *"was named"*

**Unrecognized**
- Color: flat grey, no warmth
- Motion: none
- Sound: silence
- Icon: faceless silhouette
- Tone: plain, almost apologetic — *"I don't know this file."*

**Dying**
- Color: faded sepia with frayed edges
- Motion: subtle glitching at the edges
- Sound: faint static
- Icon: a partially erased name tag
- Affordance: one button — *Give it a new name*

**Naked file**
- Visually: identical to a normal file. No badge. No warning. *Nothing.*
- This is inviolable. (P2.)

---

## 5b. The Six Deaths

The four states describe the *file-in-front-of-the-verifier right now.* They
are not the only ways a named file can lose life. There are six. Three are
covered by the four states; three layer in as **annotations** without
breaking P3 / no-fifth-state.

### Three deaths that are file states

1. **The Wound** — file altered after naming. State: **Wounded.** The
   original is gone; what's in your hand wears its clothes.
2. **The Mute** — name tag corrupted. State: **Dying.** Resurrection
   possible if the bytes underneath are intact.
3. **The Mismatch** — wrong name tag for this file. State: **Unrecognized.**
   No story to tell.

### Three deaths that are witness annotations

These do not change the file's state. The verifier still says **Alive.** The
annotation rides alongside.

4. **The Orphaning** — the witness has gone silent. Key still valid; nobody
   speaks for it anymore. *Annotation: Orphaned.*
   - Heuristic: explicit dissolution notice, **or** witness's last published
     activity older than a configurable threshold.
5. **The Renunciation** — the witness explicitly disowns the file (or all
   files signed before/after a date). Voluntary disowning. *Annotation:
   Disowned.*
6. **The Stolen Hand** — the witness's key was compromised. The witness
   publishes a compromise notice with a date. Files signed *before* the
   theft remain trustworthy; files signed *after* may be forgeries. The
   verifier shows the file's birthday relative to the compromise date.
   *Annotation: Compromised (before)* or *Compromised (after).*

### The Slow Death — the Fade

Beyond the six, the eschatology — long-term graceful decay every
cryptographic system faces.

- **Faded anchor** — RFC 3161 TSA root certificate expired or revoked
  retroactively. Anchored birthday downgrades to local-only.
- **Faded algorithm** — file signed with a since-deprecated algorithm.
  Signature still checks technically; strength has eroded.
- **Faded format** — `.win` v1 has been superseded; old verifiers may not
  exist for everyone.

The product must age gracefully. A file named in 2026 should still be
recognizable in 2050, even if every annotation says *Faded.*

### Resurrection is reincarnation, not revival

When you resurrect a Dying file (re-name it):

- **You become the new witness.** The old witness is still dead from this
  name tag's perspective.
- The new name tag *references* the dying parent's last-known inscription
  (a *previously named by [X] on [date], but that name was lost* footnote),
  preserving narrative lineage even if cryptographic continuity is broken.
- The new file is a *child generation* in the lineage, not a clone. Its
  birthday is *now,* not the original.
- The original is still gone.

**Lock:** the harsh version. Honesty is the product's moat. The verifier
says it plainly:

> *Resurrected. This file was once named by Anthropic on April 26, 2026,
> but the name was lost. You named it again today. The original is gone —
> but this file lives.*

### Sensory grammar of death (witness annotations)

- **Orphaned** — witness avatar gets a thin grey *mourning band* around it.
  Name tag stays warm. The file is alive; the parent is missed.
- **Disowned** — witness avatar is *struck through* with a thin diagonal
  line. Tone: estrangement.
- **Compromised** — witness avatar gets a small *fissure* (distinct from
  Wounded — the witness is fissured, not the file). Adjacent text shows
  compromise date relative to file birthday.
- **Faded** — the entire name tag desaturates slightly, like an old
  photograph. Still legible. Still warm. Just older.

Wounded and Faded must look distinctly different. Wounded is *violent
recent loss.* Faded is *gentle long passage.* Bruise-blue vs. sepia.

---

## 6. The Artifacts

Complete inventory. Anything not on this list, we don't build.

- **The `.win` container** — file format carrying the inscription. Specced
  in `PROOF-SPEC.md`.
- **The `winstack.dev/v/<hash>` URL** — share-anywhere form of the name
  tag. Survives Gmail/Slack/iMessage attachment-stripping. **Critical.**
- **The name tag (visual)** — rendered card: witness avatar, birthday,
  state. Same design across all surfaces.
- **The lineage view (family tree)** — graphical genealogy.
- **The verifier (offline)** — desktop, browser, extension, CLI, WASM. One
  core.
- **The witness key** — held by witnesses, never by Winstack servers.
- **The death notice** — the Wounded UI. Mournful, named, dated.
- **Witness notices** — public, signed statements from witnesses about
  their keys. The only network-dependent artifact.
- **The press kit** — public assets ready for the viral-incident moment.

### Witness directory (decision)

Witness notices live as **static, witness-signed JSON at a well-known URL**:

```
https://<witness-domain>/.well-known/winstack/notices.json
https://winstack.dev/witnesses/<key-id>.json   (community mirror)
```

Mirrored to a public Git repository for transparency and history. This is
the only piece of shared online infrastructure in the system. Verifiers
fetch notices when online; offline verification still returns the four-state
result and says plainly:

> *Alive. (No witness notices loaded; if the witness has died or been
> compromised, you won't see it here.)*

We can evolve to IPFS / content-addressed publish later without breaking
existing offline verifiers.

---

## 7. The Rituals

Six user actions. Every button in every Winstack surface reduces to one of
these.

- **Naming (sealing)** — drop a file. ~200ms wax-seal animation. The file
  gains a name tag. *"This file is alive. Witnessed by you. Born today."*
  The user feels they did something.
- **Recognition (verifying)** — drop a named file. Verifier says hello:
  warm glow, heartbeat pulse, witness face appears. The user feels: meeting
  a friend.
- **Mourning the file (Wounded)** — verifier dims, flatlines. Original
  witness and birthday appear in past tense. The user feels: small loss.
- **Mourning the witness (Orphaned / Disowned / Compromised)** — verifier
  stays warm but adds the witness annotation gently. *"This file is alive,
  but its witness is gone."* The user feels: quiet, distanced sadness —
  different from the sharp grief of Wounded.
- **Resurrection (Dying)** — one button: *Give it a new name.* A new naming
  ritual occurs. The new file becomes a generation in the lineage if
  possible. The user feels: agency.
- **Discovery (Alive in the wild)** — receiver opens email/Slack; the name
  tag is visible inline with witness avatar and birthday. The receiver
  feels: this file came from someone.

---

## 8. The Roles

- **Author** — creates the file content. May or may not be the witness.
- **Witness** — names the file with their key. May be a person, an
  organization, or a process (CMS, CI pipeline, AI model).
- **Receiver** — gets the file, reads the name tag.
- **Heir-witness** — successor key in a delegation chain. Used for key
  rotation without losing lineage.
- **Time anchor** — external RFC 3161 TSA that adds an anchored birthday.

A single file has *one* witness on its name tag, but a lineage can have many
ancestral witnesses. AI models can be witnesses (Claude → Anthropic's key,
Claude's avatar).

The author and witness can be the same. They often are. But not always
(e.g., a CMS witnesses on behalf of the author).

---

## 9. The Receiver

The receiver is the cultural engine. Not a passive consumer.

- The receiver's experience is what spreads the behavior. Sealing is friction
  the witness bears; recognition is value the receiver gets — backwards
  incentive at the design layer. Universal adoption flips it: the receiver's
  surface (Gmail, Slack, browser) decorates name tags, the absence becomes
  the signal, and witnesses adopt under social pressure.
- We invest more in the receiver's surface than in the witness's surface.
  Naming should be one ritual; recognition should be everywhere.
- The receiver never has to install anything to verify. A URL alone is
  enough — that is what `winstack.dev/v/<hash>` is for. Browser
  extensions, native chat-app integrations, and embeds are amplifiers, not
  prerequisites.
- The receiver's question — *"is it alive?"* — is the phrase we want in
  cultural circulation. Every artifact in the system should make that
  question easy to ask and easy to answer.

---

## 10. The Voice

- **Calm.** Never urgent. Even Wounded is calm-grief, not panic.
- **Tense carries meaning.** Present for alive, past for lost. *"This file
  is alive."* / *"This file was alive."*
- **Plain.** Words a 12-year-old understands. *"Unchanged since,"* not
  *"cryptographic integrity."*
- **Specific.** Always name the witness, the birthday, the lineage when
  known. Never abstract.
- **Quiet.** No exclamation points. No *Success!* No *Warning!* No emoji in
  core UI except witness avatars.
- **Honest.** When something is unknown, we say *"I don't know,"* not
  *"ERROR."*

### Canonical messages

> *Alive. Witnessed by Anthropic. Born April 26, 2026. Anchored.*

> *Wounded. This file was alive. It was named on April 26 by Anthropic, and
> changed sometime after. The original is gone.*

> *Unrecognized. I can't read this name tag. The file may still be fine,
> but I can't tell you who named it.*

> *Dying. This name tag is decomposing. The file underneath may still be
> alive. Would you like to give it a new name?*

> *Alive. Witness orphaned (Anthropic, silent since 2031). Anchored.
> Algorithm faded (Ed25519, deprecated 2034).*

> *Alive. Compromised — this file was named after the witness's hand was
> stolen on May 3, 2026. The signature is real, but it may not be the
> witness's.*

---

## 11. The Non-Goals

Explicit refusals, even when asked.

- **No trust score.** A name tag tells you who, when, and intact-or-not. It
  does not tell you whether to *believe* the witness. That is the receiver's
  job.
- **No content moderation.** Naming is not endorsement.
- **No accounts. No login. No SSO. No cloud-only mode.** Forever. (P9.)
- **No platform expansion** — not a CMS, sharing service, storage layer, or
  marketplace.
- **No encryption of content, no steganography, no hidden artifacts.** Name
  tags are visible and addressable.
- **No fifth state.** Four covers all cases.
- **No "premium" verifier.** Recognition is free, for everyone, forever.
  Any monetization is on naming-at-scale (witnesses), never on receivers.
- **No watermark.** Watermarks are hidden. Name tags are visible. We do the
  opposite of watermarking.
- **No multi-language SDKs.** One WASM verifier replaces per-language
  bindings. Python, Go, JS, Ruby, Java all call the same artifact.

**Open question (deferred):** *should hardware-backed witness keys persist
a "remember this hand" affordance for repeat naming?* Default answer: no.
Each naming is a fresh act. Reopen if friction data demands it.

---

## 12. Success Conditions

In order of escalation.

- **Local win (12 months, by 2027-04-26):** one major AI lab seals outputs
  by default in some surface. *Adoption Plan kill criterion.*
- **Surface win (24 months):** four+ recipient surfaces (Gmail, Slack,
  Chrome, mobile preview) display name tags natively. Receivers see *"Alive
  — witnessed by X"* without installing anything.
- **Linguistic win (36 months):** *"Is it alive?"* / *"Is it named?"*
  appears in tech writing, podcasts, and casual chat without prompting.
- **Cultural win (48 months):** the naked file feels socially incomplete.
  People expect name tags the way they expect HTTPS locks. Universal
  absence-as-signal.

### Anti-success — we have failed if:

- Winstack becomes a SaaS product with logged-in-user counts as the primary
  metric.
- The grammar dilutes to *verified / unverified.*
- Name tags are stripped from major surfaces and the URL fallback isn't
  there to catch them.
- A fifth state is added.
- Receivers can't verify offline.

---

## 13. How This Document Is Used

This is the constitution. Every future change in the codebase derives from
it.

**Derivation order:**
1. Verifier UI strings — first concrete change.
2. URL verifier route (`winstack.dev/v/<hash>`).
3. Type-system rename in `canon-types::VerificationStatus` (4 states).
4. Sensory grammar in CSS / animations.
5. Witness notices schema + fetcher.
6. WASM build of the `verifier` crate.
7. Lineage / family-tree view.
8. Resurrection ritual.
9. Browser extension and chat-app integrations (downstream of WASM).
10. AI-lab pitch deck (Adoption Plan Phase 2).

If a contributor proposes a feature that is not implied by this document,
they should propose it here first — as an amendment — before writing code.
