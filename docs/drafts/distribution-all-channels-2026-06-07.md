# Distribution packet — all channels — 2026-06-07

Status: DRAFTS ONLY. Nothing has been posted. Henry posts each one by hand.

## Evidence sources (read these before posting; do not exceed what they prove)

- **EP-WIN** — `/Users/thekingflame/Desktop/WinStack_Network_v1/docs/evidence-packet-2026-06-07.md`
  - L99: `passed=323 failed=0 ignored=0` (aggregate of all `test result:` lines)
  - L118–123: `crates/window-api/tests/check_endpoint_states.rs` — valid → Verified, payload-tampered → Tampered, signature-tampered → Invalid, truncated → Damaged
  - L116: `adversarial_corpus.rs` (25 passed); L116/L143: `tamper_grid.rs` (30 passed)
  - L146–149: golden `.win` regression still verifies (frozen fixture)
  - L15–17: Rust stable 1.94.1, macOS, single developer machine
  - L153–161 (LIMITS, carry verbatim): single-machine, single-run on macOS; does NOT prove the Ubuntu/Windows CI matrix, MSRV (1.82), `fmt`, `clippy`, or `cargo doc`; first-party (author's own tests run by author's agent), no external/third-party audit; does not prove cryptographic soundness, performance, or real-world adversary resistance beyond the encoded corpus; 323 is suite breadth, not coverage.
  - L165–169 (strongest defensible claim): "On a clean checkout of commit `45aa999` with Rust 1.94.1 on macOS, WinStack's own workspace test suite (`cargo test --workspace --all-features`) passes with 323 tests, 0 failures — including the integration tests that assert a valid `.win` verifies, a tampered payload reports Tampered, and a tampered signature reports Invalid."

- **EP-WOP** — `/Users/thekingflame/Desktop/wiseorder-protocol/reports/evidence_packet_make_ci_2026-06-07.md`
  - L96–98: `vectors: 33 checked, 33 passed, 0 failed`; `implementations: 2 checked, 2 passed, 0 failed`
  - L114–135: Rust verifier track + Go verifier track each independently re-derive the 33 vectors + 10 corpus entries (three implementations: Python, Rust, Go, agree)
  - L176: conformance reports regenerate byte-identical (deterministic)
  - L178–179 (LIMITS): `audit_status=NOT_AUDITED`; CI green on machines other than this host is UNVERIFIED
  - L196–201 (LIMITS): cross-machine reproducibility unproven; first-party only; threat model not claimed exhaustive

### Repo / link facts (from README.md)
- Repo: `https://github.com/Wise-Est-Systems/winstack-network`
- Site: `https://wisest.systems`
- One public file type: `.win` (proof + change-map live inside it)
- README L32–45: a verified `.win` proves the file is unchanged since sealed by *some key*; it does NOT prove the real-world identity behind the key. Integrity is separate from human trust. Carry this distinction — never imply identity is proven.

### Differentiator (weave in where natural)
Provenance / sealing = proactive proof attached at the moment of creation.
Detection (Resistant AI, Klippa, Inscribe, etc.) = reactive guessing after the fact.
The honest line: a sealed file carries its own proof; you verify, you don't guess.

---

## 1. X / Twitter — thread

- [ ] Posted

**Source:** EP-WIN L99, L118–123, L116, L153–161; README L32–45.

> 1/
> I built WIN: files that carry their own proof. You seal a file into a `.win` container; anyone can drop it into a verifier and get one answer — Verified, Tampered, or Invalid — offline, no account, no server to trust.
>
> 2/
> The point isn't detecting fakes after the fact. It's the opposite. Most tools in this space *guess* whether a document was altered or AI-generated (detection). WIN attaches the proof at creation (provenance). You verify a sealed file. You don't guess about a loose one.
>
> 3/
> Concrete receipt, today: on a clean checkout (commit 45aa999, Rust 1.94.1, macOS), the workspace test suite passes — 323 tests, 0 failures. That includes the integration tests that assert the three results actually behave:
>
> 4/
> • valid `.win` → Verified
> • payload changed → Tampered
> • signature changed → Invalid
> • truncated container → Damaged
> Plus an adversarial corpus (25) and a tamper grid (30) that the format rejects.
> (file: crates/window-api/tests/check_endpoint_states.rs)
>
> 5/
> Honest limits, stated up front: this is a single-machine, single-run result on macOS. It does NOT cover the Linux/Windows CI matrix, lint, format, or MSRV gates. It's first-party — my own tests run by me. No third party has audited it. 323 is suite breadth, not coverage.
>
> 6/
> And a `.win` proves a file is unchanged since *some key* sealed it. It does NOT prove who that key belongs to. Integrity and human identity are kept separate on purpose. I'd rather tell you what it can't do than sell you what it can.
>
> 7/
> Code is MIT, public, CI in the open:
> https://github.com/Wise-Est-Systems/winstack-network
> Reads welcome. Holes welcome more.

---

## 2. LinkedIn — single post

- [ ] Posted

**Source:** EP-WIN L99, L118–123, L153–161; README L32–45.

> Most tools for document trust try to *detect* tampering or AI generation after the fact — reactive guessing. I've been building the other approach: proof attached at the moment a file is created.
>
> The project is WIN. You seal a file into a `.win` container that carries its own proof. Anyone can verify it offline — no account, no server to trust — and get one of three answers: Verified, Tampered, or Invalid.
>
> Where it stands today, with receipts rather than adjectives:
>
> On a clean checkout (Rust 1.94.1, macOS), the workspace test suite passes — 323 tests, 0 failures. That includes integration tests proving the behavior end to end: a valid container verifies, a changed payload reports Tampered, a changed signature reports Invalid, a truncated container reports Damaged. An adversarial corpus and a tamper grid both pass.
>
> The limits, stated plainly: this is a single-machine, single-run result on macOS. It does not yet cover the cross-platform CI matrix, lint, format, or minimum-Rust-version gates. It is first-party verification — my own tests, run by me, not audited by a third party. And a verified `.win` proves a file is unchanged since some key sealed it; it does not prove the real-world identity behind that key. Integrity and human trust are kept separate by design.
>
> Code is MIT and public: https://github.com/Wise-Est-Systems/winstack-network
>
> If you work on provenance, signing, or document integrity, I'd value your eyes on it — especially where it breaks.

---

## 3. Hacker News — Show HN

- [ ] Posted

**Source:** EP-WIN L99, L118–123, L153–161; README L32–45.

**Title:**
`Show HN: WIN – files that carry their own proof (.win container, offline verify)`

**URL:**
`https://github.com/Wise-Est-Systems/winstack-network`

**First comment (paste right after posting):**

> Author here. WIN seals a file into a `.win` container that carries its own proof. A receiver drops it into a verifier and gets one of three results — Verified, Tampered, or Invalid — offline, with no account and no server to trust. It's Rust, MIT-licensed.
>
> The angle is provenance, not detection. Tools like Resistant AI, Klippa, and Inscribe try to *detect* whether a document was altered or machine-generated after it exists — that's reactive inference. WIN attaches a signed proof at seal time, so verification is a check, not a guess. Integrity is also deliberately separated from identity: a verified `.win` proves the file is unchanged since *some key* sealed it; it does not prove who that key belongs to.
>
> What I can actually back today, from the repo's own test gate: on a clean checkout (commit 45aa999, Rust 1.94.1, macOS), `cargo test --workspace --all-features` passes — 323 tests, 0 failures. That includes `crates/window-api/tests/check_endpoint_states.rs`, which asserts valid → Verified, payload-tampered → Tampered, signature-tampered → Invalid, truncated → Damaged; plus an adversarial corpus (25) and a tamper grid (30) the format rejects.
>
> Limits, because they matter: this is a single-machine, single-run result on macOS. It does NOT prove the Linux/Windows CI matrix, MSRV (1.82), `cargo fmt`, `clippy`, or `cargo doc` — those weren't run for that capture. It's first-party (my own tests), not externally audited, and it doesn't claim cryptographic soundness or adversary resistance beyond the specific inputs the corpus encodes. 323 is suite breadth, not a coverage figure.
>
> I'd genuinely value scrutiny on the container format and the verify path. Where does it break?

---

## 4. dev.to — short article

- [ ] Posted

**Source:** EP-WIN L99, L118–123, L116, L153–161; README L32–45.

**Title:** `Provenance over detection: a file format that carries its own proof`

**Body (markdown):**

```markdown
Most document-trust tools work *after* a file exists. They look at a PDF or an
image and try to detect whether it was altered or machine-generated. That's
detection — reactive, and ultimately a guess.

I've been building the other direction: **provenance**. Attach a signed proof
at the moment a file is sealed, so verification later is a check, not an
inference.

The project is **WIN**. There's one public file type: `.win`. The proof and the
change-map live *inside* the container, so it travels with the file. A receiver
drops it into a verifier and gets one of three results — **Verified**,
**Tampered**, or **Invalid** — offline, with no account and no server to trust.

## The three results, backed by tests

I don't want to describe behavior the code doesn't have, so here's the receipt.
On a clean checkout (Rust 1.94.1, macOS), the workspace test suite passes:
**323 tests, 0 failures**. The behavior is asserted directly in
`crates/window-api/tests/check_endpoint_states.rs`:

- a valid `.win` returns **Verified**
- a payload-tampered `.win` returns **Tampered**
- a signature-tampered `.win` returns **Invalid**
- a truncated container returns **Damaged**

An adversarial corpus (25 tests) and a tamper grid (30 tests) also pass —
the format rejects the malformed and mutated inputs they encode.

## What it does NOT do

- It's a **single-machine, single-run result on macOS**. It does not prove the
  Linux/Windows CI matrix, minimum-Rust-version, lint, or format gates.
- It's **first-party** — my own tests, run by me. No third party has audited it.
- A verified `.win` proves a file is unchanged since *some key* sealed it. It
  does **not** prove the real-world identity behind that key. Integrity and human
  trust are kept separate on purpose.
- 323 is suite breadth, not a coverage metric.

Code is MIT and public:
https://github.com/Wise-Est-Systems/winstack-network

If you work on signing, provenance, or document integrity, I'd value your eyes
on the container format and the verify path — especially where it breaks.
```

---

## 5. Reddit — post

- [ ] Posted

**Source:** EP-WIN L99, L118–123, L153–161; README L32–45.

**Title:** `WIN: a file format that carries its own proof — verify offline, no server to trust [Rust, MIT]`

**Body:**

> I've been building WIN: you seal a file into a `.win` container that carries its own proof. Anyone can drop it into a verifier and get one of three results — Verified, Tampered, or Invalid — offline, no account, no server to trust.
>
> The angle is provenance, not detection. Most document-trust tools try to detect tampering or AI generation after the fact (reactive guessing). WIN attaches a signed proof at seal time, so verifying is a check, not a guess.
>
> Receipts, not adjectives — on a clean checkout (Rust 1.94.1, macOS) the workspace test suite passes: 323 tests, 0 failures. That includes integration tests asserting valid → Verified, payload-tampered → Tampered, signature-tampered → Invalid, truncated → Damaged, plus an adversarial corpus and a tamper grid the format rejects.
>
> Honest limits: this is a single-machine, single-run result on macOS — it does not cover the Linux/Windows CI matrix, lint, format, or MSRV gates, and it's first-party (my own tests), not externally audited. A verified `.win` proves a file is unchanged since *some key* sealed it; it does not prove who that key belongs to. Integrity and identity are kept separate by design.
>
> Code (MIT): https://github.com/Wise-Est-Systems/winstack-network
>
> Looking for critique of the container format and the verify path. Where does it break?

**Suggested subreddits (read each one's self-promo rules first; lead with the technical content, not the link):**
- r/rust — Rust workspace, MIT, has CI; frame as a Rust project. Strongest fit.
- r/cryptography — sealing/signing + tamper detection; expect rigorous pushback on identity-vs-integrity (which the post already addresses honestly).
- r/programming — broadest reach but strictest spam filtering; only if the first two land well.

---

## 6. Mastodon — single toot (<=500 chars)

- [ ] Posted

**Source:** EP-WIN L99, L118–123, L153–161.

> WIN: files that carry their own proof. Seal a file into a `.win`; anyone verifies it offline and gets Verified / Tampered / Invalid — no account, no server. Provenance, not detection: a check, not a guess.
>
> Receipt: clean checkout, 323 tests, 0 failures (incl. the three-results behavior). Limits: single-machine macOS run, first-party, not audited.
>
> MIT, public: https://github.com/Wise-Est-Systems/winstack-network

(Length check: ~440 characters including the URL. Under 500.)

---

## 7. Bluesky — single post (<=300 chars)

- [ ] Posted

**Source:** EP-WIN L99, L118–123, L153–161.

> WIN: files that carry their own proof. Seal a file, anyone verifies it offline — Verified / Tampered / Invalid. Provenance, not detection.
>
> 323 tests pass, 0 failures (single-machine, first-party, not audited).
>
> MIT: https://github.com/Wise-Est-Systems/winstack-network

(Length check: ~265 characters including the URL. Under 300.)

---

## 8. wisest.systems — landing / announcement paragraph

- [ ] Posted

**Source:** EP-WIN L99, L118–123, L153–161; README L32–45.

> WIN gives a file its own proof. You seal a file into a `.win` container, and the proof travels inside it — so anyone can verify it offline, with no account and no server to trust, and get one clear answer: Verified, Tampered, or Invalid. This is provenance, not detection: instead of guessing after the fact whether a file was altered, the proof is attached when the file is sealed, and verifying is a check. As of 2026-06-07, the project's own test suite passes on a clean checkout — 323 tests, 0 failures — including the integration tests that prove those three results behave. To be precise about what that means: it is a single-machine, first-party result, not yet externally audited, and a verified `.win` proves a file is unchanged since some key sealed it — not the real-world identity behind that key. We keep file integrity and human trust separate on purpose, and we'd rather show you the limits than sell past them. The code is open: github.com/Wise-Est-Systems/winstack-network

---

## Recommended POST ORDER

1. **GitHub repo first (make sure it's public and the README is current).** Every other channel links here. If a curious senior engineer clicks through and the repo is stale or private, the receipts evaporate. This is the destination, not a channel — get it right before driving any traffic.

2. **Hacker News (Show HN).** Highest-scrutiny, highest-signal audience, and the one most likely to reward "here are my receipts and here's exactly what I can't prove yet." Post early in the US morning (PT). Paste the first comment immediately. If it lands here, the technical credibility carries everywhere else; if it gets torn apart, you learn the real holes before a wider audience sees them.

3. **Reddit (r/rust first).** Same engineering audience, more forgiving pacing than HN. r/rust rewards real Rust projects with honest framing. Wait until you've absorbed any HN feedback so the Reddit post reflects it.

4. **X/Twitter thread + Bluesky + Mastodon (same window).** These are amplification, not first-impression surfaces. Fire them once a real link (HN thread or repo) is live so people have somewhere credible to land. Bluesky and Mastodon can go out near-simultaneously with X.

5. **LinkedIn.** Professional network; best after the technical surfaces have validated the framing, so the post can stand on receipts rather than reach. This is where future collaborators and serious readers live — post it last, clean, with the strongest version of the limits language.

6. **dev.to + wisest.systems landing paragraph.** Evergreen surfaces. dev.to is a durable write-up that keeps earning reads after the launch-day spike. The site paragraph should be live before or alongside the social push so the homepage matches the message. Neither is time-sensitive; both should reflect any wording you tightened during steps 2–4.

Rule across all of it: lead with the proof, state the limits in the same breath, and let the work speak.
