# Adoption proposal — WIN / truth.systems — 2026-06-07

Author: Adoption agent. Status: PROPOSAL ONLY. Nothing shipped. Human-gated.

Scope of the real conversion surface inspected:
- Landing source: `/Users/thekingflame/Desktop/wisest-systems-site/index.html` (live: wisest.systems)
- Product entry source: `/Users/thekingflame/Desktop/WinStack_Network_v1/public/index.html` (live: truth.systems, linked from landing as "Open Verifier")
- Onboarding doc (witness path): `/Users/thekingflame/Desktop/WinStack_Network_v1/docs/witness-onboarding.md`

"First real action" defined: a real visitor turns their own file into a `.win`
(homepage seal flow) OR verifies a received file. The product already makes this
one step — drop a file, get a `.win` back. The product is not the problem.

---

## Drop point (exact step, with evidence)

The drop happens BEFORE the visitor ever reaches the product. It is on the
landing page, and it is structural, not a copy nuance.

Evidence, from `wisest-systems-site/index.html`:

1. The only path into the product is the "Open Verifier" link at layer `s10`
   (line 149: `<a class="p-cta" href="https://truth.systems">Open Verifier</a>`).
2. The page is a single 2400vh scroll driver (line 24:
   `.scroll-driver{height:2400vh}`) with 17 sequential layers
   (line 311: `ids=['s1',...'sf']`). Each layer occupies an equal 1/17 slice
   (line 314: `var span=1/count`). `s10` is the 10th layer, so the only CTA
   first becomes visible at roughly 53-56% scroll depth.
3. The hero (`s1`, lines 98-102) shows the brand, "Proof or nothing.", and
   "Scroll ↓ · the case for proof". There is NO action on the first screen —
   only an instruction to scroll through nine more panels before any link.
4. Every layer is `pointer-events:none` except anchors (line 27). For 9 of 17
   panels there is nothing to click at all.

Plain English: a real person lands, sees a poem, and is told to scroll. The one
door into the actual tool is past the halfway mark of a very long scroll. Anyone
who doesn't scroll ~10 panels deep never sees the product. The footer (`sf`) has
a second "Verify a file" link, but that's even further down (last layer).

Why this is the drop point and not the product: the product entry
(`public/index.html`, lines 108-118) puts the drop zone and the value line
("Drop a file. Get the truth.") on the first paint with no scroll, no signup,
no choice — the moment a visitor arrives there, the first real action is one
gesture away. The friction is entirely upstream, on the landing page.

---

## Real signals available / UNKNOWN

- Instrumentation on landing page: NONE. Grepped `index.html` for
  analytics/plausible/gtag/umami/posthog/fathom/track — no matches.
- Instrumentation on truth.systems: NONE in `public/index.html` (same grep).
- Scroll-depth measurement: UNKNOWN (not instrumented).
- Click-through on "Open Verifier": UNKNOWN (not instrumented).
- Seal/verify completion counts: UNKNOWN. By design the product is local-only
  ("Everything runs locally in your browser. Nothing is uploaded." line 118),
  so there is no server-side event to count and we must NOT invent one.
- Traffic / unique visitors: UNKNOWN.

So: the drop point above is established from the code structure (which is
ground truth), NOT from measured funnel data. There is currently zero measured
funnel data. That itself is the most important finding.

---

## Proposed changes (smallest first; each gated + feasibility-tagged)

### P1 — Put a working drop zone (or a direct CTA) on the FIRST screen of the landing page
Smallest version: add one always-visible "Verify or seal a file →" link/button
in the hero (`s1`) and/or in the fixed `nav`, pointing to truth.systems, so the
door exists before any scrolling. Larger version (later): embed the same WASM
drop zone the product uses so the first real action happens on the landing page
itself.
- Save-the-son gate: (a) does NOT touch the free promise — still free, no
  account. PASS. (b) Moves people to the real win by removing the single biggest
  barrier (the hidden door). PRIORITIZE. (c) No paid ask. PASS.
- Feasibility: SOLO for the link/button (one anchor in the hero + one in nav).
  NEEDS-HELP / SOLO-STRETCH for embedding the live WASM verifier on the landing
  page (cross-origin WASM load, headers, testing).

### P2 — Make the hero state the action, not just the slogan
Current hero (lines 98-102) is "Wise.Est / Proof or nothing. / Scroll ↓".
Proposed: keep the brand, but add one concrete line of what a visitor can DO now,
e.g. "Drop any file and watch it prove itself." paired with the P1 button.
Rationale: "Proof or nothing" is identity, not an invitation to act. The product
page already nails the actionable line ("Drop a file. Get the truth." line 109);
the landing page should borrow that voice up top.
- Save-the-son gate: (a) PASS (no promise touched). (b) Yes — frames the free
  action immediately. PRIORITIZE. (c) No paid ask. PASS.
- Feasibility: SOLO (copy + reuse the existing button from P1).

### P3 — Shorten the path: move the product card (`s10`) earlier in the scroll order
Currently the visitor reads 9 atmosphere panels before the first door. Proposed:
reorder so the WIN product card appears by the 3rd-4th panel (after the hook
"You send files... they aren't"), then let the philosophy panels follow for
people who keep scrolling. The reorder is just changing the `ids` array
(line 311) and the corresponding markup order.
- Save-the-son gate: (a) PASS. (b) Yes — cuts the distance to the first action
  roughly in half. PRIORITIZE. (c) No paid ask. PASS.
- Feasibility: SOLO-STRETCH (reordering layers is a contained edit, but the
  scroll-timed opacity math keys off array index, so it needs a careful test
  pass to confirm panels still fade correctly).

### P4 — Add privacy-respecting, real-only instrumentation so the next decision is measured, not guessed
Add a self-hosted, cookieless counter (e.g. a single first-party endpoint that
logs only: landing-page-loaded, open-verifier-clicked) — enough to measure the
ONE funnel step that matters: arrived → clicked into the product. Do NOT add
anything that counts a "user," a signup, or a seal, because seals are local and
counting them would either be a fabrication or would break the local-only
promise.
- Save-the-son gate: (a) Must NOT break "nothing is uploaded" on the product —
  so instrument the LANDING page only (a marketing page), never the verifier's
  file handling. Conditional PASS, with that hard boundary. (b) Indirectly — it
  lets every later adoption decision be real instead of UNKNOWN. PRIORITIZE
  (but after P1-P3, which don't need data to justify). (c) No paid ask. PASS.
- Feasibility: NEEDS-HELP (requires choosing/standing up an endpoint and a
  privacy stance review; not a one-line edit).

---

## What NOT to do

- Do NOT add fake counters, "X files verified" tickers, testimonial counts, or
  any social-proof number that isn't a real measured signal. There is currently
  no instrumentation, so any such number would be fabricated. Killed on sight.
- Do NOT add an email-capture wall, "sign up to verify," or account gate in
  front of the drop zone. It would break the free-forever promise and the
  no-account contract in `witness-onboarding.md` ("Witnesses do not need an
  account"). Killed by gate (a).
- Do NOT instrument the product's file handling to count seals. Seals are
  local; either you'd fabricate the number or you'd violate "nothing is
  uploaded" (line 118). Killed by gate (a)/(c).
- Do NOT introduce a mode picker / tabs / "choose verify vs seal" choice on the
  landing page. The product already auto-detects (drop a `.win` → verify, drop
  anything else → seal). The whole point is the visitor doesn't know they had a
  choice; adding one is a regression.
