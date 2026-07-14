#!/usr/bin/env node
// Honesty invariant test for the Truth.Systems share card.
//
// It extracts the REAL cardConfig() / CARD_STATUS from public/index.html
// (between the /*CARD_STATUS_*/ markers) and evaluates it, so the test
// binds to shipped code, not a copy. It proves the core law:
//
//   A share card's "VERIFIED" styling is reachable ONLY from an exact
//   r.status === "Verified" reading. Every other status — including
//   tampered, invalid, damaged, empty, or spoofed casing — fails closed
//   to a non-green, non-VERIFIED card.
//
// Run: node scripts/share-card-honesty-test.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, '..', 'public', 'index.html'), 'utf8');

const m = html.match(/\/\*CARD_STATUS_START\*\/([\s\S]*?)\/\*CARD_STATUS_END\*\//);
if (!m) {
  console.error('FAIL: could not locate CARD_STATUS markers in public/index.html');
  process.exit(1);
}
// Evaluate the extracted block and hand back its two symbols.
const factory = new Function(m[1] + '\nreturn { cardConfig, CARD_STATUS };');
const { cardConfig, CARD_STATUS } = factory();

const VERIFIED_GOLD = '#c9a84c';
let failed = 0;
const ok = (cond, msg) => { if (!cond) { console.error('  ✗ ' + msg); failed++; } else { console.log('  ✓ ' + msg); } };

// 1. The one true green path.
const v = cardConfig('Verified');
ok(v.verified === true, 'cardConfig("Verified").verified === true');
ok(v.color === VERIFIED_GOLD, 'cardConfig("Verified") uses the gold color');
ok(/VERIFIED/.test(v.label), 'cardConfig("Verified").label says VERIFIED');

// 2. Every other input must fail closed — no green, no "VERIFIED".
const badInputs = ['Tampered', 'Invalid', 'Damaged', '', 'Verified ', ' Verified',
  'verified', 'VERIFIED', 'Verifie', 'nonsense', null, undefined, 0, {}];
for (const s of badInputs) {
  const c = cardConfig(s);
  const shown = JSON.stringify(s);
  ok(c.verified === false, `cardConfig(${shown}) is not marked verified`);
  ok(c.color !== VERIFIED_GOLD, `cardConfig(${shown}) is not gold`);
  ok(!/VERIFIED/.test(c.label), `cardConfig(${shown}) label does not say VERIFIED (got "${c.label}")`);
}

// 3. Structural gate: renderShare only opens the share box for Verified.
ok(/renderShare[\s\S]{0,400}?r\.status!==['"]Verified['"][\s\S]{0,80}?classList\.add\(['"]hidden['"]\)/.test(html),
  'renderShare() hides the share box unless status === "Verified"');

// 4. No unproven claims baked into the card text.
const forbidden = [/cannot be faked/i, /authentic beyond doubt/i, /proves.{0,20}true/i, /this content is true/i];
for (const re of forbidden) {
  ok(!re.test(html), `card/site text avoids forbidden claim ${re}`);
}

// 5. Phase 6 — per-artifact share link. Extract the REAL verifyLink() and prove
//    it targets /v/<hash> for a genuine fingerprint and falls back to the
//    homepage (never a broken /v/) when no valid hash is present.
const vlm = html.match(/function verifyLink\(r\)\{.*\}/);
ok(!!vlm, 'verifyLink() is defined in public/index.html');
if (vlm) {
  const { verifyLink, VERIFY_URL } = new Function(
    "const VERIFY_URL='https://truth.systems';" + vlm[0] + '\nreturn { verifyLink, VERIFY_URL };')();
  const H = 'a'.repeat(64);
  ok(verifyLink({ payload_hash: H }) === VERIFY_URL + '/v/' + H, 'verifyLink() targets /v/<hash> for a valid fingerprint');
  ok(verifyLink({ payload_hash: H.toUpperCase() }) === VERIFY_URL + '/v/' + H, 'verifyLink() lowercases the hash');
  ok(verifyLink({}) === VERIFY_URL, 'verifyLink() with no hash falls back to homepage (no broken /v/)');
  ok(verifyLink(null) === VERIFY_URL, 'verifyLink(null) falls back to homepage');
  ok(verifyLink({ payload_hash: 'not-hex-zz' }) === VERIFY_URL, 'verifyLink() rejects a non-hex hash');
}

// 6. Every share surface must use the per-artifact link, not the bare homepage.
ok(/copyTo\(verifyLink\(_shareR\)\)/.test(html), 'Copy-link button copies the per-artifact verifyLink');
ok(!/copyTo\(VERIFY_URL\)/.test(html), 'no share surface copies the bare homepage URL');
ok(/encodeURIComponent\(verifyLink\(_shareR\)\)/.test(html), 'LinkedIn share uses the per-artifact link');
ok(/'Verify it yourself: '\+verifyLink\(r\)/.test(html), 'share/summary text uses the per-artifact link');

// 7. Fail OPEN: a /v/<hash> route with no usable preview must invite local
//    verification, never dead-end. The old dead-end copy must be gone.
ok(/function urlFlowLocalOnly\(hash,note\)/.test(html), 'urlFlowLocalOnly() fail-open handler exists');
ok(/urlFlowLocalOnly\(hash,/.test(html.replace(/function urlFlowLocalOnly[\s\S]*?show\('input-state'\);\}/, '')),
  'initUrlFlow routes failures into urlFlowLocalOnly()');
ok(!/No file sealed at this hash/.test(html), 'old dead-end 404 copy is removed');
ok(/Drop the .win file to verify locally/.test(html), 'local-only fallback tells the receiver to verify locally');

// 8. Phase 10 — post-seal share handoff must fail closed. The seal share actions
//    open ONLY on a Verified seal, and "Verify & share" re-runs the REAL verifier
//    on the sealed bytes (never trusts seal metadata).
ok(/seal-actions'\)\.classList\.toggle\('hidden',status!=='Verified'\)/.test(html),
  'post-seal share actions are gated on a Verified seal');
ok(/_lastSealWin=\(status==='Verified'\)\?Uint8Array\.from\(r\.win_bytes\):null/.test(html),
  'sealed bytes are retained only when the seal is Verified (fails closed)');
ok(/seal-share'\)\.addEventListener\([\s\S]{0,160}?rWin\(_lastSealWin\)[\s\S]{0,160}?renderResult\(chk,_lastSealName\)/.test(html),
  '"Verify & share" re-verifies the sealed bytes and lands on the standard result view');
ok(/function receiverNote\(\)\{[\s\S]*?VERIFY_URL\+'\/v\/'\+_lastSealHash/.test(html),
  'receiver note offers the per-artifact /v/<hash> link');
ok(/you’ll need this \.win file itself/.test(html),
  'receiver note is honest — the .win file itself must travel');

// 9. Phase 11 — loop instrumentation must never carry protected content. Scan every
//    track() CALL and prove its payload is only a name + a flat low-cardinality object
//    with no filename, fingerprint, bytes, key, or free text.
const trackCalls = html.match(/track\('[a-z_]+'(?:,\{[^{}]*\})?\)/g) || [];
const rawTrackCalls = (html.match(/track\('/g) || []).length;
ok(trackCalls.length === rawTrackCalls && rawTrackCalls > 0,
  `every track() call is a name + flat object (${trackCalls.length}/${rawTrackCalls} strict-shaped)`);
const FORBIDDEN = ['payload_hash', 'filename', 'file.name', 'win_bytes', 'public_key_hex',
  '_lastSealHash', '_lastSealName', '.born', 'size_bytes', 'shareText', 'summaryText',
  'receiverNote', 'verifyLink', 'fname'];
const leaky = trackCalls.filter(c => FORBIDDEN.some(t => c.includes(t)));
ok(leaky.length === 0, `no track() call carries content-derived data${leaky.length ? ' — LEAK: ' + leaky.join(' | ') : ''}`);
ok(/function track\(name,data\)\{try\{if\(typeof window!=='undefined'&&typeof window\.va==='function'\)/.test(html),
  'track() no-ops safely when analytics is unavailable');
ok(/sessionStorage\.setItem\('wnstk_v','1'\)/.test(html) && !/document\.cookie/.test(html),
  'verified-session flag uses sessionStorage, not a cookie');
ok(/if\(status==='Verified'&&hasVerified\(\)\)track\('loop_close'\)/.test(html),
  'loop_close fires ONLY on a Verified seal that followed a verify (the true loop metric)');

// 10. Self-contained share link (#p=). The whole .win rides in the URL fragment,
//     and the receiver's page must run the REAL verifier on the decoded bytes —
//     never trust the link. A tampered link therefore reads Tampered, not green.
ok(/function packedPayload\(\)\{[\s\S]*?#p=/.test(html), 'packedPayload() reads the #p= fragment');
ok(/boot\(\)\{[\s\S]{0,400}?packedPayload\(\)[\s\S]{0,120}?initPackedFlow\(packed\)[\s\S]{0,160}?return;[\s\S]{0,60}?urlHash\(\)/.test(html),
  'boot() checks the self-contained link BEFORE the /v/<hash> route');
ok(/function initPackedFlow\(b64\)\{[\s\S]*?b64urlDecode\(b64\)[\s\S]*?rWin\(bytes\)[\s\S]*?renderResult\(/.test(html),
  'initPackedFlow decodes then runs the REAL verifier (rWin) on the bytes');
ok(/if\(!isWin\(bytes\)\)/.test(html), 'initPackedFlow rejects a fragment that is not a .win container');
ok(/verifyLink\(r\)\{if\(typeof _shareWinB64!=='undefined'&&_shareWinB64\)return VERIFY_URL\+'\/#p='\+_shareWinB64/.test(html),
  'verifyLink embeds the whole artifact (#p=) when the bytes are present');
ok(/_pendingWinBytes=isWin\(buf\)\?buf:null/.test(html), 'the verify path stashes the .win bytes for self-contained sharing');
ok(/EMBED_MAX_BYTES=\d+/.test(html) && /b\.length<=EMBED_MAX_BYTES/.test(html),
  'embedding is size-capped (oversized artifacts fall back, never a broken giant URL)');

// 11. Media preview must be safe and honest: preview ONLY on a Verified reading,
//     rendered ONLY as an <img>/<audio>/<video> from a Blob URL (never inline
//     markup, so a hostile SVG/HTML payload can't execute), and never for a file
//     that failed verification.
ok(/canPreview=\(status==='Verified'\)/.test(html), 'media preview is gated on a Verified reading');
ok(/createElement\('img'\)[\s\S]{0,400}?createElement\('audio'\)[\s\S]{0,400}?createElement\('video'\)/.test(html),
  'media is rendered via createElement img/audio/video (safe elements)');
ok(/el\.src=_mediaUrl/.test(html) && /URL\.createObjectURL\(new Blob\(\[p\.bytes\]/.test(html),
  'media source is a Blob URL — the bytes are never injected as HTML');
ok(!/r-media[\s\S]{0,80}?\.innerHTML\s*=\s*[^'"]*p\.bytes/.test(html), 'payload bytes are never written as innerHTML');
ok(/status!=='Verified'\)note\.textContent='Not shown/.test(html), 'a file that failed verification is not previewed (honest note instead)');
ok(/function extractPayload\(b\)\{[\s\S]*?b\[0\]===87&&b\[1\]===73&&b\[2\]===78/.test(html), 'extractPayload checks the WIN magic before trusting the container');

console.log('');
if (failed) { console.error(`share-card-honesty-test: ${failed} assertion(s) FAILED`); process.exit(1); }
console.log('share-card-honesty-test: all assertions passed');
