#!/usr/bin/env bash
# Generate the four-state gallery — sample .win files exercising every
# verifier outcome. Used by the demo recording, the deploy smoke tests,
# and `winstack.dev` documentation screenshots.
#
# Outputs to ./gallery/ (gitignored). Regenerable.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WINSTACK="${WINSTACK_BIN:-$ROOT/target/release/winstack}"
if [[ ! -x "$WINSTACK" ]]; then
  echo "▸ Building winstack…"
  cargo build --release -p cli --bin winstack
  WINSTACK="$ROOT/target/release/winstack"
fi

# Clean output dir
GALLERY="$ROOT/gallery"
rm -rf "$GALLERY"
mkdir -p "$GALLERY"
cd "$GALLERY"

echo "▸ Building gallery in $GALLERY"
echo ""

# ─── 1. ALIVE ─────────────────────────────────────────────────────────
# The honest case. Seal a file. The .win recognizes as Alive when dropped
# into any verifier.
cat > alive.txt <<'EOF'
This is the alive sample.
A name tag was attached when this file existed in this exact form.
EOF
"$WINSTACK" seal alive.txt > /dev/null
echo "  alive.win            → Alive   (drop with the file as-is)"

# ─── 2. WOUNDED ───────────────────────────────────────────────────────
# Seal a file, then mutate the file *outside* the .win container. The
# .win still has the original's hash; the bytes you'd extract from it
# would be the original. To produce a recognizer-Wounded outcome, ship
# the .win and a *separately tampered* copy of the file. The browser
# verifier recognizes the .win itself as Alive (its content matches its
# tag), but a recipient who drops the .win + the tampered file at
# /v/<hash> sees Wounded.
#
# We produce two artifacts here:
#   wounded.txt.win  — the original, still Alive on its own
#   wounded.txt      — the tampered version (drop this with the URL)
cat > wounded-source.txt <<'EOF'
This is the wounded sample.
The bytes here were named once. The accompanying tampered file
demonstrates the Wounded state for the URL flow.
EOF
"$WINSTACK" seal wounded-source.txt > /dev/null
mv wounded-source.win wounded.win
# Tampered companion — original filename inside the .win is "wounded-source.txt",
# so the receiver should drop a file *with that content modified* at the URL.
cat > wounded-source.txt <<'EOF'
This file has been changed since it was named.
Drop this file at the recipient URL — Winstack will say Wounded.
EOF
mv wounded-source.txt wounded-tampered.txt
echo "  wounded.win            → Alive on its own"
echo "  wounded-tampered.txt   → drop with /v/<hash> URL → Wounded"

# ─── 3. UNRECOGNIZED ──────────────────────────────────────────────────
# Build a container with a mismatched proof bundle: the .win's bytes are
# fine, but the proof inside was signed against a different file. We
# achieve this by extracting the proof from one .win and packing it
# around a different file's bytes. Without `winstack repack`, the
# simplest approximation: corrupt a single byte in the proof JSON's
# signature so the cryptographic check fails while parsing still
# succeeds.
cat > unrecognized.txt <<'EOF'
This sample exercises the Unrecognized state.
The proof JSON inside the .win has one mutated signature byte.
EOF
"$WINSTACK" seal unrecognized.txt > /dev/null
# Corrupt one hex character of object_signature in the proof JSON so the
# Ed25519 check fails while parsing still succeeds. The proof JSON is
# pretty-printed, so we match `"object_signature": "<128 hex>"` with
# variable whitespace.
python3 - <<'PY'
import re, sys
p = "unrecognized.win"
with open(p, "rb") as f:
    data = f.read()
m = re.search(rb'"object_signature"\s*:\s*"([0-9a-fA-F]{128})"', data)
if not m:
    sys.exit("could not find object_signature in proof JSON")
sig_start = m.start(1)
sig_end = m.end(1)
# Flip the low bit of the last hex digit. Always produces a valid hex char.
last = data[sig_end - 1]
def flip(c):
    h = chr(c)
    return ord(format((int(h, 16) ^ 0x1), 'x'))
new = data[:sig_end - 1] + bytes([flip(last)]) + data[sig_end:]
with open(p, "wb") as f:
    f.write(new)
PY
echo "  unrecognized.win       → Unrecognized (witness signature won't verify)"

# ─── 4. DYING ─────────────────────────────────────────────────────────
# Container itself is malformed. Truncate the file mid-proof so the
# container parser can read the magic + filename + file body but the
# proof JSON is incomplete (or the magic itself is corrupt — we test
# the latter for stronger Dying signal).
cat > dying.txt <<'EOF'
This sample exercises the Dying state.
The container's header is corrupted; the recognizer cannot read it.
EOF
"$WINSTACK" seal dying.txt > /dev/null
# Corrupt the magic bytes so parsing fails immediately.
python3 - <<'PY'
p = "dying.win"
with open(p, "r+b") as f:
    f.seek(0)
    f.write(b"NOPE")  # was b"WIN\x01"
PY
echo "  dying.win              → Dying (container header corrupted)"

# ─── Publish all four to public/v/ for the URL flow ───────────────────
# Only the still-valid ones can be published. (Dying and the corrupted
# Unrecognized lose the proof bundle.)
echo ""
echo "▸ Publishing the still-valid name tags to public/v/"
"$WINSTACK" publish alive.win   --to "$ROOT/public" 2>&1 | sed 's/^/  /'
"$WINSTACK" publish wounded.win --to "$ROOT/public" 2>&1 | sed 's/^/  /'

echo ""
echo "✔ Gallery ready in $GALLERY"
echo ""
echo "Suggested smoke-test sequence:"
echo "  1. Drop alive.win on the homepage              → Alive"
echo "  2. Drop unrecognized.win on the homepage       → Unrecognized"
echo "  3. Drop dying.win on the homepage              → Dying"
echo "  4. Visit the alive URL, drop alive.txt           → Alive"
echo "  5. Visit the alive URL, drop wounded-tampered.txt → Wounded"
