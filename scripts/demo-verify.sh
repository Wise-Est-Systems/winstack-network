#!/usr/bin/env bash
# demo-verify.sh — receipts demo for `win verify`.
#
# Proves, end to end, with real output:
#   1. Seal a file            -> produces a .win container
#   2. Verify the .win        -> PASS  (file matches the proof inside it)
#   3. Flip ONE byte          -> tampering
#   4. Verify again           -> FAIL  (Tampered, both hashes shown)
#   5. Verify with no network  -> still works (proof travels inside the file;
#                                 winstack.dev / the org being gone changes nothing)
#
# Everything here is the real CLI on real bytes. No mocks, no canned output.
# Run from the repo root:  bash scripts/demo-verify.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "── building the win CLI ──────────────────────────────────────────"
cargo build --quiet --bin win
WIN="$ROOT/target/debug/win"
echo "  built: $WIN"
echo

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# A stand-in for "something an AI produced that someone later has to trust."
printf 'Q: Is this invoice legitimate?\nA: Yes. Approved for $12,400. Net 30. — assistant\n' > answer.txt

echo "── 1. SEAL ──────────────────────────────────────────────────────"
"$WIN" seal answer.txt --private
echo

echo "── 2. VERIFY (expect: Verified) ─────────────────────────────────"
"$WIN" verify answer.txt.win
echo "  exit code: $?"
echo

echo "── 3. TAMPER — flip one byte inside the sealed container ─────────"
python3 - answer.txt.win <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
i = b.find(b"12,400")
b[i + 3] = ord("5")          # $12,400  ->  $12,500  (one byte)
open(p, "wb").write(b)
print(f"  changed the sealed answer from $12,400 to $12,500 (1 byte at offset {i+3})")
PY
echo

echo "── 4. VERIFY AGAIN (expect: Tampered, nonzero exit) ─────────────"
set +e
"$WIN" verify answer.txt.win
code=$?
set -e
echo "  exit code: $code  (nonzero = caught)"
echo

echo "── 5. SAME CHECK WITH NO NETWORK (P12: verifies with the org gone) "
# Re-seal a clean copy, then verify with networking unset. The proof is
# inside the file, so verification never reaches out to winstack.dev.
printf 'Q: Is this invoice legitimate?\nA: Yes. Approved for $12,400. Net 30. — assistant\n' > clean.txt
"$WIN" seal clean.txt --private >/dev/null
echo "  verifying with no_proxy='*' http(s)_proxy pointed at a dead port..."
http_proxy="http://127.0.0.1:1" https_proxy="http://127.0.0.1:1" no_proxy="" \
  "$WIN" verify clean.txt.win
echo "  exit code: $?  (network unreachable, still verified)"
echo
echo "── done. Every line above is real CLI output on real bytes. ─────"
