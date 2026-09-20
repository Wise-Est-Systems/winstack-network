#!/usr/bin/env bash
# anchor.sh — make a file's existence UNDENIABLE by binding its SHA-256 to an
# independent, cryptographically-signed timestamp (RFC 3161) from a public
# authority, then emit public-receipt drafts (GitHub release + X post).
#
# No trust in the sealer's key or clock is required to verify the result — a
# skeptic needs only the file, this folder, and a stock `openssl`.
#
#   scripts/anchor.sh anchor <file>            -> writes <file>.anchor/ (receipt + drafts)
#   scripts/anchor.sh verify <file> <folder>   -> re-checks the anchor from scratch
#
# Depends only on: openssl (RFC 3161 built in) + curl.
set -euo pipefail

TSA_URL="https://freetsa.org/tsr"
CA_URL="https://freetsa.org/files/cacert.pem"
TSACRT_URL="https://freetsa.org/files/tsa.crt"
REPO_URL="https://github.com/Wise-Est-Systems/winstack-network"
X_HANDLE="@WiseEstSystems"

fetch_certs() { # $1 = dir
  [ -s "$1/cacert.pem" ] || curl -sS -f "$CA_URL"     -o "$1/cacert.pem"
  [ -s "$1/tsa.crt"    ] || curl -sS -f "$TSACRT_URL" -o "$1/tsa.crt"
}

cmd_anchor() {
  local file="$1"
  [ -f "$file" ] || { echo "no such file: $file" >&2; exit 1; }
  local out="${file}.anchor"
  mkdir -p "$out"
  local sha; sha="$(shasum -a 256 "$file" | awk '{print $1}')"

  # 1) RFC 3161 request over the file  2) send to TSA  3) pull certs  4) verify.
  openssl ts -query -data "$file" -sha256 -cert -out "$out/request.tsq" >/dev/null 2>&1
  curl -sS -f -H "Content-Type: application/timestamp-query" \
       --data-binary "@$out/request.tsq" "$TSA_URL" -o "$out/token.tsr"
  fetch_certs "$out"
  local gentime
  gentime="$(openssl ts -reply -in "$out/token.tsr" -text 2>/dev/null | awk -F': ' '/Time stamp/{print $2}')"
  local ok="FAILED"
  openssl ts -verify -data "$file" -in "$out/token.tsr" \
       -CAfile "$out/cacert.pem" -untrusted "$out/tsa.crt" >/dev/null 2>&1 && ok="OK"

  # --- receipt: what it proves, and how anyone re-checks it ---
  cat > "$out/RECEIPT.txt" <<EOF
UNDENIABLE-EXISTENCE RECEIPT
============================
file            : $(basename "$file")
sha256          : $sha
timestamp (UTC) : $gentime
authority       : FreeTSA (freetsa.org) — independent RFC 3161 TSA
signature check : $ok

WHAT THIS PROVES  : these exact bytes existed no later than the timestamp above,
                    attested by an independent authority's signed clock. It
                    cannot be backdated.
WHAT IT DOES NOT  : who authored the file, that its contents are true, or any
                    real-world identity.

RE-VERIFY YOURSELF (needs only this folder + the file):
  openssl ts -verify -data $(basename "$file") -in token.tsr \\
     -CAfile cacert.pem -untrusted tsa.crt
EOF

  # --- public-receipt drafts (human edits the headline; facts are filled in) ---
  cat > "$out/PUBLISH-github.md" <<EOF
# First Proof — $(basename "$file")

<!-- EDIT THIS HEADLINE / framing. Everything below is machine-fact; do not alter. -->

This file's existence is independently timestamped. You do not have to trust me.

- **SHA-256:** \`$sha\`
- **Independently timestamped (UTC):** $gentime
- **Authority:** FreeTSA (freetsa.org), RFC 3161
- **Signature check:** $ok

**Verify it yourself** (needs only the file + the attached \`token.tsr\`, \`cacert.pem\`, \`tsa.crt\`):

\`\`\`
openssl ts -verify -data $(basename "$file") -in token.tsr \\
   -CAfile cacert.pem -untrusted tsa.crt
\`\`\`

Attach to this release: the file itself, \`token.tsr\`, \`cacert.pem\`, \`tsa.crt\`.

NON ROGAT FIDEM — it does not ask for faith.
EOF

  cat > "$out/PUBLISH-x.txt" <<EOF
[EDIT the first line — your words.]
First proof. Its existence is timestamped by an independent authority — not my clock, not my word.

SHA-256: ${sha:0:32}…
Verify it yourself: $REPO_URL/releases

NON ROGAT FIDEM.
EOF

  echo "wrote $out/  (signature check: $ok)"
  echo "  RECEIPT.txt         — what it proves + re-verify command"
  echo "  PUBLISH-github.md   — release body draft ($X_HANDLE edits headline)"
  echo "  PUBLISH-x.txt       — X post draft"
  echo "  token.tsr cacert.pem tsa.crt — the proof itself (publish these)"
}

cmd_verify() {
  local file="$1" dir="$2"
  echo "file sha256 : $(shasum -a 256 "$file" | awk '{print $1}')"
  openssl ts -verify -data "$file" -in "$dir/token.tsr" \
       -CAfile "$dir/cacert.pem" -untrusted "$dir/tsa.crt"
}

case "${1:-}" in
  anchor) shift; cmd_anchor "$@";;
  verify) shift; cmd_verify "$@";;
  *) echo "usage: $0 anchor <file> | verify <file> <receipt-dir>" >&2; exit 2;;
esac
