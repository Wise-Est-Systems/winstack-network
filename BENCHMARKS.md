# BENCHMARKS

> Real numbers from a fresh build. Reproducible by anyone with the steps at the bottom of this page. No vendor wand-waving — if your numbers disagree on similar hardware, that disagreement is itself the interesting data point.

**Hardware:** Apple Silicon (Darwin 25.5.0, ARM64).
**Build profile:** `cargo build --release -p cli`.
**Date of run:** 2026-06-02.
**Commit:** the head of `main`.

---

## Container overhead

A `.win` is the original file plus a small fixed-size envelope (signature + canonical object payload + metadata). The overhead is constant — it does **not** grow with the file size.

| Original file | Original size | `.win` size | Overhead |
|---|---|---|---|
| `tiny.txt`   | 12 B    | 3,701 B    | 3,689 B |
| `1kb.bin`    | 1,024 B    | 4,714 B    | 3,690 B |
| `10kb.bin`   | 10,240 B   | 13,932 B   | 3,692 B |
| `100kb.bin`  | 102,400 B  | 106,094 B  | 3,694 B |
| `1mb.bin`    | 1,048,576 B | 1,052,269 B | 3,693 B |
| `10mb.bin`   | 10,485,760 B | 10,489,455 B | 3,695 B |

**Plain English:** ~3.7 KB of cryptographic metadata travels alongside every sealed file. For a 10 MB file, that's a 0.04% overhead. For a 1 KB file, the proof is roughly 4× the file — sealing tiny files is wasteful relative to file size but cheap in absolute terms.

---

## Verification latency

`win verify <file>.win` performs: canonical container parse → SHA-256 over the artifact payload → Ed25519 signature verify against the embedded witness key → return one of `Verified` / `Tampered` / `Invalid`.

Each row below is the median of 5 cold runs (single-process startup included).

| File size | Median | Min | Max |
|---|---|---|---|
| 12 B    | 7.11 ms  | 4.31 ms  | 8.56 ms  |
| 1 KB    | 7.23 ms  | 6.36 ms  | 7.55 ms  |
| 10 KB   | 6.16 ms  | 5.81 ms  | 7.88 ms  |
| 100 KB  | 7.30 ms  | 5.60 ms  | 8.82 ms  |
| 1 MB    | 16.00 ms | 10.86 ms | 17.25 ms |
| 10 MB   | 68.60 ms | 57.78 ms | 75.15 ms |

**Plain English:** For everything under ~100 KB, you pay ~7 ms — dominated by process startup, signature verify, and container parse. Above ~1 MB the SHA-256 hash starts to show in the timing (linear in file size from there). A 10 MB file verifies in ~70 ms on a single core.

The verifier never reads the file twice and never makes a network request.

---

## Artifact sizes

| Artifact | Size | Purpose |
|---|---|---|
| `target/release/win` (release CLI binary)             | 4.6 MB | Local `seal` / `verify` / `open` / `publish` CLI. Single static-ish binary; no runtime deps beyond `libc`. |
| `target/wasm32-unknown-unknown/release/verifier_wasm.wasm` (raw) | 1.5 MB | Raw verifier compiled to WebAssembly. |
| `public/wasm/verifier_wasm_bg.wasm` (wasm-bindgen output) | 1.1 MB | What the browser actually loads. Includes JS bindings + glue. |

**Plain English:** Loading the browser verifier costs roughly 1.1 MB on first visit (cacheable). For comparison, a single JPEG photo on a typical news site is often ~500 KB; this is two of those, once, then cached. A reader on a metered connection pays that cost the first time and zero on every subsequent verification.

---

## What is NOT in these numbers

This page is **not** a security benchmark. Verification *time* tells you nothing about verification *correctness*. The numbers above only show that the verifier completes its work quickly; they say nothing about whether its verdict is right.

For correctness, see:
- The [conformance vectors](https://github.com/Wise-Est-Systems/wiseorder-protocol/tree/main/vectors) in `wiseorder-protocol` — two independent verifiers (Go + Rust) must agree on every fingerprint.
- The [Algorithm Choice section of `wop/SECURITY.md`](https://github.com/Wise-Est-Systems/wop/blob/main/SECURITY.md) for the hash family's review status.
- The [`SECURITY.md`](./SECURITY.md) for this repo's threat model.

External cryptographic audit status: **`NOT_COMPLETE`** for the WiseDigest research-track digests. SHA-256 is the recommended algorithm in production paths.

---

## Reproduce these numbers

```bash
# 1. Clone fresh + build the release CLI
git clone https://github.com/Wise-Est-Systems/winstack-network && cd winstack-network
cargo build --release -p cli

# 2. Prepare test files
mkdir -p /tmp/bench
echo "hello world" > /tmp/bench/tiny.txt
for sz in 1 10 100 1024 10240; do
  dd if=/dev/urandom of=/tmp/bench/${sz}k.bin bs=1024 count=${sz} status=none
done

# 3. Seal each, observe overhead
for f in /tmp/bench/*; do
  ./target/release/win seal "$f" >/dev/null
  echo "$(basename "$f"): $(stat -f%z "$f") -> $(stat -f%z "$f.win")"
done

# 4. Time verification (Python harness; gives median of 5 cold runs)
python3 - <<'PY'
import subprocess, time, statistics, glob
for f in sorted(glob.glob('/tmp/bench/*.win')):
    times = []
    for _ in range(5):
        s = time.perf_counter_ns()
        subprocess.run(['./target/release/win', 'verify', f], capture_output=True)
        times.append((time.perf_counter_ns() - s) / 1e6)
    print(f'{f}: median={statistics.median(times):.2f} ms')
PY
```

If your numbers differ materially (>2× slower on similar hardware, or different verdicts), that is exactly the kind of finding the project wants to hear about. Open a [GitHub Discussion](https://github.com/Wise-Est-Systems/winstack-network/discussions) or a [Security Advisory](https://github.com/Wise-Est-Systems/winstack-network/security/advisories/new) if appropriate.
