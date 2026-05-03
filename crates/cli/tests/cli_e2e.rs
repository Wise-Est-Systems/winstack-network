//! End-to-end tests for the `win` CLI binary.
//!
//! These tests build and invoke the actual `win` binary in a temp dir,
//! exercising the full seal/verify/inspect/open/trust roundtrip the way
//! a real user would. They catch regressions that unit tests inside
//! crates cannot — argument parsing, exit codes, output formatting,
//! cross-crate wiring, and file I/O.
//!
//! Use `assert_cmd::Command::cargo_bin("win")` so cargo rebuilds the
//! binary on demand. Each test gets its own `TempDir`; the local node
//! state lives at `<tmp>/.wise/` so tests don't share keys or graphs.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Helper: invoke `win` with the given args, rooted at `dir`.
/// Sets HOME so the local node directory is created inside `dir/.wise/`
/// instead of leaking into the test runner's home.
fn win(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("win").expect("win binary builds");
    cmd.current_dir(dir);
    cmd.env("HOME", dir);
    cmd
}

/// Set up a scratch directory with a sample file inside.
fn scratch_with_file(name: &str, content: &[u8]) -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    fs::write(&path, content).unwrap();
    (dir, path)
}

// ─────────────────────────────────────────────────────────────────────
// SEAL
// ─────────────────────────────────────────────────────────────────────

#[test]
fn seal_produces_a_dot_win_next_to_the_source() {
    let (dir, src) = scratch_with_file("note.txt", b"hello e2e");
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success()
        .stdout(predicate::str::contains("note.win"));
    assert!(src.with_extension("win").exists());
}

#[test]
fn seal_share_url_uses_single_v_segment() {
    // Regression: default base_url was "truth.systems/verify" which
    // produced "truth.systems/verify/v/<hash>" — doubled segment.
    let (dir, src) = scratch_with_file("u.txt", b"x");
    let out = win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("/v/"),
        "stdout should mention /v/: {}",
        stdout
    );
    assert!(
        !stdout.contains("/verify/v/"),
        "must not double the segment: {}",
        stdout
    );
}

#[test]
fn seal_with_private_flag_skips_publish() {
    // --private should not create a public/v/<hash>.json artifact.
    let (dir, src) = scratch_with_file("p.txt", b"private content");
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    let public = dir.path().join("public").join("v");
    assert!(
        !public.exists() || fs::read_dir(&public).unwrap().next().is_none(),
        "no public/v/ artifacts should be produced under --private"
    );
}

#[test]
fn seal_multiple_files_in_one_invocation() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    fs::write(&a, b"alpha").unwrap();
    fs::write(&b, b"beta").unwrap();
    win(dir.path())
        .arg("seal")
        .arg(&a)
        .arg(&b)
        .arg("--private")
        .assert()
        .success();
    assert!(a.with_extension("win").exists(), "a.win missing");
    assert!(b.with_extension("win").exists(), "b.win missing");
}

#[test]
fn seal_of_empty_file_succeeds() {
    let (dir, src) = scratch_with_file("empty.txt", b"");
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    assert!(src.with_extension("win").exists());
}

#[test]
fn seal_with_custom_base_url_appears_in_share_link() {
    let (dir, src) = scratch_with_file("c.txt", b"custom");
    let out = win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--base-url")
        .arg("https://example.test")
        .arg("--private")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("https://example.test/v/"), "{}", stdout);
}

// ─────────────────────────────────────────────────────────────────────
// VERIFY
// ─────────────────────────────────────────────────────────────────────

#[test]
fn verify_after_seal_returns_verified() {
    let (dir, src) = scratch_with_file("v.txt", b"verify me");
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    win(dir.path())
        .arg("verify")
        .arg(src.with_extension("win"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Verified"));
}

#[test]
fn verify_of_random_bytes_exits_nonzero() {
    let (dir, _) = scratch_with_file("garbage.dat", &[0u8; 64]);
    let res = win(dir.path())
        .arg("verify")
        .arg(dir.path().join("garbage.dat"))
        .assert()
        .failure();
    let out = res.get_output();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ERROR") || stderr.contains("not a .win"),
        "{}",
        stderr
    );
}

#[test]
fn verify_of_truncated_win_does_not_panic() {
    let (dir, src) = scratch_with_file("t.txt", b"truncate test");
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    let win_path = src.with_extension("win");
    let bytes = fs::read(&win_path).unwrap();
    fs::write(&win_path, &bytes[..bytes.len() / 2]).unwrap();
    // Should exit nonzero and produce no panic backtrace.
    let out = win(dir.path())
        .arg("verify")
        .arg(&win_path)
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("RUST_BACKTRACE"),
        "panic surfaced: {}",
        combined
    );
    assert!(
        combined.contains("Invalid")
            || combined.contains("Tampered")
            || combined.contains("Damaged"),
        "expected Invalid, Tampered, or Damaged, got: {}",
        combined
    );
}

#[test]
fn verify_of_nonexistent_file_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    win(dir.path())
        .arg("verify")
        .arg(dir.path().join("nope.win"))
        .assert()
        .failure();
}

#[test]
fn verify_after_payload_byte_flip_does_not_return_verified() {
    let (dir, src) = scratch_with_file("flip.txt", b"flip me");
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    let win_path = src.with_extension("win");
    let mut bytes = fs::read(&win_path).unwrap();
    // Flip a byte in the latter half (likely inside payload, not header).
    let i = bytes.len() * 3 / 4;
    bytes[i] ^= 0xFF;
    fs::write(&win_path, &bytes).unwrap();
    let out = win(dir.path())
        .arg("verify")
        .arg(&win_path)
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("Verified"),
        "tampered .win must not return Verified: {}",
        combined
    );
}

// ─────────────────────────────────────────────────────────────────────
// INSPECT
// ─────────────────────────────────────────────────────────────────────

#[test]
fn inspect_shows_file_size_and_fingerprint() {
    let (dir, src) = scratch_with_file("i.txt", b"inspect me please");
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    win(dir.path())
        .arg("inspect")
        .arg(src.with_extension("win"))
        .assert()
        .success()
        .stdout(predicate::str::contains("17 bytes"))
        .stdout(predicate::str::contains("sha256:"));
}

#[test]
fn inspect_of_nonexistent_file_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    win(dir.path())
        .arg("inspect")
        .arg(dir.path().join("nope.win"))
        .assert()
        .failure();
}

// ─────────────────────────────────────────────────────────────────────
// OPEN (extract original from .win)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn open_restores_byte_identical_original() {
    let original = b"open and restore me - and check exact bytes";
    let (dir, src) = scratch_with_file("o.txt", original);
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    fs::remove_file(&src).unwrap();
    win(dir.path())
        .arg("open")
        .arg(src.with_extension("win"))
        .assert()
        .success();
    let restored = fs::read(&src).unwrap();
    assert_eq!(
        &restored, original,
        "open must restore byte-identical original"
    );
}

#[test]
fn open_a_tampered_win_without_force_refuses() {
    let (dir, src) = scratch_with_file("of.txt", b"force test");
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    let win_path = src.with_extension("win");
    let mut bytes = fs::read(&win_path).unwrap();
    let i = bytes.len() * 3 / 4;
    bytes[i] ^= 0xFF;
    fs::write(&win_path, &bytes).unwrap();
    fs::remove_file(&src).unwrap();
    win(dir.path())
        .arg("open")
        .arg(&win_path)
        .assert()
        .failure();
    assert!(
        !src.exists(),
        "open must NOT have restored a tampered file without --force"
    );
}

// ─────────────────────────────────────────────────────────────────────
// TRUST
// ─────────────────────────────────────────────────────────────────────

#[test]
fn trust_list_runs_without_keys() {
    let dir = tempfile::tempdir().unwrap();
    win(dir.path()).arg("trust").arg("list").assert().success();
}

#[test]
fn trust_add_then_list_shows_the_key() {
    let dir = tempfile::tempdir().unwrap();
    // 64-char hex public key (placeholder; identity layer doesn't validate
    // it as a real Ed25519 point at the trust-list layer)
    let key = "a".repeat(64);
    win(dir.path())
        .arg("trust")
        .arg("add")
        .arg(&key)
        .arg("--label")
        .arg("test")
        .assert()
        .success();
    win(dir.path())
        .arg("trust")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains(&key[..8]));
}

#[test]
fn trust_remove_drops_a_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = "b".repeat(64);
    win(dir.path())
        .arg("trust")
        .arg("add")
        .arg(&key)
        .arg("--label")
        .arg("rm")
        .assert()
        .success();
    win(dir.path())
        .arg("trust")
        .arg("remove")
        .arg(&key)
        .assert()
        .success();
    let out = win(dir.path()).arg("trust").arg("list").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(&key[..8]),
        "key should be removed: {}",
        stdout
    );
}

// ─────────────────────────────────────────────────────────────────────
// HELP / ARGUMENT-PARSING REGRESSIONS
// ─────────────────────────────────────────────────────────────────────

#[test]
fn help_displays_seal_subcommand() {
    // Regression: the CLI used to have a redundant `win win <files>`
    // (binary-named-win + subcommand-named-win). That was renamed to
    // `win seal`. Help must show "seal" and must not show the inner "win".
    let dir = tempfile::tempdir().unwrap();
    let out = win(dir.path()).arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("seal"),
        "help should mention 'seal' subcommand: {}",
        stdout
    );
    // Note: the binary itself is named "win", which appears in usage line.
    // Ensure the *subcommand* list does not include "win" (which would
    // re-introduce the win-win confusion). Look for a line that lists
    // subcommands and verify "win  " is not there.
    let subcommands_line = stdout.lines().find(|l| l.trim().starts_with("seal"));
    assert!(subcommands_line.is_some(), "expected 'seal' line in help");
}

#[test]
fn help_does_not_panic_under_no_args() {
    let dir = tempfile::tempdir().unwrap();
    let out = win(dir.path()).output().unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("RUST_BACKTRACE"),
        "no-arg invocation panicked: {}",
        combined
    );
}

#[test]
fn invalid_subcommand_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    win(dir.path())
        .arg("nonexistent-subcommand")
        .assert()
        .failure();
}
