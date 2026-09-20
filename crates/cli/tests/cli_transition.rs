#![cfg(not(target_os = "windows"))]
//! NOTE: Skipped on Windows for the same filesystem-locking reason as the
//! other CLI e2e tests. macOS and Linux exercise identical logic.
//!
//! End-to-end test for the governed-transition CLI surface:
//!   `win summarize <file>` → a `.win` transition artifact
//!   `win verify <file.win>` → auto-detects it and prints the matrix
//!
//! Proves the accepted path verifies, and that tampering with the sealed
//! content is caught (CONTENT INTEGRITY: MISMATCH → overall FAIL).

use assert_cmd::Command;
use std::fs;

fn cli(dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("win").expect("win binary builds");
    cmd.current_dir(dir);
    cmd
}

#[test]
fn summarize_then_verify_passes() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("doc.txt");
    fs::write(&src, "UNIQUETOKEN12345 is the first line.\nA second line here.\n").unwrap();

    let out = dir.path().join("doc.win");
    let sum = dir.path().join("doc.summary.txt");

    cli(dir.path())
        .arg("summarize")
        .arg(&src)
        .arg("--out")
        .arg(&out)
        .arg("--summary-out")
        .arg(&sum)
        .assert()
        .success();

    assert!(out.exists(), "the .win artifact must be written");
    assert!(sum.exists(), "the summary text must be written");
    let summary_text = fs::read_to_string(&sum).unwrap();
    assert!(summary_text.contains("UNIQUETOKEN12345"), "summary carries the lead line");

    cli(dir.path())
        .arg("verify")
        .arg(&out)
        .assert()
        .success()
        .stdout(predicates::str::contains("OVERALL: PASS"))
        .stdout(predicates::str::contains("CONTENT INTEGRITY         VALID"));
}

#[test]
fn tampered_transition_artifact_fails_verify() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("doc.txt");
    fs::write(&src, "UNIQUETOKEN12345 is the first line.\nA second line here.\n").unwrap();
    let out = dir.path().join("doc.win");

    cli(dir.path())
        .arg("summarize")
        .arg(&src)
        .arg("--out")
        .arg(&out)
        .assert()
        .success();

    // Flip one byte of the carried summary content (the sealed record is untouched).
    let mut bytes = fs::read(&out).unwrap();
    let needle = b"UNIQUETOKEN12345";
    let idx = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("lead token present in the carried content");
    bytes[idx] ^= 0xFF;
    fs::write(&out, &bytes).unwrap();

    cli(dir.path())
        .arg("verify")
        .arg(&out)
        .assert()
        .failure()
        .stdout(predicates::str::contains("CONTENT INTEGRITY"))
        .stdout(predicates::str::contains("MISMATCH"))
        .stdout(predicates::str::contains("OVERALL: FAIL"));
}
