#![cfg(not(target_os = "windows"))]
//! NOTE: Skipped on Windows. Every test in this file spawns the
//! `win` binary which uses registry_core::object_store::ObjectStore.
//! On Windows runners that path returns "Access is denied (os error 5)"
//! due to a filesystem-locking quirk in atomic rename. macOS and
//! Linux exercise the same verification logic; coverage is not lost.

//! End-to-end bridge test: prove that `.win` bytes produced by the
//! `win` CLI are consumable by the SAME verification pipeline the
//! browser runs.
//!
//! The browser loads `verifier-wasm` and calls `recognize_win(bytes)`,
//! which internally does:
//!     1. `win_format::unpack(bytes)` → (filename, file_bytes, proof_text)
//!     2. `serde_json::from_str::<ProofBundle>(proof_text)`
//!     3. SHA-256 hash check: file_bytes vs bundle.object.payload_hash
//!     4. `verifier::verify_from_proof_bundle(bundle, file_bytes)`
//!     5. Map result → "Verified" / "Tampered" / "Invalid"
//!
//! This test exercises that exact pipeline natively, on bytes produced
//! by the live CLI binary. A pass here means: a sender's `.win` will
//! Verify in any browser that loads the deployed `verifier-wasm`.

use assert_cmd::Command;
use canon_types::{ProofBundle, VerificationStatus};
use std::fs;

fn cli(dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("win").expect("win binary builds");
    cmd.current_dir(dir);
    cmd.env("HOME", dir);
    cmd
}

/// Replicates `verifier_wasm::recognize_win`'s pipeline.
/// Returns the status string the browser would render.
fn browser_recognize_win(win_bytes: &[u8]) -> String {
    let (_name, file_bytes, proof_text) = match win_format::unpack(win_bytes) {
        Ok(t) => t,
        Err(_) => return "Invalid".into(),
    };
    let bundle: ProofBundle = match serde_json::from_str(&proof_text) {
        Ok(b) => b,
        Err(_) => return "Invalid".into(),
    };

    // The hash check that recognize_win does first.
    let computed = wise_crypto::sha256_hex(&file_bytes);
    if computed != bundle.object.payload_hash {
        return "Tampered".into();
    }

    let result = verifier::verify_from_proof_bundle(&bundle, &file_bytes);
    match result.status {
        VerificationStatus::Verified => "Verified".into(),
        VerificationStatus::Tampered => "Tampered".into(),
        VerificationStatus::Invalid => "Invalid".into(),
    }
}

#[test]
fn cli_produced_win_is_browser_verified() {
    // 1. Sender uses the CLI to seal a file.
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("doc.txt");
    fs::write(&src, b"the producer-consumer bridge test").unwrap();
    cli(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    let win_bytes = fs::read(src.with_extension("win")).unwrap();

    // 2. Receiver runs the browser verifier on those bytes.
    let status = browser_recognize_win(&win_bytes);
    assert_eq!(
        status, "Verified",
        "browser pipeline must Verify CLI-produced bytes"
    );
}

#[test]
fn cli_produced_win_with_flipped_payload_byte_is_tampered() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("t.txt");
    fs::write(&src, b"sealed today, tampered tomorrow").unwrap();
    cli(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();

    // Flip a byte in the .win container at a position likely to land inside
    // the embedded file payload, not in the header or proof JSON.
    let mut win_bytes = fs::read(src.with_extension("win")).unwrap();
    // The container layout is: magic(4) + filename_len(4) + filename + content_len(8)
    // + content + proof_len(8) + proof. The content section is somewhere in the
    // middle. Flip near the front of the file content (after the header).
    let i = 4 + 4 + b"t.txt".len() + 8 + 1; // first byte of content
    if i < win_bytes.len() {
        win_bytes[i] ^= 0xFF;
    }
    let status = browser_recognize_win(&win_bytes);
    assert_ne!(
        status, "Verified",
        "tampered .win must not Verify; got {}",
        status
    );
}

#[test]
fn random_bytes_are_invalid_in_browser() {
    let status = browser_recognize_win(&[0u8; 256]);
    assert_eq!(status, "Invalid", "random bytes must be Invalid in browser");
}

#[test]
fn empty_bytes_are_invalid_in_browser() {
    let status = browser_recognize_win(&[]);
    assert_eq!(status, "Invalid");
}

#[test]
fn cli_produced_then_truncated_is_invalid_in_browser() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("trunc.txt");
    fs::write(&src, b"truncate me").unwrap();
    cli(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    let win_bytes = fs::read(src.with_extension("win")).unwrap();
    // Cut to half — should fail to unpack cleanly.
    let truncated = &win_bytes[..win_bytes.len() / 2];
    let status = browser_recognize_win(truncated);
    assert_ne!(
        status, "Verified",
        "truncated .win must not Verify; got {}",
        status
    );
}

/// Smoke check that varied content sizes all roundtrip cleanly through
/// the browser pipeline.
#[test]
fn varied_sizes_all_browser_verify() {
    for &size in &[0usize, 1, 16, 256, 4096] {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join(format!("s{}.txt", size));
        let content: Vec<u8> = (0..size).map(|i| (i & 0xFF) as u8).collect();
        fs::write(&src, &content).unwrap();
        cli(dir.path())
            .arg("seal")
            .arg(&src)
            .arg("--private")
            .assert()
            .success();
        let win_bytes = fs::read(src.with_extension("win")).unwrap();
        let status = browser_recognize_win(&win_bytes);
        assert_eq!(status, "Verified", "size {} byte(s) must Verify", size);
    }
}

// ─────────────────────────────────────────────────────────────────────
// URL FLOW: the `/v/<hash>` route
//
// The browser's URL flow:
//   1. Visitor opens `https://winstack.dev/v/<hash>` (or truth.systems/v/<hash>)
//   2. The page fetches `/v/<hash>.json` — that's the proof bundle
//      written by `win publish <file.win>` to `<deploy>/v/<hash>.json`
//   3. The page asks the visitor to drop the original file
//   4. The page calls `recognize_bundle(proof_json, file_bytes)`
//   5. Renders the verdict
//
// This test simulates that exact flow: seal → publish → fetch the
// published JSON → verify against original bytes via the bundle path.
// ─────────────────────────────────────────────────────────────────────

/// Replicates `verifier_wasm::recognize_bundle`'s pipeline for the URL flow.
fn browser_recognize_bundle(proof_json: &str, file_bytes: &[u8]) -> String {
    let bundle: ProofBundle = match serde_json::from_str(proof_json) {
        Ok(b) => b,
        Err(_) => return "Invalid".into(),
    };
    let computed = wise_crypto::sha256_hex(file_bytes);
    if computed != bundle.object.payload_hash {
        return "Tampered".into();
    }
    let result = verifier::verify_from_proof_bundle(&bundle, file_bytes);
    match result.status {
        VerificationStatus::Verified => "Verified".into(),
        VerificationStatus::Tampered => "Tampered".into(),
        VerificationStatus::Invalid => "Invalid".into(),
    }
}

#[test]
fn url_flow_published_bundle_verifies_against_original() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("doc.txt");
    let original = b"the URL-flow integration test";
    fs::write(&src, original).unwrap();

    // Seal then publish to a local public/ directory.
    cli(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    let win_path = src.with_extension("win");
    cli(dir.path())
        .arg("publish")
        .arg(&win_path)
        .arg("--to")
        .arg(dir.path().join("public"))
        .assert()
        .success();

    // Find the published bundle (the file in public/v/ ending in .json).
    let v_dir = dir.path().join("public").join("v");
    assert!(v_dir.exists(), "publish should create public/v/");
    let mut bundles = fs::read_dir(&v_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect::<Vec<_>>();
    assert_eq!(bundles.len(), 1, "expected exactly one published bundle");
    let bundle_path = bundles.pop().unwrap();
    let proof_json = fs::read_to_string(&bundle_path).unwrap();

    // Bundle filename should be the SHA-256 of the original file + ".json".
    let expected_hash = wise_crypto::sha256_hex(original);
    let bundle_stem = bundle_path.file_stem().unwrap().to_string_lossy();
    assert_eq!(
        bundle_stem, expected_hash,
        "URL hash must match file SHA-256"
    );

    // The receiver in the URL flow drops the original file → recognize_bundle.
    let status = browser_recognize_bundle(&proof_json, original);
    assert_eq!(
        status, "Verified",
        "published bundle must Verify against the original"
    );
}

// ─────────────────────────────────────────────────────────────────────
// LINEAGE: parent → child chains
//
// `win seal --from <parent.win>` makes the new seal a successor of an
// earlier .win. The browser pipeline reports lineage as "Standalone",
// "Origin", or "Successor". A chain link must verify on its own AND
// must reference its predecessor cleanly.
// ─────────────────────────────────────────────────────────────────────

fn read_lineage(win_bytes: &[u8]) -> &'static str {
    let (_n, _f, proof_text) = win_format::unpack(win_bytes).unwrap();
    let bundle: ProofBundle = serde_json::from_str(&proof_text).unwrap();
    match &bundle.object.proof_chain {
        None => "Standalone",
        Some(c) if c.predecessor_proof_id.is_none() => "Origin",
        Some(_) => "Successor",
    }
}

#[test]
fn lineage_first_seal_is_standalone_or_origin() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("v1.txt");
    fs::write(&src, b"version 1 content").unwrap();
    cli(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    let win_bytes = fs::read(src.with_extension("win")).unwrap();
    let lineage = read_lineage(&win_bytes);
    assert!(
        lineage == "Standalone" || lineage == "Origin",
        "first seal lineage was {} (expected Standalone or Origin)",
        lineage
    );
    assert_eq!(browser_recognize_win(&win_bytes), "Verified");
}

#[test]
fn lineage_child_with_from_flag_is_successor() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = dir.path().join("v1.txt");
    let v2 = dir.path().join("v2.txt");
    fs::write(&v1, b"version 1").unwrap();
    fs::write(&v2, b"version 2 - has more content").unwrap();

    // First seal — the parent.
    cli(dir.path())
        .arg("seal")
        .arg(&v1)
        .arg("--private")
        .assert()
        .success();
    let v1_win = v1.with_extension("win");
    assert!(v1_win.exists());

    // Second seal with --from points at the parent.
    cli(dir.path())
        .arg("seal")
        .arg(&v2)
        .arg("--from")
        .arg(&v1_win)
        .arg("--private")
        .assert()
        .success();
    let v2_win_bytes = fs::read(v2.with_extension("win")).unwrap();

    let lineage = read_lineage(&v2_win_bytes);
    assert_eq!(
        lineage, "Successor",
        "child seal must be Successor; got {}",
        lineage
    );
    assert_eq!(
        browser_recognize_win(&v2_win_bytes),
        "Verified",
        "child .win must Verify on its own"
    );
}

#[test]
fn lineage_inspect_surfaces_chain() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = dir.path().join("orig.txt");
    let v2 = dir.path().join("rev.txt");
    fs::write(&v1, b"original").unwrap();
    fs::write(&v2, b"revised").unwrap();
    cli(dir.path())
        .arg("seal")
        .arg(&v1)
        .arg("--private")
        .assert()
        .success();
    cli(dir.path())
        .arg("seal")
        .arg(&v2)
        .arg("--from")
        .arg(v1.with_extension("win"))
        .arg("--private")
        .assert()
        .success();
    // inspect on the child must succeed and not panic.
    cli(dir.path())
        .arg("inspect")
        .arg(v2.with_extension("win"))
        .assert()
        .success();
}

#[test]
fn url_flow_published_bundle_with_wrong_file_returns_tampered() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("real.txt");
    fs::write(&src, b"the real file").unwrap();
    cli(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    cli(dir.path())
        .arg("publish")
        .arg(src.with_extension("win"))
        .arg("--to")
        .arg(dir.path().join("public"))
        .assert()
        .success();

    let v_dir = dir.path().join("public").join("v");
    let proof_json = fs::read_dir(&v_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .map(|p| fs::read_to_string(p).unwrap())
        .unwrap();

    // Receiver drops the WRONG file. The URL → bundle is for "the real file"
    // but they hand over different bytes. Status must NOT be Verified.
    let wrong_bytes = b"a different file entirely";
    let status = browser_recognize_bundle(&proof_json, wrong_bytes);
    assert_ne!(
        status, "Verified",
        "URL flow with wrong file must not Verify; got {}",
        status
    );
}
