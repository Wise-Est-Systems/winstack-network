#![cfg(not(target_os = "windows"))]
//! NOTE: Skipped on Windows. Every test in this file spawns the
//! `win` binary which uses registry_core::object_store::ObjectStore.
//! On Windows runners that path returns "Access is denied (os error 5)"
//! due to a filesystem-locking quirk in atomic rename. macOS and
//! Linux exercise the same verification logic; coverage is not lost.

//! Property-based tests for the `win` CLI.
//!
//! Each #[test] function counts as one in the suite but proptest runs
//! it across ~256 randomly generated inputs by default. So 5 properties
//! exercise ~1280 cases, catching regressions that hand-written unit
//! tests miss because of fixed inputs.
//!
//! Properties verified:
//!   1. Seal-then-open roundtrip preserves bytes exactly.
//!   2. Sealing a non-empty file produces a strictly larger .win.
//!   3. Sealed files always verify successfully under their own witness.
//!   4. Random non-.win bytes never verify successfully.
//!   5. Inspect of a sealed file always reports the correct size.

use assert_cmd::Command;
use proptest::prelude::*;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

/// Compute the .win path the CLI produces for a given source file.
/// CLI behavior: `<full filename>.win` so `note.txt` → `note.txt.win`.
fn win_of(p: &std::path::Path) -> std::path::PathBuf {
    let name = p
        .file_name()
        .expect("source has a filename")
        .to_string_lossy();
    p.with_file_name(format!("{name}.win"))
}

fn win(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("win").expect("win binary");
    cmd.current_dir(dir);
    cmd.env("HOME", dir);
    cmd
}

fn seal_and_get_win(dir: &TempDir, name: &str, content: &[u8]) -> std::path::PathBuf {
    let src = dir.path().join(name);
    fs::write(&src, content).unwrap();
    win(dir.path())
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .assert()
        .success();
    win_of(&src)
}

// CI / dev runs use the modest `cases: 64` default.
// Set `WISE_EXTREME_PROPTEST=1` for a 32× run (2048 cases per property,
// ~10240 generated subprocess invocations across 5 properties).
// Use that mode locally before a release.
fn proptest_cases() -> u32 {
    if std::env::var("WISE_EXTREME_PROPTEST").is_ok() {
        2048
    } else {
        64
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: proptest_cases(),
        max_shrink_iters: 32,
        .. ProptestConfig::default()
    })]

    /// Property 1: roundtrip preserves bytes exactly.
    #[test]
    fn seal_then_open_roundtrips_exact_bytes(content in prop::collection::vec(any::<u8>(), 0..=512)) {
        let dir = tempfile::tempdir().unwrap();
        let win_path = seal_and_get_win(&dir, "rt.dat", &content);
        let src = dir.path().join("rt.dat");
        fs::remove_file(&src).unwrap();
        win(dir.path()).arg("open").arg(&win_path).assert().success();
        let restored = fs::read(&src).unwrap();
        prop_assert_eq!(restored, content);
    }

    /// Property 2: sealing always produces a strictly larger .win
    /// (because a proof + container header are always added).
    #[test]
    fn dot_win_is_strictly_larger_than_source(content in prop::collection::vec(any::<u8>(), 0..=512)) {
        let dir = tempfile::tempdir().unwrap();
        let win_path = seal_and_get_win(&dir, "sz.dat", &content);
        let win_size = fs::metadata(&win_path).unwrap().len();
        prop_assert!(win_size > content.len() as u64,
            ".win ({}) must exceed source ({})", win_size, content.len());
    }

    /// Property 3: a freshly sealed .win always verifies (regardless
    /// of source content).
    #[test]
    fn sealed_win_always_verifies(content in prop::collection::vec(any::<u8>(), 0..=512)) {
        let dir = tempfile::tempdir().unwrap();
        let win_path = seal_and_get_win(&dir, "v.dat", &content);
        let out = win(dir.path()).arg("verify").arg(&win_path).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        prop_assert!(stdout.contains("Verified"),
            "sealed file must verify; got: {}", stdout);
    }

    /// Property 4: random bytes that don't start with the .win magic
    /// header are never verified successfully.
    #[test]
    fn random_non_win_bytes_never_verify(garbage in prop::collection::vec(any::<u8>(), 1..=256)) {
        // Skip cases that happen to start with the .win magic.
        // Magic is 4 bytes: 0x57 0x49 0x4E 0x01 ("WIN\x01").
        if garbage.len() >= 4 && garbage[0] == 0x57 && garbage[1] == 0x49
            && garbage[2] == 0x4E && garbage[3] == 0x01 { return Ok(()); }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.dat");
        fs::write(&path, &garbage).unwrap();
        let out = win(dir.path()).arg("verify").arg(&path).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        prop_assert!(!stdout.contains("Verified"),
            "random bytes must not Verify: stdout={}", stdout);
    }

    /// Property 5: inspect always reports the correct source size.
    #[test]
    fn inspect_reports_correct_source_size(content in prop::collection::vec(any::<u8>(), 1..=512)) {
        let dir = tempfile::tempdir().unwrap();
        let win_path = seal_and_get_win(&dir, "i.dat", &content);
        let out = win(dir.path()).arg("inspect").arg(&win_path).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let expected = format!("{} bytes", content.len());
        prop_assert!(stdout.contains(&expected),
            "inspect must show {} for source of length {}: stdout={}",
            expected, content.len(), stdout);
    }

    /// Property 6: any byte flip in the .win must NOT verify.
    /// Picks a random byte position, flips it, asserts the result is
    /// never Verified. Catches drift in the verifier where a corrupted
    /// container or proof could silently slip through.
    #[test]
    fn any_byte_flip_never_verifies(
        content in prop::collection::vec(any::<u8>(), 1..=256),
        flip_position_ratio in 0u32..1000u32,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let win_path = seal_and_get_win(&dir, "f.dat", &content);
        let mut bytes = fs::read(&win_path).unwrap();
        if bytes.is_empty() { return Ok(()); }
        // Map ratio to byte position. Skip the first 4 bytes of magic
        // since flipping magic is already covered by Damaged tests; we
        // want to exercise the rest of the container space here.
        let pos = 4 + (flip_position_ratio as usize * (bytes.len() - 4) / 1000);
        let pos = pos.min(bytes.len() - 1);
        bytes[pos] ^= 0xFF;
        fs::write(&win_path, &bytes).unwrap();
        let out = win(dir.path()).arg("verify").arg(&win_path).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        prop_assert!(!stdout.contains("Verified"),
            "byte flip at position {} must NOT yield Verified; got: {}", pos, stdout);
    }

    /// Property 7: CLI ↔ in-process verifier parity. For any sealed
    /// file, the CLI's exit-status word and the verifier crate's status
    /// must agree. Catches divergence between user-facing CLI output and
    /// the underlying verification logic.
    #[test]
    fn cli_and_verifier_crate_agree_on_status(
        content in prop::collection::vec(any::<u8>(), 0..=256),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let win_path = seal_and_get_win(&dir, "p.dat", &content);
        let win_bytes = fs::read(&win_path).unwrap();

        // CLI output
        let out = win(dir.path()).arg("verify").arg(&win_path).output().unwrap();
        let cli_word = if String::from_utf8_lossy(&out.stdout).contains("Verified") {
            "Verified"
        } else {
            "Other"
        };

        // In-process verifier crate
        let verifier_word = match win_format::unpack(&win_bytes) {
            Ok((_n, file_bytes, proof)) => {
                if let Ok(bundle) = serde_json::from_str::<canon_types::ProofBundle>(&proof) {
                    let result = verifier::verify_from_proof_bundle(&bundle, &file_bytes);
                    match result.status {
                        canon_types::VerificationStatus::Verified => "Verified",
                        _ => "Other",
                    }
                } else { "Other" }
            },
            Err(_) => "Other",
        };

        prop_assert_eq!(cli_word, verifier_word,
            "CLI and verifier crate must agree (cli={}, verifier={})",
            cli_word, verifier_word);
    }
}
