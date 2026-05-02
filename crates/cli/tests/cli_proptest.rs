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

fn win(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("win").expect("win binary");
    cmd.current_dir(dir);
    cmd.env("HOME", dir);
    cmd
}

fn seal_and_get_win(dir: &TempDir, name: &str, content: &[u8]) -> std::path::PathBuf {
    let src = dir.path().join(name);
    fs::write(&src, content).unwrap();
    win(dir.path()).arg("seal").arg(&src).arg("--private").assert().success();
    src.with_extension("win")
}

proptest! {
    #![proptest_config(ProptestConfig {
        // 64 cases per property × 5 properties = 320 generated cases per run.
        // Each case spawns a `win` subprocess so we keep this modest to
        // keep total test time reasonable.
        cases: 64,
        max_shrink_iters: 32,
        .. ProptestConfig::default()
    })]

    /// Property 1: roundtrip preserves bytes exactly.
    #[test]
    fn seal_then_open_roundtrips_exact_bytes(content in prop::collection::vec(any::<u8>(), 0..=512)) {
        let dir = tempfile::tempdir().unwrap();
        let win_path = seal_and_get_win(&dir, "rt.bin", &content);
        let src = dir.path().join("rt.bin");
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
        let win_path = seal_and_get_win(&dir, "sz.bin", &content);
        let win_size = fs::metadata(&win_path).unwrap().len();
        prop_assert!(win_size > content.len() as u64,
            ".win ({}) must exceed source ({})", win_size, content.len());
    }

    /// Property 3: a freshly sealed .win always verifies (regardless
    /// of source content).
    #[test]
    fn sealed_win_always_verifies(content in prop::collection::vec(any::<u8>(), 0..=512)) {
        let dir = tempfile::tempdir().unwrap();
        let win_path = seal_and_get_win(&dir, "v.bin", &content);
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
        let path = dir.path().join("garbage.bin");
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
        let win_path = seal_and_get_win(&dir, "i.bin", &content);
        let out = win(dir.path()).arg("inspect").arg(&win_path).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let expected = format!("{} bytes", content.len());
        prop_assert!(stdout.contains(&expected),
            "inspect must show {} for source of length {}: stdout={}",
            expected, content.len(), stdout);
    }
}
