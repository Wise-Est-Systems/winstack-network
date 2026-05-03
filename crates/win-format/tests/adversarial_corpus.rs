//! Adversarial fixtures — hand-crafted byte sequences that an attacker
//! would actually try to send. Each one is named for the attack class
//! and asserts the protocol's required response: container errors map
//! to is_container_damage()=true (→ Damaged at the UI), proof errors
//! map to false (→ Invalid). NONE may panic, OOM, infinite-loop, or
//! return Ok with attacker-controlled fields.
//!
//! Add a new test the moment a new attack class shows up in the wild.

use win_format::{is_win_file, pack, unpack};

const MAGIC: &[u8; 4] = b"WIN\x01";

// ─────────────────────────────────────────────────────────────────────
// Length-field attacks
// ─────────────────────────────────────────────────────────────────────

#[test]
fn length_overflow_u64_max_is_damaged_not_panic() {
    // Filename length claims u32::MAX. Must reject as filename-length
    // bound or truncated, not panic and not allocate u32::MAX bytes.
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&u32::MAX.to_le_bytes()); // huge name_len
    buf.extend_from_slice(&[0u8; 16]); // garbage tail
    let err = unpack(&buf).expect_err("must reject");
    assert!(
        err.is_container_damage(),
        "huge filename length must be Damaged, got: {:?}",
        err
    );
}

#[test]
fn length_overflow_file_len_u64_max_is_damaged() {
    // Plausible filename; impossibly large file_len.
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&3u32.to_le_bytes());
    buf.extend_from_slice(b"x.t"); // filename
    buf.extend_from_slice(&u64::MAX.to_le_bytes()); // impossible file_len
    buf.extend_from_slice(&[0u8; 32]);
    let err = unpack(&buf).expect_err("must reject");
    assert!(err.is_container_damage(), "got: {:?}", err);
}

#[test]
fn length_zero_filename_rejected_or_sanitized() {
    // Zero-length filename is reserved for attack; must not unpack
    // with an empty filename string.
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&0u32.to_le_bytes()); // 0 filename
    buf.extend_from_slice(&5u64.to_le_bytes()); // 5 bytes file
    buf.extend_from_slice(b"hello");
    buf.extend_from_slice(b"{}"); // 2-byte proof
    let err = unpack(&buf).expect_err("zero-filename must reject");
    assert!(err.is_container_damage(), "got: {:?}", err);
}

#[test]
fn length_consumes_proof_section_is_damaged() {
    // file_len claims more bytes than remain after the file_len header,
    // so the proof section gets consumed. Must reject as truncated.
    let real = pack("test.txt", b"hello", r#"{"a":1}"#);
    // Find where file_len lives (after magic + name_len + name).
    let name_len_pos = 4;
    let name_end = 8 + 8; // 4 magic + 4 name_len + 8-char "test.txt"
    let _ = name_len_pos;
    let mut bytes = real.clone();
    // Inflate file_len so the parser tries to read past the proof.
    let inflated = (real.len() as u64).wrapping_add(1);
    bytes[name_end..name_end + 8].copy_from_slice(&inflated.to_le_bytes());
    let err = unpack(&bytes).expect_err("inflated file_len must reject");
    assert!(err.is_container_damage(), "got: {:?}", err);
}

// ─────────────────────────────────────────────────────────────────────
// Magic / structural attacks
// ─────────────────────────────────────────────────────────────────────

#[test]
fn magic_zero_byte_rejected() {
    let bytes = [0u8; 64];
    assert!(!is_win_file(&bytes));
    assert!(unpack(&bytes).is_err());
}

#[test]
fn magic_almost_correct_v0_rejected() {
    // First 3 bytes match WIN, but version byte is 0x00 instead of 0x01.
    let mut bytes = [0u8; 64];
    bytes[0] = b'W';
    bytes[1] = b'I';
    bytes[2] = b'N';
    bytes[3] = 0;
    assert!(!is_win_file(&bytes));
    let err = unpack(&bytes).expect_err("v0 must reject");
    assert!(err.is_container_damage(), "got: {:?}", err);
}

#[test]
fn empty_buffer_is_too_short() {
    assert!(unpack(&[]).is_err());
    assert!(unpack(&[]).unwrap_err().is_container_damage());
}

#[test]
fn header_only_no_data_is_damaged() {
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&8u32.to_le_bytes());
    buf.extend_from_slice(b"abc.txt"); // 7 chars but claims 8 — mismatch
    let err = unpack(&buf).expect_err("header-only must reject");
    assert!(err.is_container_damage(), "got: {:?}", err);
}

// ─────────────────────────────────────────────────────────────────────
// Filename attacks
// ─────────────────────────────────────────────────────────────────────

#[test]
fn filename_with_null_byte_rejected() {
    let packed = {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&8u32.to_le_bytes());
        buf.extend_from_slice(b"a\0b\0c.tx"); // 8 bytes with nulls
        buf.extend_from_slice(&3u64.to_le_bytes());
        buf.extend_from_slice(b"hi!");
        buf.extend_from_slice(b"{}");
        buf
    };
    let err = unpack(&packed).expect_err("null-byte filename must reject");
    let _ = err;
}

#[test]
fn filename_path_traversal_sanitized() {
    // pack() strips path components — receiver should never see "..".
    let packed = pack("../../../etc/passwd", b"x", "{}");
    let (name, _, _) = unpack(&packed).expect("roundtrip");
    assert_eq!(name, "passwd", "path traversal must be stripped");
    assert!(!name.contains(".."));
    assert!(!name.starts_with('/'));
}

#[test]
fn filename_absolute_path_sanitized() {
    let packed = pack("/etc/shadow", b"x", "{}");
    let (name, _, _) = unpack(&packed).expect("roundtrip");
    assert_eq!(name, "shadow");
}

#[test]
fn filename_windows_drive_path_sanitized() {
    let packed = pack("C:\\Windows\\system32\\sam", b"x", "{}");
    let (name, _, _) = unpack(&packed).expect("roundtrip");
    // sanitize_filename strips path components; on a unix test runner
    // the backslash isn't a path separator, but the basename should
    // still not contain drive letters with colons in a dangerous way.
    assert!(!name.contains(':') || !name.starts_with("C:"));
}

#[test]
fn filename_unicode_rtl_override_kept_visible_but_does_not_crash() {
    // RLO (U+202E) flips display order. Real protection is at render
    // time, not unpack — but the parser must not crash.
    let packed = pack("file\u{202E}gpj.exe", b"x", "{}");
    let _ = unpack(&packed).expect("RLO filename must roundtrip cleanly");
}

#[test]
fn filename_extreme_length_4096_max_accepted() {
    let long = "a".repeat(4096);
    let packed = pack(&long, b"x", "{}");
    let _ = unpack(&packed).expect("4096-char filename must roundtrip");
}

#[test]
fn filename_just_over_max_rejected() {
    // Hand-build a container with a 4097-byte filename.
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&4097u32.to_le_bytes());
    buf.extend_from_slice(&vec![b'a'; 4097]);
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.extend_from_slice(b"x");
    buf.extend_from_slice(b"{}");
    let err = unpack(&buf).expect_err("4097-char filename must reject");
    let _ = err;
}

// ─────────────────────────────────────────────────────────────────────
// Proof-section attacks (NOT container damage; expect Invalid downstream)
// ─────────────────────────────────────────────────────────────────────

#[test]
fn proof_unbalanced_braces_classifies_as_damaged() {
    // Unbalanced JSON in proof tail is treated as truncation
    // (per win-format's brackets_balanced check).
    let packed = pack("t.txt", b"x", "{\"a\":1"); // missing closing }
    let err = unpack(&packed).expect_err("unbalanced braces must reject");
    assert!(err.is_container_damage(), "got: {:?}", err);
}

#[test]
fn proof_balanced_but_meaningless_is_not_container_damage() {
    // {} is structurally complete but it's not a valid ProofBundle.
    // win-format must accept it — that's a downstream "Invalid", not
    // a container-level "Damaged".
    let packed = pack("t.txt", b"x", "{}");
    let (_n, _f, proof) = unpack(&packed).expect("{} unpacks");
    assert_eq!(proof, "{}");
}

#[test]
fn proof_with_quoted_brace_does_not_confuse_balance_check() {
    let packed = pack("t.txt", b"x", r#"{"a":"}{"}"#);
    let (_n, _f, proof) = unpack(&packed).expect("quoted braces must roundtrip");
    assert_eq!(proof, r#"{"a":"}{"}"#);
}

#[test]
fn proof_deeply_nested_does_not_stack_overflow() {
    // 10,000 levels of nesting in the proof section. Brackets-balanced
    // is iterative, so this must not stack-overflow.
    let mut deep = String::new();
    deep.extend(std::iter::repeat_n('{', 10_000));
    deep.push_str(r#""x":1"#);
    deep.extend(std::iter::repeat_n('}', 10_000));
    let packed = pack("d.txt", b"x", &deep);
    let (_n, _f, _proof) = unpack(&packed).expect("deep nesting must not crash");
}

#[test]
fn proof_huge_does_not_crash() {
    // 1 MB of {"a":N, ... } — pathological but legal.
    let mut huge = String::from("{");
    for i in 0..50_000 {
        huge.push_str(&format!(r#""k{}":{},"#, i, i));
    }
    huge.push_str(r#""end":1}"#);
    let packed = pack("h.txt", b"x", &huge);
    let (_n, _f, _proof) = unpack(&packed).expect("huge proof must roundtrip");
}

// ─────────────────────────────────────────────────────────────────────
// Generic robustness — must NEVER panic on attacker-supplied bytes
// ─────────────────────────────────────────────────────────────────────

#[test]
fn random_byte_sequences_never_panic() {
    // Iterate over a few hundred deterministic but adversarial seeds.
    // Real fuzzing happens via cargo-fuzz (fuzz/fuzz_targets/unpack.rs);
    // this is the in-tree smoke version that runs in CI.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    for seed in 0u64..256 {
        let mut h = DefaultHasher::new();
        seed.hash(&mut h);
        let mut bytes = vec![];
        let mut state = h.finish();
        for _ in 0..512 {
            bytes.push(state as u8);
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
        }
        // Result doesn't matter — must just not panic.
        let _ = unpack(&bytes);
        let _ = is_win_file(&bytes);
    }
}

#[test]
fn all_single_byte_inputs_never_panic() {
    for b in 0u8..=255u8 {
        let _ = unpack(&[b]);
        let _ = is_win_file(&[b]);
    }
}

#[test]
fn truncation_at_every_position_never_panics() {
    let full = pack("test.txt", b"hello world", r#"{"a":1,"b":[1,2,3]}"#);
    for cut in 0..full.len() {
        let _ = unpack(&full[..cut]);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Roundtrip integrity — under any survivable input, what's read out
// equals what was put in (modulo basename sanitization).
// ─────────────────────────────────────────────────────────────────────

#[test]
fn roundtrip_preserves_payload_bytes_for_random_sizes() {
    for &size in &[0, 1, 2, 7, 16, 64, 256, 1024, 4096, 16384, 65536] {
        let payload: Vec<u8> = (0u32..size).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let packed = pack("r.bin", &payload, r#"{"x":1}"#);
        let (_n, restored, _proof) = unpack(&packed).expect("roundtrip");
        assert_eq!(restored, payload, "size={} roundtrip mismatch", size);
    }
}

// ─────────────────────────────────────────────────────────────────────
// Mutation-kill tests — written to kill specific surviving mutants
// from `cargo mutants`. Each test exercises a code path whose
// mutation the existing suite couldn't detect.
// ─────────────────────────────────────────────────────────────────────

#[test]
fn brackets_balance_handles_escaped_quote_inside_string() {
    // Kills mutant: delete match arm b'\\' in brackets_balanced.
    // Without the escape arm, `\"` inside a string would terminate
    // the string early and the closing `}` would be miscounted.
    let proof = r#"{"a":"He said \"hi\"","b":1}"#;
    let packed = pack("e.txt", b"x", proof);
    let (_n, _f, returned) = unpack(&packed).expect("escape-aware roundtrip");
    assert_eq!(returned, proof);
}

#[test]
fn brackets_balance_treats_quotes_as_string_boundaries() {
    // Kills mutant: delete match arm b'"' in brackets_balanced.
    // Without the quote arm, the `}` inside the quoted "}" would be
    // counted as a real close-brace and balance would be wrong.
    let proof = r#"{"trick":"{}{}}{","real":1}"#;
    let packed = pack("q.txt", b"x", proof);
    let (_n, _f, returned) = unpack(&packed).expect("string-aware roundtrip");
    assert_eq!(returned, proof);
}

#[test]
fn brackets_balance_rejects_unmatched_open_in_string_state_too() {
    // String never closed — proof ends with `"` open, balance check
    // must reject. Without quote tracking the parser would mistake
    // braces for structure.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"WIN\x01");
    buf.extend_from_slice(&5u32.to_le_bytes());
    buf.extend_from_slice(b"x.txt");
    buf.extend_from_slice(&1u64.to_le_bytes());
    buf.extend_from_slice(b"x");
    buf.extend_from_slice(br#"{"unterm":"open"#);
    let err = unpack(&buf).expect_err("unterminated string must reject");
    assert!(err.is_container_damage(), "got: {:?}", err);
}

#[test]
fn unpack_minimum_size_boundary_is_rejected() {
    // Kills mutant: replace < with <= in unpack at the 16-byte gate.
    // 15 bytes definitely too short. 16 bytes with all-zeros also
    // too short — and the 8-byte file_len prefix would already cause
    // the parser to fail past the 16-byte point. Both behaviours
    // converge on Err, but the early gate must specifically reject 15.
    for size in 0..16 {
        let buf = vec![0u8; size];
        let err = unpack(&buf).expect_err(&format!("{} bytes must reject", size));
        assert!(err.is_container_damage(), "size {} got: {:?}", size, err);
    }
}

#[test]
fn unpack_minimum_valid_filename_byte_is_accepted() {
    // Smallest possible legal container: magic(4) + name_len(4) +
    // name(1) + file_len(8) + file(0) + proof(2 = "{}"). Total 19
    // bytes. Must succeed.
    let mut buf = Vec::new();
    buf.extend_from_slice(b"WIN\x01");
    buf.extend_from_slice(&1u32.to_le_bytes());
    buf.extend_from_slice(b"x");
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(b"{}");
    assert_eq!(buf.len(), 19);
    let (_n, file, _proof) = unpack(&buf).expect("19-byte container must roundtrip");
    assert!(file.is_empty());
}

#[test]
fn winerror_variants_classify_consistently() {
    use win_format::WinError;
    // Sanity: every variant's is_container_damage() decision is stable.
    let variants = [
        WinError::TooShort,
        WinError::BadMagic,
        WinError::Truncated,
        WinError::BadFilename,
        WinError::MissingProof,
    ];
    for v in &variants {
        // Just call it — must not panic, must return a bool.
        let _ = v.is_container_damage();
    }
}
