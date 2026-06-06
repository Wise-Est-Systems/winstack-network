//! Golden `.win` regression vector.
//!
//! The whole promise of a `.win` is: *anyone can verify it offline, later,
//! on a DIFFERENT machine.* Plain English: a sealed file must still say
//! "Verified" tomorrow, on someone else's computer, with no network.
//!
//! That promise has rested on *construction* (the code that builds a proof)
//! rather than on a *test* over a frozen artifact. This file fixes that:
//! it commits a real `.win` produced by the real sealing code, plus the
//! exact input bytes that went into it, and asserts the committed `.win`
//! still verifies to `Verified` against those bytes.
//!
//! Why a captured artifact instead of regenerating on the fly?
//! Sealing pulls fresh Ed25519 keypairs (`KeyPair::generate`, OS RNG) and a
//! wall-clock timestamp (`chrono::Utc::now()`). So the bytes are NOT
//! reproducible run-to-run — regenerating would prove nothing about
//! stability over time. Instead we freeze ONE produced `.win` and keep
//! re-verifying THAT. If a future change breaks cross-machine verification
//! of an already-sealed file, this test goes red.
//!
//! Regenerating the fixture (only when intentionally rotating it):
//!   WIN_REGEN_GOLDEN=1 cargo test -p registry-core --test golden_win
//! That writes a fresh input + `.win` into tests/vectors/golden/ and then
//! asserts the fresh artifact verifies. Commit the result deliberately.

use canon_types::{NativeBirthProposal, ProofBundle, VerificationStatus};
use registry_core::test_registry;
use std::path::PathBuf;

/// Fixed input content for the golden vector. Small, stable, human-readable.
const GOLDEN_INPUT: &[u8] =
    b"WIN golden regression vector v1.\nSealed once. Must re-verify forever, offline, anywhere.\n";

/// Filename recorded inside the golden `.win` container.
const GOLDEN_FILENAME: &str = "golden.txt";

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/golden")
}

fn input_path() -> PathBuf {
    vectors_dir().join("golden.txt")
}

fn win_path() -> PathBuf {
    vectors_dir().join("golden.win")
}

/// Produce a real `.win` from `GOLDEN_INPUT` using the production seal path,
/// and write both the input and the `.win` into the fixtures directory.
///
/// Gated behind `WIN_REGEN_GOLDEN=1` so a normal test run never mutates the
/// committed fixture. Running it always re-checks that what it just wrote
/// verifies, so a broken regen can never silently land.
#[test]
fn regenerate_golden_vector() {
    if std::env::var("WIN_REGEN_GOLDEN").as_deref() != Ok("1") {
        eprintln!("skipping regen (set WIN_REGEN_GOLDEN=1 to rotate the golden .win)");
        return;
    }

    let (mut reg, creator_id, module_id, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: GOLDEN_INPUT.to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .expect("seal_native must succeed for the golden input");

    let bundle = reg
        .build_proof_bundle(&obj.object_id)
        .expect("build_proof_bundle must succeed");
    let proof_json = serde_json::to_string_pretty(&bundle).expect("serialize bundle");
    let win_bytes = win_format::pack(GOLDEN_FILENAME, GOLDEN_INPUT, &proof_json);

    // Refuse to write a fixture that does not verify.
    let (_, file_bytes, proof_text) =
        win_format::unpack(&win_bytes).expect("freshly packed .win must unpack");
    let check_bundle: ProofBundle =
        serde_json::from_str(&proof_text).expect("proof section must deserialize");
    let result = verifier::verify_from_proof_bundle(&check_bundle, &file_bytes);
    assert_eq!(
        result.status,
        VerificationStatus::Verified,
        "regen produced a .win that does not verify: {:?}",
        result.failures
    );

    std::fs::create_dir_all(vectors_dir()).expect("create vectors dir");
    std::fs::write(input_path(), GOLDEN_INPUT).expect("write golden input");
    std::fs::write(win_path(), &win_bytes).expect("write golden .win");
    eprintln!("wrote golden vector: {}", win_path().display());
}

/// The load-bearing regression: the COMMITTED `.win` must still verify.
///
/// This is the cross-machine / over-time invariant in one assertion. It reads
/// frozen bytes off disk (no sealing, no RNG, no clock), re-derives nothing,
/// and checks the verifier still says `Verified`.
#[test]
fn committed_golden_win_verifies() {
    let win_bytes = std::fs::read(win_path()).unwrap_or_else(|e| {
        panic!(
            "golden .win fixture missing at {} ({e}). \
             Generate it with: WIN_REGEN_GOLDEN=1 cargo test -p registry-core --test golden_win",
            win_path().display()
        )
    });
    let committed_input = std::fs::read(input_path()).expect("golden input fixture missing");

    // The container must unpack cleanly.
    let (name, file_bytes, proof_text) =
        win_format::unpack(&win_bytes).expect("committed golden .win must unpack");
    assert_eq!(name, GOLDEN_FILENAME, "golden filename drifted");

    // The bytes inside the container must match the committed input exactly.
    assert_eq!(
        file_bytes, committed_input,
        "golden .win payload does not match the committed input file"
    );
    assert_eq!(
        file_bytes, GOLDEN_INPUT,
        "golden input drifted from the constant the vector was built for"
    );

    // The proof section must deserialize into a ProofBundle.
    let bundle: ProofBundle =
        serde_json::from_str(&proof_text).expect("committed proof section must deserialize");

    // The whole point: it verifies to Verified, offline, from frozen bytes.
    let result = verifier::verify_from_proof_bundle(&bundle, &file_bytes);
    assert_eq!(
        result.status,
        VerificationStatus::Verified,
        "committed golden .win failed to verify: {:?}",
        result.failures
    );
    assert!(
        result.failures.is_empty(),
        "Verified status but non-empty failures: {:?}",
        result.failures
    );
}
