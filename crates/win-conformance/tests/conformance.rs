//! The frozen conformance vectors must always reproduce their declared results.
//! A failure here means the verifier's behavior drifted from the frozen contract.

use win_conformance::{run_all, vectors_dir};

#[test]
fn all_frozen_vectors_pass() {
    let dir = vectors_dir();
    let results = run_all(&dir);
    assert!(!results.is_empty(), "no vectors found in {}", dir.display());
    let failures: Vec<String> = results
        .iter()
        .filter(|r| !r.pass)
        .map(|r| format!("{}: {}", r.id, r.detail))
        .collect();
    assert!(
        failures.is_empty(),
        "conformance vectors failed:\n{}",
        failures.join("\n")
    );
}
