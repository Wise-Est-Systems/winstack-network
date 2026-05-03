//! Direct fuzz of verifier::verify_from_proof_bundle. Bypasses the
//! container layer to focus on adversarial proof JSON. The fuzzer
//! splits its input into "proof_json + file_bytes" by length-prefix.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // First 4 bytes: u32 LE giving proof_json length. Rest is split.
    let proof_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if proof_len > data.len().saturating_sub(4) {
        return;
    }
    let proof_bytes = &data[4..4 + proof_len];
    let file_bytes = &data[4 + proof_len..];

    let proof_text = match std::str::from_utf8(proof_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    let bundle: canon_types::ProofBundle = match serde_json::from_str(proof_text) {
        Ok(b) => b,
        Err(_) => return,
    };

    // The verifier must never panic on any deserialised ProofBundle,
    // even one with adversarially-chosen field values (UUIDs, signatures,
    // hashes, time strings, lineage cycles). Result value doesn't
    // matter — survival is the property.
    let _ = verifier::verify_from_proof_bundle(&bundle, file_bytes);
});
