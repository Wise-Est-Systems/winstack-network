//! Fuzz the WASM verifier's full pipeline natively. This is the same
//! code path the browser runs — what survives here will not crash
//! in a user's browser tab.
//!
//! We can't call recognize_win() directly because it returns JsValue;
//! we recreate its pipeline using the same crate dependencies in the
//! same order: unpack → JSON → SHA-256 hash check → verify_from_proof_bundle.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (file_bytes, proof_text) = match win_format::unpack(data) {
        Ok((_n, f, p)) => (f, p),
        Err(_) => return, // container damage — already exercised by unpack target
    };

    let bundle: canon_types::ProofBundle = match serde_json::from_str(&proof_text) {
        Ok(b) => b,
        Err(_) => return, // proof JSON malformed — survival is enough
    };

    // The hash check the WASM does first.
    let computed = wise_crypto::sha256_hex(&file_bytes);
    if computed != bundle.object.payload_hash {
        return; // Tampered — handled
    }

    // Full structural verification. Must never panic on any bundle
    // that survives the JSON parse, however adversarial.
    let _ = verifier::verify_from_proof_bundle(&bundle, &file_bytes);
});
