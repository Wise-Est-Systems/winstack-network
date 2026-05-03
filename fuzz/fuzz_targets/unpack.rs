//! Fuzz the .win container parser. Must NOT panic, OOM, or hang on
//! arbitrary input — adversarial bytes are exactly what reaches this
//! function in production (a stranger emails a "what could go wrong"
//! file).
//!
//! Invariants the fuzzer enforces:
//!   - unpack() never panics
//!   - is_win_file() never panics
//!   - Ok(...) results have name and proof_text that are valid UTF-8
//!     (already guaranteed by the function signature, but we read
//!     them to ensure no later use-after-free / lazy-string surprises)

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input.
    let _ = win_format::is_win_file(data);

    if let Ok((name, file_bytes, proof_text)) = win_format::unpack(data) {
        // Touch every returned field so the optimizer doesn't elide work.
        let _ = name.len();
        let _ = file_bytes.len();
        let _ = proof_text.len();
    }
});
