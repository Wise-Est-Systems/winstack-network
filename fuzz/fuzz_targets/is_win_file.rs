//! Smallest possible target — just the magic-byte gate. Cheap to run
//! for very high iteration counts to confirm the gate has no
//! pathological short-input behaviour.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = win_format::is_win_file(data);
});
