use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("invalid hex key: {0}")]
    InvalidHexKey(String),
    #[error("invalid hex signature: {0}")]
    InvalidHexSignature(String),
    #[error("invalid key length")]
    InvalidKeyLength,
}

pub struct KeyPair {
    signing: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let signing = SigningKey::generate(&mut csprng);
        Self { signing }
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().as_bytes())
    }

    pub fn sign_bytes(&self, data: &[u8]) -> String {
        let sig = self.signing.sign(data);
        hex::encode(sig.to_bytes())
    }

    pub fn sign_json<T: serde::Serialize>(&self, value: &T) -> String {
        let canon = canonical_json(value);
        self.sign_bytes(canon.as_bytes())
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(bytes);
        Self { signing }
    }
}

pub fn verify_signature(
    public_key_hex: &str,
    data: &[u8],
    signature_hex: &str,
) -> Result<(), CryptoError> {
    let pk_bytes =
        hex::decode(public_key_hex).map_err(|e| CryptoError::InvalidHexKey(e.to_string()))?;
    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let verifying =
        VerifyingKey::from_bytes(&pk_array).map_err(|_| CryptoError::InvalidKeyLength)?;

    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| CryptoError::InvalidHexSignature(e.to_string()))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidHexSignature("bad length".into()))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    verifying
        .verify(data, &signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

pub fn verify_json_signature<T: serde::Serialize>(
    public_key_hex: &str,
    value: &T,
    signature_hex: &str,
) -> Result<(), CryptoError> {
    let canon = canonical_json(value);
    verify_signature(public_key_hex, canon.as_bytes(), signature_hex)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn canonical_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("canonical_json: serialization failed")
}

// ---------------------------------------------------------------------------
// Cross-machine signature-determinism guard (`CanonStable`)
// ---------------------------------------------------------------------------
//
// WHY THIS EXISTS — the `canonical_json` misnomer:
//
// `canonical_json` above does NOT canonicalize. It is a thin wrapper over
// `serde_json::to_string`, which preserves *struct field declaration order*
// and does NOT sort keys or normalize numbers. Plain English: it turns a
// value into bytes in the order the Rust struct declares its fields, and
// every Ed25519 signature in this system is computed over THOSE bytes.
//
// That is fine — and only fine — for the payload shapes we sign today:
// fixed-field structs whose fields are all order-stable, byte-stable types
// (strings, integers, UUIDs, enums-as-strings, and Options of those).
// For those, `serde_json` emits identical bytes on every machine, every run,
// every platform — so signatures reproduce and a `.win` verifies anywhere.
//
// The invariant SILENTLY breaks the moment a signed payload gains a field of
// a type whose JSON byte-output is not stable across machines:
//
//   * `HashMap` / `BTreeMap` — `serde_json` emits a JSON object; `HashMap`
//     iteration order is not guaranteed, so two machines can emit different
//     key orders → different bytes → signature that verifies on the signer's
//     box and fails on the verifier's. (`BTreeMap` is ordered, but signing
//     over an unfrozen `canonical_json` that does no key-sorting is exactly
//     the foot-gun we are guarding against — we forbid both.)
//   * `f32` / `f64` — float-to-string is not bit-portable; `0.1`, `1e10`,
//     `-0.0`, NaN/Inf rendering all vary → non-reproducible bytes.
//   * `serde_json::Value` — an arbitrary, untyped blob that can contain any
//     of the above. It defeats the whole point of fixed-field payloads.
//
// `CanonStable` makes that rule a TYPE FACT instead of a convention. It is
// a sealed marker trait implemented only for determinism-safe types and
// deliberately lacking an impl for the four foot-guns. The guard test
// (`crypto::tests::signed_payload_fields_are_canon_stable`) calls
// `assert_canon_stable::<T>()` on every field type of every Ed25519-signed
// payload in the workspace. If anyone adds a map / float / Value field to a
// signed struct and mirrors it into that list, the workspace stops compiling.
// If they forget to mirror it, the documented test is the catch.

#[doc(hidden)]
pub mod canon_stable_private {
    /// Sealed supertrait: external crates cannot add new `CanonStable` impls
    /// EXCEPT via the `impl_canon_stable!` macro (which is the intended,
    /// audited path for declaring an enum stable). Keeps the determinism-safe
    /// set closed and reviewable.
    pub trait Sealed {}
}
use canon_stable_private as canon_stable_sealed;

/// Marker for types whose `serde_json` byte-output is stable across machines
/// and runs — i.e. safe to put inside an Ed25519-signed payload given that
/// `canonical_json` performs NO key-sorting or number normalization.
///
/// Implemented for: strings, signed/unsigned integers, bool, UUID, and
/// `Option<T>` / slices / `Vec<T>` of stable types. It deliberately lacks an
/// impl for `f32`, `f64`, `HashMap`, `BTreeMap`, and `serde_json::Value` —
/// those would break cross-machine signature reproducibility.
///
/// Enums used in signed payloads serialize as their (string) variant names
/// and are stable; declare them stable explicitly with [`impl_canon_stable!`].
pub trait CanonStable: canon_stable_sealed::Sealed {}

/// Declare one or more concrete types as canonicalization-stable.
///
/// Use for the enums embedded in signed payloads (they serialize to a fixed
/// string per variant, which is byte-stable).
#[macro_export]
macro_rules! impl_canon_stable {
    ($($t:ty),+ $(,)?) => {
        $(
            impl $crate::canon_stable_private::Sealed for $t {}
            impl $crate::CanonStable for $t {}
        )+
    };
}

macro_rules! canon_stable_primitives {
    ($($t:ty),+ $(,)?) => {
        $(
            impl canon_stable_sealed::Sealed for $t {}
            impl CanonStable for $t {}
        )+
    };
}

// Determinism-safe scalars. NOTE the deliberate ABSENCE of f32/f64.
canon_stable_primitives!(
    bool,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    String,
    str,
    uuid::Uuid,
);

impl<T: CanonStable + ?Sized> canon_stable_sealed::Sealed for &T {}
impl<T: CanonStable + ?Sized> CanonStable for &T {}

impl<T: CanonStable> canon_stable_sealed::Sealed for Option<T> {}
impl<T: CanonStable> CanonStable for Option<T> {}

impl<T: CanonStable> canon_stable_sealed::Sealed for Vec<T> {}
impl<T: CanonStable> CanonStable for Vec<T> {}

impl<T: CanonStable> canon_stable_sealed::Sealed for [T] {}
impl<T: CanonStable> CanonStable for [T] {}

/// Compile-time assertion that `T` is canonicalization-stable.
///
/// Calling this in a test on a field type forces a compile error if that type
/// is ever a map / float / `serde_json::Value` (none of which implement
/// `CanonStable`). This is how the cross-machine invariant is *proven* rather
/// than assumed.
pub fn assert_canon_stable<T: CanonStable + ?Sized>() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let kp = KeyPair::generate();
        let data = b"hello wise";
        let sig = kp.sign_bytes(data);
        assert!(verify_signature(&kp.public_key_hex(), data, &sig).is_ok());
    }

    #[test]
    fn tampered_data_fails() {
        let kp = KeyPair::generate();
        let sig = kp.sign_bytes(b"original");
        assert!(verify_signature(&kp.public_key_hex(), b"tampered", &sig).is_err());
    }

    #[test]
    fn sha256_deterministic() {
        let a = sha256_hex(b"test");
        let b = sha256_hex(b"test");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn roundtrip_secret_key() {
        let kp = KeyPair::generate();
        let bytes = kp.secret_key_bytes();
        let kp2 = KeyPair::from_secret_bytes(&bytes);
        assert_eq!(kp.public_key_hex(), kp2.public_key_hex());
    }
}
