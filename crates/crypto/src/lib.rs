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
