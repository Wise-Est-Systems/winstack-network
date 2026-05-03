//! Local trusted key list — ~/.wise/trusted_keys.json
//!
//! A simple local store of public keys the user has chosen to trust.
//! This is a local decision only — it does not affect proof validity.
//!
//! A signing key on a `.win` is classified by the verifier into one of:
//!   - `Local`    — no display name, not in this list
//!   - `Named`    — declares a display name (still up to receiver)
//!   - `Official` — fingerprint matches an entry here, not revoked
//!   - `Unknown`  — valid sig, no further trust signal
//!
//! There is **no central Wise.Est Systems key** seeded here by default;
//! receivers add fingerprints they have chosen to trust through some
//! external process (in-person key exchange, published release key, etc).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Receiver-side classification of how a signing key is trusted.
/// Stored alongside the fingerprint; controls whether the verifier
/// surfaces a key as Official or merely Named.
///
/// Default is Named — receivers must explicitly elevate to Official.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TrustClass {
    /// Receiver explicitly accepts this key as a published official key.
    /// The verifier is allowed to surface this seal as "Official Win".
    Official,
    /// Receiver knows this key by name but treats it as a regular signer.
    /// The verifier surfaces this seal as "Named Win" with the label.
    #[default]
    Named,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    /// Hex-encoded Ed25519 public key (64 chars).
    pub key: String,
    /// Optional human-readable display name for the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Receiver-side trust classification. Defaults to Named (display
    /// name only); Official requires explicit elevation by the receiver.
    #[serde(default)]
    pub trust_class: TrustClass,
    /// Free-form purpose: "release-signing", "internal", "personal".
    /// Surfaced for human review; not used in verification logic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// RFC 3339 timestamp of when this entry was added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// If true, the verifier MUST treat this entry as if absent.
    /// Receivers set this when they want to keep history but stop
    /// trusting a key (rotation, compromise, end-of-life).
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    pub keys: Vec<TrustedKey>,
}

impl TrustStore {
    pub fn path(node_dir: &Path) -> PathBuf {
        node_dir.join("trusted_keys.json")
    }

    pub fn load(node_dir: &Path) -> Self {
        let path = Self::path(node_dir);
        if !path.exists() {
            return Self::default();
        }
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => return Self::default(),
        };
        serde_json::from_str(&data).unwrap_or_default()
    }

    pub fn save(&self, node_dir: &Path) -> Result<(), std::io::Error> {
        let path = Self::path(node_dir);
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json)?;
        // Restrict permissions — trust list is a local security decision
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn is_trusted(&self, public_key_hex: &str) -> bool {
        self.keys
            .iter()
            .any(|k| k.key == public_key_hex && !k.revoked)
    }

    /// True only if the matched, non-revoked entry has TrustClass::Official.
    /// This is the only path that allows the verifier to surface a key
    /// as "Official Win".
    #[allow(dead_code)]
    pub fn is_official(&self, public_key_hex: &str) -> bool {
        self.keys
            .iter()
            .any(|k| k.key == public_key_hex && !k.revoked && k.trust_class == TrustClass::Official)
    }

    pub fn add(&mut self, key: String, label: Option<String>) -> bool {
        if self.is_trusted(&key) {
            return false; // already exists
        }
        self.keys.push(TrustedKey {
            key,
            label,
            trust_class: TrustClass::Named,
            purpose: None,
            created_at: Some(chrono::Utc::now().to_rfc3339()),
            revoked: false,
        });
        true
    }

    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.keys.len();
        self.keys.retain(|k| k.key != key);
        self.keys.len() < before
    }

    #[allow(dead_code)] // used in tests; available for verbose mode
    pub fn label_for(&self, public_key_hex: &str) -> Option<&str> {
        self.keys
            .iter()
            .find(|k| k.key == public_key_hex && !k.revoked)
            .and_then(|k| k.label.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_check_trusted() {
        let mut store = TrustStore::default();
        assert!(!store.is_trusted("abc123"));
        assert!(store.add("abc123".into(), Some("Test key".into())));
        assert!(store.is_trusted("abc123"));
    }

    #[test]
    fn add_duplicate_returns_false() {
        let mut store = TrustStore::default();
        assert!(store.add("abc123".into(), None));
        assert!(!store.add("abc123".into(), None));
        assert_eq!(store.keys.len(), 1);
    }

    #[test]
    fn remove_key() {
        let mut store = TrustStore::default();
        store.add("abc123".into(), None);
        assert!(store.is_trusted("abc123"));
        assert!(store.remove("abc123"));
        assert!(!store.is_trusted("abc123"));
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let mut store = TrustStore::default();
        assert!(!store.remove("doesnotexist"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("wise-trust-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut store = TrustStore::default();
        store.add("key1".into(), Some("My key".into()));
        store.add("key2".into(), None);
        store.save(&dir).unwrap();

        let loaded = TrustStore::load(&dir);
        assert_eq!(loaded.keys.len(), 2);
        assert!(loaded.is_trusted("key1"));
        assert!(loaded.is_trusted("key2"));
        assert_eq!(loaded.label_for("key1"), Some("My key"));
        assert_eq!(loaded.label_for("key2"), None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = std::env::temp_dir().join(format!("wise-trust-empty-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = TrustStore::load(&dir);
        assert!(store.keys.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn remove_updates_trust_immediately() {
        let mut store = TrustStore::default();
        store.add("key1".into(), Some("Trusted".into()));
        assert!(store.is_trusted("key1"));
        store.remove("key1");
        assert!(!store.is_trusted("key1"));
        assert!(store.label_for("key1").is_none());
    }

    #[test]
    fn revoked_entry_is_not_trusted() {
        let mut store = TrustStore::default();
        store.keys.push(TrustedKey {
            key: "abc".into(),
            label: Some("former".into()),
            trust_class: TrustClass::Official,
            purpose: Some("release-signing".into()),
            created_at: Some("2026-01-01T00:00:00Z".into()),
            revoked: true,
        });
        assert!(
            !store.is_trusted("abc"),
            "revoked entry must NOT be trusted"
        );
        assert!(
            !store.is_official("abc"),
            "revoked entry must NOT count as Official"
        );
        assert!(
            store.label_for("abc").is_none(),
            "revoked entry must NOT surface a label"
        );
    }

    #[test]
    fn named_trust_is_not_official_unless_elevated() {
        let mut store = TrustStore::default();
        store.add("key1".into(), Some("Alice".into()));
        assert!(store.is_trusted("key1"));
        assert!(
            !store.is_official("key1"),
            "default add() entries are Named, not Official"
        );
    }

    #[test]
    fn explicit_official_entry_passes_official_check() {
        let mut store = TrustStore::default();
        store.keys.push(TrustedKey {
            key: "off1".into(),
            label: Some("Wise.Est release v1".into()),
            trust_class: TrustClass::Official,
            purpose: Some("release-signing".into()),
            created_at: Some("2026-05-03T00:00:00Z".into()),
            revoked: false,
        });
        assert!(store.is_trusted("off1"));
        assert!(
            store.is_official("off1"),
            "explicitly-elevated entry must pass is_official"
        );
    }

    #[test]
    fn unknown_key_is_neither_trusted_nor_official() {
        let store = TrustStore::default();
        assert!(!store.is_trusted("unknown_fingerprint_xyz"));
        assert!(!store.is_official("unknown_fingerprint_xyz"));
    }

    #[test]
    fn no_official_keys_seeded_by_default() {
        // The default trust list MUST be empty. There is no central
        // Wise.Est Systems "official" key seeded into Wise; receivers
        // add fingerprints they have chosen to trust.
        let store = TrustStore::default();
        assert_eq!(
            store.keys.len(),
            0,
            "default trust list must be empty — \
             no Wise.Est Systems key is trusted by default"
        );
    }
}
