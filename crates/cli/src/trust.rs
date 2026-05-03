//! Local trusted key list — ~/.wise/trusted_keys.json
//!
//! A simple local store of public keys the user has chosen to trust.
//! This is a local decision only — it does not affect proof validity.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
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
        self.keys.iter().any(|k| k.key == public_key_hex)
    }

    pub fn add(&mut self, key: String, label: Option<String>) -> bool {
        if self.is_trusted(&key) {
            return false; // already exists
        }
        self.keys.push(TrustedKey { key, label });
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
            .find(|k| k.key == public_key_hex)
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
}
