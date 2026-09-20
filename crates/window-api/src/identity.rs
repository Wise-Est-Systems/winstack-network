//! Desktop identity + trust management.
//!
//! Reads/writes the same node-dir files the CLI uses, so formats stay
//! compatible:
//!   - `win-identity.json` — the persistent authorizer identity (+ self-asserted
//!     name/context the user set in Settings).
//!   - `trusted_keys.json` — the receiver's trusted-keys list (same shape as the
//!     CLI's `TrustStore`; all fields preserved so CLI data round-trips).
//!
//! The node directory is resolved from `WISE_NODE_DIR` (set by the desktop) or a
//! per-OS default, so the app and any co-located CLI share one identity + trust.

use std::path::PathBuf;

use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use win_transition::{assert_identity, IdentityAssertion, Persistence, TrustLookup};
use wise_crypto::KeyPair;

pub fn node_dir() -> PathBuf {
    if let Ok(d) = std::env::var("WISE_NODE_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    #[cfg(target_os = "macos")]
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h)
            .join("Library")
            .join("Application Support")
            .join("Wise");
    }
    #[cfg(target_os = "windows")]
    if let Ok(d) = std::env::var("APPDATA") {
        return PathBuf::from(d).join("Wise");
    }
    std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".wise"))
        .unwrap_or_else(|_| PathBuf::from(".wise"))
}

// ── Persistent identity ────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Default)]
struct StoredIdentity {
    identity_id: Option<Uuid>,
    secret_hex: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    context: Option<String>,
}

fn identity_path() -> PathBuf {
    node_dir().join("win-identity.json")
}

fn read_identity() -> StoredIdentity {
    std::fs::read_to_string(identity_path())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn write_identity(s: &StoredIdentity) {
    let dir = node_dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(json) = serde_json::to_string_pretty(s) {
        let _ = std::fs::write(identity_path(), json);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                identity_path(),
                std::fs::Permissions::from_mode(0o600),
            );
        }
    }
}

/// Load — or create on first use — the persistent authorizer identity, returning
/// the key and the self-asserted name/context the user set.
pub struct Identity {
    pub id: Uuid,
    pub key: KeyPair,
    pub name: Option<String>,
    pub context: Option<String>,
}

pub fn load_or_create_identity() -> Identity {
    let mut stored = read_identity();
    let secret = stored.secret_hex.as_ref().and_then(|h| {
        hex::decode(h)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
    });
    let (id, secret) = match (stored.identity_id, secret) {
        (Some(id), Some(sec)) => (id, sec),
        _ => {
            let kp = KeyPair::generate();
            let sec = kp.secret_key_bytes();
            let id = Uuid::new_v4();
            stored.identity_id = Some(id);
            stored.secret_hex = Some(hex::encode(sec));
            write_identity(&stored);
            (id, sec)
        }
    };
    Identity {
        id,
        key: KeyPair::from_secret_bytes(&secret),
        name: stored.name,
        context: stored.context,
    }
}

/// Build the self-signed identity assertion for the persistent authorizer key.
pub fn identity_assertion(idn: &Identity) -> IdentityAssertion {
    assert_identity(
        &idn.key,
        idn.name.clone(),
        idn.context.clone(),
        Persistence::Persistent,
    )
}

// ── Trusted-keys list (CLI-compatible) ─────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TrustClass {
    Official,
    #[default]
    Named,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub trust_class: TrustClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrustStore {
    pub keys: Vec<TrustedKey>,
}

impl TrustStore {
    fn path() -> PathBuf {
        node_dir().join("trusted_keys.json")
    }
    pub fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }
    fn save(&self) {
        let _ = std::fs::create_dir_all(node_dir());
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(Self::path(), json);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    Self::path(),
                    std::fs::Permissions::from_mode(0o600),
                );
            }
        }
    }
    fn add(&mut self, key: String, label: Option<String>) -> bool {
        if self.keys.iter().any(|k| k.key == key && !k.revoked) {
            return false;
        }
        self.keys.push(TrustedKey {
            key,
            label,
            trust_class: TrustClass::Named,
            purpose: None,
            created_at: None,
            revoked: false,
        });
        true
    }
    fn remove(&mut self, key: &str) -> bool {
        let before = self.keys.len();
        self.keys.retain(|k| k.key != key);
        self.keys.len() < before
    }
}

impl TrustLookup for TrustStore {
    fn is_trusted(&self, key_hex: &str) -> bool {
        self.keys.iter().any(|k| k.key == key_hex && !k.revoked)
    }
    fn label_for(&self, key_hex: &str) -> Option<String> {
        self.keys
            .iter()
            .find(|k| k.key == key_hex && !k.revoked)
            .and_then(|k| k.label.clone())
    }
}

// ── HTTP handlers ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct IdentityView {
    pub public_key: String,
    pub name: Option<String>,
    pub context: Option<String>,
}

/// GET /identity — the app's own authorizing identity.
pub async fn get_identity() -> Json<IdentityView> {
    let idn = load_or_create_identity();
    Json(IdentityView {
        public_key: idn.key.public_key_hex(),
        name: idn.name,
        context: idn.context,
    })
}

#[derive(Deserialize)]
pub struct SetIdentity {
    pub name: Option<String>,
    pub context: Option<String>,
}

/// POST /identity — set your self-asserted name/context.
pub async fn set_identity(Json(body): Json<SetIdentity>) -> Json<IdentityView> {
    // Ensure the identity exists, then update its self-asserted fields.
    let idn = load_or_create_identity();
    let mut stored = read_identity();
    stored.name = body.name.filter(|s| !s.is_empty());
    stored.context = body.context.filter(|s| !s.is_empty());
    write_identity(&stored);
    Json(IdentityView {
        public_key: idn.key.public_key_hex(),
        name: stored.name,
        context: stored.context,
    })
}

/// GET /trust — the receiver's trusted-keys list.
pub async fn list_trust() -> Json<Vec<TrustedKey>> {
    Json(TrustStore::load().keys)
}

#[derive(Deserialize)]
pub struct TrustBody {
    pub key: String,
    pub label: Option<String>,
}

/// POST /trust — trust a key.
pub async fn add_trust(Json(body): Json<TrustBody>) -> Result<Json<Vec<TrustedKey>>, StatusCode> {
    if body.key.len() != 64 || hex::decode(&body.key).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut store = TrustStore::load();
    store.add(body.key, body.label.filter(|s| !s.is_empty()));
    store.save();
    Ok(Json(store.keys))
}

#[derive(Deserialize)]
pub struct UntrustBody {
    pub key: String,
}

/// POST /trust/remove — stop trusting a key.
pub async fn remove_trust(Json(body): Json<UntrustBody>) -> Json<Vec<TrustedKey>> {
    let mut store = TrustStore::load();
    store.remove(&body.key);
    store.save();
    Json(store.keys)
}
