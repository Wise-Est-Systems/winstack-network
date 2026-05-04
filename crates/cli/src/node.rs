use canon_types::*;
use std::path::Path;
use wise_crypto as crypto;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct NodeConfig {
    pub creator_id: uuid::Uuid,
    #[serde(with = "hex_bytes")]
    pub creator_secret: [u8; 32],
    pub ta_id: uuid::Uuid,
    #[serde(with = "hex_bytes")]
    pub ta_secret: [u8; 32],
    pub pe_id: uuid::Uuid,
    #[serde(with = "hex_bytes")]
    pub pe_secret: [u8; 32],
    pub module_id: uuid::Uuid,
    pub module_hash: String,
    pub created_at: String,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        Ok(arr)
    }
}

/// Check and repair file permissions on sensitive node files.
/// Warns on stderr if permissions were too loose and tightens them.
///
/// On non-Unix targets (Windows) this is a no-op — POSIX mode bits
/// don't apply, and Windows ACLs need a different code path that
/// hasn't been written yet. The `node_dir` parameter is therefore
/// unused on those targets.
pub fn check_and_repair_permissions(
    #[cfg_attr(not(unix), allow(unused_variables))] node_dir: &Path,
) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let check = |path: &std::path::Path, expected_mode: u32, label: &str| {
            if !path.exists() {
                return;
            }
            if let Ok(meta) = std::fs::metadata(path) {
                let current = meta.permissions().mode() & 0o777;
                if current != expected_mode {
                    eprintln!(
                        "  WARNING: {} has permissions {:04o}, expected {:04o} — repairing",
                        label, current, expected_mode
                    );
                    let _ = std::fs::set_permissions(
                        path,
                        std::fs::Permissions::from_mode(expected_mode),
                    );
                    // Verify repair succeeded
                    if let Ok(m2) = std::fs::metadata(path) {
                        let after = m2.permissions().mode() & 0o777;
                        if after != expected_mode {
                            eprintln!(
                                "  WARNING: could not repair {} — permissions are {:04o}, should be {:04o}",
                                label, after, expected_mode
                            );
                            eprintln!("  Run: chmod {:04o} {}", expected_mode, path.display());
                        }
                    }
                }
            }
        };

        check(node_dir, 0o700, "node directory");
        check(
            &node_dir.join("node.json"),
            0o600,
            "node.json (contains private keys)",
        );
        check(
            &node_dir.join("graph.db"),
            0o600,
            "graph.db (contains seal history)",
        );
        check(
            &node_dir.join("trusted_keys.json"),
            0o600,
            "trusted_keys.json (local trust list)",
        );
    }
}

pub fn load_registry_from_node(node_dir: &Path) -> registry_core::Registry {
    let node_json = node_dir.join("node.json");

    if !node_json.exists() {
        eprintln!("ERROR: node not initialized — run 'win prove <file>' first");
        std::process::exit(2);
    }

    // Check and repair permissions on every load
    check_and_repair_permissions(node_dir);

    let data = std::fs::read_to_string(&node_json).unwrap_or_else(|e| {
        eprintln!("ERROR: could not read node.json: {}", e);
        std::process::exit(2);
    });
    let node: NodeConfig = serde_json::from_str(&data).unwrap_or_else(|e| {
        eprintln!("ERROR: invalid node.json: {}", e);
        std::process::exit(2);
    });

    load_registry_from_config(&node, node_dir)
}

pub fn load_registry_from_config(node: &NodeConfig, node_dir: &Path) -> registry_core::Registry {
    let obj_store = object_store::ObjectStore::with_path(&node_dir.join("store_data"))
        .unwrap_or_else(|e| {
            eprintln!("ERROR: could not open object store: {}", e);
            std::process::exit(2);
        });
    let graph = graph_index::GraphIndex::open(node_dir.join("graph.db").to_str().unwrap())
        .unwrap_or_else(|e| {
            eprintln!("ERROR: could not open graph db: {}", e);
            std::process::exit(2);
        });

    let mut identity_store = identity_core::IdentityStore::new();

    // Each secret is used exactly twice: once for the identity record, once for the authority/evaluator.
    let creator_key = crypto::KeyPair::from_secret_bytes(&node.creator_secret);
    let creator_rec = IdentityRecord {
        identity_id: node.creator_id,
        kind: IdentityKind::Personal,
        status: IdentityStatus::Active,
        public_key_hex: creator_key.public_key_hex(),
        created_at: node.created_at.clone(),
        signature: String::new(),
    };
    identity_store.insert_identity(creator_rec, creator_key);

    let ta_key_for_identity = crypto::KeyPair::from_secret_bytes(&node.ta_secret);
    let ta_rec = IdentityRecord {
        identity_id: node.ta_id,
        kind: IdentityKind::Service,
        status: IdentityStatus::Active,
        public_key_hex: ta_key_for_identity.public_key_hex(),
        created_at: node.created_at.clone(),
        signature: String::new(),
    };
    identity_store.insert_identity(ta_rec, ta_key_for_identity);

    let pe_key_for_identity = crypto::KeyPair::from_secret_bytes(&node.pe_secret);
    let pe_rec = IdentityRecord {
        identity_id: node.pe_id,
        kind: IdentityKind::Service,
        status: IdentityStatus::Active,
        public_key_hex: pe_key_for_identity.public_key_hex(),
        created_at: node.created_at.clone(),
        signature: String::new(),
    };
    identity_store.insert_identity(pe_rec, pe_key_for_identity);

    let ta_key = crypto::KeyPair::from_secret_bytes(&node.ta_secret);
    let time_authority = time_core::TimeAuthority::new(node.ta_id, ta_key);

    let pe_key = crypto::KeyPair::from_secret_bytes(&node.pe_secret);
    let policy_evaluator = policy_core::PolicyEvaluator::new(node.pe_id, pe_key);

    let mut module_registry = identity_core::ModuleRegistry::new();
    let mod_key = crypto::KeyPair::from_secret_bytes(&node.creator_secret);
    let mod_reg = ModuleRegistration {
        module_id: node.module_id,
        kind: ModuleKind::Document,
        scope: "*".to_string(),
        binary_hash: node.module_hash.clone(),
        registered_by: node.creator_id,
        signature: mod_key.sign_json(&serde_json::json!({
            "module_id": node.module_id,
            "kind": "Document",
            "scope": "*",
            "binary_hash": node.module_hash,
            "registered_by": node.creator_id,
        })),
    };
    module_registry.insert_module(mod_reg);

    registry_core::Registry {
        identity_store,
        module_registry,
        time_authority,
        policy_evaluator,
        object_store: obj_store,
        graph,
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn make_temp_node() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wise-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // Create a dummy node.json
        std::fs::write(dir.join("node.json"), "{}").unwrap();
        // Create a dummy graph.db
        std::fs::write(dir.join("graph.db"), "").unwrap();
        dir
    }

    #[test]
    fn repairs_loose_directory_permissions() {
        let dir = make_temp_node();
        // Set directory to world-readable
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        check_and_repair_permissions(&dir);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "directory should be 0700 after repair");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repairs_loose_node_json_permissions() {
        let dir = make_temp_node();
        let node_json = dir.join("node.json");
        // Set to world-readable
        std::fs::set_permissions(&node_json, std::fs::Permissions::from_mode(0o644)).unwrap();
        check_and_repair_permissions(&dir);
        let mode = std::fs::metadata(&node_json).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "node.json should be 0600 after repair");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repairs_loose_graph_db_permissions() {
        let dir = make_temp_node();
        let graph_db = dir.join("graph.db");
        std::fs::set_permissions(&graph_db, std::fs::Permissions::from_mode(0o644)).unwrap();
        check_and_repair_permissions(&dir);
        let mode = std::fs::metadata(&graph_db).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "graph.db should be 0600 after repair");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn correct_permissions_unchanged() {
        let dir = make_temp_node();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            dir.join("node.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        std::fs::set_permissions(dir.join("graph.db"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        // Should not change anything
        check_and_repair_permissions(&dir);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(dir.join("node.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(dir.join("graph.db"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_files_do_not_crash() {
        let dir = std::env::temp_dir().join(format!("wise-test-empty-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // No node.json or graph.db — should not panic
        check_and_repair_permissions(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }
}
