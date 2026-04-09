use canon_types::*;
use std::path::Path;
use winstack_crypto as crypto;

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

pub fn load_registry_from_node(node_dir: &Path) -> registry_core::Registry {
    let node_json = node_dir.join("node.json");

    if !node_json.exists() {
        eprintln!("ERROR: node not initialized — run 'winstack prove <file>' first");
        std::process::exit(2);
    }

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
