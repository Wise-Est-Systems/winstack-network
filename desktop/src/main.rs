// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use canon_types::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use winstack_crypto as crypto;

fn node_dir() -> PathBuf {
    let base = dirs_next().unwrap_or_else(|| std::env::current_dir().unwrap());
    base.join(".winstack")
}

fn dirs_next() -> Option<PathBuf> {
    // Use platform-appropriate data directory
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME").ok().map(|h| {
            PathBuf::from(h)
                .join("Library")
                .join("Application Support")
                .join("Winstack")
        })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA")
            .ok()
            .map(|d| PathBuf::from(d).join("Winstack"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".winstack"))
    }
}

fn ensure_node(node_path: &PathBuf) {
    let node_json = node_path.join("node.json");
    if node_json.exists() {
        return;
    }

    std::fs::create_dir_all(node_path).unwrap();
    // Restrict .winstack directory to owner-only access
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(node_path, std::fs::Permissions::from_mode(0o700));
    }
    std::fs::create_dir_all(node_path.join("store_data")).unwrap();

    let mut identity_store = identity_core::IdentityStore::new();
    let (creator_id, _) = identity_store.create_identity(IdentityKind::Personal);
    let creator_secret = identity_store
        .get_key(&creator_id)
        .unwrap()
        .secret_key_bytes();

    let (ta_id, _) = identity_store.create_identity(IdentityKind::Service);
    let ta_secret = identity_store.get_key(&ta_id).unwrap().secret_key_bytes();

    let (pe_id, _) = identity_store.create_identity(IdentityKind::Service);
    let pe_secret = identity_store.get_key(&pe_id).unwrap().secret_key_bytes();

    let mod_key = crypto::KeyPair::from_secret_bytes(&creator_secret);
    let module_hash = crypto::sha256_hex(b"winstack-desktop");

    let mut module_registry = identity_core::ModuleRegistry::new();
    let (module_id, _) = module_registry.register(
        ModuleKind::Document,
        "*",
        &module_hash,
        creator_id,
        &mod_key,
    );

    let now = chrono::Utc::now().to_rfc3339();

    #[derive(serde::Serialize, serde::Deserialize)]
    struct NodeConfig {
        creator_id: uuid::Uuid,
        #[serde(with = "hex_bytes")]
        creator_secret: [u8; 32],
        ta_id: uuid::Uuid,
        #[serde(with = "hex_bytes")]
        ta_secret: [u8; 32],
        pe_id: uuid::Uuid,
        #[serde(with = "hex_bytes")]
        pe_secret: [u8; 32],
        module_id: uuid::Uuid,
        module_hash: String,
        created_at: String,
    }

    let config = NodeConfig {
        creator_id,
        creator_secret,
        ta_id,
        ta_secret,
        pe_id,
        pe_secret,
        module_id,
        module_hash,
        created_at: now,
    };

    let json = serde_json::to_string_pretty(&config).unwrap();
    std::fs::write(&node_json, json).unwrap();
    // Restrict permissions — private keys must not be world-readable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&node_json, std::fs::Permissions::from_mode(0o600));
    }
    // Restrict graph.db to owner-only
    let graph_path = node_path.join("graph.db");
    if graph_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&graph_path, std::fs::Permissions::from_mode(0o600));
        }
    }
}

fn check_and_repair_permissions(node_path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let check = |path: &std::path::Path, expected: u32, label: &str| {
            if !path.exists() { return; }
            if let Ok(meta) = std::fs::metadata(path) {
                let current = meta.permissions().mode() & 0o777;
                if current != expected {
                    eprintln!("  WARNING: {} has permissions {:04o}, expected {:04o} — repairing", label, current, expected);
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(expected));
                }
            }
        };
        check(node_path, 0o700, "node directory");
        check(&node_path.join("node.json"), 0o600, "node.json");
        check(&node_path.join("graph.db"), 0o600, "graph.db");
    }
}

fn load_registry(node_path: &std::path::Path) -> registry_core::Registry {
    check_and_repair_permissions(node_path);
    let node_json = node_path.join("node.json");
    let data = std::fs::read_to_string(&node_json).unwrap();

    #[derive(serde::Deserialize)]
    struct NodeConfig {
        creator_id: uuid::Uuid,
        #[serde(with = "hex_bytes")]
        creator_secret: [u8; 32],
        ta_id: uuid::Uuid,
        #[serde(with = "hex_bytes")]
        ta_secret: [u8; 32],
        pe_id: uuid::Uuid,
        #[serde(with = "hex_bytes")]
        pe_secret: [u8; 32],
        module_id: uuid::Uuid,
        module_hash: String,
        created_at: String,
    }

    let node: NodeConfig = serde_json::from_str(&data).unwrap();

    let obj_store = object_store::ObjectStore::with_path(&node_path.join("store_data")).unwrap();
    let graph =
        graph_index::GraphIndex::open(node_path.join("graph.db").to_str().unwrap()).unwrap();

    let mut identity_store = identity_core::IdentityStore::new();

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

    let ta_key_id = crypto::KeyPair::from_secret_bytes(&node.ta_secret);
    let ta_rec = IdentityRecord {
        identity_id: node.ta_id,
        kind: IdentityKind::Service,
        status: IdentityStatus::Active,
        public_key_hex: ta_key_id.public_key_hex(),
        created_at: node.created_at.clone(),
        signature: String::new(),
    };
    identity_store.insert_identity(ta_rec, ta_key_id);

    let pe_key_id = crypto::KeyPair::from_secret_bytes(&node.pe_secret);
    let pe_rec = IdentityRecord {
        identity_id: node.pe_id,
        kind: IdentityKind::Service,
        status: IdentityStatus::Active,
        public_key_hex: pe_key_id.public_key_hex(),
        created_at: node.created_at.clone(),
        signature: String::new(),
    };
    identity_store.insert_identity(pe_rec, pe_key_id);

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

fn find_available_port() -> u16 {
    // Try fixed port first for reliable UI connection
    const PREFERRED: u16 = 13845;
    if std::net::TcpListener::bind(format!("127.0.0.1:{}", PREFERRED)).is_ok() {
        return PREFERRED;
    }
    // Fallback to random
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn main() {
    let nd = node_dir();
    ensure_node(&nd);
    let registry = load_registry(&nd);
    let shared = Arc::new(Mutex::new(registry));

    let port = find_available_port();
    let addr = format!("127.0.0.1:{}", port);
    let session_token = window_api::generate_session_token();

    // Start the API server with auth token in a background thread
    let shared_clone = shared.clone();
    let addr_clone = addr.clone();
    let token_clone = session_token.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            window_api::serve_with_token(shared_clone, &addr_clone, Some(token_clone))
                .await
                .unwrap();
        });
    });

    // Wait for server to be ready
    for _ in 0..50 {
        if std::net::TcpStream::connect(&addr).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let inject_js = format!(
        "window.WINSTACK_API_BASE = 'http://{}'; window.WINSTACK_TOKEN = '{}';",
        addr, session_token
    );

    let app = tauri::Builder::default()
        .on_page_load(move |webview, payload| {
            use tauri::webview::PageLoadEvent;
            if let PageLoadEvent::Finished { .. } = payload.event() {
                webview.eval(&inject_js).ok();
            }
        })
        .build(tauri::generate_context!("./tauri.conf.json"))
        .expect("error while building Winstack");

    app.run(move |_app_handle, event| {
        if let tauri::RunEvent::Opened { urls } = event {
            // macOS opened a .win file with this app
            for url in &urls {
                if let Ok(path) = url.to_file_path() {
                    if path.extension().map(|e| e == "win").unwrap_or(false) {
                        let raw = match std::fs::read(&path) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        // Unpack, verify, and open the file
                        let (name, artifact, proof_json) = match win_format::unpack(&raw) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        let bundle: canon_types::ProofBundle = match serde_json::from_str(&proof_json) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        let vr = verifier::verify_from_proof_bundle(&bundle, &artifact);
                        if vr.status.is_alive() {
                            if let Ok(home) = std::env::var("HOME") {
                                let save_path = std::path::Path::new(&home)
                                    .join("Downloads")
                                    .join(&name);
                                if std::fs::write(&save_path, &artifact).is_ok() {
                                    // Wait a beat, then open — so the file viewer lands on top
                                    let sp = save_path.clone();
                                    std::thread::spawn(move || {
                                        std::thread::sleep(std::time::Duration::from_millis(300));
                                        let _ = std::process::Command::new("open")
                                            .arg(&sp)
                                            .status();
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}
