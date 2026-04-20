use canon_types::*;
use clap::{Parser, Subcommand};
use std::io::Read as _;
use std::path::PathBuf;
use winstack_crypto as crypto;

// Shared node loading logic
#[path = "../node.rs"]
mod node;

#[derive(Parser)]
#[command(name = "winstack", about = "Winstack — seal and verify files")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Seal a file → creates a .win container
    Seal {
        file: PathBuf,
        #[arg(long)]
        tsa_url: Option<String>,
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Verify a .win file (or legacy file + proof pair)
    Verify {
        /// A .win file, or a regular file (if --proof is given)
        file: PathBuf,
        /// Legacy: separate proof file (not needed for .win)
        #[arg(long)]
        proof: Option<PathBuf>,
        #[arg(long)]
        tsa_root: Vec<String>,
    },
    /// Extract the original file from a .win container
    Open { file: PathBuf },
    /// Legacy: create a .proof.json sidecar (use 'seal' for .win)
    Prove {
        file: PathBuf,
        #[arg(long)]
        tsa_url: Option<String>,
        #[arg(long)]
        from: Option<PathBuf>,
    },
}

fn resolve_node_dir() -> PathBuf {
    let bin_path = std::env::current_exe().unwrap();
    let project_root = bin_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();
    project_root.join(".winstack")
}

fn ensure_node() -> (registry_core::Registry, PathBuf) {
    let node_path = resolve_node_dir();
    let node_json = node_path.join("node.json");

    if node_path.exists() && node_json.exists() {
        let reg = node::load_registry_from_node(&node_path);
        (reg, node_path)
    } else {
        // Initialize new node
        std::fs::create_dir_all(&node_path).unwrap();
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

        let ta_key = crypto::KeyPair::from_secret_bytes(&ta_secret);
        let time_authority = time_core::TimeAuthority::new(ta_id, ta_key);

        let pe_key = crypto::KeyPair::from_secret_bytes(&pe_secret);
        let policy_evaluator = policy_core::PolicyEvaluator::new(pe_id, pe_key);

        let obj_store =
            object_store::ObjectStore::with_path(&node_path.join("store_data")).unwrap();
        let graph =
            graph_index::GraphIndex::open(node_path.join("graph.db").to_str().unwrap()).unwrap();

        let mut module_registry = identity_core::ModuleRegistry::new();
        let mod_key = crypto::KeyPair::from_secret_bytes(&creator_secret);
        let module_hash = crypto::sha256_hex(b"winstack-cli");
        let (module_id, _) = module_registry.register(
            ModuleKind::Document,
            "*",
            &module_hash,
            creator_id,
            &mod_key,
        );

        let now = chrono::Utc::now().to_rfc3339();
        let node_config = node::NodeConfig {
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

        let json = serde_json::to_string_pretty(&node_config).unwrap();
        std::fs::write(&node_json, json).unwrap();

        let reg = registry_core::Registry {
            identity_store,
            module_registry,
            time_authority,
            policy_evaluator,
            object_store: obj_store,
            graph,
        };

        (reg, node_path)
    }
}

fn fetch_tsa_token(
    tsa_url: &str,
    payload_hash_hex: &str,
) -> Result<TsaAttachment, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let req_bytes = time_core::tsa::build_timestamp_request(payload_hash_hex)?;

    let resp = ureq::post(tsa_url)
        .set("Content-Type", "application/timestamp-query")
        .send_bytes(&req_bytes)?;

    let mut resp_bytes = Vec::new();
    resp.into_reader().read_to_end(&mut resp_bytes)?;

    let info = time_core::tsa::parse_timestamp_response(&resp_bytes)?;

    if info.message_hash_hex != payload_hash_hex {
        return Err("TSA returned token with different hash".into());
    }

    Ok(TsaAttachment {
        token_base64: B64.encode(&resp_bytes),
        anchored_time: info.gen_time,
    })
}

fn seal_file(
    file: &std::path::Path,
    tsa_url: &Option<String>,
    from: &Option<PathBuf>,
) -> (Vec<u8>, canon_types::ProofBundle, String) {
    eprintln!("node: {}", resolve_node_dir().display());
    let artifact_bytes = std::fs::read(file).unwrap_or_else(|e| {
        eprintln!("ERROR: could not read file: {}", e);
        std::process::exit(2);
    });

    let (mut reg, node_path) = ensure_node();
    let node_json_path = node_path.join("node.json");
    let node_data = std::fs::read_to_string(&node_json_path).unwrap();
    let node_cfg: node::NodeConfig = serde_json::from_str(&node_data).unwrap();

    let tsa_attachment = if let Some(ref url) = tsa_url {
        let payload_hash = crypto::sha256_hex(&artifact_bytes);
        match fetch_tsa_token(url, &payload_hash) {
            Ok(att) => {
                eprintln!("  TSA anchored: {}", att.anchored_time);
                Some(att)
            }
            Err(e) => {
                eprintln!("  TSA warning: {} (using local time)", e);
                None
            }
        }
    } else {
        None
    };

    let proof_chain = if let Some(ref from_path) = from {
        let pred_data = std::fs::read_to_string(from_path).unwrap_or_else(|e| {
            eprintln!("ERROR: could not read predecessor: {}", e);
            std::process::exit(2);
        });
        let pred_bundle: ProofBundle = serde_json::from_str(&pred_data).unwrap_or_else(|e| {
            eprintln!("ERROR: invalid predecessor: {}", e);
            std::process::exit(2);
        });
        let lineage_id = pred_bundle
            .object
            .proof_chain
            .as_ref()
            .map(|c| c.lineage_id)
            .unwrap_or(pred_bundle.object.object_id);
        Some(ProofChain {
            lineage_id,
            predecessor_proof_id: Some(pred_bundle.object.object_id),
            predecessor_payload_hash: Some(pred_bundle.object.payload_hash.clone()),
            key_delegation: None,
        })
    } else {
        None
    };

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact_bytes.clone(),
            creator_identity_id: node_cfg.creator_id,
            module_id: node_cfg.module_id,
            parent_ids: vec![],
            tsa_attachment,
            proof_chain,
        })
        .unwrap_or_else(|e| {
            eprintln!("ERROR: sealing failed: {}", e);
            std::process::exit(2);
        });

    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    let proof_json = serde_json::to_string_pretty(&bundle).unwrap();

    (artifact_bytes, bundle, proof_json)
}

fn verify_bundle(artifact_bytes: &[u8], bundle: &ProofBundle, tsa_root: &[String], label: &str) {
    let file_hash = crypto::sha256_hex(artifact_bytes);
    if file_hash != bundle.object.payload_hash {
        println!("  TAMPERED  {}", label);
        println!("    file      sha256:{}", file_hash);
        println!("    expected  sha256:{}", bundle.object.payload_hash);
        std::process::exit(1);
    }

    let trust_store = if tsa_root.is_empty() {
        None
    } else {
        eprintln!("  TSA trust: pinned ({} roots)", tsa_root.len());
        Some(time_core::tsa::TrustStore::with_roots(tsa_root.to_vec()))
    };
    let result = verifier::verify_from_proof_bundle_with_trust(bundle, artifact_bytes, trust_store);
    match result.status {
        VerificationStatus::Verified => {
            println!(
                "  VERIFIED  sha256:{}  {}",
                &bundle.object.payload_hash[..12],
                label
            );
            std::process::exit(0);
        }
        VerificationStatus::Invalid => {
            println!(
                "  INVALID   sha256:{}  {}",
                &bundle.object.payload_hash[..12],
                label
            );
            for (i, f) in result.failures.iter().enumerate() {
                println!("    [{}] {:?} — {}", i, f.code, f.reason);
            }
            std::process::exit(1);
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        // ── SEAL: file → .win ──
        Commands::Seal {
            file,
            tsa_url,
            from,
        } => {
            if !file.exists() {
                eprintln!("ERROR: file not found: {}", file.display());
                std::process::exit(2);
            }
            let (artifact_bytes, _bundle, proof_json) = seal_file(&file, &tsa_url, &from);
            let filename = file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let win_bytes = win_format::pack(&filename, &artifact_bytes, &proof_json);
            let win_path = format!("{}.win", file.display());
            std::fs::write(&win_path, win_bytes).unwrap_or_else(|e| {
                eprintln!("ERROR: could not write .win file: {}", e);
                std::process::exit(2);
            });
            println!("  SEALED   {}", file.display());
            println!("  →  {}", win_path);
            std::process::exit(0);
        }

        // ── VERIFY: .win or file+proof ──
        Commands::Verify {
            file,
            proof,
            tsa_root,
        } => {
            if !file.exists() {
                eprintln!("ERROR: file not found: {}", file.display());
                std::process::exit(2);
            }

            let raw = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("ERROR: could not read file: {}", e);
                std::process::exit(2);
            });

            if win_format::is_win_file(&raw) {
                // .win container
                let (_name, artifact_bytes, proof_text) =
                    win_format::unpack(&raw).unwrap_or_else(|e| {
                        eprintln!("ERROR: invalid .win file: {}", e);
                        std::process::exit(2);
                    });
                let bundle: ProofBundle = serde_json::from_str(&proof_text).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid proof in .win: {}", e);
                    std::process::exit(2);
                });
                verify_bundle(
                    &artifact_bytes,
                    &bundle,
                    &tsa_root,
                    &file.display().to_string(),
                );
            } else if let Some(ref proof_path) = proof {
                // Legacy: file + separate proof
                if !proof_path.exists() {
                    eprintln!("ERROR: proof not found: {}", proof_path.display());
                    std::process::exit(2);
                }
                let proof_text = std::fs::read_to_string(proof_path).unwrap_or_else(|e| {
                    eprintln!("ERROR: could not read proof: {}", e);
                    std::process::exit(2);
                });
                let bundle: ProofBundle = serde_json::from_str(&proof_text).unwrap_or_else(|e| {
                    eprintln!("ERROR: invalid proof: {}", e);
                    std::process::exit(2);
                });
                verify_bundle(&raw, &bundle, &tsa_root, &file.display().to_string());
            } else {
                eprintln!("ERROR: not a .win file. Use --proof to provide a separate proof file.");
                std::process::exit(2);
            }
        }

        // ── OPEN: .win → extract original file ──
        Commands::Open { file } => {
            if !file.exists() {
                eprintln!("ERROR: file not found: {}", file.display());
                std::process::exit(2);
            }
            let raw = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("ERROR: could not read file: {}", e);
                std::process::exit(2);
            });
            let (name, artifact_bytes, _proof) = win_format::unpack(&raw).unwrap_or_else(|e| {
                eprintln!("ERROR: invalid .win file: {}", e);
                std::process::exit(2);
            });
            std::fs::write(&name, &artifact_bytes).unwrap_or_else(|e| {
                eprintln!("ERROR: could not write file: {}", e);
                std::process::exit(2);
            });
            println!("  EXTRACTED  {}", name);
            std::process::exit(0);
        }

        // ── PROVE: legacy sidecar .proof.json ──
        Commands::Prove {
            file,
            tsa_url,
            from,
        } => {
            if !file.exists() {
                eprintln!("ERROR: file not found: {}", file.display());
                std::process::exit(2);
            }
            let (_artifact, _bundle, proof_json) = seal_file(&file, &tsa_url, &from);
            let proof_path = format!("{}.proof.json", file.display());
            std::fs::write(&proof_path, proof_json).unwrap();
            println!("  SEALED   {}", file.display());
            println!("  →  {}", proof_path);
            std::process::exit(0);
        }
    }
}
