use canon_types::*;
use clap::{Parser, Subcommand};
use std::io::Read as _;
use std::path::PathBuf;
use wise_crypto as crypto;

// Shared node loading logic
#[path = "../node.rs"]
mod node;
#[path = "../trust.rs"]
mod trust;

#[derive(Parser)]
#[command(name = "win", about = "Wise — seal and verify files")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Seal one or more files → produces `.win` containers and (by default)
    /// publishes their win tags so the share URLs resolve immediately.
    /// Use `--private` to skip publishing.
    Seal {
        /// Files to seal. Accepts shell globs: `win seal *.pdf`.
        #[arg(num_args = 1..)]
        files: Vec<PathBuf>,
        #[arg(long)]
        tsa_url: Option<String>,
        #[arg(long)]
        from: Option<PathBuf>,
        /// Skip publishing the win tag(s). The `.win` is still produced
        /// locally; share URLs print but won't resolve.
        #[arg(long)]
        private: bool,
        /// Override the publish target. Defaults to `WISE_PUBLISH_DIR`,
        /// then to the nearest `public/` directory in the file tree.
        #[arg(long)]
        publish_to: Option<PathBuf>,
        /// Base URL for the share links. Defaults to `https://winstack.dev`.
        #[arg(long, default_value = "https://winstack.dev")]
        base_url: String,
        /// Suppress writing the share URL(s) to the system clipboard.
        /// Auto-enabled when stdout is not a TTY (CI, scripts) so the
        /// command never clobbers a user's clipboard from a pipeline.
        #[arg(long)]
        no_clipboard: bool,
    },
    /// Verify a .win file
    Verify {
        /// A .win file
        file: PathBuf,
        #[arg(long)]
        tsa_root: Vec<String>,
    },
    /// Inspect a .win file — show contents and proof details without extracting
    Inspect { file: PathBuf },
    /// Extract the original file from a .win container
    Open {
        file: PathBuf,
        /// Extract even if tampered or invalid (for inspection)
        #[arg(long)]
        force: bool,
    },
    /// Publish a win tag to a hash-indexed directory (creates `<dir>/v/<hash>.json`).
    /// The directory is the deploy root — e.g. `public/` for the Vercel build.
    Publish {
        /// A .win file to publish
        file: PathBuf,
        /// Output directory. Default: `public/` relative to the current dir.
        #[arg(long, default_value = "public")]
        to: PathBuf,
        /// Base URL where the directory will be served from.
        #[arg(long, default_value = "https://winstack.dev")]
        base_url: String,
    },
    /// Manage local trusted keys
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
}

#[derive(Subcommand)]
enum TrustAction {
    /// Add a public key to your local trust list
    Add {
        /// Public key (64-char hex)
        key: String,
        /// Optional label for this key
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a public key from your local trust list
    Remove {
        /// Public key to remove
        key: String,
    },
    /// List all locally trusted keys
    List,
}

/// Locate where to publish win tags. Returns the directory that should
/// contain `v/<hash>.json` once the file is sealed.
///
/// Resolution order:
/// 1. `WISE_PUBLISH_DIR` env var (explicit override).
/// 2. The nearest ancestor directory containing a `public/` subdirectory
///    AND a `vercel.json` file — this is the "you're inside a Wise
///    deploy project" heuristic.
/// 3. None — caller will skip auto-publishing.
fn detect_publish_dir() -> Option<PathBuf> {
    if let Ok(d) = std::env::var("WISE_PUBLISH_DIR") {
        let p = PathBuf::from(d);
        if !p.as_os_str().is_empty() {
            return Some(p);
        }
    }
    let mut dir = std::env::current_dir().ok()?;
    loop {
        if dir.join("public").is_dir() && dir.join("vercel.json").is_file() {
            return Some(dir.join("public"));
        }
        match dir.parent() {
            Some(p) => dir = p.to_path_buf(),
            None => return None,
        }
    }
}

/// Copy text to the OS clipboard. Returns `true` on success. Best-effort —
/// failure is silent because clipboard isn't load-bearing.
fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let candidates: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("pbcopy", &[])]
    } else if cfg!(target_os = "windows") {
        &[("clip", &[])]
    } else {
        &[
            ("wl-copy", &[]),
            ("xclip", &["-selection", "clipboard"]),
            ("xsel", &["--clipboard", "--input"]),
        ]
    };

    for (cmd, args) in candidates {
        let Ok(mut child) = Command::new(cmd)
            .args(*args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(stdin) = child.stdin.as_mut() {
            if stdin.write_all(text.as_bytes()).is_err() {
                continue;
            }
        }
        if child.wait().is_ok() {
            return true;
        }
    }
    false
}

fn resolve_node_dir() -> PathBuf {
    let bin_path = std::env::current_exe().unwrap();
    let project_root = bin_path
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();
    project_root.join(".wise")
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
        // Restrict .wise directory to owner-only access
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&node_path, std::fs::Permissions::from_mode(0o700));
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
        let module_hash = crypto::sha256_hex(b"wise-cli");
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
                let _ =
                    std::fs::set_permissions(&graph_path, std::fs::Permissions::from_mode(0o600));
            }
        }

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

fn win_file(
    file: &std::path::Path,
    tsa_url: &Option<String>,
    from: &Option<PathBuf>,
) -> (Vec<u8>, canon_types::ProofBundle, String) {
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
            },
            Err(e) => {
                eprintln!("  TSA warning: {} (using local time)", e);
                None
            },
        }
    } else {
        None
    };

    let proof_chain = if let Some(ref from_path) = from {
        let pred_raw = std::fs::read(from_path).unwrap_or_else(|e| {
            eprintln!("ERROR: could not read predecessor: {}", e);
            std::process::exit(2);
        });
        // Predecessor can be either a `.win` container (canonical) or a
        // legacy `.proof.json` sidecar. Detect by magic bytes; fall back
        // to JSON parsing.
        let pred_proof_text: String = if win_format::is_win_file(&pred_raw) {
            match win_format::unpack(&pred_raw) {
                Ok((_name, _file_bytes, proof_text)) => proof_text,
                Err(e) => {
                    eprintln!("ERROR: predecessor .win is malformed: {}", e);
                    std::process::exit(2);
                },
            }
        } else {
            String::from_utf8(pred_raw).unwrap_or_else(|e| {
                eprintln!(
                    "ERROR: predecessor is neither a .win nor valid UTF-8 JSON: {}",
                    e
                );
                std::process::exit(2);
            })
        };
        let pred_bundle: ProofBundle = serde_json::from_str(&pred_proof_text).unwrap_or_else(|e| {
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
        println!("  Tampered      {}", label);
        println!(
            "    The file no longer matches the proof inside this .win \
             container. At least one byte changed."
        );
        println!("    file      sha256:{}", file_hash);
        println!("    expected  sha256:{}", bundle.object.payload_hash);
        std::process::exit(1);
    }

    let tsa_trust_store = if tsa_root.is_empty() {
        None
    } else {
        eprintln!("  TSA trust: pinned ({} roots)", tsa_root.len());
        Some(time_core::tsa::TrustStore::with_roots(tsa_root.to_vec()))
    };
    let result =
        verifier::verify_from_proof_bundle_with_trust(bundle, artifact_bytes, tsa_trust_store);
    match result.status {
        VerificationStatus::Verified => {
            println!(
                "  Verified      sha256:{}  {}",
                &bundle.object.payload_hash[..12],
                label
            );
            println!(
                "    The file matches the proof inside this .win container. \
                 No byte changes detected."
            );
            std::process::exit(0);
        },
        VerificationStatus::Tampered => {
            println!(
                "  Tampered      sha256:{}  {}",
                &bundle.object.payload_hash[..12],
                label
            );
            println!(
                "    The file no longer matches the proof inside this .win \
                 container. At least one byte changed."
            );
            for (i, f) in result.failures.iter().enumerate() {
                println!("    [{}] {:?} — {}", i, f.code, f.reason);
            }
            std::process::exit(1);
        },
        VerificationStatus::Invalid => {
            println!(
                "  Invalid       sha256:{}  {}",
                &bundle.object.payload_hash[..12],
                label
            );
            println!("    This .win container is not valid or cannot be verified.");
            for (i, f) in result.failures.iter().enumerate() {
                println!("    [{}] {:?} — {}", i, f.code, f.reason);
            }
            std::process::exit(1);
        },
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        // ── WIN: file(s) → .win + auto-publish (default) ──
        Commands::Seal {
            files,
            tsa_url,
            from,
            private,
            publish_to,
            base_url,
            no_clipboard,
        } => {
            if files.is_empty() {
                eprintln!("ERROR: at least one file required");
                std::process::exit(2);
            }
            // Resolve the publish destination once, before sealing. Skipped
            // entirely when --private is set.
            let publish_dir = if private {
                None
            } else {
                publish_to.clone().or_else(detect_publish_dir)
            };

            let mut share_urls: Vec<String> = Vec::new();
            let base = base_url.trim_end_matches('/').to_string();

            for file in &files {
                if !file.exists() {
                    eprintln!("ERROR: file not found: {}", file.display());
                    std::process::exit(2);
                }
                let (artifact_bytes, bundle, proof_json) = win_file(file, &tsa_url, &from);

                // The container's internal filename keeps the full original
                // name (with extension) so `win open` restores `report.pdf`.
                // The filesystem name is just `<basename>.win`.
                let internal_filename = file
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let win_bytes = win_format::pack(&internal_filename, &artifact_bytes, &proof_json);
                // Append `.win` to the FULL filename so `invoice.txt` becomes
                // `invoice.txt.win` — matching the browser/WASM behavior so
                // verification works the same across surfaces. (Earlier the
                // CLI used file_stem() which dropped the original extension
                // and produced `invoice.win`, diverging from the web.)
                let parent = file.parent().unwrap_or_else(|| std::path::Path::new("."));
                let mut candidate = parent.join(format!("{internal_filename}.win"));
                if candidate.exists() && candidate != *file {
                    let short = &bundle.object.payload_hash[..8];
                    candidate = parent.join(format!("{internal_filename}-{short}.win"));
                }
                std::fs::write(&candidate, win_bytes).unwrap_or_else(|e| {
                    eprintln!("ERROR: could not write .win file: {}", e);
                    std::process::exit(2);
                });

                let hash = bundle.object.payload_hash.clone();
                let url = format!("{}/v/{}", base, hash);
                println!("  Sealed        {}", file.display());
                println!("  →             {}", candidate.display());

                // Auto-publish unless private.
                if let Some(ref dir) = publish_dir {
                    let v_dir = dir.join("v");
                    if let Err(e) = std::fs::create_dir_all(&v_dir) {
                        eprintln!(
                            "  WARN          could not create {}: {}",
                            v_dir.display(),
                            e
                        );
                    } else {
                        let p = v_dir.join(format!("{}.json", hash));
                        match std::fs::write(&p, &proof_json) {
                            Ok(_) => println!("  Published     {}", p.display()),
                            Err(e) => eprintln!(
                                "  WARN          could not publish to {}: {}",
                                p.display(),
                                e
                            ),
                        }
                    }
                }

                println!("  Share URL     {}", url);
                share_urls.push(url);
                println!();
            }

            // Copy share URL(s) to the clipboard — interactive runs only.
            // Skip when --no-clipboard is set OR when stdout is not a TTY
            // (the user is piping output, in CI, or running from a script —
            // any of those would silently clobber the system clipboard).
            let stdout_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
            if !no_clipboard && stdout_is_tty {
                let clipboard_text = share_urls.join("\n");
                if copy_to_clipboard(&clipboard_text) {
                    let label = if share_urls.len() == 1 {
                        "URL copied to clipboard".to_string()
                    } else {
                        format!("{} URLs copied to clipboard", share_urls.len())
                    };
                    println!("  ({label})");
                }
            }

            // Helpful nudge if the user's seal can't actually resolve yet.
            if publish_dir.is_none() && !private {
                println!();
                println!("  (Set WISE_PUBLISH_DIR or run inside a project with a `public/`");
                println!(
                    "   directory to make share URLs resolve. Use --private to silence this.)"
                );
            }

            std::process::exit(0);
        },

        // ── VERIFY: .win ──
        Commands::Verify { file, tsa_root } => {
            if !file.exists() {
                eprintln!("ERROR: file not found: {}", file.display());
                std::process::exit(2);
            }

            let raw = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("ERROR: could not read file: {}", e);
                std::process::exit(2);
            });

            if !file.extension().map(|e| e == "win").unwrap_or(false)
                && !win_format::is_win_file(&raw)
            {
                eprintln!("ERROR: not a .win file.");
                std::process::exit(2);
            }

            // .win container — distinguish three failure classes:
            //   Damaged  — container itself unreadable (bytes missing,
            //              truncated, wrong magic). Per is_container_damage().
            //   Invalid  — container readable but proof section malformed
            //              (proof JSON broken, structurally invalid).
            //   Tampered — handled inside verify_bundle when the file
            //              digest doesn't match the proof's payload_hash.
            let (_name, artifact_bytes, proof_text) =
                win_format::unpack(&raw).unwrap_or_else(|e| {
                    if e.is_container_damage() {
                        println!("  Damaged       {}", file.display());
                        println!("    This .win file appears incomplete or corrupted.");
                        println!("    {}", e);
                    } else {
                        println!("  Invalid       {}", file.display());
                        println!("    This .win container is not valid or cannot be verified.");
                        println!("    {}", e);
                    }
                    std::process::exit(1);
                });
            let bundle: ProofBundle = serde_json::from_str(&proof_text).unwrap_or_else(|e| {
                println!("  Invalid       {}", file.display());
                println!("    This .win container is not valid or cannot be verified.");
                println!("    win tag's proof section is not valid JSON: {}", e);
                std::process::exit(1);
            });
            verify_bundle(
                &artifact_bytes,
                &bundle,
                &tsa_root,
                &file.display().to_string(),
            );
        },

        // ── INSPECT: show what's inside a .win ──
        Commands::Inspect { file } => {
            if !file.exists() {
                eprintln!("ERROR: file not found: {}", file.display());
                std::process::exit(2);
            }
            let raw = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("ERROR: could not read file: {}", e);
                std::process::exit(2);
            });
            let (name, artifact_bytes, proof_json) = win_format::unpack(&raw).unwrap_or_else(|e| {
                println!("  Invalid       {}", file.display());
                println!("    {}", e);
                std::process::exit(3);
            });
            let bundle: canon_types::ProofBundle = serde_json::from_str(&proof_json)
                .unwrap_or_else(|e| {
                    println!("  Invalid       {}", file.display());
                    println!("    win tag's proof section is not valid JSON: {}", e);
                    std::process::exit(3);
                });

            // Verify
            let file_hash = crypto::sha256_hex(&artifact_bytes);
            let status = if file_hash != bundle.object.payload_hash {
                VerificationStatus::Tampered
            } else {
                verifier::verify_from_proof_bundle(&bundle, &artifact_bytes).status
            };
            let status_label = match status {
                VerificationStatus::Verified => "Verified",
                VerificationStatus::Tampered => "Tampered",
                VerificationStatus::Invalid => "Invalid ",
            };

            // Trust
            let node_dir = resolve_node_dir();
            let key_trust = trust::TrustStore::load(&node_dir);
            let creator_key = &bundle.creator_identity.public_key_hex;
            let trust_label = if key_trust.is_trusted(creator_key) {
                key_trust
                    .label_for(creator_key)
                    .unwrap_or("Trusted key")
                    .to_string()
            } else {
                "Untrusted key".to_string()
            };

            let time_label = match bundle.object.time_event.time_source {
                canon_types::TimeSource::External => "Anchored — externally timestamped (RFC 3161)",
                canon_types::TimeSource::Local => "Local — from the witness's device clock",
            };

            println!("  {}  {}", status_label, file.display());
            println!();
            println!("  File        {}", name);
            println!("  Size        {} bytes", artifact_bytes.len());
            println!("  Fingerprint sha256:{}", bundle.object.payload_hash);
            println!("  Created     {}", bundle.object.origin.created_at);
            println!("  Time        {}", time_label);
            println!(
                "  Witness     {}...{}",
                &creator_key[..8],
                &creator_key[56..]
            );
            println!("  Trust       {}", trust_label);

            if status.is_verified() {
                std::process::exit(0);
            } else {
                std::process::exit(1);
            }
        },

        // ── OPEN: .win → extract original file ──
        Commands::Open { file, force } => {
            if !file.exists() {
                eprintln!("ERROR: file not found: {}", file.display());
                std::process::exit(2);
            }
            let raw = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("ERROR: could not read file: {}", e);
                std::process::exit(2);
            });
            let (name, artifact_bytes, proof_json) = win_format::unpack(&raw).unwrap_or_else(|e| {
                println!("  Invalid       {}", file.display());
                println!("    {}", e);
                std::process::exit(3);
            });
            let bundle: canon_types::ProofBundle = serde_json::from_str(&proof_json)
                .unwrap_or_else(|e| {
                    println!("  Invalid       {}", file.display());
                    println!("    win tag's proof section is not valid JSON: {}", e);
                    std::process::exit(3);
                });
            let vr = verifier::verify_from_proof_bundle(&bundle, &artifact_bytes);
            match vr.status {
                canon_types::VerificationStatus::Verified => {
                    println!("  Verified");
                },
                canon_types::VerificationStatus::Tampered => {
                    let file_hash = wise_crypto::sha256_hex(&artifact_bytes);
                    let expected = &bundle.object.payload_hash;
                    println!("  Tampered      {}", file.display());
                    println!("    file      sha256:{}", file_hash);
                    println!("    expected  sha256:{}", expected);
                    if !force {
                        println!("  Use --force to extract anyway.");
                        std::process::exit(1);
                    }
                    println!("  Extracting anyway (--force).");
                },
                canon_types::VerificationStatus::Invalid => {
                    println!("  Invalid       {}", file.display());
                    for f in &vr.failures {
                        println!("    {:?}: {}", f.code, f.reason);
                    }
                    if !force {
                        println!("  Use --force to extract anyway.");
                        std::process::exit(1);
                    }
                    println!("  Extracting anyway (--force).");
                },
            }
            std::fs::write(&name, &artifact_bytes).unwrap_or_else(|e| {
                eprintln!("ERROR: could not write file: {}", e);
                std::process::exit(2);
            });
            println!("  Opened        {}", name);
            // Open with system default app
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("open").arg(&name).spawn();
            }
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("cmd")
                    .args(["/C", "start", "", &name])
                    .spawn();
            }
            #[cfg(target_os = "linux")]
            {
                let _ = std::process::Command::new("xdg-open").arg(&name).spawn();
            }
            std::process::exit(0);
        },

        // ── PUBLISH: extract a win tag and write it to a hash-indexed directory ──
        Commands::Publish { file, to, base_url } => {
            if !file.exists() {
                eprintln!("ERROR: file not found: {}", file.display());
                std::process::exit(2);
            }
            let raw = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("ERROR: could not read file: {}", e);
                std::process::exit(2);
            });
            let (_name, _artifact, proof_text) = win_format::unpack(&raw).unwrap_or_else(|e| {
                println!("  Invalid       {}", file.display());
                println!("    {}", e);
                std::process::exit(3);
            });
            let bundle: ProofBundle = serde_json::from_str(&proof_text).unwrap_or_else(|e| {
                println!("  Invalid       {}", file.display());
                println!("    proof section is not valid JSON: {}", e);
                std::process::exit(3);
            });
            let hash = bundle.object.payload_hash.clone();
            if !hash.chars().all(|c| c.is_ascii_hexdigit()) || hash.len() < 32 {
                eprintln!("ERROR: win tag's payload hash is malformed");
                std::process::exit(2);
            }
            let v_dir = to.join("v");
            if let Err(e) = std::fs::create_dir_all(&v_dir) {
                eprintln!("ERROR: could not create {}: {}", v_dir.display(), e);
                std::process::exit(2);
            }
            let out_path = v_dir.join(format!("{}.json", hash));
            if let Err(e) = std::fs::write(&out_path, &proof_text) {
                eprintln!("ERROR: could not write {}: {}", out_path.display(), e);
                std::process::exit(2);
            }
            let url = format!("{}/v/{}", base_url.trim_end_matches('/'), hash);
            println!("  Published     {}", out_path.display());
            println!("  →  {}", url);
            std::process::exit(0);
        },

        // ── TRUST: manage local trusted keys ──
        Commands::Trust { action } => {
            let node_dir = resolve_node_dir();
            // Ensure node directory exists for trust store
            if !node_dir.exists() {
                std::fs::create_dir_all(&node_dir).unwrap_or_else(|e| {
                    eprintln!("ERROR: could not create node directory: {}", e);
                    std::process::exit(2);
                });
            }
            let mut store = trust::TrustStore::load(&node_dir);

            match action {
                TrustAction::Add { key, label } => {
                    if key.len() != 64 || hex::decode(&key).is_err() {
                        eprintln!(
                            "ERROR: key must be a 64-character hex string (Ed25519 public key)"
                        );
                        std::process::exit(2);
                    }
                    if store.add(key.clone(), label.clone()) {
                        store.save(&node_dir).unwrap_or_else(|e| {
                            eprintln!("ERROR: could not save trust store: {}", e);
                            std::process::exit(2);
                        });
                        println!("  TRUSTED   {}...{}", &key[..8], &key[56..]);
                        if let Some(l) = label {
                            println!("    label   {}", l);
                        }
                    } else {
                        println!("  Already trusted: {}...{}", &key[..8], &key[56..]);
                    }
                },
                TrustAction::Remove { key } => {
                    if store.remove(&key) {
                        store.save(&node_dir).unwrap_or_else(|e| {
                            eprintln!("ERROR: could not save trust store: {}", e);
                            std::process::exit(2);
                        });
                        println!("  REMOVED   {}...{}", &key[..8], &key[56..]);
                    } else {
                        println!("  Not found: {}...{}", &key[..8], &key[56..]);
                    }
                },
                TrustAction::List => {
                    if store.keys.is_empty() {
                        println!("  No trusted keys.");
                    } else {
                        for k in &store.keys {
                            let label = k.label.as_deref().unwrap_or("(no label)");
                            println!("  {}  {}", k.key, label);
                        }
                    }
                },
            }
        },
    }
}
