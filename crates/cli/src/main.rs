mod node;

use canon_types::VerificationStatus;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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

#[derive(Parser)]
#[command(name = "win", about = "Winstack internal inspection CLI")]
struct Cli {
    #[arg(long)]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Verify {
        object_id: String,
    },
    Inspect {
        object_id: String,
    },
    Export {
        object_id: String,
        output: PathBuf,
    },
    Serve {
        #[arg(long, default_value = "127.0.0.1:3001")]
        addr: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let node_dir = cli.store.unwrap_or_else(resolve_node_dir);
    eprintln!("node: {}", node_dir.display());
    let reg = node::load_registry_from_node(&node_dir);

    match cli.command {
        Commands::Verify { object_id } => {
            let id = uuid::Uuid::parse_str(&object_id).unwrap_or_else(|_| {
                eprintln!("ERROR: invalid uuid: {}", object_id);
                std::process::exit(2);
            });
            match reg.verify_object(&id) {
                Some(result) => match result.status {
                    VerificationStatus::Verified => {
                        println!("VERIFIED  {}", id);
                        std::process::exit(0);
                    }
                    VerificationStatus::Invalid => {
                        println!("INVALID   {}", id);
                        for (i, f) in result.failures.iter().enumerate() {
                            println!("  [{}] {:?} — {}", i, f.code, f.reason);
                        }
                        std::process::exit(1);
                    }
                },
                None => {
                    eprintln!("ERROR: object not found: {}", id);
                    std::process::exit(2);
                }
            }
        }
        Commands::Inspect { object_id } => {
            let id = uuid::Uuid::parse_str(&object_id).unwrap_or_else(|_| {
                eprintln!("ERROR: invalid uuid: {}", object_id);
                std::process::exit(2);
            });
            match reg.object_store.get(&id) {
                Some(obj) => {
                    let json = serde_json::to_string_pretty(obj).unwrap();
                    println!("{}", json);
                }
                None => {
                    eprintln!("ERROR: object not found: {}", id);
                    std::process::exit(2);
                }
            }
        }
        Commands::Export { object_id, output } => {
            let id = uuid::Uuid::parse_str(&object_id).unwrap_or_else(|_| {
                eprintln!("ERROR: invalid uuid: {}", object_id);
                std::process::exit(2);
            });
            match reg.build_proof_bundle(&id) {
                Some(bundle) => {
                    let json = serde_json::to_string_pretty(&bundle).unwrap();
                    std::fs::write(&output, json).unwrap_or_else(|e| {
                        eprintln!("ERROR: write failed: {}", e);
                        std::process::exit(2);
                    });
                    println!("EXPORTED  {}  →  {}", id, output.display());
                }
                None => {
                    eprintln!("ERROR: could not build proof bundle for: {}", id);
                    std::process::exit(2);
                }
            }
        }
        Commands::Serve { addr } => {
            println!("Winstack Window API listening on {}", addr);
            let shared = Arc::new(Mutex::new(reg));
            window_api::serve(shared, &addr).await.unwrap_or_else(|e| {
                eprintln!("ERROR: server failed: {}", e);
                std::process::exit(2);
            });
        }
    }
}
