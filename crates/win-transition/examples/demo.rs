//! End-to-end W.I.N. governed-transition demonstration.
//!
//! Produces the demo artifacts the product directive requires and verifies each
//! one independently from its bytes:
//!
//! ```text
//! cargo run -p win-transition --example demo -- <output-dir>   # default: ./demo
//! ```
//!
//! It runs the full lifecycle twice:
//! 1. **Accepted** — a local proposer suggests a summary; the authorizer grants
//!    only `LocalWrite`; the executor creates `Summary.txt`; the transition is
//!    sealed to `accepted-transition.win`.
//! 2. **Refused** — the same proposer asks to *publish* the summary; the grant
//!    covers only local writing, so it is refused with no side effect and sealed
//!    to `refused-transition.win`.
//!
//! Then it tampers with the accepted artifact's content to produce
//! `tampered-example.win`, and writes `expected-verification-results.txt`.

use std::path::{Path, PathBuf};

use uuid::Uuid;
use win_transition::{
    govern, render_verification_matrix, seal_win, verify_win, Authority, Authorizer, Executor,
    FilesystemExecutor, GovernRequest, PortableProof, Recorder, RequestedAction,
    TransitionPublicKeys,
};
use wise_crypto::{sha256_hex, KeyPair};

use win_transition::proposers::propose_summary;

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn main() {
    let out_dir: PathBuf = std::env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("demo"), PathBuf::from);
    std::fs::create_dir_all(&out_dir).expect("create output dir");

    // --- The four separated roles, each with its own key. ---
    let proposer_id = Uuid::new_v4();
    let authorizer = Authorizer::new(Uuid::new_v4(), KeyPair::generate());
    let executor = FilesystemExecutor::new(Uuid::new_v4(), KeyPair::generate());
    let recorder = Recorder::new(Uuid::new_v4(), KeyPair::generate());
    let keys = TransitionPublicKeys::new(
        recorder.public_key_hex(),
        authorizer.public_key_hex(),
        executor.public_key_hex(),
        None,
    );

    // --- Step 1: import a source document. ---
    let source_text = "\
This Agreement is entered into between Party A and Party B on the terms below.
Party A shall deliver the goods within thirty days of the effective date.
Party B shall remit payment within fifteen days of delivery.
Neither party may assign this Agreement without prior written consent.
";
    let source_path = out_dir.join("Contract.txt");
    write(&source_path, source_text.as_bytes());
    let subject = format!("sha256:{}", sha256_hex(source_text.as_bytes()));
    println!("Imported source: {}\n  subject = {subject}\n", source_path.display());

    // --- Step 2-3: the local proposer proposes a summary. ---
    let summary = propose_summary(source_text.as_bytes());
    let summary_path = out_dir.join("Summary.txt");

    // --- Steps 4-9 (ACCEPTED): govern the local-write transition. ---
    let grant = authorizer.issue_grant(Authority::LocalWrite, &subject);
    let action = RequestedAction::new(
        "create_file",
        &subject,
        summary_path.to_str().unwrap(),
        Authority::LocalWrite,
    );
    let accepted = govern(
        GovernRequest {
            proposer_identity_id: proposer_id,
            proposer_model: Some(canon_ai("win-local-extractive-proposer", "0.1")),
            prior_state_id: Some(subject.clone()),
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: summary.as_bytes(),
        },
        &executor,
        &recorder,
    );
    assert!(accepted.was_executed(), "accepted path must execute");
    let accepted_win = seal_win(
        &PortableProof::new(accepted, keys.clone()),
        "Summary.txt.win",
        summary.as_bytes(),
    );
    let accepted_path = out_dir.join("accepted-transition.win");
    write(&accepted_path, &accepted_win);
    println!("Accepted transition → {}", accepted_path.display());

    // --- Step (REFUSED): the proposer now asks to publish externally. ---
    let publish_grant = authorizer.issue_grant(Authority::LocalWrite, &subject);
    let publish_action = RequestedAction::new(
        "publish",
        &subject,
        "https://example.com/publish",
        Authority::ExternalPublish,
    );
    let refused = govern(
        GovernRequest {
            proposer_identity_id: proposer_id,
            proposer_model: Some(canon_ai("win-local-extractive-proposer", "0.1")),
            prior_state_id: Some(subject.clone()),
            subject_content_id: subject.clone(),
            action: publish_action,
            grant: publish_grant,
            authorizer_public_key: authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"",
        },
        &executor,
        &recorder,
    );
    assert!(refused.was_refused(), "publish must be refused");
    let refused_win = seal_win(&PortableProof::new(refused, keys.clone()), "refusal.win", b"");
    let refused_path = out_dir.join("refused-transition.win");
    write(&refused_path, &refused_win);
    println!("Refused transition  → {}", refused_path.display());

    // --- Tampered example: flip one byte of the accepted artifact's content. ---
    let mut tampered = accepted_win.clone();
    if let Some(idx) = tampered
        .windows(summary.len())
        .position(|w| w == summary.as_bytes())
    {
        tampered[idx] ^= 0xFF;
    }
    let tampered_path = out_dir.join("tampered-example.win");
    write(&tampered_path, &tampered);
    println!("Tampered example    → {}\n", tampered_path.display());

    // --- Independently verify all three from bytes alone. ---
    let mut report = String::new();
    for (label, path) in [
        ("ACCEPTED", &accepted_path),
        ("REFUSED", &refused_path),
        ("TAMPERED", &tampered_path),
    ] {
        let bytes = std::fs::read(path).unwrap();
        let header = format!(
            "===== {label}  ({}) =====\n",
            path.file_name().unwrap().to_string_lossy()
        );
        report.push_str(&header);
        print!("{header}");
        match verify_win(&bytes) {
            Ok(v) => {
                let matrix = render_verification_matrix(&v);
                let verdict = format!(
                    "OVERALL: {}\n\n",
                    if v.all_checks_pass() {
                        "PASS"
                    } else {
                        "FAIL (see rows above)"
                    }
                );
                report.push_str(&matrix);
                report.push_str(&verdict);
                print!("{matrix}{verdict}");
            }
            Err(e) => {
                let line = format!("UNREADABLE: {e}\n\n");
                report.push_str(&line);
                print!("{line}");
            }
        }
    }

    let expected_path = out_dir.join("expected-verification-results.txt");
    write(&expected_path, report.as_bytes());
    println!("Wrote {}", expected_path.display());
}

fn canon_ai(name: &str, version: &str) -> canon_types::AiModelInfo {
    canon_types::AiModelInfo {
        model_name: name.to_string(),
        model_version: version.to_string(),
    }
}
