//! Governed-transition HTTP surface for the desktop app.
//!
//! Three endpoints drive the directive's document workflow from the window:
//!
//! * `POST /transition/summarize` — a local proposer suggests a summary; a
//!   scoped `LocalWrite` authorization permits it; the executor creates the
//!   file; the sealed `.win` transition is returned (base64) with its matrix.
//! * `POST /transition/publish`  — the same document, but a *publish* action is
//!   requested under a local-write-only grant → **refused**, no side effect, and
//!   a sealed refusal proof is returned.
//! * `POST /transition/verify`   — verify a `.win` transition artifact and
//!   return its per-dimension matrix.
//!
//! Each handler takes a single multipart `file` field. The authorizer uses the
//! app's PERSISTENT identity (set in Settings), so artifacts read `CLAIMED` /
//! `CONSISTENT ACTOR`, and `TRUSTED` when the recipient's trust list vouches for
//! the key. Executor/recorder keys remain session-scoped.

use axum::{extract::Multipart, http::StatusCode, Json};
use base64::Engine as _;
use serde::Serialize;
use uuid::Uuid;
use win_transition::{
    govern, render_verification_matrix, seal_win, verify_win_with_trust, Authority, Authorizer,
    Executor as _, FilesystemExecutor, GovernRequest, IdentityAssertion, PortableProof, Recorder,
    RequestedAction, TransitionPublicKeys, VerifiedArtifact,
};
use wise_crypto::{sha256_hex, KeyPair};

use crate::identity;

#[derive(Serialize)]
pub struct TransitionErr {
    pub error: String,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<TransitionErr>)>;

fn bad(msg: impl Into<String>) -> (StatusCode, Json<TransitionErr>) {
    (
        StatusCode::BAD_REQUEST,
        Json(TransitionErr { error: msg.into() }),
    )
}

/// Pull a single `file` field (bytes + original filename) out of a multipart body.
async fn read_file_field(mut mp: Multipart) -> Result<(String, Vec<u8>), (StatusCode, Json<TransitionErr>)> {
    let mut filename = "document".to_string();
    let mut bytes: Option<Vec<u8>> = None;
    while let Some(field) = mp.next_field().await.map_err(|e| bad(format!("multipart error: {e}")))? {
        let name = field.name().unwrap_or("").to_string();
        let fname = field.file_name().map(std::string::ToString::to_string);
        let data = field.bytes().await.map_err(|e| bad(format!("read error: {e}")))?;
        if name == "file" {
            if let Some(f) = fname {
                if !f.is_empty() {
                    filename = f;
                }
            }
            bytes = Some(data.to_vec());
        }
    }
    let bytes = bytes.ok_or_else(|| bad("missing 'file' field"))?;
    Ok((filename, bytes))
}

/// A shared response describing a sealed transition and its verification.
#[derive(Serialize)]
pub struct TransitionResponse {
    pub outcome: String,
    pub refusal_reason: Option<String>,
    pub summary_text: Option<String>,
    pub subject_content_id: String,
    pub resulting_state_id: Option<String>,
    pub matrix: String,
    pub all_checks_pass: bool,
    pub verification: VerifiedArtifact,
    pub win_base64: String,
    pub win_filename: String,
}

struct Roles {
    proposer_id: Uuid,
    authorizer: Authorizer,
    executor: FilesystemExecutor,
    recorder: Recorder,
}

impl Roles {
    /// The authorizer uses the app's PERSISTENT identity (so "who authorized" is
    /// stable and can be trusted); executor/recorder stay session-scoped. Returns
    /// the authorizer's self-signed identity assertion to seal into the artifact.
    fn persistent() -> (Self, IdentityAssertion) {
        let idn = identity::load_or_create_identity();
        let assertion = identity::identity_assertion(&idn);
        let roles = Self {
            proposer_id: Uuid::new_v4(),
            authorizer: Authorizer::new(idn.id, idn.key),
            executor: FilesystemExecutor::new(Uuid::new_v4(), KeyPair::generate()),
            recorder: Recorder::new(Uuid::new_v4(), KeyPair::generate()),
        };
        (roles, assertion)
    }

    fn keys(&self) -> TransitionPublicKeys {
        TransitionPublicKeys::new(
            self.recorder.public_key_hex(),
            self.authorizer.public_key_hex(),
            self.executor.public_key_hex(),
            None,
        )
    }
}

fn ai_model() -> canon_types::AiModelInfo {
    canon_types::AiModelInfo {
        model_name: "win-local-extractive-proposer".to_string(),
        model_version: "0.1".to_string(),
    }
}

/// The proposal preview shown on the human-review screen — computed WITHOUT
/// executing or sealing anything. Nothing is written until the user authorizes.
#[derive(Serialize)]
pub struct ProposalPreview {
    pub proposer: String,
    pub proposed_action: String,
    pub source_filename: String,
    pub subject_content_id: String,
    pub required_authority: String,
    pub external_actions: String,
    pub claims: Vec<String>,
    pub summary_text: String,
}

/// POST /transition/propose — preview only. No side effect, no seal.
pub async fn propose(mp: Multipart) -> ApiResult<ProposalPreview> {
    let (filename, source) = read_file_field(mp).await?;
    let subject = format!("sha256:{}", sha256_hex(&source));
    let summary = win_transition::proposers::propose_summary(&source);
    Ok(Json(ProposalPreview {
        proposer: "Local AI proposer (win-local-extractive-proposer v0.1)".to_string(),
        proposed_action: format!("Create {filename}.summary.txt from {filename}"),
        source_filename: filename,
        subject_content_id: subject,
        required_authority: "LocalWrite".to_string(),
        external_actions: "None".to_string(),
        claims: vec![
            "Summary derived from the identified source".to_string(),
            "No claim of independent factual validation".to_string(),
        ],
        summary_text: summary,
    }))
}

/// POST /transition/summarize
pub async fn summarize(mp: Multipart) -> ApiResult<TransitionResponse> {
    let (filename, source) = read_file_field(mp).await?;
    let subject = format!("sha256:{}", sha256_hex(&source));
    let summary = win_transition::proposers::propose_summary(&source);

    let (roles, assertion) = Roles::persistent();

    // The executor performs a real side effect: it writes to a private working
    // directory, then we package the result. The working file is not the user's
    // deliverable — the returned `.win` (and summary text) are.
    let work = std::env::temp_dir().join(format!("wise-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&work).map_err(|e| bad(format!("workspace error: {e}")))?;
    let target = work.join("Summary.txt");

    let grant = roles.authorizer.issue_grant(Authority::LocalWrite, &subject);
    let action = RequestedAction::new(
        "create_file",
        &subject,
        target.to_string_lossy(),
        Authority::LocalWrite,
    );
    let transition = govern(
        GovernRequest {
            proposer_identity_id: roles.proposer_id,
            proposer_model: Some(ai_model()),
            prior_state_id: Some(subject.clone()),
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: roles.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: summary.as_bytes(),
        },
        &roles.executor,
        &roles.recorder,
    );

    let win_filename = format!("{filename}.summary.win");
    let win_bytes = seal_win(
        &PortableProof::new(transition, roles.keys()).with_identities(vec![assertion]),
        &win_filename,
        summary.as_bytes(),
    );
    let _ = std::fs::remove_dir_all(&work);

    let v = verify_win_with_trust(&win_bytes, &identity::TrustStore::load())
        .map_err(|e| bad(format!("internal verification failed: {e}")))?;
    Ok(Json(build_response(
        v,
        &win_bytes,
        win_filename,
        subject,
        Some(summary),
    )))
}

/// POST /transition/publish — demonstrates the refusal boundary.
pub async fn publish(mp: Multipart) -> ApiResult<TransitionResponse> {
    let (filename, source) = read_file_field(mp).await?;
    let subject = format!("sha256:{}", sha256_hex(&source));
    let (roles, assertion) = Roles::persistent();

    // Grant covers only local writing; the action requests external publication.
    let grant = roles.authorizer.issue_grant(Authority::LocalWrite, &subject);
    let action = RequestedAction::new(
        "publish",
        &subject,
        "https://example.com/publish",
        Authority::ExternalPublish,
    );
    let transition = govern(
        GovernRequest {
            proposer_identity_id: roles.proposer_id,
            proposer_model: Some(ai_model()),
            prior_state_id: Some(subject.clone()),
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: roles.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"",
        },
        &roles.executor,
        &roles.recorder,
    );

    let win_filename = format!("{filename}.refusal.win");
    let win_bytes = seal_win(
        &PortableProof::new(transition, roles.keys()).with_identities(vec![assertion]),
        &win_filename,
        b"",
    );
    let v = verify_win_with_trust(&win_bytes, &identity::TrustStore::load())
        .map_err(|e| bad(format!("internal verification failed: {e}")))?;
    Ok(Json(build_response(v, &win_bytes, win_filename, subject, None)))
}

/// POST /transition/verify
#[derive(Serialize)]
pub struct VerifyResponse {
    pub ok: bool,
    pub all_checks_pass: bool,
    pub matrix: String,
    pub verification: Option<VerifiedArtifact>,
    pub error: Option<String>,
}

pub async fn verify(mp: Multipart) -> ApiResult<VerifyResponse> {
    let (_filename, bytes) = read_file_field(mp).await?;
    match verify_win_with_trust(&bytes, &identity::TrustStore::load()) {
        Ok(v) => {
            let matrix = render_verification_matrix(&v);
            let pass = v.all_checks_pass();
            Ok(Json(VerifyResponse {
                ok: true,
                all_checks_pass: pass,
                matrix,
                verification: Some(v),
                error: None,
            }))
        }
        Err(e) => Ok(Json(VerifyResponse {
            ok: false,
            all_checks_pass: false,
            matrix: String::new(),
            verification: None,
            error: Some(e.to_string()),
        })),
    }
}

fn build_response(
    v: VerifiedArtifact,
    win_bytes: &[u8],
    win_filename: String,
    subject: String,
    summary_text: Option<String>,
) -> TransitionResponse {
    let matrix = render_verification_matrix(&v);
    let outcome = if v.was_executed { "EXECUTED" } else { "REFUSED" }.to_string();
    let refusal_reason = v.refusal_reason.map(|r| format!("{r:?}"));
    let win_base64 = base64::engine::general_purpose::STANDARD.encode(win_bytes);
    TransitionResponse {
        outcome,
        refusal_reason,
        summary_text,
        subject_content_id: subject,
        resulting_state_id: v.resulting_state_id.clone(),
        matrix,
        all_checks_pass: v.all_checks_pass(),
        verification: v,
        win_base64,
        win_filename,
    }
}
