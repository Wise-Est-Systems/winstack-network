//! # win-transition — the governed state-transition engine
//!
//! This crate is the heart of the W.I.N. Unified Transition Protocol: it turns
//! a *proposed* digital change into an accountable record of what was proposed,
//! which authority permitted or refused it, what actually executed, and what
//! state resulted — all cryptographically sealed and independently verifiable.
//!
//! ## Roles are separated on purpose (protocol §18)
//!
//! In plain English: the thing that *asks* for a change is never the thing that
//! *allows* it, and the thing that *does* the change is never the thing that
//! *allowed* it. This crate enforces those boundaries even though every role can
//! run on one local machine:
//!
//! * **Proposer** — asks for a change (may be an AI). Holds no authority.
//! * **Authorizer** — issues a narrowly *scoped* [`AuthorizationGrant`].
//! * **Verifier** — checks the grant's signature (the [`govern`] entry point).
//! * **Executor** — performs the permitted side effect and returns a signed
//!   [`ExecutionReceipt`], or a signed [`Refusal`] if the action exceeds scope.
//! * **Recorder** — seals the whole [`Transition`] so it can travel and verify.
//!
//! Three invariants this crate guarantees and tests prove:
//!
//! 1. **AI is never the authority.** If the proposer identity equals the
//!    authorizer identity, the action is refused ([`RefusalCode::SelfApproval`]).
//! 2. **The executor never approves itself.** If the executor identity equals
//!    the authorizer identity, the action is refused.
//! 3. **A refusal never disappears.** Every refusal becomes a signed record
//!    inside the transition — with proof that no side effect occurred.
//!
//! Signing follows the exact discipline of the rest of the workspace: fixed-field
//! payload structs signed with [`wise_crypto`], no maps in signed payloads, so
//! the bytes reproduce on every machine and a sealed transition verifies offline.

use canon_types::{AiModelInfo, PolicyProof};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wise_crypto::{self as crypto, sha256_hex, KeyPair};

mod artifact;
pub use artifact::{
    open_win, render_verification_matrix, seal_win, verify_win, verify_win_with_trust,
    IntegrityStatus, PortableProof, TransitionPublicKeys, VerifiedArtifact, WinOpenError,
    ARTIFACT_FORMAT,
};

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Reference proposers. A proposer only *suggests* a change; it holds no
/// authority and never writes to authoritative state. These are the shared
/// implementations used by the CLI, the desktop API, and the demo so the
/// proposal text is identical across surfaces.
pub mod proposers {
    use wise_crypto::sha256_hex;

    /// Propose a summary for a source object, honestly adapting to its content.
    ///
    /// If the bytes are real text, it extracts a lead line and statistics. If
    /// they are **not** text (an image, PDF, archive, or other binary), it does
    /// **not** pretend to summarize unreadable bytes — it returns a truthful
    /// object description (detected type, size, content identity) and says a
    /// text summary is not applicable. Deterministic, offline, not an LLM.
    #[must_use]
    pub fn propose_summary(source: &[u8]) -> String {
        match as_text(source) {
            Some(text) => extractive_text_summary(&text),
            None => object_description(source),
        }
    }

    /// A deterministic extractive summary of text.
    #[must_use]
    pub fn extractive_text_summary(text: &str) -> String {
        let lead = text
            .split(['.', '\n'])
            .map(str::trim)
            .find(|s| !s.is_empty())
            .unwrap_or("");
        let words = text.split_whitespace().count();
        let lines = text.lines().count();
        format!(
            "SUMMARY (win-local-extractive-proposer v0.1)\n\nLead: {lead}.\n\n\
             Source statistics: {words} words across {lines} lines.\n\n\
             Note: derived mechanically from the identified source; not an \
             independent validation of its factual claims.\n"
        )
    }

    /// An honest description of a non-text object: type, size, identity.
    #[must_use]
    pub fn object_description(source: &[u8]) -> String {
        let kind = detect_media_type(source);
        let bytes = source.len();
        let hash = sha256_hex(source);
        format!(
            "OBJECT SUMMARY (win-local-proposer v0.1)\n\n\
             This is a {kind} ({bytes} bytes).\n\
             Content identity: sha256:{hash}.\n\n\
             A mechanical text summary is not applicable to this content type. \
             W.I.N. records the object's exact identity and type; it makes no \
             claim about what the content depicts.\n"
        )
    }

    /// Is this real text? Valid UTF-8, no NUL bytes, and mostly printable.
    fn as_text(source: &[u8]) -> Option<String> {
        if source.is_empty() {
            return Some(String::new());
        }
        let text = std::str::from_utf8(source).ok()?;
        if text.contains('\0') {
            return None;
        }
        let printable = text
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
            .count();
        let total = text.chars().count();
        if total > 0 && (printable as f64) / (total as f64) >= 0.85 {
            Some(text.to_string())
        } else {
            None
        }
    }

    /// Detect a coarse media type from magic bytes. Deliberately small and
    /// honest — it names only what it recognizes, else "binary file".
    fn detect_media_type(source: &[u8]) -> &'static str {
        let b = source;
        let starts = |sig: &[u8]| b.len() >= sig.len() && &b[..sig.len()] == sig;
        if starts(&[0xFF, 0xD8, 0xFF]) {
            "JPEG image"
        } else if starts(&[0x89, b'P', b'N', b'G']) {
            "PNG image"
        } else if starts(b"GIF8") {
            "GIF image"
        } else if starts(b"%PDF") {
            "PDF document"
        } else if starts(b"PK\x03\x04") {
            "ZIP archive"
        } else if starts(b"RIFF") && b.len() >= 12 && &b[8..12] == b"WEBP" {
            "WebP image"
        } else if starts(b"RIFF") && b.len() >= 12 && &b[8..12] == b"WAVE" {
            "WAV audio"
        } else if starts(b"\x1F\x8B") {
            "gzip archive"
        } else if starts(b"OggS") {
            "Ogg media"
        } else if starts(b"\x00\x00\x00") && b.len() >= 12 && &b[4..8] == b"ftyp" {
            "MP4 media"
        } else {
            "binary file"
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn text_gets_an_extractive_summary() {
            let s = propose_summary(b"UNIQUE9 opening clause.\nsecond line.\n");
            assert!(s.contains("Lead:"));
            assert!(s.contains("UNIQUE9"));
        }

        #[test]
        fn jpeg_bytes_get_an_honest_object_description_not_garbage() {
            // Minimal JPEG magic + JFIF, then binary noise.
            let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
            jpeg.extend_from_slice(b"JFIF\0");
            jpeg.extend_from_slice(&[0x01, 0x00, 0x00, 0xFF, 0xD9, 0x7F, 0x80]);
            let s = propose_summary(&jpeg);
            assert!(s.contains("JPEG image"), "must identify the type: {s}");
            assert!(s.contains("sha256:"), "must state content identity");
            assert!(!s.contains("Lead:"), "must not fake a text lead line");
            assert!(!s.contains("JFIF"), "must not leak raw header bytes");
        }

        #[test]
        fn png_and_pdf_detected() {
            assert!(propose_summary(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A]).contains("PNG image"));
            assert!(propose_summary(b"%PDF-1.7\n\x00\x01binary").contains("PDF document"));
        }

        #[test]
        fn unknown_binary_is_named_honestly() {
            let s = propose_summary(&[0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE]);
            assert!(s.contains("binary file"));
            assert!(!s.contains("Lead:"));
        }
    }
}

// ---------------------------------------------------------------------------
// Authority — the capability vocabulary
// ---------------------------------------------------------------------------

/// A narrowly scoped capability. An [`AuthorizationGrant`] carries exactly one.
///
/// Unit-only variants: each serializes to a fixed string (`"LocalWrite"`, …), so
/// it is byte-stable inside signed payloads. The [`authority_serialization_is_stable`]
/// test pins those strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Authority {
    /// Read a local object. No mutation.
    LocalRead,
    /// Create or write a local file. No network, no external effect.
    LocalWrite,
    /// Publish content to an external destination (network side effect).
    ExternalPublish,
    /// Send data over the network to a named recipient.
    NetworkSend,
}

impl Authority {
    /// Does a *granted* authority cover a *required* one?
    ///
    /// Strict exact-match: a `LocalWrite` grant covers only `LocalWrite` actions.
    /// We intentionally do **not** silently imply that write covers read, or that
    /// a broad grant swallows narrower ones — every capability must be granted
    /// explicitly. Truthful and un-surprising beats convenient.
    #[must_use]
    pub fn covers(self, required: Authority) -> bool {
        self == required
    }
}

// ---------------------------------------------------------------------------
// RequestedAction — what a proposer wants done
// ---------------------------------------------------------------------------

/// A concrete action a proposer requests. Carries the authority it *requires*;
/// the executor compares that against what was actually granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedAction {
    pub action_id: Uuid,
    /// e.g. `"create_file"`, `"publish"`.
    pub verb: String,
    /// Content identity (sha256 hex) of the subject this action operates on.
    pub subject_content_id: String,
    /// Destination — a local path for writes, or an external target for publish.
    pub target: String,
    /// The authority this action needs to be permitted.
    pub required_authority: Authority,
}

impl RequestedAction {
    #[must_use]
    pub fn new(
        verb: impl Into<String>,
        subject_content_id: impl Into<String>,
        target: impl Into<String>,
        required_authority: Authority,
    ) -> Self {
        Self {
            action_id: Uuid::new_v4(),
            verb: verb.into(),
            subject_content_id: subject_content_id.into(),
            target: target.into(),
            required_authority,
        }
    }
}

// ---------------------------------------------------------------------------
// AuthorizationGrant — a signed, scoped permission
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("authorization signature invalid")]
    SignatureInvalid,
}

/// A signed grant of exactly one [`Authority`], bound to one subject.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationGrant {
    pub grant_id: Uuid,
    pub granted_authority: Authority,
    /// The exact subject (sha256 hex) this grant applies to. Binding the grant to
    /// the subject stops it being replayed against a different object.
    pub subject_content_id: String,
    pub authorizer_identity_id: Uuid,
    pub granted_at: String,
    pub signature: String,
}

#[derive(Serialize)]
struct GrantPayload<'a> {
    grant_id: &'a Uuid,
    granted_authority: &'a Authority,
    subject_content_id: &'a str,
    authorizer_identity_id: &'a Uuid,
    granted_at: &'a str,
}

/// The authorizer role: holds the key that grants scoped permissions.
pub struct Authorizer {
    identity_id: Uuid,
    key: KeyPair,
}

impl Authorizer {
    #[must_use]
    pub fn new(identity_id: Uuid, key: KeyPair) -> Self {
        Self { identity_id, key }
    }

    #[must_use]
    pub fn identity_id(&self) -> Uuid {
        self.identity_id
    }

    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.key.public_key_hex()
    }

    /// Issue a scoped grant for a specific subject.
    #[must_use]
    pub fn issue_grant(
        &self,
        granted_authority: Authority,
        subject_content_id: &str,
    ) -> AuthorizationGrant {
        let grant_id = Uuid::new_v4();
        let granted_at = now_rfc3339();
        let payload = GrantPayload {
            grant_id: &grant_id,
            granted_authority: &granted_authority,
            subject_content_id,
            authorizer_identity_id: &self.identity_id,
            granted_at: &granted_at,
        };
        let signature = self.key.sign_json(&payload);
        AuthorizationGrant {
            grant_id,
            granted_authority,
            subject_content_id: subject_content_id.to_string(),
            authorizer_identity_id: self.identity_id,
            granted_at,
            signature,
        }
    }
}

/// Verify a grant's signature against the authorizer's public key.
///
/// This is the **verifier** role — it proves the grant is authentic and
/// untampered. It says nothing about whether the grant's scope covers a given
/// action; that check lives in the executor.
pub fn verify_authorization(
    grant: &AuthorizationGrant,
    authorizer_public_key: &str,
) -> Result<(), AuthzError> {
    let payload = GrantPayload {
        grant_id: &grant.grant_id,
        granted_authority: &grant.granted_authority,
        subject_content_id: &grant.subject_content_id,
        authorizer_identity_id: &grant.authorizer_identity_id,
        granted_at: &grant.granted_at,
    };
    crypto::verify_json_signature(authorizer_public_key, &payload, &grant.signature)
        .map_err(|_| AuthzError::SignatureInvalid)
}

// ---------------------------------------------------------------------------
// Identity — the honest identity ladder
// ---------------------------------------------------------------------------
//
// A signing key proves *custody* (this key signed), never *ownership* (who holds
// the key). Identity here is a ladder, and every artifact declares — and every
// verifier reports — exactly which rung it reached. We never claim more than the
// evidence supports.
//
//   NotEstablished  — a throwaway key; no claim, not trusted.
//   ConsistentActor — a persistent key: the same signer across history, no name.
//   SelfAsserted    — the key CLAIMS a name/context. A claim, not proof.
//   Trusted         — the party verifying chose to trust this key (web of trust).

/// Whether a signing key is a throwaway or a stable, reused identity. This is a
/// self-claim by the signer about its own key management.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Persistence {
    Ephemeral,
    Persistent,
}

/// A self-signed claim a key makes about itself. The signature proves the key
/// *makes* this claim — not that the claim is true.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityAssertion {
    pub key_public_hex: String,
    pub claimed_name: Option<String>,
    pub claimed_context: Option<String>,
    pub persistence: Persistence,
    pub asserted_at: String,
    pub self_signature: String,
}

#[derive(Serialize)]
struct IdentityPayload<'a> {
    key_public_hex: &'a str,
    claimed_name: &'a Option<String>,
    claimed_context: &'a Option<String>,
    persistence: &'a Persistence,
    asserted_at: &'a str,
}

/// Build a self-signed [`IdentityAssertion`] for `key`.
#[must_use]
pub fn assert_identity(
    key: &KeyPair,
    claimed_name: Option<String>,
    claimed_context: Option<String>,
    persistence: Persistence,
) -> IdentityAssertion {
    let key_public_hex = key.public_key_hex();
    let asserted_at = now_rfc3339();
    let payload = IdentityPayload {
        key_public_hex: &key_public_hex,
        claimed_name: &claimed_name,
        claimed_context: &claimed_context,
        persistence: &persistence,
        asserted_at: &asserted_at,
    };
    let self_signature = key.sign_json(&payload);
    IdentityAssertion {
        key_public_hex,
        claimed_name,
        claimed_context,
        persistence,
        asserted_at,
        self_signature,
    }
}

/// Verify that an assertion is genuinely self-signed by the key it names.
#[must_use]
pub fn verify_identity_assertion(a: &IdentityAssertion) -> bool {
    let payload = IdentityPayload {
        key_public_hex: &a.key_public_hex,
        claimed_name: &a.claimed_name,
        claimed_context: &a.claimed_context,
        persistence: &a.persistence,
        asserted_at: &a.asserted_at,
    };
    crypto::verify_json_signature(&a.key_public_hex, &payload, &a.self_signature).is_ok()
}

/// The rung of the identity ladder a key reached, from a verifier's point of view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    NotEstablished,
    ConsistentActor,
    SelfAsserted { claimed: String },
    Trusted { label: String },
}

impl IdentityStatus {
    /// A one-line, honest rendering for the verification matrix.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            IdentityStatus::NotEstablished => "NOT ESTABLISHED".to_string(),
            IdentityStatus::ConsistentActor => {
                "CONSISTENT ACTOR (persistent key, no name)".to_string()
            }
            IdentityStatus::SelfAsserted { claimed } => {
                format!("CLAIMED \"{claimed}\" — SELF-ASSERTED, NOT VERIFIED")
            }
            IdentityStatus::Trusted { label } => {
                format!("TRUSTED \"{label}\" (via your trust list)")
            }
        }
    }
}

/// A recipient's view of which keys they trust. Local-first web of trust: the
/// person verifying decides whom to trust; there is no central authority.
pub trait TrustLookup {
    fn is_trusted(&self, key_hex: &str) -> bool;
    fn label_for(&self, key_hex: &str) -> Option<String>;
}

/// The default: trust no one. Yields at most `SelfAsserted` / `ConsistentActor`.
pub struct NoTrust;

impl TrustLookup for NoTrust {
    fn is_trusted(&self, _key_hex: &str) -> bool {
        false
    }
    fn label_for(&self, _key_hex: &str) -> Option<String> {
        None
    }
}

/// Resolve the highest honest identity rung for `key_hex`, given the assertions
/// carried in the artifact and the recipient's trust list.
#[must_use]
pub fn resolve_identity(
    key_hex: &str,
    identities: &[IdentityAssertion],
    trust: &dyn TrustLookup,
) -> IdentityStatus {
    if trust.is_trusted(key_hex) {
        return IdentityStatus::Trusted {
            label: trust
                .label_for(key_hex)
                .unwrap_or_else(|| "trusted key".to_string()),
        };
    }
    // An assertion only counts if it is genuinely self-signed by this key.
    let assertion = identities
        .iter()
        .find(|a| a.key_public_hex == key_hex && verify_identity_assertion(a));
    match assertion {
        Some(a) => {
            if let Some(name) = &a.claimed_name {
                IdentityStatus::SelfAsserted {
                    claimed: name.clone(),
                }
            } else if a.persistence == Persistence::Persistent {
                IdentityStatus::ConsistentActor
            } else {
                IdentityStatus::NotEstablished
            }
        }
        None => IdentityStatus::NotEstablished,
    }
}

// ---------------------------------------------------------------------------
// Execution receipt & refusal — what actually happened
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecResult {
    Completed,
    Failed,
    Partial,
}

/// Signed record of an executed side effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    pub receipt_id: Uuid,
    pub requested_verb: String,
    pub actual_verb: String,
    pub destination: String,
    /// sha256 hex of the produced output, when a file was written.
    pub output_content_id: Option<String>,
    pub result: ExecResult,
    pub side_effect_occurred: bool,
    pub error: Option<String>,
    pub executor_identity_id: Uuid,
    pub executed_at: String,
    pub signature: String,
}

#[derive(Serialize)]
struct ReceiptPayload<'a> {
    receipt_id: &'a Uuid,
    requested_verb: &'a str,
    actual_verb: &'a str,
    destination: &'a str,
    output_content_id: &'a Option<String>,
    result: &'a ExecResult,
    side_effect_occurred: bool,
    error: &'a Option<String>,
    executor_identity_id: &'a Uuid,
    executed_at: &'a str,
}

/// Why an action was refused. Every variant means: **no side effect happened.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefusalCode {
    /// The action needed an authority the grant did not cover.
    AuthorizationScopeExceeded,
    /// The grant's signature did not verify.
    AuthorizationInvalid,
    /// Proposer or executor tried to act as its own authorizer.
    SelfApproval,
    /// A policy proof was required and did not evaluate to Permit.
    PolicyDenied,
    /// The grant was issued for a different subject than the action targets.
    SubjectMismatch,
    /// The executor does not implement the requested verb.
    UnsupportedAction,
}

/// Signed record of a refusal. Proof that a prohibited effect did **not** occur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refusal {
    pub refusal_id: Uuid,
    pub requested_verb: String,
    pub requested_authority: Authority,
    pub permitted_authority: Authority,
    pub reason: RefusalCode,
    pub side_effect_occurred: bool,
    pub recorded: bool,
    pub refused_by_identity_id: Uuid,
    pub refused_at: String,
    pub signature: String,
}

#[derive(Serialize)]
struct RefusalPayload<'a> {
    refusal_id: &'a Uuid,
    requested_verb: &'a str,
    requested_authority: &'a Authority,
    permitted_authority: &'a Authority,
    reason: &'a RefusalCode,
    side_effect_occurred: bool,
    recorded: bool,
    refused_by_identity_id: &'a Uuid,
    refused_at: &'a str,
}

/// The result of asking an executor to settle an action: it either executed
/// (with a receipt) or refused (with a sealed refusal). Never both, never
/// neither.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionOutcome {
    Executed(ExecutionReceipt),
    Refused(Refusal),
}

// ---------------------------------------------------------------------------
// Executor — performs the permitted effect, or refuses
// ---------------------------------------------------------------------------

/// An executor performs a narrowly bounded kind of side effect. It signs its own
/// receipts and refusals, and it **independently** re-checks scope (defense in
/// depth): even if the orchestrator were bypassed, an out-of-scope action is
/// refused here.
pub trait Executor {
    fn identity_id(&self) -> Uuid;
    fn public_key_hex(&self) -> String;
    /// The single authority this executor is willing to act under.
    fn bound_authority(&self) -> Authority;
    /// Settle an action. `precheck` carries any governance-level refusal decided
    /// upstream (bad signature, self-approval, policy denial); if it is `Err`,
    /// the executor records that refusal and performs no side effect.
    fn settle(
        &self,
        action: &RequestedAction,
        grant: &AuthorizationGrant,
        content: &[u8],
        precheck: Result<(), RefusalCode>,
    ) -> TransitionOutcome;
}

/// Helper: build and sign a [`Refusal`] from an executor identity/key.
fn sign_refusal(
    identity_id: Uuid,
    key: &KeyPair,
    action: &RequestedAction,
    permitted_authority: Authority,
    reason: RefusalCode,
) -> Refusal {
    let refusal_id = Uuid::new_v4();
    let refused_at = now_rfc3339();
    let payload = RefusalPayload {
        refusal_id: &refusal_id,
        requested_verb: &action.verb,
        requested_authority: &action.required_authority,
        permitted_authority: &permitted_authority,
        reason: &reason,
        side_effect_occurred: false,
        recorded: true,
        refused_by_identity_id: &identity_id,
        refused_at: &refused_at,
    };
    let signature = key.sign_json(&payload);
    Refusal {
        refusal_id,
        requested_verb: action.verb.clone(),
        requested_authority: action.required_authority,
        permitted_authority,
        reason,
        side_effect_occurred: false,
        recorded: true,
        refused_by_identity_id: identity_id,
        refused_at,
        signature,
    }
}

/// Helper: build and sign an [`ExecutionReceipt`].
#[allow(clippy::too_many_arguments)]
fn sign_receipt(
    identity_id: Uuid,
    key: &KeyPair,
    requested_verb: &str,
    actual_verb: &str,
    destination: &str,
    output_content_id: Option<String>,
    result: ExecResult,
    side_effect_occurred: bool,
    error: Option<String>,
) -> ExecutionReceipt {
    let receipt_id = Uuid::new_v4();
    let executed_at = now_rfc3339();
    let payload = ReceiptPayload {
        receipt_id: &receipt_id,
        requested_verb,
        actual_verb,
        destination,
        output_content_id: &output_content_id,
        result: &result,
        side_effect_occurred,
        error: &error,
        executor_identity_id: &identity_id,
        executed_at: &executed_at,
    };
    let signature = key.sign_json(&payload);
    ExecutionReceipt {
        receipt_id,
        requested_verb: requested_verb.to_string(),
        actual_verb: actual_verb.to_string(),
        destination: destination.to_string(),
        output_content_id,
        result,
        side_effect_occurred,
        error,
        executor_identity_id: identity_id,
        executed_at,
        signature,
    }
}

/// A bounded executor that creates local files and nothing else.
///
/// It acts only under [`Authority::LocalWrite`] and only implements the
/// `"create_file"` verb. Any request for external publication, network send, or
/// an unsupported verb is refused with no side effect.
pub struct FilesystemExecutor {
    identity_id: Uuid,
    key: KeyPair,
}

impl FilesystemExecutor {
    #[must_use]
    pub fn new(identity_id: Uuid, key: KeyPair) -> Self {
        Self { identity_id, key }
    }
}

impl Executor for FilesystemExecutor {
    fn identity_id(&self) -> Uuid {
        self.identity_id
    }

    fn public_key_hex(&self) -> String {
        self.key.public_key_hex()
    }

    fn bound_authority(&self) -> Authority {
        Authority::LocalWrite
    }

    fn settle(
        &self,
        action: &RequestedAction,
        grant: &AuthorizationGrant,
        content: &[u8],
        precheck: Result<(), RefusalCode>,
    ) -> TransitionOutcome {
        let refuse = |reason: RefusalCode| {
            TransitionOutcome::Refused(sign_refusal(
                self.identity_id,
                &self.key,
                action,
                grant.granted_authority,
                reason,
            ))
        };

        // 1. Honor any governance-level refusal decided upstream.
        if let Err(reason) = precheck {
            return refuse(reason);
        }
        // 2. The grant must be for this exact subject.
        if action.subject_content_id != grant.subject_content_id {
            return refuse(RefusalCode::SubjectMismatch);
        }
        // 3. The granted authority must cover what the action requires.
        if !grant.granted_authority.covers(action.required_authority) {
            return refuse(RefusalCode::AuthorizationScopeExceeded);
        }
        // 4. This executor only acts under its bound authority.
        if action.required_authority != self.bound_authority() {
            return refuse(RefusalCode::AuthorizationScopeExceeded);
        }
        // 5. This executor only implements one verb.
        if action.verb != "create_file" {
            return refuse(RefusalCode::UnsupportedAction);
        }

        // Permitted — perform the side effect.
        match std::fs::write(&action.target, content) {
            Ok(()) => {
                let cid = format!("sha256:{}", sha256_hex(content));
                TransitionOutcome::Executed(sign_receipt(
                    self.identity_id,
                    &self.key,
                    &action.verb,
                    "create_file",
                    &action.target,
                    Some(cid),
                    ExecResult::Completed,
                    true,
                    None,
                ))
            }
            Err(e) => TransitionOutcome::Executed(sign_receipt(
                self.identity_id,
                &self.key,
                &action.verb,
                "create_file",
                &action.target,
                None,
                ExecResult::Failed,
                false,
                Some(e.to_string()),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Recorder & Transition — sealing the whole record
// ---------------------------------------------------------------------------

/// The recorder role: seals the finished transition with its signature.
pub struct Recorder {
    identity_id: Uuid,
    key: KeyPair,
}

impl Recorder {
    #[must_use]
    pub fn new(identity_id: Uuid, key: KeyPair) -> Self {
        Self { identity_id, key }
    }

    #[must_use]
    pub fn identity_id(&self) -> Uuid {
        self.identity_id
    }

    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.key.public_key_hex()
    }
}

pub const PROTOCOL: &str = "WIN-UTP/0.1";

/// The central object of W.I.N.: a signed, self-describing record of one
/// governed change — proposal, authority, outcome, and resulting state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub protocol: String,
    pub transition_id: Uuid,
    pub prior_state_id: Option<String>,
    pub subject_content_id: String,
    pub proposer_identity_id: Uuid,
    pub proposer_model: Option<AiModelInfo>,
    pub action: RequestedAction,
    pub policy: Option<PolicyProof>,
    pub authorization: AuthorizationGrant,
    pub outcome: TransitionOutcome,
    pub resulting_state_id: Option<String>,
    pub recorder_identity_id: Uuid,
    pub recorded_at: String,
    pub signature: String,
}

#[derive(Serialize)]
struct TransitionPayload<'a> {
    protocol: &'a str,
    transition_id: &'a Uuid,
    prior_state_id: &'a Option<String>,
    subject_content_id: &'a str,
    proposer_identity_id: &'a Uuid,
    proposer_model: &'a Option<AiModelInfo>,
    action: &'a RequestedAction,
    policy: &'a Option<PolicyProof>,
    authorization: &'a AuthorizationGrant,
    outcome: &'a TransitionOutcome,
    resulting_state_id: &'a Option<String>,
    recorder_identity_id: &'a Uuid,
    recorded_at: &'a str,
}

impl Transition {
    #[must_use]
    pub fn was_executed(&self) -> bool {
        matches!(self.outcome, TransitionOutcome::Executed(_))
    }

    #[must_use]
    pub fn was_refused(&self) -> bool {
        matches!(self.outcome, TransitionOutcome::Refused(_))
    }
}

// ---------------------------------------------------------------------------
// govern — the orchestrator that enforces the lifecycle & separations
// ---------------------------------------------------------------------------

/// Everything needed to run one governed transition. The proposer supplies the
/// action and the content; the authorizer's grant and public key come from a
/// *different* party; the policy proof (if any) from a third.
pub struct GovernRequest<'a> {
    pub proposer_identity_id: Uuid,
    pub proposer_model: Option<AiModelInfo>,
    pub prior_state_id: Option<String>,
    pub subject_content_id: String,
    pub action: RequestedAction,
    pub grant: AuthorizationGrant,
    pub authorizer_public_key: String,
    pub policy: Option<PolicyProof>,
    pub policy_evaluator_public_key: Option<String>,
    pub content: &'a [u8],
}

/// Run one governed transition end to end and return a sealed [`Transition`].
///
/// Governance pre-checks (verifier + separation + policy) happen here; the
/// executor performs or refuses the side effect; the recorder seals the record.
/// **This function never itself writes a file** — only the executor can, and
/// only when every gate passes.
pub fn govern<E: Executor>(req: GovernRequest<'_>, executor: &E, recorder: &Recorder) -> Transition {
    // --- Verifier role: is the grant authentic? ---
    let mut precheck: Result<(), RefusalCode> = Ok(());
    if verify_authorization(&req.grant, &req.authorizer_public_key).is_err() {
        precheck = Err(RefusalCode::AuthorizationInvalid);
    }
    // --- Separation: AI/proposer is never the authority. ---
    if precheck.is_ok() && req.proposer_identity_id == req.grant.authorizer_identity_id {
        precheck = Err(RefusalCode::SelfApproval);
    }
    // --- Separation: the executor never approves itself. ---
    if precheck.is_ok() && executor.identity_id() == req.grant.authorizer_identity_id {
        precheck = Err(RefusalCode::SelfApproval);
    }
    // --- Policy evaluation (if a proof is required). ---
    if precheck.is_ok() {
        if let Some(policy) = &req.policy {
            let pk = req.policy_evaluator_public_key.as_deref().unwrap_or("");
            if policy_core::verify_policy_proof(policy, pk, policy_core::CURRENT_POLICY_VERSION)
                .is_err()
            {
                precheck = Err(RefusalCode::PolicyDenied);
            }
        }
    }

    // --- Executor role: perform or refuse. ---
    let outcome = executor.settle(&req.action, &req.grant, req.content, precheck);

    let resulting_state_id = match &outcome {
        TransitionOutcome::Executed(r) => r.output_content_id.clone(),
        TransitionOutcome::Refused(_) => None,
    };

    // --- Recorder role: seal. ---
    let transition_id = Uuid::new_v4();
    let recorded_at = now_rfc3339();
    let payload = TransitionPayload {
        protocol: PROTOCOL,
        transition_id: &transition_id,
        prior_state_id: &req.prior_state_id,
        subject_content_id: &req.subject_content_id,
        proposer_identity_id: &req.proposer_identity_id,
        proposer_model: &req.proposer_model,
        action: &req.action,
        policy: &req.policy,
        authorization: &req.grant,
        outcome: &outcome,
        resulting_state_id: &resulting_state_id,
        recorder_identity_id: &recorder.identity_id,
        recorded_at: &recorded_at,
    };
    let signature = recorder.key.sign_json(&payload);

    Transition {
        protocol: PROTOCOL.to_string(),
        transition_id,
        prior_state_id: req.prior_state_id,
        subject_content_id: req.subject_content_id,
        proposer_identity_id: req.proposer_identity_id,
        proposer_model: req.proposer_model,
        action: req.action,
        policy: req.policy,
        authorization: req.grant,
        outcome,
        resulting_state_id,
        recorder_identity_id: recorder.identity_id,
        recorded_at,
        signature,
    }
}

// ---------------------------------------------------------------------------
// Independent verification of a sealed transition
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error("recorder signature invalid")]
    RecorderSignatureInvalid,
    #[error("authorization signature invalid")]
    AuthorizationSignatureInvalid,
    #[error("execution receipt signature invalid")]
    ReceiptSignatureInvalid,
    #[error("refusal signature invalid")]
    RefusalSignatureInvalid,
    #[error("policy proof signature invalid")]
    PolicySignatureInvalid,
    #[error("internal inconsistency: {0}")]
    Inconsistent(String),
}

/// Public keys needed to independently verify a [`Transition`].
pub struct TransitionKeys<'a> {
    pub recorder_pk: &'a str,
    pub authorizer_pk: &'a str,
    pub executor_pk: &'a str,
    pub policy_evaluator_pk: Option<&'a str>,
}

/// Independently verify a sealed transition without trusting the runtime that
/// produced it. Checks every embedded signature and the internal consistency
/// invariants (subject binding; a refusal proves no side effect; an execution's
/// output matches the recorded resulting state).
pub fn verify_transition(t: &Transition, keys: &TransitionKeys<'_>) -> Result<(), TransitionError> {
    // Recorder signature over the whole record.
    let payload = TransitionPayload {
        protocol: &t.protocol,
        transition_id: &t.transition_id,
        prior_state_id: &t.prior_state_id,
        subject_content_id: &t.subject_content_id,
        proposer_identity_id: &t.proposer_identity_id,
        proposer_model: &t.proposer_model,
        action: &t.action,
        policy: &t.policy,
        authorization: &t.authorization,
        outcome: &t.outcome,
        resulting_state_id: &t.resulting_state_id,
        recorder_identity_id: &t.recorder_identity_id,
        recorded_at: &t.recorded_at,
    };
    crypto::verify_json_signature(keys.recorder_pk, &payload, &t.signature)
        .map_err(|_| TransitionError::RecorderSignatureInvalid)?;

    // Authorization signature.
    verify_authorization(&t.authorization, keys.authorizer_pk)
        .map_err(|_| TransitionError::AuthorizationSignatureInvalid)?;

    // Subject binding.
    if t.action.subject_content_id != t.subject_content_id {
        return Err(TransitionError::Inconsistent(
            "action subject does not match transition subject".into(),
        ));
    }

    // Policy proof, if present. A stored policy proof is only required to be a
    // valid Permit when the transition actually EXECUTED — that is what would
    // have authorized the side effect. On a REFUSED transition the proof may
    // legitimately be a Deny (the very reason for refusal), so we do not require
    // Permit there; the recorder signature above already guarantees the stored
    // proof was not tampered with.
    if let (Some(policy), TransitionOutcome::Executed(_)) = (&t.policy, &t.outcome) {
        let pk = keys.policy_evaluator_pk.ok_or_else(|| {
            TransitionError::Inconsistent("policy proof present but no evaluator key".into())
        })?;
        policy_core::verify_policy_proof(policy, pk, policy_core::CURRENT_POLICY_VERSION)
            .map_err(|_| TransitionError::PolicySignatureInvalid)?;
    }

    // Outcome signature + consistency.
    match &t.outcome {
        TransitionOutcome::Executed(r) => {
            let payload = ReceiptPayload {
                receipt_id: &r.receipt_id,
                requested_verb: &r.requested_verb,
                actual_verb: &r.actual_verb,
                destination: &r.destination,
                output_content_id: &r.output_content_id,
                result: &r.result,
                side_effect_occurred: r.side_effect_occurred,
                error: &r.error,
                executor_identity_id: &r.executor_identity_id,
                executed_at: &r.executed_at,
            };
            crypto::verify_json_signature(keys.executor_pk, &payload, &r.signature)
                .map_err(|_| TransitionError::ReceiptSignatureInvalid)?;
            if r.result == ExecResult::Completed && t.resulting_state_id != r.output_content_id {
                return Err(TransitionError::Inconsistent(
                    "resulting state does not match execution output".into(),
                ));
            }
        }
        TransitionOutcome::Refused(rf) => {
            let payload = RefusalPayload {
                refusal_id: &rf.refusal_id,
                requested_verb: &rf.requested_verb,
                requested_authority: &rf.requested_authority,
                permitted_authority: &rf.permitted_authority,
                reason: &rf.reason,
                side_effect_occurred: rf.side_effect_occurred,
                recorded: rf.recorded,
                refused_by_identity_id: &rf.refused_by_identity_id,
                refused_at: &rf.refused_at,
            };
            crypto::verify_json_signature(keys.executor_pk, &payload, &rf.signature)
                .map_err(|_| TransitionError::RefusalSignatureInvalid)?;
            if rf.side_effect_occurred {
                return Err(TransitionError::Inconsistent(
                    "a refusal must prove no side effect occurred".into(),
                ));
            }
            if t.resulting_state_id.is_some() {
                return Err(TransitionError::Inconsistent(
                    "a refused transition must have no resulting state".into(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct World {
        proposer_id: Uuid,
        authorizer: Authorizer,
        executor: FilesystemExecutor,
        recorder: Recorder,
    }

    fn world() -> World {
        World {
            proposer_id: Uuid::new_v4(),
            authorizer: Authorizer::new(Uuid::new_v4(), KeyPair::generate()),
            executor: FilesystemExecutor::new(Uuid::new_v4(), KeyPair::generate()),
            recorder: Recorder::new(Uuid::new_v4(), KeyPair::generate()),
        }
    }

    fn keys<'a>(w: &'a World, policy_pk: Option<&'a str>) -> (String, String, String, Option<String>) {
        (
            w.recorder.public_key_hex(),
            w.authorizer.public_key_hex(),
            w.executor.public_key_hex(),
            policy_pk.map(std::string::ToString::to_string),
        )
    }

    #[test]
    fn authority_serialization_is_stable() {
        // These exact strings ride inside signed payloads. If they ever change,
        // every prior signature breaks — so pin them.
        assert_eq!(serde_json::to_string(&Authority::LocalRead).unwrap(), "\"LocalRead\"");
        assert_eq!(serde_json::to_string(&Authority::LocalWrite).unwrap(), "\"LocalWrite\"");
        assert_eq!(serde_json::to_string(&Authority::ExternalPublish).unwrap(), "\"ExternalPublish\"");
        assert_eq!(serde_json::to_string(&Authority::NetworkSend).unwrap(), "\"NetworkSend\"");
    }

    #[test]
    fn accepted_local_write_produces_file_and_verifies() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("Summary.txt");
        let content = b"a governed summary of the source document";
        let subject = format!("sha256:{}", sha256_hex(b"the source contract"));

        let grant = w.authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action = RequestedAction::new(
            "create_file",
            &subject,
            target.to_str().unwrap(),
            Authority::LocalWrite,
        );

        let req = GovernRequest {
            proposer_identity_id: w.proposer_id,
            proposer_model: Some(AiModelInfo {
                model_name: "local-proposer".into(),
                model_version: "0.1".into(),
            }),
            prior_state_id: Some(subject.clone()),
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content,
        };

        let t = govern(req, &w.executor, &w.recorder);

        assert!(t.was_executed(), "expected an executed transition");
        assert!(target.exists(), "the authorized file must exist on disk");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            content,
            "file content must match what was executed"
        );
        let expected_cid = format!("sha256:{}", sha256_hex(content));
        assert_eq!(t.resulting_state_id.as_deref(), Some(expected_cid.as_str()));

        let (r, a, e, p) = keys(&w, None);
        let tkeys = TransitionKeys {
            recorder_pk: &r,
            authorizer_pk: &a,
            executor_pk: &e,
            policy_evaluator_pk: p.as_deref(),
        };
        assert!(verify_transition(&t, &tkeys).is_ok(), "sealed transition must verify");
    }

    #[test]
    fn publish_under_local_write_is_refused_with_no_side_effect() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        // A target we will assert never gets created.
        let forbidden = dir.path().join("published.txt");
        let subject = format!("sha256:{}", sha256_hex(b"the source contract"));

        // The authority granted is ONLY local write.
        let grant = w.authorizer.issue_grant(Authority::LocalWrite, &subject);
        // But the action requests external publication.
        let action = RequestedAction::new(
            "publish",
            &subject,
            forbidden.to_str().unwrap(),
            Authority::ExternalPublish,
        );

        let req = GovernRequest {
            proposer_identity_id: w.proposer_id,
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"should never be written",
        };

        let t = govern(req, &w.executor, &w.recorder);

        assert!(t.was_refused(), "publish must be refused under a local-write grant");
        assert!(!forbidden.exists(), "no external side effect: nothing may be written");
        assert!(t.resulting_state_id.is_none());
        match &t.outcome {
            TransitionOutcome::Refused(rf) => {
                assert_eq!(rf.reason, RefusalCode::AuthorizationScopeExceeded);
                assert!(!rf.side_effect_occurred);
                assert!(rf.recorded, "a refusal must be recorded, never discarded");
            }
            TransitionOutcome::Executed(_) => panic!("must not execute"),
        }

        let (r, a, e, p) = keys(&w, None);
        let tkeys = TransitionKeys {
            recorder_pk: &r,
            authorizer_pk: &a,
            executor_pk: &e,
            policy_evaluator_pk: p.as_deref(),
        };
        assert!(verify_transition(&t, &tkeys).is_ok(), "a refusal record must itself verify");
    }

    #[test]
    fn executor_cannot_be_its_own_authorizer() {
        // Build an executor whose identity IS the authorizer's identity.
        let auth_key = KeyPair::generate();
        let auth_id = Uuid::new_v4();
        let authorizer = Authorizer::new(auth_id, auth_key);
        // Executor shares the authorizer's identity id — self-approval attempt.
        let executor = FilesystemExecutor::new(auth_id, KeyPair::generate());
        let recorder = Recorder::new(Uuid::new_v4(), KeyPair::generate());

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("self.txt");
        let subject = format!("sha256:{}", sha256_hex(b"x"));
        let grant = authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action =
            RequestedAction::new("create_file", &subject, target.to_str().unwrap(), Authority::LocalWrite);

        let req = GovernRequest {
            proposer_identity_id: Uuid::new_v4(),
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"nope",
        };
        let t = govern(req, &executor, &recorder);
        assert!(t.was_refused());
        assert!(!target.exists());
        match t.outcome {
            TransitionOutcome::Refused(rf) => assert_eq!(rf.reason, RefusalCode::SelfApproval),
            TransitionOutcome::Executed(_) => panic!("self-approval must be refused"),
        }
    }

    #[test]
    fn proposer_cannot_be_the_authorizer() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("p.txt");
        let subject = format!("sha256:{}", sha256_hex(b"y"));
        let grant = w.authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action =
            RequestedAction::new("create_file", &subject, target.to_str().unwrap(), Authority::LocalWrite);
        let req = GovernRequest {
            // proposer IS the authorizer — AI acting as its own authority.
            proposer_identity_id: w.authorizer.identity_id(),
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"nope",
        };
        let t = govern(req, &w.executor, &w.recorder);
        assert!(t.was_refused());
        assert!(!target.exists());
    }

    #[test]
    fn forged_authorization_is_refused() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("forged.txt");
        let subject = format!("sha256:{}", sha256_hex(b"z"));
        let mut grant = w.authorizer.issue_grant(Authority::LocalWrite, &subject);
        // Tamper: flip the signature.
        grant.signature = "00".repeat(64);
        let action =
            RequestedAction::new("create_file", &subject, target.to_str().unwrap(), Authority::LocalWrite);
        let req = GovernRequest {
            proposer_identity_id: w.proposer_id,
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"nope",
        };
        let t = govern(req, &w.executor, &w.recorder);
        assert!(t.was_refused());
        assert!(!target.exists());
        match t.outcome {
            TransitionOutcome::Refused(rf) => assert_eq!(rf.reason, RefusalCode::AuthorizationInvalid),
            TransitionOutcome::Executed(_) => panic!("forged grant must be refused"),
        }
    }

    #[test]
    fn policy_permit_is_honored_and_recorded() {
        let w = world();
        let policy_key = KeyPair::generate();
        let policy_pk = policy_key.public_key_hex();
        let evaluator = policy_core::PolicyEvaluator::new(Uuid::new_v4(), policy_key);

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("Summary.txt");
        let content = b"summary";
        let subject = format!("sha256:{}", sha256_hex(b"src"));
        let ctx = sha256_hex(b"context");
        let permit = evaluator.permit(&ctx);

        let grant = w.authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action =
            RequestedAction::new("create_file", &subject, target.to_str().unwrap(), Authority::LocalWrite);
        let req = GovernRequest {
            proposer_identity_id: w.proposer_id,
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: Some(permit),
            policy_evaluator_public_key: Some(policy_pk.clone()),
            content,
        };
        let t = govern(req, &w.executor, &w.recorder);
        assert!(t.was_executed());
        assert!(target.exists());
        assert!(t.policy.is_some(), "the policy proof must be recorded in the transition");

        let tkeys = TransitionKeys {
            recorder_pk: &w.recorder.public_key_hex(),
            authorizer_pk: &w.authorizer.public_key_hex(),
            executor_pk: &w.executor.public_key_hex(),
            policy_evaluator_pk: Some(&policy_pk),
        };
        assert!(verify_transition(&t, &tkeys).is_ok());
    }

    #[test]
    fn policy_deny_blocks_with_no_side_effect() {
        let w = world();
        let policy_key = KeyPair::generate();
        let policy_pk = policy_key.public_key_hex();
        let evaluator = policy_core::PolicyEvaluator::new(Uuid::new_v4(), policy_key);

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("denied.txt");
        let subject = format!("sha256:{}", sha256_hex(b"src"));
        let deny = evaluator.deny(&sha256_hex(b"context"));

        let grant = w.authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action =
            RequestedAction::new("create_file", &subject, target.to_str().unwrap(), Authority::LocalWrite);
        let req = GovernRequest {
            proposer_identity_id: w.proposer_id,
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: Some(deny),
            policy_evaluator_public_key: Some(policy_pk.clone()),
            content: b"nope",
        };
        let t = govern(req, &w.executor, &w.recorder);
        assert!(t.was_refused());
        assert!(!target.exists());
        assert!(t.policy.is_some(), "the deny proof is recorded on the refusal");
        match &t.outcome {
            TransitionOutcome::Refused(rf) => assert_eq!(rf.reason, RefusalCode::PolicyDenied),
            TransitionOutcome::Executed(_) => panic!("policy deny must block"),
        }

        // A refusal caused by a policy deny is itself a valid, verifiable record:
        // the stored Deny proof must NOT make the transition verification fail.
        let tkeys = TransitionKeys {
            recorder_pk: &w.recorder.public_key_hex(),
            authorizer_pk: &w.authorizer.public_key_hex(),
            executor_pk: &w.executor.public_key_hex(),
            policy_evaluator_pk: Some(&policy_pk),
        };
        assert!(
            verify_transition(&t, &tkeys).is_ok(),
            "a policy-deny refusal must still verify as a valid record"
        );
    }

    #[test]
    fn tampering_with_a_sealed_transition_is_detected() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("Summary.txt");
        let subject = format!("sha256:{}", sha256_hex(b"src"));
        let grant = w.authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action =
            RequestedAction::new("create_file", &subject, target.to_str().unwrap(), Authority::LocalWrite);
        let req = GovernRequest {
            proposer_identity_id: w.proposer_id,
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"summary",
        };
        let mut t = govern(req, &w.executor, &w.recorder);
        // Tamper with the resulting state after sealing.
        t.resulting_state_id = Some("sha256:deadbeef".into());

        let tkeys = TransitionKeys {
            recorder_pk: &w.recorder.public_key_hex(),
            authorizer_pk: &w.authorizer.public_key_hex(),
            executor_pk: &w.executor.public_key_hex(),
            policy_evaluator_pk: None,
        };
        assert!(
            verify_transition(&t, &tkeys).is_err(),
            "a tampered transition must fail verification"
        );
    }

    #[test]
    fn grant_bound_to_a_different_subject_is_refused() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("mismatch.txt");
        let subject = format!("sha256:{}", sha256_hex(b"real subject"));
        let other_subject = format!("sha256:{}", sha256_hex(b"different subject"));
        // Grant is for `other_subject`, action targets `subject`.
        let grant = w.authorizer.issue_grant(Authority::LocalWrite, &other_subject);
        let action =
            RequestedAction::new("create_file", &subject, target.to_str().unwrap(), Authority::LocalWrite);
        let req = GovernRequest {
            proposer_identity_id: w.proposer_id,
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject.clone(),
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"nope",
        };
        let t = govern(req, &w.executor, &w.recorder);
        assert!(t.was_refused());
        assert!(!target.exists());
        match t.outcome {
            TransitionOutcome::Refused(rf) => assert_eq!(rf.reason, RefusalCode::SubjectMismatch),
            TransitionOutcome::Executed(_) => panic!("subject mismatch must be refused"),
        }
    }
}
