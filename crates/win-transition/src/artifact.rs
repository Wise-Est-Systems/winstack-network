//! Portable proof — sealing a [`Transition`] into a `.win` artifact and
//! independently verifying it.
//!
//! A W.I.N. transition artifact is one `.win` container carrying:
//! * the produced **content** (the file the transition created; empty for a
//!   refusal), and
//! * a **proof JSON** — the full signed [`Transition`] plus the public keys
//!   needed to check every signature inside it.
//!
//! ## What "independently verifiable" honestly means here
//!
//! [`verify_win`] takes **only the artifact bytes**. It imports no runtime
//! state, no session, no database — it reconstructs every check from what is
//! inside the file. That is what makes it independent.
//!
//! But the signing keys travel *inside* the artifact and are self-attested. So a
//! passing verification proves three things and **no more**: the container is
//! structurally intact, the carried content matches the hash the transition
//! sealed, and every signature was made by the keys the artifact names. It does
//! **not** prove who owns those keys. [`VerifiedArtifact::real_world_identity`]
//! says exactly that — `NOT ESTABLISHED`.

use serde::{Deserialize, Serialize};
use wise_crypto::sha256_hex;

use crate::{
    resolve_identity, verify_transition, Authority, IdentityAssertion, IdentityStatus, NoTrust,
    RefusalCode, Transition, TransitionKeys, TransitionOutcome, TrustLookup,
};

/// Format tag written into every artifact's proof JSON.
pub const ARTIFACT_FORMAT: &str = "WIN-UTP-ARTIFACT/0.1";

/// The public keys required to verify a sealed transition. They travel with the
/// artifact so a recipient needs nothing else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionPublicKeys {
    pub recorder_pk: String,
    pub authorizer_pk: String,
    pub executor_pk: String,
    pub policy_evaluator_pk: Option<String>,
}

impl TransitionPublicKeys {
    #[must_use]
    pub fn new(
        recorder_pk: impl Into<String>,
        authorizer_pk: impl Into<String>,
        executor_pk: impl Into<String>,
        policy_evaluator_pk: Option<String>,
    ) -> Self {
        Self {
            recorder_pk: recorder_pk.into(),
            authorizer_pk: authorizer_pk.into(),
            executor_pk: executor_pk.into(),
            policy_evaluator_pk,
        }
    }

    fn as_transition_keys(&self) -> TransitionKeys<'_> {
        TransitionKeys {
            recorder_pk: &self.recorder_pk,
            authorizer_pk: &self.authorizer_pk,
            executor_pk: &self.executor_pk,
            policy_evaluator_pk: self.policy_evaluator_pk.as_deref(),
        }
    }
}

/// The proof JSON stored inside a `.win` transition artifact.
///
/// `identities` is an additive, self-signed envelope: each assertion is signed by
/// its own key, so an attacker without the private keys cannot forge an identity
/// for a key used in the transition. Stripping assertions only downgrades the
/// reported identity (fail-safe); it cannot upgrade it. Older artifacts without
/// the field deserialize with an empty list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableProof {
    pub format: String,
    pub transition: Transition,
    pub keys: TransitionPublicKeys,
    #[serde(default)]
    pub identities: Vec<IdentityAssertion>,
}

impl PortableProof {
    #[must_use]
    pub fn new(transition: Transition, keys: TransitionPublicKeys) -> Self {
        Self {
            format: ARTIFACT_FORMAT.to_string(),
            transition,
            keys,
            identities: Vec::new(),
        }
    }

    /// Attach self-signed identity assertions (e.g. for the authorizer/recorder).
    #[must_use]
    pub fn with_identities(mut self, identities: Vec<IdentityAssertion>) -> Self {
        self.identities = identities;
        self
    }
}

/// Seal a transition into `.win` bytes.
///
/// `output_filename` / `output_content` are the file the transition produced.
/// For a refused transition pass empty content — the refusal proof is the point.
#[must_use]
pub fn seal_win(proof: &PortableProof, output_filename: &str, output_content: &[u8]) -> Vec<u8> {
    let proof_json = wise_crypto::canonical_json(proof);
    win_format::pack(output_filename, output_content, &proof_json)
}

/// Why an artifact could not even be read into a proof record. These are
/// *damage / not-a-W.I.N.-artifact* conditions, distinct from a proof that reads
/// fine but fails a verification dimension.
#[derive(Debug, thiserror::Error)]
pub enum WinOpenError {
    #[error("container damage: {0}")]
    Container(String),
    #[error("proof is not valid JSON: {0}")]
    ProofParse(String),
    #[error("not a W.I.N. transition artifact (format tag `{0}`)")]
    NotUtpArtifact(String),
}

/// Open a `.win` transition artifact → (filename, content, proof).
pub fn open_win(bytes: &[u8]) -> Result<(String, Vec<u8>, PortableProof), WinOpenError> {
    let (filename, content, proof_json) =
        win_format::unpack(bytes).map_err(|e| WinOpenError::Container(e.to_string()))?;
    let proof: PortableProof =
        serde_json::from_str(&proof_json).map_err(|e| WinOpenError::ProofParse(e.to_string()))?;
    if proof.format != ARTIFACT_FORMAT {
        return Err(WinOpenError::NotUtpArtifact(proof.format));
    }
    Ok((filename, content, proof))
}

/// Content-integrity status of the carried file vs the hash the transition sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityStatus {
    /// The carried content's hash matches the sealed output identity.
    Valid,
    /// The carried content was changed after sealing.
    Mismatch,
    /// No output content is expected (a refusal, or a failed execution).
    NotApplicable,
}

/// The result of independently verifying a `.win` transition artifact — a
/// per-dimension matrix, not a single opaque "verified".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedArtifact {
    pub filename: String,
    pub content_len: usize,
    /// Always true here — we could only build this after a clean unpack.
    pub container_structure_valid: bool,
    pub content_integrity: IntegrityStatus,
    /// Every signature inside the transition verified and the record is
    /// internally consistent.
    pub transition_valid: bool,
    pub was_executed: bool,
    pub was_refused: bool,
    pub refusal_reason: Option<RefusalCode>,
    pub subject_content_id: String,
    pub resulting_state_id: Option<String>,
    /// The scoped authority the transition was granted.
    pub granted_authority: Authority,
    /// Whether a policy proof was evaluated as part of this transition.
    pub policy_evaluated: bool,
    /// Whether an execution receipt is present (i.e. a side effect was attempted).
    pub execution_receipt_present: bool,
    pub signing_keys: TransitionPublicKeys,
    /// The identity rung reached for the **authorizer** ("who authorized this").
    pub authorizer_identity: IdentityStatus,
    /// The identity rung reached for the **recorder** ("who sealed this").
    pub recorder_identity: IdentityStatus,
    /// Human rendering of `authorizer_identity` for the matrix. The honest limit
    /// stays on the label: signatures prove key custody, not who holds the key.
    pub real_world_identity: String,
}

impl VerifiedArtifact {
    /// True only if the container is intact, the content matches (or is N/A),
    /// and every signature verified.
    #[must_use]
    pub fn all_checks_pass(&self) -> bool {
        self.container_structure_valid
            && self.transition_valid
            && self.content_integrity != IntegrityStatus::Mismatch
    }
}

fn short_key(k: &str) -> String {
    if k.len() <= 14 {
        format!("key:{k}")
    } else {
        format!("key:{}…", &k[..14])
    }
}

/// Render an honest, per-dimension verification matrix for a `.win` transition
/// artifact — the text surface behind the directive's Object-Record verification
/// view. Every row states an exact guarantee; nothing is inflated to "truth".
#[must_use]
pub fn render_verification_matrix(v: &VerifiedArtifact) -> String {
    let row = |label: &str, val: &str| format!("{label:<26}{val}\n");

    let sigs = if v.transition_valid { "VALID" } else { "INVALID" };
    let container = if v.container_structure_valid {
        "VALID"
    } else {
        "DAMAGED"
    };
    let integrity = match v.content_integrity {
        IntegrityStatus::Valid => "VALID",
        IntegrityStatus::Mismatch => "MISMATCH — content altered after sealing",
        IntegrityStatus::NotApplicable => "N/A — no output content",
    };
    let authority = format!("{:?}", v.granted_authority);
    let policy = if v.policy_evaluated { "PASSED" } else { "NONE" };
    let receipt = if v.execution_receipt_present {
        "PRESENT"
    } else {
        "NONE — action was refused"
    };
    let outcome = if v.was_executed {
        "EXECUTED".to_string()
    } else if let Some(reason) = v.refusal_reason {
        format!("REFUSED — {reason:?}")
    } else {
        "REFUSED".to_string()
    };

    let mut out = String::new();
    out.push_str(&row("CONTAINER STRUCTURE", container));
    out.push_str(&row("CONTENT INTEGRITY", integrity));
    out.push_str(&row("SIGNATURES", sigs));
    out.push_str(&row("SIGNING KEY (recorder)", &short_key(&v.signing_keys.recorder_pk)));
    out.push_str(&row("REAL-WORLD IDENTITY", &v.real_world_identity));
    out.push_str(&row("AUTHORIZATION", &format!("SCOPED TO {authority}")));
    out.push_str(&row("POLICY EVALUATION", policy));
    out.push_str(&row("EXECUTION RECEIPT", receipt));
    out.push_str(&row("OUTCOME", &outcome));
    out.push_str(&row("FACTUAL CLAIMS", "NOT INDEPENDENTLY ESTABLISHED"));
    out.push_str(&row("EXTERNAL DEPENDENCIES", "NONE — verified offline"));
    out
}

/// Independently verify a `.win` transition artifact from its bytes alone.
///
/// Returns `Err` only when the bytes cannot be read into a proof at all
/// (container damage / not a W.I.N. artifact). When the proof reads, it always
/// returns a [`VerifiedArtifact`] whose per-dimension fields report exactly what
/// passed and what failed — a forged signature or altered content yields a
/// record with that dimension `false`/`Mismatch`, not an error.
pub fn verify_win(bytes: &[u8]) -> Result<VerifiedArtifact, WinOpenError> {
    verify_win_with_trust(bytes, &NoTrust)
}

/// Like [`verify_win`], but resolves identity against a recipient's trust list,
/// so a trusted authorizer/recorder key is reported as `Trusted` rather than
/// merely `SelfAsserted`.
pub fn verify_win_with_trust(
    bytes: &[u8],
    trust: &dyn TrustLookup,
) -> Result<VerifiedArtifact, WinOpenError> {
    let (filename, content, proof) = open_win(bytes)?;
    let t = &proof.transition;

    let content_integrity = match &t.outcome {
        TransitionOutcome::Executed(r) => match &r.output_content_id {
            Some(sealed) => {
                let actual = format!("sha256:{}", sha256_hex(&content));
                if &actual == sealed {
                    IntegrityStatus::Valid
                } else {
                    IntegrityStatus::Mismatch
                }
            }
            None => IntegrityStatus::NotApplicable,
        },
        TransitionOutcome::Refused(_) => IntegrityStatus::NotApplicable,
    };

    let transition_valid = verify_transition(t, &proof.keys.as_transition_keys()).is_ok();

    let refusal_reason = match &t.outcome {
        TransitionOutcome::Refused(rf) => Some(rf.reason),
        TransitionOutcome::Executed(_) => None,
    };

    let authorizer_identity =
        resolve_identity(&proof.keys.authorizer_pk, &proof.identities, trust);
    let recorder_identity = resolve_identity(&proof.keys.recorder_pk, &proof.identities, trust);
    let real_world_identity = authorizer_identity.summary();

    Ok(VerifiedArtifact {
        filename,
        content_len: content.len(),
        container_structure_valid: true,
        content_integrity,
        transition_valid,
        was_executed: t.was_executed(),
        was_refused: t.was_refused(),
        refusal_reason,
        subject_content_id: t.subject_content_id.clone(),
        resulting_state_id: t.resulting_state_id.clone(),
        granted_authority: t.authorization.granted_authority,
        policy_evaluated: t.policy.is_some(),
        execution_receipt_present: t.was_executed(),
        signing_keys: proof.keys.clone(),
        authorizer_identity,
        recorder_identity,
        real_world_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assert_identity, govern, Authority, Authorizer, Executor, FilesystemExecutor,
        GovernRequest, IdentityStatus, Persistence, Recorder, RequestedAction, TrustLookup,
    };
    use uuid::Uuid;
    use wise_crypto::KeyPair;

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

    fn keys(w: &World) -> TransitionPublicKeys {
        TransitionPublicKeys::new(
            w.recorder.public_key_hex(),
            w.authorizer.public_key_hex(),
            w.executor.public_key_hex(),
            None,
        )
    }

    fn accepted_transition(w: &World, dir: &std::path::Path, content: &[u8]) -> Transition {
        let target = dir.join("Summary.txt");
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
            proposer_model: None,
            prior_state_id: Some(subject.clone()),
            subject_content_id: subject,
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content,
        };
        govern(req, &w.executor, &w.recorder)
    }

    #[test]
    fn seal_open_roundtrip_and_independent_verify() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let content = b"a governed summary of the source document";
        let t = accepted_transition(&w, dir.path(), content);
        assert!(t.was_executed());

        let proof = PortableProof::new(t, keys(&w));
        let win_bytes = seal_win(&proof, "Summary.txt.win", content);

        // Reopen in isolation — nothing but the bytes.
        let (name, opened_content, opened_proof) = open_win(&win_bytes).unwrap();
        assert_eq!(name, "Summary.txt.win");
        assert_eq!(opened_content, content);
        assert_eq!(opened_proof.format, ARTIFACT_FORMAT);

        // Independent verification from bytes alone.
        let v = verify_win(&win_bytes).unwrap();
        assert!(v.all_checks_pass(), "a freshly sealed artifact must verify");
        assert_eq!(v.content_integrity, IntegrityStatus::Valid);
        assert!(v.transition_valid);
        assert!(v.was_executed);
        assert!(v.real_world_identity.contains("NOT ESTABLISHED"));
    }

    #[test]
    fn refusal_seals_and_verifies_with_no_content() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let subject = format!("sha256:{}", sha256_hex(b"src"));
        let grant = w.authorizer.issue_grant(Authority::LocalWrite, &subject);
        // Ask to publish under a local-write-only grant → refusal.
        let action = RequestedAction::new(
            "publish",
            &subject,
            dir.path().join("nope.txt").to_str().unwrap(),
            Authority::ExternalPublish,
        );
        let req = GovernRequest {
            proposer_identity_id: w.proposer_id,
            proposer_model: None,
            prior_state_id: None,
            subject_content_id: subject,
            action,
            grant,
            authorizer_public_key: w.authorizer.public_key_hex(),
            policy: None,
            policy_evaluator_public_key: None,
            content: b"",
        };
        let t = govern(req, &w.executor, &w.recorder);
        assert!(t.was_refused());

        let proof = PortableProof::new(t, keys(&w));
        let win_bytes = seal_win(&proof, "refusal.win", b"");

        let v = verify_win(&win_bytes).unwrap();
        assert!(v.all_checks_pass());
        assert!(v.was_refused);
        assert_eq!(v.content_integrity, IntegrityStatus::NotApplicable);
        assert_eq!(v.refusal_reason, Some(RefusalCode::AuthorizationScopeExceeded));
    }

    #[test]
    fn tampering_with_carried_content_fails_content_integrity() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let content = b"original summary content";
        let t = accepted_transition(&w, dir.path(), content);
        let proof = PortableProof::new(t, keys(&w));
        let mut win_bytes = seal_win(&proof, "Summary.txt.win", content);

        // Flip one byte inside the carried content region.
        let idx = win_bytes
            .windows(content.len())
            .position(|win| win == content)
            .expect("content present in container");
        win_bytes[idx] ^= 0xFF;

        // Container still unpacks (structural), but content no longer matches the seal.
        let v = verify_win(&win_bytes).unwrap();
        assert_eq!(v.content_integrity, IntegrityStatus::Mismatch);
        assert!(!v.all_checks_pass(), "tampered content must fail overall");
        // The signed transition record itself is untouched, so it still verifies.
        assert!(v.transition_valid);
    }

    #[test]
    fn tampering_with_the_proof_fails_signature() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let content = b"summary";
        let t = accepted_transition(&w, dir.path(), content);
        let mut proof = PortableProof::new(t, keys(&w));
        // Tamper the sealed record: change the resulting state id.
        proof.transition.resulting_state_id = Some("sha256:deadbeef".into());
        let win_bytes = seal_win(&proof, "Summary.txt.win", content);

        let v = verify_win(&win_bytes).unwrap();
        assert!(!v.transition_valid, "a tampered record must fail its signature");
        assert!(!v.all_checks_pass());
    }

    #[test]
    fn truncated_container_is_reported_as_damage() {
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let content = b"summary content here";
        let t = accepted_transition(&w, dir.path(), content);
        let proof = PortableProof::new(t, keys(&w));
        let win_bytes = seal_win(&proof, "Summary.txt.win", content);

        // Cut the container short.
        let err = verify_win(&win_bytes[..win_bytes.len() / 2]).unwrap_err();
        assert!(matches!(err, WinOpenError::Container(_)));
    }

    #[test]
    fn foreign_key_does_not_verify() {
        // Seal with the real keys, then try to verify a proof whose named keys
        // are swapped for an attacker's — signatures must fail.
        let w = world();
        let dir = tempfile::tempdir().unwrap();
        let content = b"summary";
        let t = accepted_transition(&w, dir.path(), content);

        let attacker = KeyPair::generate();
        let forged_keys = TransitionPublicKeys::new(
            attacker.public_key_hex(),
            w.authorizer.public_key_hex(),
            w.executor.public_key_hex(),
            None,
        );
        let proof = PortableProof::new(t, forged_keys);
        let win_bytes = seal_win(&proof, "Summary.txt.win", content);

        let v = verify_win(&win_bytes).unwrap();
        assert!(!v.transition_valid, "recorder signature must not verify under a foreign key");
    }

    // ── Identity ladder ────────────────────────────────────────────────

    /// Build an authorizer whose keypair we also keep, so we can self-assert.
    fn authorizer_with_key() -> (Authorizer, KeyPair) {
        let secret = KeyPair::generate().secret_key_bytes();
        (
            Authorizer::new(Uuid::new_v4(), KeyPair::from_secret_bytes(&secret)),
            KeyPair::from_secret_bytes(&secret),
        )
    }

    struct MockTrust {
        key: String,
        label: String,
    }
    impl TrustLookup for MockTrust {
        fn is_trusted(&self, k: &str) -> bool {
            k == self.key
        }
        fn label_for(&self, k: &str) -> Option<String> {
            (k == self.key).then(|| self.label.clone())
        }
    }

    /// Seal an accepted transition whose authorizer is `authorizer`, optionally
    /// carrying `identities`.
    fn sealed_with(
        authorizer: &Authorizer,
        identities: Vec<crate::IdentityAssertion>,
    ) -> (Vec<u8>, String) {
        let executor = FilesystemExecutor::new(Uuid::new_v4(), KeyPair::generate());
        let recorder = Recorder::new(Uuid::new_v4(), KeyPair::generate());
        let dir = tempfile::tempdir().unwrap();
        let content = b"summary";
        let subject = format!("sha256:{}", sha256_hex(b"src"));
        let grant = authorizer.issue_grant(Authority::LocalWrite, &subject);
        let action = RequestedAction::new(
            "create_file",
            &subject,
            dir.path().join("s.txt").to_str().unwrap(),
            Authority::LocalWrite,
        );
        let t = govern(
            GovernRequest {
                proposer_identity_id: Uuid::new_v4(),
                proposer_model: None,
                prior_state_id: None,
                subject_content_id: subject,
                action,
                grant,
                authorizer_public_key: authorizer.public_key_hex(),
                policy: None,
                policy_evaluator_public_key: None,
                content,
            },
            &executor,
            &recorder,
        );
        let keys = TransitionPublicKeys::new(
            recorder.public_key_hex(),
            authorizer.public_key_hex(),
            executor.public_key_hex(),
            None,
        );
        let proof = PortableProof::new(t, keys).with_identities(identities);
        (seal_win(&proof, "s.win", content), authorizer.public_key_hex())
    }

    #[test]
    fn no_identity_reads_not_established() {
        let (auth, _) = authorizer_with_key();
        let (win, _) = sealed_with(&auth, vec![]);
        let v = verify_win(&win).unwrap();
        assert_eq!(v.authorizer_identity, IdentityStatus::NotEstablished);
        assert!(v.real_world_identity.contains("NOT ESTABLISHED"));
    }

    #[test]
    fn self_asserted_name_reads_claimed() {
        let (auth, key) = authorizer_with_key();
        let ident = assert_identity(
            &key,
            Some("Acme Ops".into()),
            Some("acme.co".into()),
            Persistence::Persistent,
        );
        let (win, _) = sealed_with(&auth, vec![ident]);
        let v = verify_win(&win).unwrap();
        assert_eq!(
            v.authorizer_identity,
            IdentityStatus::SelfAsserted { claimed: "Acme Ops".into() }
        );
        assert!(v.real_world_identity.contains("CLAIMED"));
        assert!(v.real_world_identity.contains("SELF-ASSERTED"));
    }

    #[test]
    fn trusted_key_reads_trusted() {
        let (auth, key) = authorizer_with_key();
        let ident = assert_identity(&key, Some("Acme Ops".into()), None, Persistence::Persistent);
        let (win, auth_pk) = sealed_with(&auth, vec![ident]);
        let trust = MockTrust { key: auth_pk, label: "Acme Ops".into() };
        let v = crate::verify_win_with_trust(&win, &trust).unwrap();
        assert_eq!(
            v.authorizer_identity,
            IdentityStatus::Trusted { label: "Acme Ops".into() }
        );
        assert!(v.real_world_identity.contains("TRUSTED"));
    }

    #[test]
    fn persistent_key_without_name_reads_consistent_actor() {
        let (auth, key) = authorizer_with_key();
        let ident = assert_identity(&key, None, None, Persistence::Persistent);
        let (win, _) = sealed_with(&auth, vec![ident]);
        let v = verify_win(&win).unwrap();
        assert_eq!(v.authorizer_identity, IdentityStatus::ConsistentActor);
    }

    #[test]
    fn forged_identity_assertion_is_ignored() {
        // An assertion whose self-signature is invalid must not be honored.
        let (auth, key) = authorizer_with_key();
        let mut ident = assert_identity(&key, Some("Impostor".into()), None, Persistence::Persistent);
        ident.self_signature = "00".repeat(64); // break the self-signature
        let (win, _) = sealed_with(&auth, vec![ident]);
        let v = verify_win(&win).unwrap();
        assert_eq!(
            v.authorizer_identity,
            IdentityStatus::NotEstablished,
            "a forged identity assertion must be ignored, not honored"
        );
    }

    #[test]
    fn identity_for_a_key_not_in_the_transition_is_ignored() {
        // An assertion for some OTHER key cannot lend identity to the authorizer.
        let (auth, _) = authorizer_with_key();
        let stranger = KeyPair::generate();
        let ident = assert_identity(&stranger, Some("Stranger".into()), None, Persistence::Persistent);
        let (win, _) = sealed_with(&auth, vec![ident]);
        let v = verify_win(&win).unwrap();
        assert_eq!(v.authorizer_identity, IdentityStatus::NotEstablished);
    }
}
