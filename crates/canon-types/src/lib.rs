use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityKind {
    Personal,
    Organization,
    Service,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub identity_id: Uuid,
    pub kind: IdentityKind,
    pub status: IdentityStatus,
    pub public_key_hex: String,
    pub created_at: String,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModuleKind {
    Import,
    AiGeneration,
    Capture,
    Document,
    Posting,
    CodeExecution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRegistration {
    pub module_id: Uuid,
    pub kind: ModuleKind,
    pub scope: String,
    pub binary_hash: String,
    pub registered_by: Uuid,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeSource {
    Local,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedTimeEvent {
    pub time_event_id: Uuid,
    pub timestamp: String,
    pub time_authority_identity_id: Uuid,
    pub predecessor_event_id: Option<Uuid>,
    pub predecessor_hash: Option<String>,
    pub payload_hash: String,
    pub signature: String,
    #[serde(default = "default_time_source")]
    pub time_source: TimeSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rfc3161_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored_time: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaAttachment {
    pub token_base64: String,
    pub anchored_time: String,
}

fn default_time_source() -> TimeSource {
    TimeSource::Local
}

impl ChainedTimeEvent {
    pub fn is_genesis(&self) -> bool {
        self.predecessor_event_id.is_none()
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Permit,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyProof {
    pub policy_proof_id: Uuid,
    pub decision: PolicyDecision,
    pub policy_version: u64,
    pub context_hash: String,
    pub evaluator_identity_id: Uuid,
    pub evaluated_at: String,
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Object
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjectClass {
    Native,
    AiGenerated,
    SealedImport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrustClass {
    Native,
    Foreign,
}

impl ObjectClass {
    pub fn trust_class(&self) -> TrustClass {
        match self {
            ObjectClass::Native | ObjectClass::AiGenerated => TrustClass::Native,
            ObjectClass::SealedImport => TrustClass::Foreign,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginRecord {
    pub origin_record_id: Uuid,
    pub object_id: Uuid,
    pub object_class: ObjectClass,
    pub creator_identity_id: Uuid,
    pub module_identity_id: Uuid,
    pub time_authority_identity_id: Uuid,
    pub created_at: String,
    pub protocol: String,
    pub foreign_source_uri: Option<String>,
    pub ai_model: Option<AiModelInfo>,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiModelInfo {
    pub model_name: String,
    pub model_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiGenerationRecord {
    pub generation_id: Uuid,
    pub object_id: Uuid,
    pub model: AiModelInfo,
    pub prompt_hash: String,
    pub output_hash: String,
    pub module_id: Uuid,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportDeclaration {
    pub import_id: Uuid,
    pub object_id: Uuid,
    pub source_uri: String,
    pub claimed_content_type: String,
    pub reason: String,
    pub module_id: Uuid,
    pub signature: String,
}

/// Signed key delegation for chain continuity across key rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDelegation {
    pub delegation_id: Uuid,
    pub lineage_id: Uuid,
    pub from_key_hex: String,
    pub to_key_hex: String,
    pub delegated_at: String,
    /// Signed by the OLD key over the delegation payload
    pub signature: String,
}

/// Chain linkage for proof continuity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofChain {
    pub lineage_id: Uuid,
    pub predecessor_proof_id: Option<Uuid>,
    pub predecessor_payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_delegation: Option<KeyDelegation>,
}

/// Result of a full chain walk verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationResult {
    pub chain_status: ChainStatus,
    pub depth: usize,
    pub failures: Vec<Failure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainStatus {
    /// No chain — standalone proof
    Standalone,
    /// Origin of a lineage
    Origin,
    /// Successor, full history verified
    FullHistoryVerified,
    /// Successor, only current proof verified (predecessors not supplied)
    HistoryIncomplete,
    /// Chain broken
    HistoryBroken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedObject {
    pub object_id: Uuid,
    pub object_class: ObjectClass,
    pub payload_hash: String,
    pub artifact_size_bytes: u64,
    pub parent_ids: Vec<Uuid>,
    pub origin: OriginRecord,
    pub time_event: ChainedTimeEvent,
    pub policy_proof: PolicyProof,
    pub ai_generation: Option<AiGenerationRecord>,
    pub import_declaration: Option<ImportDeclaration>,
    pub object_signature: String,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_chain: Option<ProofChain>,
}

// ---------------------------------------------------------------------------
// Verification result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailureCode {
    PayloadHashMismatch,
    ObjectSignatureInvalid,
    CreatorIdentityInvalid,
    CreatorIdentityNotActive,
    CreatorIdentityNotFound,
    ModuleNotRegistered,
    ModuleScopeMismatch,
    ModuleBinaryHashMismatch,
    ModuleKindMismatch,
    TimeSignatureInvalid,
    TimePredecessorMissing,
    TimePredecessorHashMismatch,
    TimeChainBroken,
    PolicyProofMissing,
    PolicyProofSignatureInvalid,
    PolicyDecisionNotPermit,
    PolicyVersionMismatch,
    PolicyContextMismatch,
    OriginRecordMissing,
    OriginObjectIdMismatch,
    OriginCreatorMismatch,
    OriginModuleMismatch,
    OriginTimeMismatch,
    AiGenerationRecordMissing,
    AiGenerationObjectIdMismatch,
    AiGenerationOutputHashMismatch,
    ImportDeclarationMissing,
    LineageParentMissing,
    LineageParentInvalid,
    LineageParentTimestampViolation,
    LineageSelfCycle,
    LineageCycleDetected,
    SessionCannotCreateNative,
    TsaTokenMissing,
    TsaTokenHashMismatch,
    TsaTokenMalformed,
    TsaSignatureInvalid,
    TsaCertificateChainInvalid,
    TsaCertificateExpired,
    TsaNotTrusted,
    ChainPredecessorHashMismatch,
    ChainPredecessorMissing,
    ChainPredecessorBundleMissing,
    ChainPredecessorIdMismatch,
    ChainPredecessorInvalid,
    ChainCycleDetected,
    ChainDelegationMissing,
    ChainDelegationInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub code: FailureCode,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Verified,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub status: VerificationStatus,
    pub object_id: Uuid,
    pub failures: Vec<Failure>,
}

// ---------------------------------------------------------------------------
// Proof bundle (self-contained for offline verify)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofBundle {
    pub object: SealedObject,
    pub creator_identity: IdentityRecord,
    pub module_registration: ModuleRegistration,
    pub time_authority_identity: IdentityRecord,
    pub policy_evaluator_identity: IdentityRecord,
    pub predecessor_time_event: Option<ChainedTimeEvent>,
    pub parent_objects: Vec<SealedObject>,
    pub parent_proofs: Vec<ProofBundle>,
}

// ---------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RejectCode {
    PayloadHashInvalid,
    CreatorInvalid,
    CreatorNotActive,
    CreatorNotFound,
    ModuleNotRegistered,
    ModuleScopeMismatch,
    ModuleBinaryHashInvalid,
    ModuleKindMismatch,
    LineageCycle,
    LineageParentMissing,
    LineageParentInvalid,
    PolicyDeny,
    PolicyMissing,
    TimeAttestationFailed,
    VerificationFailed,
    PersistenceFailed,
    SessionCannotCreateNative,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejection {
    pub code: RejectCode,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Birth proposals
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeBirthProposal {
    pub artifact_bytes: Vec<u8>,
    pub creator_identity_id: Uuid,
    pub module_id: Uuid,
    pub parent_ids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa_attachment: Option<TsaAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_chain: Option<ProofChain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiBirthProposal {
    pub artifact_bytes: Vec<u8>,
    pub creator_identity_id: Uuid,
    pub module_id: Uuid,
    pub parent_ids: Vec<Uuid>,
    pub model: AiModelInfo,
    pub prompt_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa_attachment: Option<TsaAttachment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportBirthProposal {
    pub artifact_bytes: Vec<u8>,
    pub creator_identity_id: Uuid,
    pub module_id: Uuid,
    pub parent_ids: Vec<Uuid>,
    pub source_uri: String,
    pub claimed_content_type: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa_attachment: Option<TsaAttachment>,
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub object_id: Uuid,
    pub action: String,
    pub timestamp: String,
}
