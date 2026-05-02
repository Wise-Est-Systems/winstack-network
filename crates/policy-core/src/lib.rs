use canon_types::*;
use uuid::Uuid;
use wise_crypto::{self as crypto, KeyPair};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("policy proof missing")]
    ProofMissing,
    #[error("policy decision is not Permit")]
    DecisionNotPermit,
    #[error("policy version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u64, actual: u64 },
    #[error("policy context mismatch")]
    ContextMismatch,
    #[error("policy signature invalid")]
    SignatureInvalid,
}

pub const CURRENT_POLICY_VERSION: u64 = 1;

pub struct PolicyEvaluator {
    evaluator_id: Uuid,
    key: KeyPair,
    version: u64,
}

impl PolicyEvaluator {
    pub fn new(evaluator_id: Uuid, key: KeyPair) -> Self {
        Self {
            evaluator_id,
            key,
            version: CURRENT_POLICY_VERSION,
        }
    }

    pub fn evaluator_id(&self) -> Uuid {
        self.evaluator_id
    }

    pub fn evaluate(&self, context_hash: &str, decision: PolicyDecision) -> PolicyProof {
        let proof_id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339();

        #[derive(serde::Serialize)]
        struct SignPayload<'a> {
            policy_proof_id: &'a Uuid,
            decision: &'a PolicyDecision,
            policy_version: u64,
            context_hash: &'a str,
            evaluator_identity_id: &'a Uuid,
            evaluated_at: &'a str,
        }

        let payload = SignPayload {
            policy_proof_id: &proof_id,
            decision: &decision,
            policy_version: self.version,
            context_hash,
            evaluator_identity_id: &self.evaluator_id,
            evaluated_at: &now,
        };
        let sig = self.key.sign_json(&payload);

        PolicyProof {
            policy_proof_id: proof_id,
            decision,
            policy_version: self.version,
            context_hash: context_hash.to_string(),
            evaluator_identity_id: self.evaluator_id,
            evaluated_at: now,
            signature: sig,
        }
    }

    pub fn permit(&self, context_hash: &str) -> PolicyProof {
        self.evaluate(context_hash, PolicyDecision::Permit)
    }

    pub fn deny(&self, context_hash: &str) -> PolicyProof {
        self.evaluate(context_hash, PolicyDecision::Deny)
    }
}

pub fn verify_policy_proof(
    proof: &PolicyProof,
    evaluator_public_key: &str,
    expected_version: u64,
) -> Result<(), PolicyError> {
    if proof.decision != PolicyDecision::Permit {
        return Err(PolicyError::DecisionNotPermit);
    }

    if proof.policy_version != expected_version {
        return Err(PolicyError::VersionMismatch {
            expected: expected_version,
            actual: proof.policy_version,
        });
    }

    #[derive(serde::Serialize)]
    struct SignPayload<'a> {
        policy_proof_id: &'a Uuid,
        decision: &'a PolicyDecision,
        policy_version: u64,
        context_hash: &'a str,
        evaluator_identity_id: &'a Uuid,
        evaluated_at: &'a str,
    }

    let payload = SignPayload {
        policy_proof_id: &proof.policy_proof_id,
        decision: &proof.decision,
        policy_version: proof.policy_version,
        context_hash: &proof.context_hash,
        evaluator_identity_id: &proof.evaluator_identity_id,
        evaluated_at: &proof.evaluated_at,
    };

    crypto::verify_json_signature(evaluator_public_key, &payload, &proof.signature)
        .map_err(|_| PolicyError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permit_proof_verifies() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_hex();
        let id = Uuid::new_v4();
        let eval = PolicyEvaluator::new(id, kp);
        let proof = eval.permit("ctx_hash");
        assert!(verify_policy_proof(&proof, &pk, CURRENT_POLICY_VERSION).is_ok());
    }

    #[test]
    fn deny_proof_rejected() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_hex();
        let id = Uuid::new_v4();
        let eval = PolicyEvaluator::new(id, kp);
        let proof = eval.deny("ctx_hash");
        assert!(matches!(
            verify_policy_proof(&proof, &pk, CURRENT_POLICY_VERSION),
            Err(PolicyError::DecisionNotPermit)
        ));
    }

    #[test]
    fn version_mismatch_rejected() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_hex();
        let id = Uuid::new_v4();
        let eval = PolicyEvaluator::new(id, kp);
        let proof = eval.permit("ctx_hash");
        assert!(matches!(
            verify_policy_proof(&proof, &pk, 999),
            Err(PolicyError::VersionMismatch { .. })
        ));
    }
}
