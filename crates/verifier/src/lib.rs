use canon_types::*;
use winstack_crypto as crypto;

pub struct VerificationInput {
    pub object: SealedObject,
    pub artifact_bytes: Vec<u8>,
    pub creator_identity: IdentityRecord,
    pub module_registration: ModuleRegistration,
    pub time_authority_identity: IdentityRecord,
    pub policy_evaluator_identity: IdentityRecord,
    pub predecessor_time_event: Option<ChainedTimeEvent>,
    pub parent_objects: Vec<SealedObject>,
    pub tsa_trust_store: Option<time_core::tsa::TrustStore>,
}

pub const SUPPORTED_PROTOCOL: &str = "V1";

pub fn verify_object(input: &VerificationInput) -> VerificationResult {
    let obj = &input.object;
    let mut failures: Vec<Failure> = Vec::new();

    // 0. Protocol version gate
    if obj.protocol != SUPPORTED_PROTOCOL {
        return VerificationResult {
            status: VerificationStatus::Invalid,
            object_id: obj.object_id,
            failures: vec![Failure {
                code: FailureCode::OriginRecordMissing,
                reason: format!(
                    "unsupported protocol version: {} (this verifier supports {})",
                    obj.protocol, SUPPORTED_PROTOCOL
                ),
            }],
        };
    }

    // 1. Payload hash
    let computed_hash = crypto::sha256_hex(&input.artifact_bytes);
    if computed_hash != obj.payload_hash {
        failures.push(Failure {
            code: FailureCode::PayloadHashMismatch,
            reason: format!("expected {}, computed {}", obj.payload_hash, computed_hash),
        });
    }

    // 2. Object signature
    {
        #[derive(serde::Serialize)]
        struct ObjSignPayload<'a> {
            object_id: &'a uuid::Uuid,
            object_class: &'a ObjectClass,
            payload_hash: &'a str,
            artifact_size_bytes: u64,
            parent_ids: &'a [uuid::Uuid],
            protocol: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            proof_chain: &'a Option<ProofChain>,
        }
        let payload = ObjSignPayload {
            object_id: &obj.object_id,
            object_class: &obj.object_class,
            payload_hash: &obj.payload_hash,
            artifact_size_bytes: obj.artifact_size_bytes,
            parent_ids: &obj.parent_ids,
            protocol: &obj.protocol,
            proof_chain: &obj.proof_chain,
        };
        if crypto::verify_json_signature(
            &input.creator_identity.public_key_hex,
            &payload,
            &obj.object_signature,
        )
        .is_err()
        {
            failures.push(Failure {
                code: FailureCode::ObjectSignatureInvalid,
                reason: "object signature does not verify against creator key".into(),
            });
        }
    }

    // 3. Creator identity
    if input.creator_identity.identity_id != obj.origin.creator_identity_id {
        failures.push(Failure {
            code: FailureCode::OriginCreatorMismatch,
            reason: "creator identity id does not match origin record".into(),
        });
    }
    if input.creator_identity.status != IdentityStatus::Active {
        failures.push(Failure {
            code: FailureCode::CreatorIdentityNotActive,
            reason: format!("creator status is {:?}", input.creator_identity.status),
        });
    }
    // Session cannot create native
    if input.creator_identity.kind == IdentityKind::Session
        && matches!(
            obj.object_class,
            ObjectClass::Native | ObjectClass::AiGenerated
        )
    {
        failures.push(Failure {
            code: FailureCode::SessionCannotCreateNative,
            reason: "session identity cannot create permanent native objects".into(),
        });
    }

    // 4. Module validation
    if input.module_registration.module_id != obj.origin.module_identity_id {
        failures.push(Failure {
            code: FailureCode::OriginModuleMismatch,
            reason: "module id does not match origin record".into(),
        });
    }
    {
        let expected_kind = match obj.object_class {
            ObjectClass::SealedImport => Some(ModuleKind::Import),
            ObjectClass::AiGenerated => Some(ModuleKind::AiGeneration),
            ObjectClass::Native => None,
        };
        if let Some(ek) = expected_kind {
            if input.module_registration.kind != ek {
                failures.push(Failure {
                    code: FailureCode::ModuleKindMismatch,
                    reason: format!(
                        "module kind {:?} does not match expected {:?}",
                        input.module_registration.kind, ek
                    ),
                });
            }
        }
    }

    // 5. Time signature verification
    if input.time_authority_identity.identity_id != obj.origin.time_authority_identity_id {
        failures.push(Failure {
            code: FailureCode::OriginTimeMismatch,
            reason: "time authority does not match origin record".into(),
        });
    }
    if time_core::verify_time_signature(
        &obj.time_event,
        &input.time_authority_identity.public_key_hex,
    )
    .is_err()
    {
        failures.push(Failure {
            code: FailureCode::TimeSignatureInvalid,
            reason: "time event signature verification failed".into(),
        });
    }

    // 6. Time chain verification
    if obj.time_event.is_genesis() {
        // Genesis is fine with no predecessor
    } else {
        match &input.predecessor_time_event {
            None => {
                failures.push(Failure {
                    code: FailureCode::TimePredecessorMissing,
                    reason: "non-genesis time event has no predecessor provided".into(),
                });
            }
            Some(pred) => {
                if time_core::verify_time_chain(&obj.time_event, Some(pred)).is_err() {
                    failures.push(Failure {
                        code: FailureCode::TimePredecessorHashMismatch,
                        reason: "time chain predecessor hash does not match".into(),
                    });
                }
            }
        }
    }

    // 6b. TSA token verification (if External time claimed)
    if obj.time_event.time_source == TimeSource::External {
        match &obj.time_event.rfc3161_token {
            None => {
                failures.push(Failure {
                    code: FailureCode::TsaTokenMissing,
                    reason: "time source is External but no RFC 3161 token present".into(),
                });
            }
            Some(token_b64) => {
                // Full CMS verification with provided trust store (default: open)
                let default_store = time_core::tsa::TrustStore::new();
                let trust_store = input.tsa_trust_store.as_ref().unwrap_or(&default_store);
                match time_core::tsa::verify_token_full(token_b64, &obj.payload_hash, trust_store) {
                    Ok(_) => {} // CMS signature valid, hash matches
                    Err(time_core::tsa::TsaError::HashMismatch) => {
                        failures.push(Failure {
                            code: FailureCode::TsaTokenHashMismatch,
                            reason: "RFC 3161 token hash does not match payload hash".into(),
                        });
                    }
                    Err(time_core::tsa::TsaError::SignatureInvalid(reason)) => {
                        failures.push(Failure {
                            code: FailureCode::TsaSignatureInvalid,
                            reason: format!("RFC 3161 CMS signature invalid: {}", reason),
                        });
                    }
                    Err(time_core::tsa::TsaError::CertificateChainInvalid(reason)) => {
                        failures.push(Failure {
                            code: FailureCode::TsaCertificateChainInvalid,
                            reason: format!("RFC 3161 certificate chain invalid: {}", reason),
                        });
                    }
                    Err(time_core::tsa::TsaError::CertificateExpired(reason)) => {
                        failures.push(Failure {
                            code: FailureCode::TsaCertificateExpired,
                            reason: format!("RFC 3161 certificate expired: {}", reason),
                        });
                    }
                    Err(time_core::tsa::TsaError::NotTrusted(reason)) => {
                        failures.push(Failure {
                            code: FailureCode::TsaNotTrusted,
                            reason: format!("RFC 3161 TSA not trusted: {}", reason),
                        });
                    }
                    Err(e) => {
                        failures.push(Failure {
                            code: FailureCode::TsaTokenMalformed,
                            reason: format!("RFC 3161 token cannot be verified: {}", e),
                        });
                    }
                }
            }
        }
    }

    // 7. Policy proof
    if obj.policy_proof.decision != PolicyDecision::Permit {
        failures.push(Failure {
            code: FailureCode::PolicyDecisionNotPermit,
            reason: format!("policy decision is {:?}", obj.policy_proof.decision),
        });
    }
    if policy_core::verify_policy_proof(
        &obj.policy_proof,
        &input.policy_evaluator_identity.public_key_hex,
        policy_core::CURRENT_POLICY_VERSION,
    )
    .is_err()
    {
        failures.push(Failure {
            code: FailureCode::PolicyProofSignatureInvalid,
            reason: "policy proof signature verification failed".into(),
        });
    }

    // 8. Origin record consistency
    if obj.origin.object_id != obj.object_id {
        failures.push(Failure {
            code: FailureCode::OriginObjectIdMismatch,
            reason: "origin record object_id does not match object".into(),
        });
    }

    // 9. AI generation record
    if obj.object_class == ObjectClass::AiGenerated {
        match &obj.ai_generation {
            None => {
                failures.push(Failure {
                    code: FailureCode::AiGenerationRecordMissing,
                    reason: "AI-generated object has no generation record".into(),
                });
            }
            Some(gen) => {
                if gen.object_id != obj.object_id {
                    failures.push(Failure {
                        code: FailureCode::AiGenerationObjectIdMismatch,
                        reason: "generation record object_id mismatch".into(),
                    });
                }
                let output_hash = crypto::sha256_hex(&input.artifact_bytes);
                if gen.output_hash != output_hash {
                    failures.push(Failure {
                        code: FailureCode::AiGenerationOutputHashMismatch,
                        reason: "generation output hash does not match artifact".into(),
                    });
                }
            }
        }
    }

    // 10. Import declaration
    if obj.object_class == ObjectClass::SealedImport {
        match &obj.import_declaration {
            None => {
                failures.push(Failure {
                    code: FailureCode::ImportDeclarationMissing,
                    reason: "sealed import has no import declaration".into(),
                });
            }
            Some(_decl) => {
                // Import declaration present — foreign content stays foreign
            }
        }
    }

    // 11. Lineage
    for pid in &obj.parent_ids {
        if *pid == obj.object_id {
            failures.push(Failure {
                code: FailureCode::LineageSelfCycle,
                reason: "object lists itself as parent".into(),
            });
        }
        match input.parent_objects.iter().find(|p| p.object_id == *pid) {
            None => {
                failures.push(Failure {
                    code: FailureCode::LineageParentMissing,
                    reason: format!("parent {} not found", pid),
                });
            }
            Some(parent) => {
                // Parent must be older (by timestamp string comparison)
                if parent.time_event.timestamp >= obj.time_event.timestamp {
                    failures.push(Failure {
                        code: FailureCode::LineageParentTimestampViolation,
                        reason: format!(
                            "parent {} timestamp {} is not before child {}",
                            pid, parent.time_event.timestamp, obj.time_event.timestamp
                        ),
                    });
                }
            }
        }
    }

    // 12. Proof chain validation
    if let Some(ref chain) = obj.proof_chain {
        if let Some(ref pred_id) = chain.predecessor_proof_id {
            // Successor proof — predecessor fields must be present and consistent
            match &chain.predecessor_payload_hash {
                None => {
                    failures.push(Failure {
                        code: FailureCode::ChainPredecessorMissing,
                        reason: format!(
                            "proof declares predecessor {} but has no predecessor hash",
                            pred_id
                        ),
                    });
                }
                Some(_) => {
                    // Hash is present and signed — the chain link is structurally valid.
                    // Full chain walk (loading the predecessor bundle) is the caller's
                    // responsibility; the verifier validates what's inside this proof.
                }
            }
        }
        // Origin proof (predecessor_proof_id is None) — no chain checks needed
    }

    let status = if failures.is_empty() {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Invalid
    };

    VerificationResult {
        status,
        object_id: obj.object_id,
        failures,
    }
}

pub fn verify_from_proof_bundle(bundle: &ProofBundle, artifact_bytes: &[u8]) -> VerificationResult {
    verify_from_proof_bundle_with_trust(bundle, artifact_bytes, None)
}

/// Predecessor bundle paired with its artifact bytes.
pub struct ChainLink {
    pub bundle: ProofBundle,
    pub artifact_bytes: Vec<u8>,
}

/// Verify a proof and optionally walk its full chain.
///
/// If the proof has chain linkage and `predecessors` are supplied, each predecessor
/// is verified recursively back to the origin. Linkage fields (object_id, payload_hash)
/// are cross-checked at each step.
pub fn verify_chain(
    bundle: &ProofBundle,
    artifact_bytes: &[u8],
    predecessors: &[ChainLink],
) -> ChainVerificationResult {
    // 1. Verify the current proof itself
    let current = verify_from_proof_bundle(bundle, artifact_bytes);
    if current.status != VerificationStatus::Verified {
        return ChainVerificationResult {
            chain_status: ChainStatus::HistoryBroken,
            depth: 1,
            failures: current.failures,
        };
    }

    // 2. Determine chain status
    let chain = match &bundle.object.proof_chain {
        None => {
            return ChainVerificationResult {
                chain_status: ChainStatus::Standalone,
                depth: 1,
                failures: vec![],
            };
        }
        Some(c) => c,
    };

    if chain.predecessor_proof_id.is_none() {
        return ChainVerificationResult {
            chain_status: ChainStatus::Origin,
            depth: 1,
            failures: vec![],
        };
    }

    // 3. This is a successor — walk the chain
    if predecessors.is_empty() {
        return ChainVerificationResult {
            chain_status: ChainStatus::HistoryIncomplete,
            depth: 1,
            failures: vec![],
        };
    }

    let mut failures: Vec<Failure> = Vec::new();
    let mut visited = std::collections::HashSet::new();
    visited.insert(bundle.object.object_id);

    let mut current_chain = Some(chain);
    let mut depth: usize = 1;
    let mut current_creator_key = bundle.creator_identity.public_key_hex.clone();

    while let Some(chain_ref) = current_chain {
        let pred_id = match &chain_ref.predecessor_proof_id {
            Some(id) => *id,
            None => break, // reached origin
        };

        let pred_hash = match &chain_ref.predecessor_payload_hash {
            Some(h) => h.clone(),
            None => {
                failures.push(Failure {
                    code: FailureCode::ChainPredecessorMissing,
                    reason: format!("predecessor {} declared without hash", pred_id),
                });
                break;
            }
        };

        // Cycle detection
        if !visited.insert(pred_id) {
            failures.push(Failure {
                code: FailureCode::ChainCycleDetected,
                reason: format!("cycle at {}", pred_id),
            });
            break;
        }

        // Find the predecessor bundle
        let pred_link = predecessors
            .iter()
            .find(|l| l.bundle.object.object_id == pred_id);
        let pred_link = match pred_link {
            Some(l) => l,
            None => {
                failures.push(Failure {
                    code: FailureCode::ChainPredecessorBundleMissing,
                    reason: format!("predecessor bundle {} not supplied", pred_id),
                });
                break;
            }
        };

        // Check predecessor payload hash matches
        if pred_link.bundle.object.payload_hash != pred_hash {
            failures.push(Failure {
                code: FailureCode::ChainPredecessorHashMismatch,
                reason: format!(
                    "predecessor {} hash mismatch: expected {}, got {}",
                    pred_id, pred_hash, pred_link.bundle.object.payload_hash
                ),
            });
            break;
        }

        // Key continuity check
        let pred_creator_key = pred_link.bundle.creator_identity.public_key_hex.clone();
        if pred_creator_key != current_creator_key {
            // Different key — need valid delegation
            match &chain_ref.key_delegation {
                None => {
                    failures.push(Failure {
                        code: FailureCode::ChainDelegationMissing,
                        reason: "key changed without delegation".into(),
                    });
                    break;
                }
                Some(deleg) => {
                    if !verify_delegation(
                        deleg,
                        &pred_creator_key,
                        &current_creator_key,
                        chain_ref.lineage_id,
                    ) {
                        failures.push(Failure {
                            code: FailureCode::ChainDelegationInvalid,
                            reason: "delegation signature invalid or fields mismatch".into(),
                        });
                        break;
                    }
                }
            }
        }

        // Verify predecessor proof
        let pred_result = verify_from_proof_bundle(&pred_link.bundle, &pred_link.artifact_bytes);
        if pred_result.status != VerificationStatus::Verified {
            failures.push(Failure {
                code: FailureCode::ChainPredecessorInvalid,
                reason: format!("predecessor {} failed verification", pred_id),
            });
            failures.extend(pred_result.failures);
            break;
        }

        depth += 1;
        current_creator_key = pred_creator_key;
        current_chain = pred_link.bundle.object.proof_chain.as_ref();
    }

    let status = if failures.is_empty() {
        ChainStatus::FullHistoryVerified
    } else {
        ChainStatus::HistoryBroken
    };

    ChainVerificationResult {
        chain_status: status,
        depth,
        failures,
    }
}

/// Verify a key delegation signature.
pub fn verify_delegation(
    deleg: &KeyDelegation,
    expected_from_key: &str,
    expected_to_key: &str,
    expected_lineage: uuid::Uuid,
) -> bool {
    if deleg.from_key_hex != expected_from_key {
        return false;
    }
    if deleg.to_key_hex != expected_to_key {
        return false;
    }
    if deleg.lineage_id != expected_lineage {
        return false;
    }

    #[derive(serde::Serialize)]
    struct DelegPayload<'a> {
        delegation_id: &'a uuid::Uuid,
        lineage_id: &'a uuid::Uuid,
        from_key_hex: &'a str,
        to_key_hex: &'a str,
        delegated_at: &'a str,
    }

    let payload = DelegPayload {
        delegation_id: &deleg.delegation_id,
        lineage_id: &deleg.lineage_id,
        from_key_hex: &deleg.from_key_hex,
        to_key_hex: &deleg.to_key_hex,
        delegated_at: &deleg.delegated_at,
    };

    crypto::verify_json_signature(&deleg.from_key_hex, &payload, &deleg.signature).is_ok()
}

/// Create a signed key delegation from old key to new key.
pub fn create_delegation(
    lineage_id: uuid::Uuid,
    old_key: &crypto::KeyPair,
    new_key_hex: &str,
) -> KeyDelegation {
    let deleg_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();

    #[derive(serde::Serialize)]
    struct DelegPayload<'a> {
        delegation_id: &'a uuid::Uuid,
        lineage_id: &'a uuid::Uuid,
        from_key_hex: &'a str,
        to_key_hex: &'a str,
        delegated_at: &'a str,
    }

    let from_hex = old_key.public_key_hex();
    let payload = DelegPayload {
        delegation_id: &deleg_id,
        lineage_id: &lineage_id,
        from_key_hex: &from_hex,
        to_key_hex: new_key_hex,
        delegated_at: &now,
    };
    let sig = old_key.sign_json(&payload);

    KeyDelegation {
        delegation_id: deleg_id,
        lineage_id,
        from_key_hex: from_hex,
        to_key_hex: new_key_hex.to_string(),
        delegated_at: now,
        signature: sig,
    }
}

pub fn verify_from_proof_bundle_with_trust(
    bundle: &ProofBundle,
    artifact_bytes: &[u8],
    trust_store: Option<time_core::tsa::TrustStore>,
) -> VerificationResult {
    let input = VerificationInput {
        object: bundle.object.clone(),
        artifact_bytes: artifact_bytes.to_vec(),
        creator_identity: bundle.creator_identity.clone(),
        module_registration: bundle.module_registration.clone(),
        time_authority_identity: bundle.time_authority_identity.clone(),
        policy_evaluator_identity: bundle.policy_evaluator_identity.clone(),
        predecessor_time_event: bundle.predecessor_time_event.clone(),
        parent_objects: bundle.parent_objects.clone(),
        tsa_trust_store: trust_store,
    };
    verify_object(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_detects_failures() {
        // A minimal broken object should produce failures, not panic
        let kp = winstack_crypto::KeyPair::generate();
        let id = uuid::Uuid::new_v4();
        let obj = SealedObject {
            object_id: id,
            object_class: ObjectClass::Native,
            payload_hash: "wrong".into(),
            artifact_size_bytes: 5,
            parent_ids: vec![],
            origin: OriginRecord {
                origin_record_id: uuid::Uuid::new_v4(),
                object_id: id,
                object_class: ObjectClass::Native,
                creator_identity_id: uuid::Uuid::new_v4(),
                module_identity_id: uuid::Uuid::new_v4(),
                time_authority_identity_id: uuid::Uuid::new_v4(),
                created_at: "t".into(),
                protocol: "V1".into(),
                foreign_source_uri: None,
                ai_model: None,
                signature: "bad".into(),
            },
            time_event: ChainedTimeEvent {
                time_event_id: uuid::Uuid::new_v4(),
                timestamp: "t".into(),
                time_authority_identity_id: uuid::Uuid::new_v4(),
                predecessor_event_id: None,
                predecessor_hash: None,
                payload_hash: "ph".into(),
                signature: "bad".into(),
                time_source: canon_types::TimeSource::Local,
                rfc3161_token: None,
                anchored_time: None,
            },
            policy_proof: PolicyProof {
                policy_proof_id: uuid::Uuid::new_v4(),
                decision: PolicyDecision::Permit,
                policy_version: 1,
                context_hash: "ch".into(),
                evaluator_identity_id: uuid::Uuid::new_v4(),
                evaluated_at: "t".into(),
                signature: "bad".into(),
            },
            ai_generation: None,
            import_declaration: None,
            object_signature: "bad".into(),
            protocol: "V1".into(),
            proof_chain: None,
        };

        let ident = IdentityRecord {
            identity_id: uuid::Uuid::new_v4(),
            kind: IdentityKind::Personal,
            status: IdentityStatus::Active,
            public_key_hex: kp.public_key_hex(),
            created_at: "t".into(),
            signature: "s".into(),
        };

        let module = ModuleRegistration {
            module_id: uuid::Uuid::new_v4(),
            kind: ModuleKind::Document,
            scope: "*".into(),
            binary_hash: "h".into(),
            registered_by: uuid::Uuid::new_v4(),
            signature: "s".into(),
        };

        let input = VerificationInput {
            object: obj,
            artifact_bytes: b"hello".to_vec(),
            creator_identity: ident.clone(),
            module_registration: module,
            time_authority_identity: ident.clone(),
            policy_evaluator_identity: ident,
            predecessor_time_event: None,
            parent_objects: vec![],
            tsa_trust_store: None,
        };
        let result = verify_object(&input);
        assert_eq!(result.status, VerificationStatus::Invalid);
        assert!(!result.failures.is_empty());
    }
}
