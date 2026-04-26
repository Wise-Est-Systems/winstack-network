use canon_types::*;
use registry_core::test_registry;
use uuid::Uuid;
use winstack_crypto as crypto;

// ---------------------------------------------------------------------------
// 1. Valid native object seals and re-verifies
// ---------------------------------------------------------------------------
#[test]
fn valid_native_object() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"hello world".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    assert_eq!(obj.object_class, ObjectClass::Native);
    assert_eq!(obj.origin.object_class, ObjectClass::Native);
    assert_eq!(obj.origin.creator_identity_id, creator_id);

    // Re-verify from store
    let result = reg.verify_object(&obj.object_id).unwrap();
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// 2. Valid AI object seals and re-verifies
// ---------------------------------------------------------------------------
#[test]
fn valid_ai_object() {
    let (mut reg, creator_id, _, ai_mod_id) = test_registry();
    let obj = reg
        .seal_ai(AiBirthProposal {
            artifact_bytes: b"ai output content".to_vec(),
            creator_identity_id: creator_id,
            module_id: ai_mod_id,
            parent_ids: vec![],
            model: AiModelInfo {
                model_name: "test-model".into(),
                model_version: "1.0".into(),
            },
            prompt_hash: crypto::sha256_hex(b"test prompt"),
            tsa_attachment: None,
        })
        .unwrap();

    assert_eq!(obj.object_class, ObjectClass::AiGenerated);
    assert!(obj.ai_generation.is_some());
    assert_eq!(obj.origin.object_class, ObjectClass::AiGenerated);

    let result = reg.verify_object(&obj.object_id).unwrap();
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// 3. Valid sealed import
// ---------------------------------------------------------------------------
#[test]
fn valid_sealed_import() {
    let (mut reg, creator_id, _, _) = test_registry();

    // Need an import module
    let ck_bytes = reg
        .identity_store
        .get_key(&creator_id)
        .unwrap()
        .secret_key_bytes();
    let ck = winstack_crypto::KeyPair::from_secret_bytes(&ck_bytes);
    let (import_mod_id, _) = reg.module_registry.register(
        ModuleKind::Import,
        "imports/*",
        &crypto::sha256_hex(b"import-bin"),
        creator_id,
        &ck,
    );

    let obj = reg
        .seal_import(ImportBirthProposal {
            artifact_bytes: b"external document".to_vec(),
            creator_identity_id: creator_id,
            module_id: import_mod_id,
            parent_ids: vec![],
            source_uri: "https://example.com/doc.pdf".into(),
            claimed_content_type: "application/pdf".into(),
            reason: "archival reference".into(),
            tsa_attachment: None,
        })
        .unwrap();

    assert_eq!(obj.object_class, ObjectClass::SealedImport);
    assert!(obj.import_declaration.is_some());
    assert_eq!(obj.object_class.trust_class(), TrustClass::Foreign);

    let result = reg.verify_object(&obj.object_id).unwrap();
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// 4. Valid lineage chain
// ---------------------------------------------------------------------------
#[test]
fn valid_lineage_chain() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    let parent = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"parent".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    // Small delay to ensure timestamp ordering
    std::thread::sleep(std::time::Duration::from_millis(10));

    let child = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"child".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![parent.object_id],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    assert_eq!(child.parent_ids, vec![parent.object_id]);

    let result = reg.verify_object(&child.object_id).unwrap();
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// 5. Valid non-genesis time chain
// ---------------------------------------------------------------------------
#[test]
fn valid_non_genesis_time_chain() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    // First object uses genesis time event
    let _first = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"first".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    // Second object has non-genesis time event
    let second = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"second".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    assert!(!second.time_event.is_genesis());
    assert!(second.time_event.predecessor_event_id.is_some());

    let result = reg.verify_object(&second.object_id).unwrap();
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// 6. Missing policy proof fails (simulated via verifier)
// ---------------------------------------------------------------------------
#[test]
fn missing_policy_proof_fails() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"test".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    // Manually build a verification with tampered policy
    let artifact = reg.object_store.get_artifact(&obj.object_id).unwrap();
    let mut tampered = obj.clone();
    tampered.policy_proof.decision = PolicyDecision::Deny;

    let creator = reg
        .identity_store
        .get(&obj.origin.creator_identity_id)
        .unwrap()
        .clone();
    let module = reg
        .module_registry
        .get(&obj.origin.module_identity_id)
        .unwrap()
        .clone();
    let ta = reg
        .identity_store
        .get(&obj.origin.time_authority_identity_id)
        .unwrap()
        .clone();
    let pe = reg
        .identity_store
        .get(&obj.policy_proof.evaluator_identity_id)
        .unwrap()
        .clone();

    let input = verifier::VerificationInput {
        object: tampered,
        artifact_bytes: artifact.to_vec(),
        creator_identity: creator,
        module_registration: module,
        time_authority_identity: ta,
        policy_evaluator_identity: pe,
        predecessor_time_event: None,
        parent_objects: vec![],
        tsa_trust_store: None,
    };

    let result = verifier::verify_object(&input);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::PolicyDecisionNotPermit));
}

// ---------------------------------------------------------------------------
// 7. Missing AI generation record fails
// ---------------------------------------------------------------------------
#[test]
fn missing_ai_generation_record_fails() {
    let (mut reg, creator_id, _, ai_mod_id) = test_registry();

    let obj = reg
        .seal_ai(AiBirthProposal {
            artifact_bytes: b"ai content".to_vec(),
            creator_identity_id: creator_id,
            module_id: ai_mod_id,
            parent_ids: vec![],
            model: AiModelInfo {
                model_name: "m".into(),
                model_version: "1".into(),
            },
            prompt_hash: crypto::sha256_hex(b"prompt"),
            tsa_attachment: None,
        })
        .unwrap();

    // Tamper: remove AI generation record
    let artifact = reg.object_store.get_artifact(&obj.object_id).unwrap();
    let mut tampered = obj.clone();
    tampered.ai_generation = None;

    let creator = reg
        .identity_store
        .get(&obj.origin.creator_identity_id)
        .unwrap()
        .clone();
    let module = reg
        .module_registry
        .get(&obj.origin.module_identity_id)
        .unwrap()
        .clone();
    let ta = reg
        .identity_store
        .get(&obj.origin.time_authority_identity_id)
        .unwrap()
        .clone();
    let pe = reg
        .identity_store
        .get(&obj.policy_proof.evaluator_identity_id)
        .unwrap()
        .clone();

    let input = verifier::VerificationInput {
        object: tampered,
        artifact_bytes: artifact.to_vec(),
        creator_identity: creator,
        module_registration: module,
        time_authority_identity: ta,
        policy_evaluator_identity: pe,
        predecessor_time_event: None,
        parent_objects: vec![],
        tsa_trust_store: None,
    };

    let result = verifier::verify_object(&input);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::AiGenerationRecordMissing));
}

// ---------------------------------------------------------------------------
// 8. Missing parent fails
// ---------------------------------------------------------------------------
#[test]
fn missing_parent_fails() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    let fake_parent = Uuid::new_v4(); // does not exist
    let result = reg.seal_native(NativeBirthProposal {
        artifact_bytes: b"orphan".to_vec(),
        creator_identity_id: creator_id,
        module_id,
        parent_ids: vec![fake_parent],
        tsa_attachment: None,
        proof_chain: None,
    });

    assert!(result.is_err());
    match result {
        Err(registry_core::RegistryError::Rejected(r)) => {
            assert_eq!(r.code, RejectCode::LineageParentMissing);
        }
        other => panic!("expected LineageParentMissing, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 9. Invalid parent fails verification
// ---------------------------------------------------------------------------
#[test]
fn invalid_parent_fails_verification() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    let parent = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"parent".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));

    let child = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"child".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![parent.object_id],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    // Verify child with tampered parent (wrong timestamp - future)
    let artifact = reg.object_store.get_artifact(&child.object_id).unwrap();
    let mut bad_parent = parent.clone();
    bad_parent.time_event.timestamp = "9999-12-31T23:59:59+00:00".to_string();

    let creator = reg
        .identity_store
        .get(&child.origin.creator_identity_id)
        .unwrap()
        .clone();
    let module_reg = reg
        .module_registry
        .get(&child.origin.module_identity_id)
        .unwrap()
        .clone();
    let ta = reg
        .identity_store
        .get(&child.origin.time_authority_identity_id)
        .unwrap()
        .clone();
    let pe = reg
        .identity_store
        .get(&child.policy_proof.evaluator_identity_id)
        .unwrap()
        .clone();

    let pred = child
        .time_event
        .predecessor_event_id
        .and_then(|pid| reg.time_authority.get_event(&pid).cloned());

    let input = verifier::VerificationInput {
        object: child.clone(),
        artifact_bytes: artifact.to_vec(),
        creator_identity: creator,
        module_registration: module_reg,
        time_authority_identity: ta,
        policy_evaluator_identity: pe,
        predecessor_time_event: pred,
        parent_objects: vec![bad_parent],
        tsa_trust_store: None,
    };

    let result = verifier::verify_object(&input);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::LineageParentTimestampViolation));
}

// ---------------------------------------------------------------------------
// 10. Self-cycle fails
// ---------------------------------------------------------------------------
#[test]
fn self_cycle_fails() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    // We can't create a self-cycle through the registry since object_id is
    // generated internally. But we can test the verifier directly.
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"test".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    let artifact = reg.object_store.get_artifact(&obj.object_id).unwrap();
    let mut tampered = obj.clone();
    tampered.parent_ids = vec![obj.object_id]; // self-cycle

    let creator = reg
        .identity_store
        .get(&obj.origin.creator_identity_id)
        .unwrap()
        .clone();
    let module_reg = reg
        .module_registry
        .get(&obj.origin.module_identity_id)
        .unwrap()
        .clone();
    let ta = reg
        .identity_store
        .get(&obj.origin.time_authority_identity_id)
        .unwrap()
        .clone();
    let pe = reg
        .identity_store
        .get(&obj.policy_proof.evaluator_identity_id)
        .unwrap()
        .clone();

    let input = verifier::VerificationInput {
        object: tampered,
        artifact_bytes: artifact.to_vec(),
        creator_identity: creator,
        module_registration: module_reg,
        time_authority_identity: ta,
        policy_evaluator_identity: pe,
        predecessor_time_event: None,
        parent_objects: vec![],
        tsa_trust_store: None,
    };

    let result = verifier::verify_object(&input);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::LineageSelfCycle));
}

// ---------------------------------------------------------------------------
// 11. Wrong predecessor fails
// ---------------------------------------------------------------------------
#[test]
fn wrong_predecessor_fails() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    let _first = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"first".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    let second = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"second".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    assert!(!second.time_event.is_genesis());

    // Feed a wrong predecessor
    let artifact = reg.object_store.get_artifact(&second.object_id).unwrap();
    let creator = reg
        .identity_store
        .get(&second.origin.creator_identity_id)
        .unwrap()
        .clone();
    let module_reg = reg
        .module_registry
        .get(&second.origin.module_identity_id)
        .unwrap()
        .clone();
    let ta = reg
        .identity_store
        .get(&second.origin.time_authority_identity_id)
        .unwrap()
        .clone();
    let pe = reg
        .identity_store
        .get(&second.policy_proof.evaluator_identity_id)
        .unwrap()
        .clone();

    // Make a fake predecessor with wrong content
    let fake_pred = ChainedTimeEvent {
        time_event_id: second.time_event.predecessor_event_id.unwrap(),
        timestamp: "fake".into(),
        time_authority_identity_id: Uuid::new_v4(),
        predecessor_event_id: None,
        predecessor_hash: None,
        payload_hash: "fake".into(),
        signature: "fake".into(),
        time_source: canon_types::TimeSource::Local,
        rfc3161_token: None,
        anchored_time: None,
    };

    let input = verifier::VerificationInput {
        object: second.clone(),
        artifact_bytes: artifact.to_vec(),
        creator_identity: creator,
        module_registration: module_reg,
        time_authority_identity: ta,
        policy_evaluator_identity: pe,
        predecessor_time_event: Some(fake_pred),
        parent_objects: vec![],
        tsa_trust_store: None,
    };

    let result = verifier::verify_object(&input);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::TimePredecessorHashMismatch));
}

// ---------------------------------------------------------------------------
// 12. Missing predecessor fails
// ---------------------------------------------------------------------------
#[test]
fn missing_predecessor_fails() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    let _first = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"first".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    let second = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"second".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    assert!(!second.time_event.is_genesis());

    let artifact = reg.object_store.get_artifact(&second.object_id).unwrap();
    let creator = reg
        .identity_store
        .get(&second.origin.creator_identity_id)
        .unwrap()
        .clone();
    let module_reg = reg
        .module_registry
        .get(&second.origin.module_identity_id)
        .unwrap()
        .clone();
    let ta = reg
        .identity_store
        .get(&second.origin.time_authority_identity_id)
        .unwrap()
        .clone();
    let pe = reg
        .identity_store
        .get(&second.policy_proof.evaluator_identity_id)
        .unwrap()
        .clone();

    let input = verifier::VerificationInput {
        object: second.clone(),
        artifact_bytes: artifact.to_vec(),
        creator_identity: creator,
        module_registration: module_reg,
        time_authority_identity: ta,
        policy_evaluator_identity: pe,
        predecessor_time_event: None, // missing!
        parent_objects: vec![],
        tsa_trust_store: None,
    };

    let result = verifier::verify_object(&input);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::TimePredecessorMissing));
}

// ---------------------------------------------------------------------------
// 13. Module scope mismatch fails
// ---------------------------------------------------------------------------
#[test]
fn module_scope_mismatch_fails() {
    let (mut reg, creator_id, _, _) = test_registry();

    // Register an import module
    let ck_bytes = reg
        .identity_store
        .get_key(&creator_id)
        .unwrap()
        .secret_key_bytes();
    let ck = winstack_crypto::KeyPair::from_secret_bytes(&ck_bytes);
    let (import_mod_id, _) = reg.module_registry.register(
        ModuleKind::Import,
        "imports/*",
        &crypto::sha256_hex(b"imp-bin"),
        creator_id,
        &ck,
    );

    // Try to seal a native object with an import module
    let _result = reg.seal_native(NativeBirthProposal {
        artifact_bytes: b"test".to_vec(),
        creator_identity_id: creator_id,
        module_id: import_mod_id, // wrong kind for native
        parent_ids: vec![],
        tsa_attachment: None,
        proof_chain: None,
    });

    // The registry should still succeed for Native (any module kind is allowed)
    // But if we try to seal an AI object with import module, it should fail
    let ai_result = reg.seal_ai(AiBirthProposal {
        artifact_bytes: b"ai".to_vec(),
        creator_identity_id: creator_id,
        module_id: import_mod_id, // Import module, but AI object
        parent_ids: vec![],
        model: AiModelInfo {
            model_name: "m".into(),
            model_version: "1".into(),
        },
        prompt_hash: crypto::sha256_hex(b"p"),
        tsa_attachment: None,
    });

    assert!(ai_result.is_err());
}

// ---------------------------------------------------------------------------
// 14. Proof bundle is self-contained
// ---------------------------------------------------------------------------
#[test]
fn proof_bundle_self_contained() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"bundle test".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    let artifact = reg.object_store.get_artifact(&obj.object_id).unwrap();

    // Verify from bundle alone (offline)
    let result = verifier::verify_from_proof_bundle(&bundle, artifact);
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// 15. Session identity cannot create native
// ---------------------------------------------------------------------------
#[test]
fn session_cannot_create_native() {
    let (mut reg, _creator_id, module_id, _) = test_registry();

    let (session_id, _) = reg.identity_store.create_identity(IdentityKind::Session);

    let result = reg.seal_native(NativeBirthProposal {
        artifact_bytes: b"test".to_vec(),
        creator_identity_id: session_id,
        module_id,
        parent_ids: vec![],
        tsa_attachment: None,
        proof_chain: None,
    });

    assert!(result.is_err());
    match result {
        Err(registry_core::RegistryError::Rejected(r)) => {
            assert_eq!(r.code, RejectCode::SessionCannotCreateNative);
        }
        other => panic!("expected SessionCannotCreateNative, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 16. Proof bundle verifies without any node state (proof independence)
// ---------------------------------------------------------------------------
#[test]
fn proof_bundle_verifies_without_node_state() {
    // Create a registry, seal an object, extract the proof bundle
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"independent verification test".to_vec();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();

    // Serialize and deserialize to simulate receiving it from someone else
    let json = serde_json::to_string(&bundle).unwrap();
    let received: canon_types::ProofBundle = serde_json::from_str(&json).unwrap();

    // Verify using ONLY the proof bundle and the file bytes — no registry, no store
    let result = verifier::verify_from_proof_bundle(&received, &artifact);
    assert_eq!(result.status, VerificationStatus::Verified);
    assert!(result.failures.is_empty());
}

// ---------------------------------------------------------------------------
// 17. Proof bundle detects tamper without node state
// ---------------------------------------------------------------------------
#[test]
fn proof_bundle_detects_tamper_without_node_state() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"original".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let received: canon_types::ProofBundle = serde_json::from_str(&json).unwrap();

    // Verify with tampered bytes — should fail with PayloadHashMismatch
    let result = verifier::verify_from_proof_bundle(&received, b"tampered");
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::PayloadHashMismatch));
}

// ---------------------------------------------------------------------------
// 18. Time source is marked as Local
// ---------------------------------------------------------------------------
#[test]
fn time_source_is_local() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"time source test".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(obj.time_event.time_source, canon_types::TimeSource::Local);
    assert!(obj.time_event.rfc3161_token.is_none());
    assert!(obj.time_event.anchored_time.is_none());
}

// ---------------------------------------------------------------------------
// 19. External timestamp with valid TSA token
// ---------------------------------------------------------------------------
#[test]
fn synthetic_tsa_token_rejected_by_full_verification() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"tsa anchored content".to_vec();
    let payload_hash = winstack_crypto::sha256_hex(&artifact);
    let hash_bytes = hex::decode(&payload_hash).unwrap();

    // Synthetic TSA response has correct hash but no real CMS signatures/certs.
    // Full CMS verification should reject it at seal time (fail-closed).
    let tsa_resp = time_core::tsa::build_test_tsa_response(&hash_bytes);
    let info = time_core::tsa::parse_timestamp_response(&tsa_resp).unwrap();

    let result = reg.seal_native(NativeBirthProposal {
        artifact_bytes: artifact,
        creator_identity_id: creator_id,
        module_id,
        parent_ids: vec![],
        tsa_attachment: Some(TsaAttachment {
            token_base64: B64.encode(&tsa_resp),
            anchored_time: info.gen_time,
        }),
        proof_chain: None,
    });

    // Must be rejected: unsigned test fixture cannot pass CMS verification
    assert!(result.is_err());
    match result {
        Err(registry_core::RegistryError::Rejected(r)) => {
            assert_eq!(r.code, RejectCode::VerificationFailed);
        }
        other => panic!("expected VerificationFailed, got {:?}", other),
    }
}

#[test]
fn tsa_hash_only_verification_still_works() {
    // verify_token (hash-only, no CMS) still works for basic parsing
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let artifact = b"hash check content".to_vec();
    let payload_hash = winstack_crypto::sha256_hex(&artifact);
    let hash_bytes = hex::decode(&payload_hash).unwrap();

    let tsa_resp = time_core::tsa::build_test_tsa_response(&hash_bytes);
    let token_b64 = B64.encode(&tsa_resp);

    // Hash-only verify passes (backward compat function)
    let info = time_core::tsa::verify_token(&token_b64, &payload_hash).unwrap();
    assert_eq!(info.message_hash_hex, payload_hash);

    // Full CMS verify fails (no certificates)
    let store = time_core::tsa::TrustStore::new();
    let full_result = time_core::tsa::verify_token_full(&token_b64, &payload_hash, &store);
    assert!(full_result.is_err());
}

// ---------------------------------------------------------------------------
// 20. External timestamp with wrong hash fails
// ---------------------------------------------------------------------------
#[test]
fn external_timestamp_wrong_hash_fails() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"content for wrong hash test".to_vec();

    // Build TSA response with WRONG hash (all zeros)
    let wrong_hash = [0u8; 32];
    let tsa_resp = time_core::tsa::build_test_tsa_response(&wrong_hash);
    let info = time_core::tsa::parse_timestamp_response(&tsa_resp).unwrap();

    // Seal should be rejected because the TSA token hash doesn't match (fail-closed)
    let result = reg.seal_native(NativeBirthProposal {
        artifact_bytes: artifact,
        creator_identity_id: creator_id,
        module_id,
        parent_ids: vec![],
        tsa_attachment: Some(TsaAttachment {
            token_base64: B64.encode(&tsa_resp),
            anchored_time: info.gen_time,
        }),
        proof_chain: None,
    });

    assert!(result.is_err());
    match result {
        Err(registry_core::RegistryError::Rejected(r)) => {
            assert_eq!(r.code, RejectCode::VerificationFailed);
        }
        other => panic!("expected VerificationFailed, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 21. External time source without token fails
// ---------------------------------------------------------------------------
#[test]
fn external_time_without_token_fails() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"missing token test".to_vec();

    let mut obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    // Manually set External without a token (simulates corruption)
    obj.time_event.time_source = canon_types::TimeSource::External;

    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    // Replace the object in the bundle with our tampered version
    let mut tampered_bundle = bundle;
    tampered_bundle.object.time_event.time_source = canon_types::TimeSource::External;
    tampered_bundle.object.time_event.rfc3161_token = None;

    let result = verifier::verify_from_proof_bundle(&tampered_bundle, &artifact);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::TsaTokenMissing));
}

// ---------------------------------------------------------------------------
// 22. Malformed TSA token fails
// ---------------------------------------------------------------------------
#[test]
fn malformed_tsa_token_fails() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"malformed token test".to_vec();

    // A malformed TSA token should cause the seal to be rejected (fail-closed)
    let result = reg.seal_native(NativeBirthProposal {
        artifact_bytes: artifact,
        creator_identity_id: creator_id,
        module_id,
        parent_ids: vec![],
        tsa_attachment: Some(TsaAttachment {
            token_base64: B64.encode(b"not valid DER"),
            anchored_time: "bad".into(),
        }),
        proof_chain: None,
    });

    assert!(result.is_err());
    match result {
        Err(registry_core::RegistryError::Rejected(r)) => {
            assert_eq!(r.code, RejectCode::VerificationFailed);
        }
        other => panic!("expected VerificationFailed, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 23. Local time proof still works (backward compat)
// ---------------------------------------------------------------------------
#[test]
fn local_time_backward_compat() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"backward compat".to_vec();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    assert_eq!(obj.time_event.time_source, canon_types::TimeSource::Local);
    assert!(obj.time_event.rfc3161_token.is_none());

    // Serialize, strip time_source and rfc3161_token to simulate old format
    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    let mut json_val: serde_json::Value = serde_json::to_value(&bundle).unwrap();
    json_val["object"]["time_event"]
        .as_object_mut()
        .unwrap()
        .remove("time_source");
    json_val["object"]["time_event"]
        .as_object_mut()
        .unwrap()
        .remove("rfc3161_token");
    json_val["object"]["time_event"]
        .as_object_mut()
        .unwrap()
        .remove("anchored_time");

    let old_bundle: canon_types::ProofBundle = serde_json::from_value(json_val).unwrap();
    assert_eq!(
        old_bundle.object.time_event.time_source,
        canon_types::TimeSource::Local
    );
    assert!(old_bundle.object.time_event.rfc3161_token.is_none());

    let result = verifier::verify_from_proof_bundle(&old_bundle, &artifact);
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// SECURITY: time_source downgrade attack is blocked
// ---------------------------------------------------------------------------
#[test]
fn time_source_downgrade_invalidates_signature() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"time source downgrade test".to_vec();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    // Tamper: change time_source from Local to External
    let mut bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    bundle.object.time_event.time_source = canon_types::TimeSource::External;

    // Signature should now fail because time_source is signed
    let result = verifier::verify_from_proof_bundle(&bundle, &artifact);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::TimeSignatureInvalid));
}

// ---------------------------------------------------------------------------
// SECURITY: rfc3161_token field tampering invalidates signature
// ---------------------------------------------------------------------------
#[test]
fn rfc3161_token_tampering_invalidates_signature() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"token tamper test".to_vec();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    // Tamper: inject a fake rfc3161_token into a Local time event
    let mut bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    bundle.object.time_event.rfc3161_token = Some("ZmFrZXRva2Vu".to_string());

    // Signature should fail because rfc3161_token is signed
    let result = verifier::verify_from_proof_bundle(&bundle, &artifact);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::TimeSignatureInvalid));
}

// ---------------------------------------------------------------------------
// SECURITY: policy version forgery is blocked
// ---------------------------------------------------------------------------
#[test]
fn policy_version_forgery_blocked() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"policy version test".to_vec();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    // Tamper: change the policy version to something other than CURRENT_POLICY_VERSION
    let mut bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    bundle.object.policy_proof.policy_version = 999;

    // Should fail: version 999 != CURRENT_POLICY_VERSION (1)
    let result = verifier::verify_from_proof_bundle(&bundle, &artifact);
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::PolicyProofSignatureInvalid));
}

// ---------------------------------------------------------------------------
// PRODUCTION: unknown protocol version rejected
// ---------------------------------------------------------------------------
#[test]
fn unknown_protocol_version_rejected() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"protocol gate test".to_vec();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    let mut bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    bundle.object.protocol = "V2".to_string();

    let result = verifier::verify_from_proof_bundle(&bundle, &artifact);
    assert_eq!(result.status, VerificationStatus::Invalid);
}

// ===========================================================================
// PROOF CHAINING TESTS
// ===========================================================================

// ---------------------------------------------------------------------------
// CHAIN: origin proof creation (no predecessor)
// ---------------------------------------------------------------------------
#[test]
fn chain_origin_proof() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"origin content".to_vec();
    let lineage_id = uuid::Uuid::new_v4();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id,
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();

    assert!(obj.proof_chain.is_some());
    let chain = obj.proof_chain.as_ref().unwrap();
    assert_eq!(chain.lineage_id, lineage_id);
    assert!(chain.predecessor_proof_id.is_none());

    let result = reg.verify_object(&obj.object_id).unwrap();
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// CHAIN: successor proof creation
// ---------------------------------------------------------------------------
#[test]
fn chain_successor_proof() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let lineage_id = uuid::Uuid::new_v4();

    // Create origin
    let origin_obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"version 1".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id,
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(10));

    // Create successor
    let succ_obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"version 2".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id,
                predecessor_proof_id: Some(origin_obj.object_id),
                predecessor_payload_hash: Some(origin_obj.payload_hash.clone()),
                key_delegation: None,
            }),
        })
        .unwrap();

    let chain = succ_obj.proof_chain.as_ref().unwrap();
    assert_eq!(chain.lineage_id, lineage_id);
    assert_eq!(chain.predecessor_proof_id, Some(origin_obj.object_id));
    assert_eq!(
        chain.predecessor_payload_hash.as_deref(),
        Some(origin_obj.payload_hash.as_str())
    );

    let result = reg.verify_object(&succ_obj.object_id).unwrap();
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// CHAIN: tampering with chain fields invalidates signature
// ---------------------------------------------------------------------------
#[test]
fn chain_tamper_invalidates_signature() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let lineage_id = uuid::Uuid::new_v4();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"chain tamper test".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id,
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();

    let mut bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    // Tamper: change the lineage_id
    bundle.object.proof_chain.as_mut().unwrap().lineage_id = uuid::Uuid::new_v4();

    let result = verifier::verify_from_proof_bundle(&bundle, b"chain tamper test");
    assert_eq!(result.status, VerificationStatus::Invalid);
    assert!(result
        .failures
        .iter()
        .any(|f| f.code == FailureCode::ObjectSignatureInvalid));
}

// ---------------------------------------------------------------------------
// CHAIN: standalone proof (no chain) still verifies
// ---------------------------------------------------------------------------
#[test]
fn chain_standalone_backward_compat() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"standalone".to_vec();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    assert!(obj.proof_chain.is_none());

    let result = reg.verify_object(&obj.object_id).unwrap();
    assert_eq!(result.status, VerificationStatus::Verified);

    // Also verify from bundle
    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    let result = verifier::verify_from_proof_bundle(&bundle, &artifact);
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ---------------------------------------------------------------------------
// CHAIN: successor with missing predecessor hash → INVALID
// ---------------------------------------------------------------------------
#[test]
fn chain_missing_predecessor_hash_rejected_at_seal() {
    let (mut reg, creator_id, module_id, _) = test_registry();

    // Declaring a predecessor without a hash should be rejected at seal time (fail-closed)
    let result = reg.seal_native(NativeBirthProposal {
        artifact_bytes: b"missing pred hash".to_vec(),
        creator_identity_id: creator_id,
        module_id,
        parent_ids: vec![],
        tsa_attachment: None,
        proof_chain: Some(ProofChain {
            lineage_id: uuid::Uuid::new_v4(),
            predecessor_proof_id: Some(uuid::Uuid::new_v4()),
            predecessor_payload_hash: None,
            key_delegation: None,
        }),
    });

    assert!(result.is_err());
    match result {
        Err(registry_core::RegistryError::Rejected(r)) => {
            assert_eq!(r.code, RejectCode::VerificationFailed);
        }
        other => panic!("expected VerificationFailed, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// CHAIN: old proof without chain fields deserializes and verifies
// ---------------------------------------------------------------------------
#[test]
fn chain_old_proof_format_compat() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let artifact = b"old format".to_vec();

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();

    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    let mut json_val: serde_json::Value = serde_json::to_value(&bundle).unwrap();

    // Strip proof_chain from JSON to simulate old format
    json_val["object"]
        .as_object_mut()
        .unwrap()
        .remove("proof_chain");

    let old_bundle: ProofBundle = serde_json::from_value(json_val).unwrap();
    assert!(old_bundle.object.proof_chain.is_none());

    let result = verifier::verify_from_proof_bundle(&old_bundle, &artifact);
    assert_eq!(result.status, VerificationStatus::Verified);
}

// ===========================================================================
// CHAIN WALK + KEY DELEGATION TESTS
// ===========================================================================

#[test]
fn chain_walk_full_history() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let lineage = uuid::Uuid::new_v4();
    let v1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v1".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let v2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v2".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: Some(v1.object_id),
                predecessor_payload_hash: Some(v1.payload_hash.clone()),
                key_delegation: None,
            }),
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let v3 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v3".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: Some(v2.object_id),
                predecessor_payload_hash: Some(v2.payload_hash.clone()),
                key_delegation: None,
            }),
        })
        .unwrap();
    let b3 = reg.build_proof_bundle(&v3.object_id).unwrap();
    let b2 = reg.build_proof_bundle(&v2.object_id).unwrap();
    let b1 = reg.build_proof_bundle(&v1.object_id).unwrap();
    let preds = vec![
        verifier::ChainLink {
            bundle: b2,
            artifact_bytes: b"v2".to_vec(),
        },
        verifier::ChainLink {
            bundle: b1,
            artifact_bytes: b"v1".to_vec(),
        },
    ];
    let cr = verifier::verify_chain(&b3, b"v3", &preds);
    assert_eq!(cr.chain_status, ChainStatus::FullHistoryVerified);
    assert_eq!(cr.depth, 3);
    assert!(cr.failures.is_empty());
}

#[test]
fn chain_walk_missing_predecessor() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let lineage = uuid::Uuid::new_v4();
    let v1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v1".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let v2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v2".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: Some(v1.object_id),
                predecessor_payload_hash: Some(v1.payload_hash.clone()),
                key_delegation: None,
            }),
        })
        .unwrap();
    let b2 = reg.build_proof_bundle(&v2.object_id).unwrap();
    let cr = verifier::verify_chain(&b2, b"v2", &[]);
    assert_eq!(cr.chain_status, ChainStatus::HistoryIncomplete);
}

#[test]
fn chain_walk_wrong_predecessor_content() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let lineage = uuid::Uuid::new_v4();
    let v1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v1".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let v2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v2".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: Some(v1.object_id),
                predecessor_payload_hash: Some(v1.payload_hash.clone()),
                key_delegation: None,
            }),
        })
        .unwrap();
    let b2 = reg.build_proof_bundle(&v2.object_id).unwrap();
    let b1 = reg.build_proof_bundle(&v1.object_id).unwrap();
    let preds = vec![verifier::ChainLink {
        bundle: b1,
        artifact_bytes: b"WRONG".to_vec(),
    }];
    let cr = verifier::verify_chain(&b2, b"v2", &preds);
    assert_eq!(cr.chain_status, ChainStatus::HistoryBroken);
    assert!(cr
        .failures
        .iter()
        .any(|f| f.code == FailureCode::ChainPredecessorInvalid));
}

#[test]
fn key_delegation_valid() {
    let old_key = winstack_crypto::KeyPair::generate();
    let new_key = winstack_crypto::KeyPair::generate();
    let lineage = uuid::Uuid::new_v4();
    let deleg = verifier::create_delegation(lineage, &old_key, &new_key.public_key_hex());
    assert!(verifier::verify_delegation(
        &deleg,
        &old_key.public_key_hex(),
        &new_key.public_key_hex(),
        lineage
    ));
}

#[test]
fn key_delegation_tampered_fails() {
    let old_key = winstack_crypto::KeyPair::generate();
    let new_key = winstack_crypto::KeyPair::generate();
    let lineage = uuid::Uuid::new_v4();
    let mut deleg = verifier::create_delegation(lineage, &old_key, &new_key.public_key_hex());
    deleg.to_key_hex = "aa".repeat(32);
    assert!(!verifier::verify_delegation(
        &deleg,
        &old_key.public_key_hex(),
        &"aa".repeat(32),
        lineage
    ));
}

#[test]
fn chain_walk_missing_delegation_fails() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let lineage = uuid::Uuid::new_v4();
    let v1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v1".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();
    let (creator2_id, _) = reg.identity_store.create_identity(IdentityKind::Personal);
    std::thread::sleep(std::time::Duration::from_millis(10));
    let v2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v2".to_vec(),
            creator_identity_id: creator2_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: Some(v1.object_id),
                predecessor_payload_hash: Some(v1.payload_hash.clone()),
                key_delegation: None,
            }),
        })
        .unwrap();
    let b2 = reg.build_proof_bundle(&v2.object_id).unwrap();
    let b1 = reg.build_proof_bundle(&v1.object_id).unwrap();
    let preds = vec![verifier::ChainLink {
        bundle: b1,
        artifact_bytes: b"v1".to_vec(),
    }];
    let cr = verifier::verify_chain(&b2, b"v2", &preds);
    assert_eq!(cr.chain_status, ChainStatus::HistoryBroken);
    assert!(cr
        .failures
        .iter()
        .any(|f| f.code == FailureCode::ChainDelegationMissing));
}

#[test]
fn chain_walk_with_valid_delegation() {
    let (mut reg, creator_id, module_id, _) = test_registry();
    let lineage = uuid::Uuid::new_v4();
    let v1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v1".to_vec(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();
    let (creator2_id, _) = reg.identity_store.create_identity(IdentityKind::Personal);
    let old_key_bytes = reg
        .identity_store
        .get_key(&creator_id)
        .unwrap()
        .secret_key_bytes();
    let old_key = winstack_crypto::KeyPair::from_secret_bytes(&old_key_bytes);
    let new_pub = reg
        .identity_store
        .get(&creator2_id)
        .unwrap()
        .public_key_hex
        .clone();
    let deleg = verifier::create_delegation(lineage, &old_key, &new_pub);
    std::thread::sleep(std::time::Duration::from_millis(10));
    let v2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v2".to_vec(),
            creator_identity_id: creator2_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lineage,
                predecessor_proof_id: Some(v1.object_id),
                predecessor_payload_hash: Some(v1.payload_hash.clone()),
                key_delegation: Some(deleg),
            }),
        })
        .unwrap();
    let b2 = reg.build_proof_bundle(&v2.object_id).unwrap();
    let b1 = reg.build_proof_bundle(&v1.object_id).unwrap();
    let preds = vec![verifier::ChainLink {
        bundle: b1,
        artifact_bytes: b"v1".to_vec(),
    }];
    let cr = verifier::verify_chain(&b2, b"v2", &preds);
    assert_eq!(cr.chain_status, ChainStatus::FullHistoryVerified);
    assert_eq!(cr.depth, 2);
    assert!(cr.failures.is_empty());
}

// ===========================================================================
// HARDENING TESTS — bringing total to 150
// ===========================================================================

// ── CRYPTO EDGE CASES ──

#[test]
fn empty_file_seals_and_verifies() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: vec![],
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let r = reg.verify_object(&obj.object_id).unwrap();
    assert_eq!(r.status, VerificationStatus::Verified);
}

#[test]
fn single_byte_file() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: vec![0x42],
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let r = verifier::verify_from_proof_bundle(&b, &[0x42]);
    assert_eq!(r.status, VerificationStatus::Verified);
}

#[test]
fn large_artifact_hash_deterministic() {
    let data = vec![0xAB; 1_000_000];
    let h1 = winstack_crypto::sha256_hex(&data);
    let h2 = winstack_crypto::sha256_hex(&data);
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 64);
}

#[test]
fn different_data_different_hash() {
    let h1 = winstack_crypto::sha256_hex(b"hello");
    let h2 = winstack_crypto::sha256_hex(b"hello!");
    assert_ne!(h1, h2);
}

#[test]
fn signature_with_wrong_key_fails() {
    let k1 = winstack_crypto::KeyPair::generate();
    let k2 = winstack_crypto::KeyPair::generate();
    let sig = k1.sign_bytes(b"test");
    assert!(winstack_crypto::verify_signature(&k2.public_key_hex(), b"test", &sig).is_err());
}

#[test]
fn signature_over_empty_data() {
    let kp = winstack_crypto::KeyPair::generate();
    let sig = kp.sign_bytes(b"");
    assert!(winstack_crypto::verify_signature(&kp.public_key_hex(), b"", &sig).is_ok());
}

// ── IDENTITY EDGE CASES ──

#[test]
fn revoked_identity_cannot_seal() {
    let (mut reg, cid, mid, _) = test_registry();
    reg.identity_store.revoke(&cid).unwrap();
    let r = reg.seal_native(NativeBirthProposal {
        artifact_bytes: b"x".to_vec(),
        creator_identity_id: cid,
        module_id: mid,
        parent_ids: vec![],
        tsa_attachment: None,
        proof_chain: None,
    });
    assert!(r.is_err());
}

#[test]
fn suspended_identity_cannot_seal() {
    let (mut reg, cid, mid, _) = test_registry();
    reg.identity_store.suspend(&cid).unwrap();
    let r = reg.seal_native(NativeBirthProposal {
        artifact_bytes: b"x".to_vec(),
        creator_identity_id: cid,
        module_id: mid,
        parent_ids: vec![],
        tsa_attachment: None,
        proof_chain: None,
    });
    assert!(r.is_err());
}

#[test]
fn nonexistent_creator_rejected() {
    let (mut reg, _, mid, _) = test_registry();
    let fake = Uuid::new_v4();
    let r = reg.seal_native(NativeBirthProposal {
        artifact_bytes: b"x".to_vec(),
        creator_identity_id: fake,
        module_id: mid,
        parent_ids: vec![],
        tsa_attachment: None,
        proof_chain: None,
    });
    assert!(r.is_err());
}

#[test]
fn nonexistent_module_rejected() {
    let (mut reg, cid, _, _) = test_registry();
    let fake = Uuid::new_v4();
    let r = reg.seal_native(NativeBirthProposal {
        artifact_bytes: b"x".to_vec(),
        creator_identity_id: cid,
        module_id: fake,
        parent_ids: vec![],
        tsa_attachment: None,
        proof_chain: None,
    });
    assert!(r.is_err());
}

#[test]
fn multiple_identities_independent() {
    let (mut reg, cid1, mid, _) = test_registry();
    let (cid2, _) = reg.identity_store.create_identity(IdentityKind::Personal);
    let o1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"by1".to_vec(),
            creator_identity_id: cid1,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let o2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"by2".to_vec(),
            creator_identity_id: cid2,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_ne!(o1.origin.creator_identity_id, o2.origin.creator_identity_id);
    assert_eq!(
        reg.verify_object(&o1.object_id).unwrap().status,
        VerificationStatus::Verified
    );
    assert_eq!(
        reg.verify_object(&o2.object_id).unwrap().status,
        VerificationStatus::Verified
    );
}

// ── OBJECT STORE ──

#[test]
fn object_store_is_immutable() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"immut".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    // Try to insert same object_id again
    let r = reg.object_store.insert(obj.clone(), b"immut".to_vec());
    assert!(r.is_err());
}

#[test]
fn artifact_bytes_retrievable() {
    let (mut reg, cid, mid, _) = test_registry();
    let data = b"retrieve me".to_vec();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: data.clone(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(
        reg.object_store.get_artifact(&obj.object_id).unwrap(),
        data.as_slice()
    );
}

// ── PROOF BUNDLE ──

#[test]
fn proof_bundle_roundtrip_json() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"roundtrip".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    let decoded: ProofBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.object.object_id, obj.object_id);
    assert_eq!(decoded.object.payload_hash, obj.payload_hash);
    let r = verifier::verify_from_proof_bundle(&decoded, b"roundtrip");
    assert_eq!(r.status, VerificationStatus::Verified);
}

#[test]
fn proof_bundle_contains_all_identities() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"ids".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    assert_eq!(
        b.creator_identity.identity_id,
        obj.origin.creator_identity_id
    );
    assert_eq!(
        b.module_registration.module_id,
        obj.origin.module_identity_id
    );
    assert_eq!(
        b.time_authority_identity.identity_id,
        obj.origin.time_authority_identity_id
    );
    assert_eq!(
        b.policy_evaluator_identity.identity_id,
        obj.policy_proof.evaluator_identity_id
    );
}

#[test]
fn proof_bundle_has_no_file_paths() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"privacy".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let json = serde_json::to_string(&b).unwrap();
    assert!(!json.contains("/Users/"));
    assert!(!json.contains("/home/"));
    assert!(!json.contains("/tmp/"));
    assert!(!json.contains("\\Users\\"));
}

// ── TAMPER DETECTION ──

#[test]
fn one_bit_change_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let mut data = vec![0u8; 100];
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: data.clone(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    data[50] ^= 1; // flip one bit
    let r = verifier::verify_from_proof_bundle(&b, &data);
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::PayloadHashMismatch));
}

#[test]
fn appended_byte_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let data = b"original".to_vec();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: data.clone(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let mut tampered = data.clone();
    tampered.push(0);
    let r = verifier::verify_from_proof_bundle(&b, &tampered);
    assert_eq!(r.status, VerificationStatus::Invalid);
}

#[test]
fn truncated_file_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let data = b"some content here".to_vec();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: data.clone(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let r = verifier::verify_from_proof_bundle(&b, &data[..5]);
    assert_eq!(r.status, VerificationStatus::Invalid);
}

#[test]
fn empty_vs_nonempty_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"not empty".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let r = verifier::verify_from_proof_bundle(&b, b"");
    assert_eq!(r.status, VerificationStatus::Invalid);
}

// ── SIGNATURE FORGERY ──

#[test]
fn forged_object_signature_fails() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"sig test".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.object_signature = "ff".repeat(64);
    let r = verifier::verify_from_proof_bundle(&b, b"sig test");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::ObjectSignatureInvalid));
}

#[test]
fn forged_time_signature_fails() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"time sig".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.time_event.signature = "ff".repeat(64);
    let r = verifier::verify_from_proof_bundle(&b, b"time sig");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::TimeSignatureInvalid));
}

#[test]
fn forged_policy_signature_fails() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"pol sig".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.policy_proof.signature = "ff".repeat(64);
    let r = verifier::verify_from_proof_bundle(&b, b"pol sig");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::PolicyProofSignatureInvalid));
}

#[test]
fn swapped_creator_key_fails() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"key swap".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let fake = winstack_crypto::KeyPair::generate();
    b.creator_identity.public_key_hex = fake.public_key_hex();
    let r = verifier::verify_from_proof_bundle(&b, b"key swap");
    assert_eq!(r.status, VerificationStatus::Invalid);
}

// ── POLICY ──

#[test]
fn policy_deny_changes_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"deny".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.policy_proof.decision = PolicyDecision::Deny;
    let r = verifier::verify_from_proof_bundle(&b, b"deny");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::PolicyDecisionNotPermit));
}

// ── ORIGIN RECORD ──

#[test]
fn origin_object_id_mismatch_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"origin".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.origin.object_id = Uuid::new_v4();
    let r = verifier::verify_from_proof_bundle(&b, b"origin");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::OriginObjectIdMismatch));
}

#[test]
fn origin_creator_mismatch_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"cre mis".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.origin.creator_identity_id = Uuid::new_v4();
    let r = verifier::verify_from_proof_bundle(&b, b"cre mis");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::OriginCreatorMismatch));
}

#[test]
fn origin_module_mismatch_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"mod mis".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.origin.module_identity_id = Uuid::new_v4();
    let r = verifier::verify_from_proof_bundle(&b, b"mod mis");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::OriginModuleMismatch));
}

// ── TIME ──

#[test]
fn time_authority_mismatch_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"ta mis".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.origin.time_authority_identity_id = Uuid::new_v4();
    let r = verifier::verify_from_proof_bundle(&b, b"ta mis");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::OriginTimeMismatch));
}

#[test]
fn time_events_are_chained() {
    let (mut reg, cid, mid, _) = test_registry();
    let o1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"t1".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let o2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"t2".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert!(o1.time_event.is_genesis() || o1.time_event.predecessor_event_id.is_some());
    assert!(o2.time_event.predecessor_event_id.is_some());
    assert_ne!(o1.time_event.time_event_id, o2.time_event.time_event_id);
}

// ── LINEAGE ──

#[test]
fn parent_child_lineage_valid() {
    let (mut reg, cid, mid, _) = test_registry();
    let parent = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"parent".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let child = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"child".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![parent.object_id],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(child.parent_ids, vec![parent.object_id]);
    assert_eq!(
        reg.verify_object(&child.object_id).unwrap().status,
        VerificationStatus::Verified
    );
}

#[test]
fn multi_parent_lineage() {
    let (mut reg, cid, mid, _) = test_registry();
    let p1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"p1".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let p2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"p2".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let child = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"child2".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![p1.object_id, p2.object_id],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(child.parent_ids.len(), 2);
    assert_eq!(
        reg.verify_object(&child.object_id).unwrap().status,
        VerificationStatus::Verified
    );
}

// ── GRAPH ──

#[test]
fn graph_tracks_children() {
    let (mut reg, cid, mid, _) = test_registry();
    let p = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"gp".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let _c = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"gc".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![p.object_id],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(reg.graph.child_count(p.object_id).unwrap(), 1);
}

// ── PROTOCOL ──

#[test]
fn protocol_v1_required() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"proto".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(obj.protocol, "V1");
}

#[test]
fn protocol_v99_rejected() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"v99".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.protocol = "V99".to_string();
    let r = verifier::verify_from_proof_bundle(&b, b"v99");
    assert_eq!(r.status, VerificationStatus::Invalid);
}

#[test]
fn protocol_empty_rejected() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"empty proto".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.protocol = "".to_string();
    let r = verifier::verify_from_proof_bundle(&b, b"empty proto");
    assert_eq!(r.status, VerificationStatus::Invalid);
}

// ── CHAIN ADVANCED ──

#[test]
fn chain_four_deep() {
    let (mut reg, cid, mid, _) = test_registry();
    let lin = Uuid::new_v4();
    let mut prev_id = None;
    let mut prev_hash = None;
    let mut bundles = vec![];
    for i in 0..4u8 {
        let data = vec![i; 10];
        std::thread::sleep(std::time::Duration::from_millis(10));
        let obj = reg
            .seal_native(NativeBirthProposal {
                artifact_bytes: data.clone(),
                creator_identity_id: cid,
                module_id: mid,
                parent_ids: vec![],
                tsa_attachment: None,
                proof_chain: Some(ProofChain {
                    lineage_id: lin,
                    predecessor_proof_id: prev_id,
                    predecessor_payload_hash: prev_hash.clone(),
                    key_delegation: None,
                }),
            })
            .unwrap();
        prev_id = Some(obj.object_id);
        prev_hash = Some(obj.payload_hash.clone());
        bundles.push((reg.build_proof_bundle(&obj.object_id).unwrap(), data));
    }
    let (last_b, last_d) = &bundles[3];
    let preds: Vec<verifier::ChainLink> = bundles[..3]
        .iter()
        .map(|(b, d)| verifier::ChainLink {
            bundle: b.clone(),
            artifact_bytes: d.clone(),
        })
        .collect();
    let cr = verifier::verify_chain(last_b, last_d, &preds);
    assert_eq!(cr.chain_status, ChainStatus::FullHistoryVerified);
    assert_eq!(cr.depth, 4);
}

#[test]
fn chain_lineage_id_consistent() {
    let (mut reg, cid, mid, _) = test_registry();
    let lin = Uuid::new_v4();
    let v1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"c1".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lin,
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let v2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"c2".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: lin,
                predecessor_proof_id: Some(v1.object_id),
                predecessor_payload_hash: Some(v1.payload_hash.clone()),
                key_delegation: None,
            }),
        })
        .unwrap();
    assert_eq!(
        v1.proof_chain.as_ref().unwrap().lineage_id,
        v2.proof_chain.as_ref().unwrap().lineage_id
    );
}

#[test]
fn chain_wrong_lineage_invalidates_sig() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"lin".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: Uuid::new_v4(),
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.proof_chain.as_mut().unwrap().lineage_id = Uuid::new_v4();
    let r = verifier::verify_from_proof_bundle(&b, b"lin");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::ObjectSignatureInvalid));
}

// ── KEY DELEGATION ADVANCED ──

#[test]
fn delegation_wrong_lineage_fails() {
    let old = winstack_crypto::KeyPair::generate();
    let new = winstack_crypto::KeyPair::generate();
    let lin1 = Uuid::new_v4();
    let lin2 = Uuid::new_v4();
    let deleg = verifier::create_delegation(lin1, &old, &new.public_key_hex());
    assert!(!verifier::verify_delegation(
        &deleg,
        &old.public_key_hex(),
        &new.public_key_hex(),
        lin2
    ));
}

#[test]
fn delegation_wrong_from_key_fails() {
    let old = winstack_crypto::KeyPair::generate();
    let new = winstack_crypto::KeyPair::generate();
    let other = winstack_crypto::KeyPair::generate();
    let lin = Uuid::new_v4();
    let deleg = verifier::create_delegation(lin, &old, &new.public_key_hex());
    assert!(!verifier::verify_delegation(
        &deleg,
        &other.public_key_hex(),
        &new.public_key_hex(),
        lin
    ));
}

#[test]
fn delegation_wrong_to_key_fails() {
    let old = winstack_crypto::KeyPair::generate();
    let new = winstack_crypto::KeyPair::generate();
    let other = winstack_crypto::KeyPair::generate();
    let lin = Uuid::new_v4();
    let deleg = verifier::create_delegation(lin, &old, &new.public_key_hex());
    assert!(!verifier::verify_delegation(
        &deleg,
        &old.public_key_hex(),
        &other.public_key_hex(),
        lin
    ));
}

// ── MULTIPLE SEALS ──

#[test]
fn seal_ten_objects_all_verify() {
    let (mut reg, cid, mid, _) = test_registry();
    let mut ids = vec![];
    for i in 0..10u8 {
        let obj = reg
            .seal_native(NativeBirthProposal {
                artifact_bytes: vec![i; 20],
                creator_identity_id: cid,
                module_id: mid,
                parent_ids: vec![],
                tsa_attachment: None,
                proof_chain: None,
            })
            .unwrap();
        ids.push(obj.object_id);
    }
    for id in &ids {
        assert_eq!(
            reg.verify_object(id).unwrap().status,
            VerificationStatus::Verified
        );
    }
}

#[test]
fn same_content_different_proofs() {
    let (mut reg, cid, mid, _) = test_registry();
    let data = b"duplicate".to_vec();
    let o1 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: data.clone(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let o2 = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: data.clone(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_ne!(o1.object_id, o2.object_id);
    assert_eq!(o1.payload_hash, o2.payload_hash);
    assert_eq!(
        reg.verify_object(&o1.object_id).unwrap().status,
        VerificationStatus::Verified
    );
    assert_eq!(
        reg.verify_object(&o2.object_id).unwrap().status,
        VerificationStatus::Verified
    );
}

// ── BACKWARD COMPAT ──

#[test]
fn old_proof_without_chain_or_tsa_verifies() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"old style".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let mut j: serde_json::Value = serde_json::to_value(&b).unwrap();
    j["object"].as_object_mut().unwrap().remove("proof_chain");
    j["object"]["time_event"]
        .as_object_mut()
        .unwrap()
        .remove("time_source");
    j["object"]["time_event"]
        .as_object_mut()
        .unwrap()
        .remove("rfc3161_token");
    j["object"]["time_event"]
        .as_object_mut()
        .unwrap()
        .remove("anchored_time");
    let old: ProofBundle = serde_json::from_value(j).unwrap();
    assert!(old.object.proof_chain.is_none());
    assert_eq!(old.object.time_event.time_source, TimeSource::Local);
    let r = verifier::verify_from_proof_bundle(&old, b"old style");
    assert_eq!(r.status, VerificationStatus::Verified);
}

// ── AI + IMPORT ──

#[test]
fn ai_object_without_generation_record_fails() {
    let (mut reg, cid, _, ai_mid) = test_registry();
    let obj = reg
        .seal_ai(AiBirthProposal {
            artifact_bytes: b"ai".to_vec(),
            creator_identity_id: cid,
            module_id: ai_mid,
            parent_ids: vec![],
            model: AiModelInfo {
                model_name: "m".into(),
                model_version: "1".into(),
            },
            prompt_hash: crypto::sha256_hex(b"p"),
            tsa_attachment: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.ai_generation = None;
    let r = verifier::verify_from_proof_bundle(&b, b"ai");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r
        .failures
        .iter()
        .any(|f| f.code == FailureCode::AiGenerationRecordMissing));
}

#[test]
fn sealed_import_is_foreign() {
    let (mut reg, cid, _, _) = test_registry();
    let ck = reg.identity_store.get_key(&cid).unwrap().secret_key_bytes();
    let k = winstack_crypto::KeyPair::from_secret_bytes(&ck);
    let (imp_mid, _) = reg.module_registry.register(
        ModuleKind::Import,
        "imp/*",
        &crypto::sha256_hex(b"imp"),
        cid,
        &k,
    );
    let obj = reg
        .seal_import(ImportBirthProposal {
            artifact_bytes: b"ext".to_vec(),
            creator_identity_id: cid,
            module_id: imp_mid,
            parent_ids: vec![],
            source_uri: "https://example.com".into(),
            claimed_content_type: "text/plain".into(),
            reason: "test".into(),
            tsa_attachment: None,
        })
        .unwrap();
    assert_eq!(obj.object_class, ObjectClass::SealedImport);
    assert_eq!(obj.object_class.trust_class(), TrustClass::Foreign);
}

// ── VERIFIER RESULT INTEGRITY ──

#[test]
fn verified_has_zero_failures() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"zero".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let r = reg.verify_object(&obj.object_id).unwrap();
    assert_eq!(r.status, VerificationStatus::Verified);
    assert!(r.failures.is_empty());
}

#[test]
fn invalid_has_at_least_one_failure() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"fail".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.object_signature = "00".repeat(64);
    let r = verifier::verify_from_proof_bundle(&b, b"fail");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(!r.failures.is_empty());
}

#[test]
fn multiple_failures_all_reported() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"multi".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.object_signature = "00".repeat(64);
    b.object.policy_proof.decision = PolicyDecision::Deny;
    b.object.origin.object_id = Uuid::new_v4();
    let r = verifier::verify_from_proof_bundle(&b, b"wrong bytes");
    assert_eq!(r.status, VerificationStatus::Invalid);
    assert!(r.failures.len() >= 3);
}

// ── OBJECT CLASS ──

#[test]
fn native_is_native_trust() {
    assert_eq!(ObjectClass::Native.trust_class(), TrustClass::Native);
}

#[test]
fn ai_is_native_trust() {
    assert_eq!(ObjectClass::AiGenerated.trust_class(), TrustClass::Native);
}

#[test]
fn import_is_foreign_trust() {
    assert_eq!(ObjectClass::SealedImport.trust_class(), TrustClass::Foreign);
}

// ── CHAIN WALK EDGE CASES ──

#[test]
fn chain_walk_standalone_returns_standalone() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"sa".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let cr = verifier::verify_chain(&b, b"sa", &[]);
    assert_eq!(cr.chain_status, ChainStatus::Standalone);
    assert_eq!(cr.depth, 1);
}

#[test]
fn chain_walk_origin_returns_origin() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"or".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: Some(ProofChain {
                lineage_id: Uuid::new_v4(),
                predecessor_proof_id: None,
                predecessor_payload_hash: None,
                key_delegation: None,
            }),
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let cr = verifier::verify_chain(&b, b"or", &[]);
    assert_eq!(cr.chain_status, ChainStatus::Origin);
    assert_eq!(cr.depth, 1);
}

#[test]
fn chain_walk_broken_proof_returns_broken() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"br".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    b.object.object_signature = "00".repeat(64);
    let cr = verifier::verify_chain(&b, b"br", &[]);
    assert_eq!(cr.chain_status, ChainStatus::HistoryBroken);
}

// ── SERIALIZATION ──

#[test]
fn all_failure_codes_serialize() {
    let codes = vec![
        FailureCode::PayloadHashMismatch,
        FailureCode::ObjectSignatureInvalid,
        FailureCode::TsaTokenMissing,
        FailureCode::ChainDelegationInvalid,
    ];
    for c in codes {
        let json = serde_json::to_string(&c).unwrap();
        let back: FailureCode = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

#[test]
fn chain_status_serializes() {
    let statuses = vec![
        ChainStatus::Standalone,
        ChainStatus::Origin,
        ChainStatus::FullHistoryVerified,
        ChainStatus::HistoryIncomplete,
        ChainStatus::HistoryBroken,
    ];
    for s in statuses {
        let json = serde_json::to_string(&s).unwrap();
        let back: ChainStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn time_source_serializes() {
    let json = serde_json::to_string(&TimeSource::Local).unwrap();
    assert_eq!(json, "\"Local\"");
    let json = serde_json::to_string(&TimeSource::External).unwrap();
    assert_eq!(json, "\"External\"");
}

// ── FINAL HARDENING (to 150) ──

#[test]
fn payload_hash_is_64_hex_chars() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"hash len".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(obj.payload_hash.len(), 64);
    assert!(obj.payload_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn object_id_is_uuid_v4() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"uuid".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(obj.object_id.get_version(), Some(uuid::Version::Random));
}

#[test]
fn object_signature_is_128_hex_chars() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"sig len".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(obj.object_signature.len(), 128);
}

#[test]
fn artifact_size_matches_actual() {
    let (mut reg, cid, mid, _) = test_registry();
    let data = b"exact size check".to_vec();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: data.clone(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(obj.artifact_size_bytes, data.len() as u64);
}

#[test]
fn binary_data_seals_correctly() {
    let (mut reg, cid, mid, _) = test_registry();
    let data: Vec<u8> = (0..=255).collect();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: data.clone(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let r = verifier::verify_from_proof_bundle(&b, &data);
    assert_eq!(r.status, VerificationStatus::Verified);
}

#[test]
fn null_bytes_in_file() {
    let (mut reg, cid, mid, _) = test_registry();
    let data = vec![0u8; 1000];
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: data.clone(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let b = reg.build_proof_bundle(&obj.object_id).unwrap();
    let r = verifier::verify_from_proof_bundle(&b, &data);
    assert_eq!(r.status, VerificationStatus::Verified);
}

#[test]
fn origin_record_protocol_is_v1() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"proto check".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(obj.origin.protocol, "V1");
}

#[test]
fn object_class_is_native_for_native_seal() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"class".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(obj.object_class, ObjectClass::Native);
    assert_eq!(obj.origin.object_class, ObjectClass::Native);
}

#[test]
fn verify_result_contains_correct_object_id() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"id check".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let r = reg.verify_object(&obj.object_id).unwrap();
    assert_eq!(r.object_id, obj.object_id);
}

#[test]
fn timestamp_is_rfc3339() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"ts".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert!(obj.time_event.timestamp.contains('T'));
    assert!(obj.time_event.timestamp.contains('+') || obj.time_event.timestamp.contains('Z'));
}

#[test]
fn created_at_is_rfc3339() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"ca".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert!(obj.origin.created_at.contains('T'));
}

#[test]
fn key_pair_roundtrip() {
    let kp = winstack_crypto::KeyPair::generate();
    let bytes = kp.secret_key_bytes();
    let kp2 = winstack_crypto::KeyPair::from_secret_bytes(&bytes);
    assert_eq!(kp.public_key_hex(), kp2.public_key_hex());
    let sig = kp.sign_bytes(b"test");
    assert!(winstack_crypto::verify_signature(&kp2.public_key_hex(), b"test", &sig).is_ok());
}

#[test]
fn two_different_keys_produce_different_sigs() {
    let k1 = winstack_crypto::KeyPair::generate();
    let k2 = winstack_crypto::KeyPair::generate();
    let s1 = k1.sign_bytes(b"same data");
    let s2 = k2.sign_bytes(b"same data");
    assert_ne!(s1, s2);
}

#[test]
fn proof_bundle_for_nonexistent_object_is_none() {
    let (reg, _, _, _) = test_registry();
    assert!(reg.build_proof_bundle(&Uuid::new_v4()).is_none());
}

// ── PHASE 1: artifact_size_bytes verified ──

#[test]
fn artifact_size_mismatch_detected() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"real content".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut b = reg.build_proof_bundle(&obj.object_id).unwrap();
    // Tamper: change claimed size without changing hash
    b.object.artifact_size_bytes = 999;
    let r = verifier::verify_from_proof_bundle(&b, b"real content");
    assert_eq!(r.status, VerificationStatus::Invalid);
    // Should catch both size mismatch AND signature invalid (size is signed)
    assert!(r
        .failures
        .iter()
        .any(|f| f.reason.contains("artifact_size_bytes")));
}

// ── PHASE 5: TIME HONESTY ──

#[test]
fn time_source_local_default_on_seal() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"time test".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    assert_eq!(obj.time_event.time_source, TimeSource::Local);
    assert!(obj.time_event.rfc3161_token.is_none());
    assert!(obj.time_event.anchored_time.is_none());
}

#[test]
fn time_source_local_survives_proof_bundle_roundtrip() {
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"roundtrip test".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    // Serialize and deserialize
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: ProofBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.object.time_event.time_source, TimeSource::Local);
    assert!(restored.object.time_event.rfc3161_token.is_none());
    assert!(restored.object.time_event.anchored_time.is_none());
}

#[test]
fn time_source_external_preserved_in_serialization() {
    // Cannot inject a fake TSA attachment through seal (fail-closed),
    // so test serialization roundtrip of External time_source directly.
    let (mut reg, cid, mid, _) = test_registry();
    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: b"external time test".to_vec(),
            creator_identity_id: cid,
            module_id: mid,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .unwrap();
    let mut bundle = reg.build_proof_bundle(&obj.object_id).unwrap();
    // Manually set External fields to test serialization roundtrip
    bundle.object.time_event.time_source = TimeSource::External;
    bundle.object.time_event.rfc3161_token = Some("dGVzdHRva2Vu".to_string());
    bundle.object.time_event.anchored_time = Some("20260421T120000Z".to_string());
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: ProofBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.object.time_event.time_source, TimeSource::External);
    assert_eq!(
        restored.object.time_event.rfc3161_token.as_deref(),
        Some("dGVzdHRva2Vu")
    );
    assert_eq!(
        restored.object.time_event.anchored_time.as_deref(),
        Some("20260421T120000Z")
    );
}

#[test]
fn time_source_deserializes_from_string() {
    let local: TimeSource = serde_json::from_str("\"Local\"").unwrap();
    assert_eq!(local, TimeSource::Local);
    let external: TimeSource = serde_json::from_str("\"External\"").unwrap();
    assert_eq!(external, TimeSource::External);
}

#[test]
fn time_source_display_values_match_spec() {
    // The serialized values must be exactly "Local" and "External"
    // as referenced by all UI code and PROOF-SPEC.md
    assert_eq!(serde_json::to_string(&TimeSource::Local).unwrap(), "\"Local\"");
    assert_eq!(serde_json::to_string(&TimeSource::External).unwrap(), "\"External\"");
}
