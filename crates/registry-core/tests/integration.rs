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
