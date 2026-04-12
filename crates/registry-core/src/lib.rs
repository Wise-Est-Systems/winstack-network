use canon_types::*;
use graph_index::GraphIndex;
use identity_core::{IdentityStore, ModuleRegistry};
use object_store::ObjectStore;
use policy_core::PolicyEvaluator;
use time_core::TimeAuthority;
use uuid::Uuid;
use winstack_crypto::{self as crypto, KeyPair};

#[derive(Debug)]
pub enum RegistryError {
    Rejected(Rejection),
    Store(object_store::StoreError),
    Graph(graph_index::GraphError),
    Identity(identity_core::IdentityError),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::Rejected(r) => write!(f, "rejected: {:?}: {}", r.code, r.reason),
            RegistryError::Store(e) => write!(f, "store error: {}", e),
            RegistryError::Graph(e) => write!(f, "graph error: {}", e),
            RegistryError::Identity(e) => write!(f, "identity error: {}", e),
        }
    }
}

impl std::error::Error for RegistryError {}

impl From<object_store::StoreError> for RegistryError {
    fn from(e: object_store::StoreError) -> Self {
        RegistryError::Store(e)
    }
}

impl From<graph_index::GraphError> for RegistryError {
    fn from(e: graph_index::GraphError) -> Self {
        RegistryError::Graph(e)
    }
}

impl From<identity_core::IdentityError> for RegistryError {
    fn from(e: identity_core::IdentityError) -> Self {
        RegistryError::Identity(e)
    }
}

pub struct Registry {
    pub identity_store: IdentityStore,
    pub module_registry: ModuleRegistry,
    pub time_authority: TimeAuthority,
    pub policy_evaluator: PolicyEvaluator,
    pub object_store: ObjectStore,
    pub graph: GraphIndex,
}

impl Registry {
    pub fn new_in_memory() -> Self {
        let mut identity_store = IdentityStore::new();

        // Create time authority identity
        let (ta_id, _ta_rec) = identity_store.create_identity(IdentityKind::Service);
        let ta_key_bytes = identity_store.get_key(&ta_id).unwrap().secret_key_bytes();
        let ta_key = KeyPair::from_secret_bytes(&ta_key_bytes);
        let time_authority = TimeAuthority::new(ta_id, ta_key);

        // Create policy evaluator identity
        let (pe_id, _pe_rec) = identity_store.create_identity(IdentityKind::Service);
        let pe_key_bytes = identity_store.get_key(&pe_id).unwrap().secret_key_bytes();
        let pe_key = KeyPair::from_secret_bytes(&pe_key_bytes);
        let policy_evaluator = PolicyEvaluator::new(pe_id, pe_key);

        let object_store = ObjectStore::new();
        let graph = GraphIndex::in_memory().unwrap();
        let module_registry = ModuleRegistry::new();

        Self {
            identity_store,
            module_registry,
            time_authority,
            policy_evaluator,
            object_store,
            graph,
        }
    }

    pub fn seal_native(
        &mut self,
        proposal: NativeBirthProposal,
    ) -> Result<SealedObject, RegistryError> {
        let object_id = Uuid::new_v4();
        let payload_hash = crypto::sha256_hex(&proposal.artifact_bytes);
        let artifact_size = proposal.artifact_bytes.len() as u64;

        // Step 1: Structural validation
        for pid in &proposal.parent_ids {
            if *pid == object_id {
                return Err(RegistryError::Rejected(Rejection {
                    code: RejectCode::LineageCycle,
                    reason: "self-cycle".into(),
                }));
            }
        }

        // Step 2: Creator identity
        let creator = self
            .identity_store
            .validate_creator_for_class(&proposal.creator_identity_id, ObjectClass::Native)
            .map_err(|e| match e {
                identity_core::IdentityError::NotFound(id) => RegistryError::Rejected(Rejection {
                    code: RejectCode::CreatorNotFound,
                    reason: format!("creator not found: {}", id),
                }),
                identity_core::IdentityError::NotActive(id) => RegistryError::Rejected(Rejection {
                    code: RejectCode::CreatorInvalid,
                    reason: format!("creator not active: {}", id),
                }),
                identity_core::IdentityError::SessionCannotCreateNative => {
                    RegistryError::Rejected(Rejection {
                        code: RejectCode::SessionCannotCreateNative,
                        reason: "session identity cannot create native objects".into(),
                    })
                }
                other => RegistryError::Rejected(Rejection {
                    code: RejectCode::CreatorInvalid,
                    reason: other.to_string(),
                }),
            })?;

        // Step 3: Module validation
        let module = self
            .module_registry
            .validate_module_for_object(&proposal.module_id, ObjectClass::Native)
            .map_err(|e| {
                RegistryError::Rejected(Rejection {
                    code: RejectCode::ModuleNotRegistered,
                    reason: e.to_string(),
                })
            })?;

        // Step 4: Lineage
        for pid in &proposal.parent_ids {
            if !self.object_store.contains(pid) {
                return Err(RegistryError::Rejected(Rejection {
                    code: RejectCode::LineageParentMissing,
                    reason: format!("parent not found: {}", pid),
                }));
            }
        }
        // Step 5: Policy evaluation
        let context_hash = crypto::sha256_hex(
            format!(
                "{}:{}:{}",
                object_id, payload_hash, proposal.creator_identity_id
            )
            .as_bytes(),
        );
        let policy_proof = self.policy_evaluator.permit(&context_hash);

        // Step 6: Time attestation
        let mut time_event = self.time_authority.attest_time(&payload_hash);

        // Attach TSA token if provided, then re-sign to cover new fields
        if let Some(tsa) = &proposal.tsa_attachment {
            time_event.rfc3161_token = Some(tsa.token_base64.clone());
            time_event.anchored_time = Some(tsa.anchored_time.clone());
            time_event.time_source = TimeSource::External;
            self.time_authority.re_sign_event(&mut time_event);
        }

        // Step 7: Object assembly
        let now = chrono::Utc::now().to_rfc3339();
        let origin = OriginRecord {
            origin_record_id: Uuid::new_v4(),
            object_id,
            object_class: ObjectClass::Native,
            creator_identity_id: proposal.creator_identity_id,
            module_identity_id: proposal.module_id,
            time_authority_identity_id: self.time_authority.authority_id(),
            created_at: now,
            protocol: "V1".to_string(),
            foreign_source_uri: None,
            ai_model: None,
            signature: String::new(), // will be signed below
        };

        // Chain linkage
        let sealed_chain = proposal.proof_chain.clone();

        // Sign object
        let creator_key = self
            .identity_store
            .get_key(&proposal.creator_identity_id)
            .unwrap();

        #[derive(serde::Serialize)]
        struct ObjSignPayload<'a> {
            object_id: &'a Uuid,
            object_class: &'a ObjectClass,
            payload_hash: &'a str,
            artifact_size_bytes: u64,
            parent_ids: &'a [Uuid],
            protocol: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            proof_chain: &'a Option<ProofChain>,
        }

        let sign_payload = ObjSignPayload {
            object_id: &object_id,
            object_class: &ObjectClass::Native,
            payload_hash: &payload_hash,
            artifact_size_bytes: artifact_size,
            parent_ids: &proposal.parent_ids,
            protocol: "V1",
            proof_chain: &sealed_chain,
        };
        let object_signature = creator_key.sign_json(&sign_payload);

        // Sign origin record
        let origin_sig = creator_key.sign_json(&origin);
        let origin = OriginRecord {
            signature: origin_sig,
            ..origin
        };

        let sealed = SealedObject {
            object_id,
            object_class: ObjectClass::Native,
            payload_hash,
            artifact_size_bytes: artifact_size,
            parent_ids: proposal.parent_ids.clone(),
            origin,
            time_event,
            policy_proof,
            ai_generation: None,
            import_declaration: None,
            object_signature,
            protocol: "V1".to_string(),
            proof_chain: sealed_chain,
        };

        // Step 8: Final verification
        let pred_event = self
            .time_authority
            .get_predecessor(&sealed.time_event)
            .cloned();

        let parent_objects: Vec<SealedObject> = proposal
            .parent_ids
            .iter()
            .filter_map(|pid| self.object_store.get(pid).cloned())
            .collect();

        let pe_id = self.policy_evaluator.evaluator_id();
        let pe_identity = self.identity_store.get(&pe_id).unwrap().clone();

        let ta_id = self.time_authority.authority_id();
        let ta_identity = self.identity_store.get(&ta_id).unwrap().clone();

        let verification_input = verifier::VerificationInput {
            object: sealed.clone(),
            artifact_bytes: proposal.artifact_bytes.clone(),
            creator_identity: creator.clone(),
            module_registration: module.clone(),
            time_authority_identity: ta_identity,
            policy_evaluator_identity: pe_identity,
            predecessor_time_event: pred_event,
            parent_objects,
            tsa_trust_store: None,
        };

        let result = verifier::verify_object(&verification_input);
        if result.status != VerificationStatus::Verified {
            return Err(RegistryError::Rejected(Rejection {
                code: RejectCode::VerificationFailed,
                reason: format!("pre-write verification failed: {:?}", result.failures),
            }));
        }

        // Step 9: Atomic persistence
        self.object_store
            .insert(sealed.clone(), proposal.artifact_bytes)?;

        // Step 10: Audit event (graph insert acts as commit signal)
        let class_str = format!("{:?}", sealed.object_class);
        self.graph.insert_object(
            object_id,
            &class_str,
            &sealed.origin.created_at,
            &proposal.parent_ids,
        )?;

        Ok(sealed)
    }

    pub fn seal_ai(&mut self, proposal: AiBirthProposal) -> Result<SealedObject, RegistryError> {
        let object_id = Uuid::new_v4();
        let payload_hash = crypto::sha256_hex(&proposal.artifact_bytes);
        let artifact_size = proposal.artifact_bytes.len() as u64;
        let output_hash = payload_hash.clone();

        // Step 1: Structural validation
        // Step 2: Creator identity
        let creator = self
            .identity_store
            .validate_creator_for_class(&proposal.creator_identity_id, ObjectClass::AiGenerated)
            .map_err(|e| {
                RegistryError::Rejected(Rejection {
                    code: RejectCode::CreatorInvalid,
                    reason: e.to_string(),
                })
            })?;

        // Step 3: Module validation
        let module = self
            .module_registry
            .validate_module_for_object(&proposal.module_id, ObjectClass::AiGenerated)
            .map_err(|e| {
                RegistryError::Rejected(Rejection {
                    code: RejectCode::ModuleNotRegistered,
                    reason: e.to_string(),
                })
            })?;

        // Step 4: Lineage
        for pid in &proposal.parent_ids {
            if !self.object_store.contains(pid) {
                return Err(RegistryError::Rejected(Rejection {
                    code: RejectCode::LineageParentMissing,
                    reason: format!("parent not found: {}", pid),
                }));
            }
        }

        // Step 5: Policy
        let context_hash = crypto::sha256_hex(
            format!(
                "{}:{}:{}",
                object_id, payload_hash, proposal.creator_identity_id
            )
            .as_bytes(),
        );
        let policy_proof = self.policy_evaluator.permit(&context_hash);

        // Step 6: Time
        let mut time_event = self.time_authority.attest_time(&payload_hash);
        if let Some(tsa) = &proposal.tsa_attachment {
            time_event.rfc3161_token = Some(tsa.token_base64.clone());
            time_event.anchored_time = Some(tsa.anchored_time.clone());
            time_event.time_source = TimeSource::External;
            self.time_authority.re_sign_event(&mut time_event);
        }

        // Step 7: Assembly
        let now = chrono::Utc::now().to_rfc3339();

        let ai_gen = AiGenerationRecord {
            generation_id: Uuid::new_v4(),
            object_id,
            model: proposal.model.clone(),
            prompt_hash: proposal.prompt_hash.clone(),
            output_hash,
            module_id: proposal.module_id,
            signature: String::new(),
        };

        let creator_key = self
            .identity_store
            .get_key(&proposal.creator_identity_id)
            .unwrap();

        let ai_gen_sig = creator_key.sign_json(&ai_gen);
        let ai_gen = AiGenerationRecord {
            signature: ai_gen_sig,
            ..ai_gen
        };

        let origin = OriginRecord {
            origin_record_id: Uuid::new_v4(),
            object_id,
            object_class: ObjectClass::AiGenerated,
            creator_identity_id: proposal.creator_identity_id,
            module_identity_id: proposal.module_id,
            time_authority_identity_id: self.time_authority.authority_id(),
            created_at: now,
            protocol: "V1".to_string(),
            foreign_source_uri: None,
            ai_model: Some(proposal.model),
            signature: String::new(),
        };
        let origin_sig = creator_key.sign_json(&origin);
        let origin = OriginRecord {
            signature: origin_sig,
            ..origin
        };

        #[derive(serde::Serialize)]
        struct ObjSignPayload<'a> {
            object_id: &'a Uuid,
            object_class: &'a ObjectClass,
            payload_hash: &'a str,
            artifact_size_bytes: u64,
            parent_ids: &'a [Uuid],
            protocol: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            proof_chain: &'a Option<canon_types::ProofChain>,
        }
        let sign_payload = ObjSignPayload {
            object_id: &object_id,
            object_class: &ObjectClass::AiGenerated,
            payload_hash: &payload_hash,
            artifact_size_bytes: artifact_size,
            parent_ids: &proposal.parent_ids,
            protocol: "V1",
            proof_chain: &None,
        };
        let object_signature = creator_key.sign_json(&sign_payload);

        let sealed = SealedObject {
            object_id,
            object_class: ObjectClass::AiGenerated,
            payload_hash,
            artifact_size_bytes: artifact_size,
            parent_ids: proposal.parent_ids.clone(),
            origin,
            time_event,
            policy_proof,
            ai_generation: Some(ai_gen),
            import_declaration: None,
            object_signature,
            protocol: "V1".to_string(),
            proof_chain: None,
        };

        // Step 8: Verification
        let pred_event = self
            .time_authority
            .get_predecessor(&sealed.time_event)
            .cloned();
        let parent_objects: Vec<SealedObject> = proposal
            .parent_ids
            .iter()
            .filter_map(|pid| self.object_store.get(pid).cloned())
            .collect();

        let pe_id = self.policy_evaluator.evaluator_id();
        let pe_identity = self.identity_store.get(&pe_id).unwrap().clone();
        let ta_id = self.time_authority.authority_id();
        let ta_identity = self.identity_store.get(&ta_id).unwrap().clone();

        let verification_input = verifier::VerificationInput {
            object: sealed.clone(),
            artifact_bytes: proposal.artifact_bytes.clone(),
            creator_identity: creator.clone(),
            module_registration: module.clone(),
            time_authority_identity: ta_identity,
            policy_evaluator_identity: pe_identity,
            predecessor_time_event: pred_event,
            parent_objects,
            tsa_trust_store: None,
        };

        let result = verifier::verify_object(&verification_input);
        if result.status != VerificationStatus::Verified {
            return Err(RegistryError::Rejected(Rejection {
                code: RejectCode::VerificationFailed,
                reason: format!("pre-write verification failed: {:?}", result.failures),
            }));
        }

        // Step 9: Persist
        self.object_store
            .insert(sealed.clone(), proposal.artifact_bytes)?;

        // Step 10: Audit
        let class_str = format!("{:?}", sealed.object_class);
        self.graph.insert_object(
            object_id,
            &class_str,
            &sealed.origin.created_at,
            &proposal.parent_ids,
        )?;

        Ok(sealed)
    }

    pub fn seal_import(
        &mut self,
        proposal: ImportBirthProposal,
    ) -> Result<SealedObject, RegistryError> {
        let object_id = Uuid::new_v4();
        let payload_hash = crypto::sha256_hex(&proposal.artifact_bytes);
        let artifact_size = proposal.artifact_bytes.len() as u64;

        // Step 2: Creator
        let creator = self
            .identity_store
            .validate_identity(&proposal.creator_identity_id)
            .map_err(|e| {
                RegistryError::Rejected(Rejection {
                    code: RejectCode::CreatorInvalid,
                    reason: e.to_string(),
                })
            })?;

        // Step 3: Module (must be Import kind)
        let module = self
            .module_registry
            .validate_module_for_object(&proposal.module_id, ObjectClass::SealedImport)
            .map_err(|e| {
                RegistryError::Rejected(Rejection {
                    code: RejectCode::ModuleNotRegistered,
                    reason: e.to_string(),
                })
            })?;

        // Step 4: Lineage
        for pid in &proposal.parent_ids {
            if !self.object_store.contains(pid) {
                return Err(RegistryError::Rejected(Rejection {
                    code: RejectCode::LineageParentMissing,
                    reason: format!("parent not found: {}", pid),
                }));
            }
        }

        // Step 5: Policy
        let context_hash = crypto::sha256_hex(
            format!(
                "{}:{}:{}",
                object_id, payload_hash, proposal.creator_identity_id
            )
            .as_bytes(),
        );
        let policy_proof = self.policy_evaluator.permit(&context_hash);

        // Step 6: Time
        let mut time_event = self.time_authority.attest_time(&payload_hash);
        if let Some(tsa) = &proposal.tsa_attachment {
            time_event.rfc3161_token = Some(tsa.token_base64.clone());
            time_event.anchored_time = Some(tsa.anchored_time.clone());
            time_event.time_source = TimeSource::External;
            self.time_authority.re_sign_event(&mut time_event);
        }

        // Step 7: Assembly
        let now = chrono::Utc::now().to_rfc3339();

        let import_decl = ImportDeclaration {
            import_id: Uuid::new_v4(),
            object_id,
            source_uri: proposal.source_uri.clone(),
            claimed_content_type: proposal.claimed_content_type.clone(),
            reason: proposal.reason.clone(),
            module_id: proposal.module_id,
            signature: String::new(),
        };

        let creator_key = self
            .identity_store
            .get_key(&proposal.creator_identity_id)
            .unwrap();

        let import_sig = creator_key.sign_json(&import_decl);
        let import_decl = ImportDeclaration {
            signature: import_sig,
            ..import_decl
        };

        let origin = OriginRecord {
            origin_record_id: Uuid::new_v4(),
            object_id,
            object_class: ObjectClass::SealedImport,
            creator_identity_id: proposal.creator_identity_id,
            module_identity_id: proposal.module_id,
            time_authority_identity_id: self.time_authority.authority_id(),
            created_at: now,
            protocol: "V1".to_string(),
            foreign_source_uri: Some(proposal.source_uri),
            ai_model: None,
            signature: String::new(),
        };
        let origin_sig = creator_key.sign_json(&origin);
        let origin = OriginRecord {
            signature: origin_sig,
            ..origin
        };

        #[derive(serde::Serialize)]
        struct ObjSignPayload<'a> {
            object_id: &'a Uuid,
            object_class: &'a ObjectClass,
            payload_hash: &'a str,
            artifact_size_bytes: u64,
            parent_ids: &'a [Uuid],
            protocol: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            proof_chain: &'a Option<canon_types::ProofChain>,
        }
        let sign_payload = ObjSignPayload {
            object_id: &object_id,
            object_class: &ObjectClass::SealedImport,
            payload_hash: &payload_hash,
            artifact_size_bytes: artifact_size,
            parent_ids: &proposal.parent_ids,
            protocol: "V1",
            proof_chain: &None,
        };
        let object_signature = creator_key.sign_json(&sign_payload);

        let sealed = SealedObject {
            object_id,
            object_class: ObjectClass::SealedImport,
            payload_hash,
            artifact_size_bytes: artifact_size,
            parent_ids: proposal.parent_ids.clone(),
            origin,
            time_event,
            policy_proof,
            ai_generation: None,
            import_declaration: Some(import_decl),
            object_signature,
            protocol: "V1".to_string(),
            proof_chain: None,
        };

        // Step 8: Verify
        let pred_event = self
            .time_authority
            .get_predecessor(&sealed.time_event)
            .cloned();
        let parent_objects: Vec<SealedObject> = proposal
            .parent_ids
            .iter()
            .filter_map(|pid| self.object_store.get(pid).cloned())
            .collect();

        let pe_id = self.policy_evaluator.evaluator_id();
        let pe_identity = self.identity_store.get(&pe_id).unwrap().clone();
        let ta_id = self.time_authority.authority_id();
        let ta_identity = self.identity_store.get(&ta_id).unwrap().clone();

        let verification_input = verifier::VerificationInput {
            object: sealed.clone(),
            artifact_bytes: proposal.artifact_bytes.clone(),
            creator_identity: creator.clone(),
            module_registration: module.clone(),
            time_authority_identity: ta_identity,
            policy_evaluator_identity: pe_identity,
            predecessor_time_event: pred_event,
            parent_objects,
            tsa_trust_store: None,
        };

        let result = verifier::verify_object(&verification_input);
        if result.status != VerificationStatus::Verified {
            return Err(RegistryError::Rejected(Rejection {
                code: RejectCode::VerificationFailed,
                reason: format!("pre-write verification failed: {:?}", result.failures),
            }));
        }

        // Step 9: Persist
        self.object_store
            .insert(sealed.clone(), proposal.artifact_bytes)?;

        // Step 10: Audit
        let class_str = format!("{:?}", sealed.object_class);
        self.graph.insert_object(
            object_id,
            &class_str,
            &sealed.origin.created_at,
            &proposal.parent_ids,
        )?;

        Ok(sealed)
    }

    pub fn build_proof_bundle(&self, object_id: &Uuid) -> Option<ProofBundle> {
        let obj = self.object_store.get(object_id)?.clone();

        let creator = self
            .identity_store
            .get(&obj.origin.creator_identity_id)?
            .clone();
        let module = self
            .module_registry
            .get(&obj.origin.module_identity_id)?
            .clone();
        let ta = self
            .identity_store
            .get(&obj.origin.time_authority_identity_id)?
            .clone();
        let pe = self
            .identity_store
            .get(&obj.policy_proof.evaluator_identity_id)?
            .clone();

        let pred = if !obj.time_event.is_genesis() {
            obj.time_event
                .predecessor_event_id
                .and_then(|pid| self.time_authority.get_event(&pid).cloned())
        } else {
            None
        };

        let parent_objects: Vec<SealedObject> = obj
            .parent_ids
            .iter()
            .filter_map(|pid| self.object_store.get(pid).cloned())
            .collect();

        let parent_proofs: Vec<ProofBundle> = obj
            .parent_ids
            .iter()
            .filter_map(|pid| self.build_proof_bundle(pid))
            .collect();

        Some(ProofBundle {
            object: obj,
            creator_identity: creator,
            module_registration: module,
            time_authority_identity: ta,
            policy_evaluator_identity: pe,
            predecessor_time_event: pred,
            parent_objects,
            parent_proofs,
        })
    }

    pub fn verify_object(&self, object_id: &Uuid) -> Option<VerificationResult> {
        let obj = self.object_store.get(object_id)?;
        let artifact = self.object_store.get_artifact(object_id)?;

        let creator = self
            .identity_store
            .get(&obj.origin.creator_identity_id)?
            .clone();
        let module = self
            .module_registry
            .get(&obj.origin.module_identity_id)?
            .clone();
        let ta = self
            .identity_store
            .get(&obj.origin.time_authority_identity_id)?
            .clone();
        let pe = self
            .identity_store
            .get(&obj.policy_proof.evaluator_identity_id)?
            .clone();

        let pred = if !obj.time_event.is_genesis() {
            obj.time_event
                .predecessor_event_id
                .and_then(|pid| self.time_authority.get_event(&pid).cloned())
        } else {
            None
        };

        let parent_objects: Vec<SealedObject> = obj
            .parent_ids
            .iter()
            .filter_map(|pid| self.object_store.get(pid).cloned())
            .collect();

        let input = verifier::VerificationInput {
            object: obj.clone(),
            artifact_bytes: artifact.to_vec(),
            creator_identity: creator,
            module_registration: module,
            time_authority_identity: ta,
            policy_evaluator_identity: pe,
            predecessor_time_event: pred,
            parent_objects,
            tsa_trust_store: None,
        };

        Some(verifier::verify_object(&input))
    }
}

// Helper: create a fully bootstrapped registry for testing
pub fn test_registry() -> (Registry, Uuid, Uuid, Uuid) {
    let mut reg = Registry::new_in_memory();

    // Create a creator identity (Personal)
    let (creator_id, _) = reg.identity_store.create_identity(IdentityKind::Personal);

    // Register a native document module
    let creator_key_bytes = reg
        .identity_store
        .get_key(&creator_id)
        .unwrap()
        .secret_key_bytes();
    let creator_key = KeyPair::from_secret_bytes(&creator_key_bytes);
    let (native_mod_id, _) = reg.module_registry.register(
        ModuleKind::Document,
        "documents/*",
        &crypto::sha256_hex(b"native-module-binary"),
        creator_id,
        &creator_key,
    );

    // Register an AI generation module
    let (ai_mod_id, _) = reg.module_registry.register(
        ModuleKind::AiGeneration,
        "ai/*",
        &crypto::sha256_hex(b"ai-module-binary"),
        creator_id,
        &creator_key,
    );

    // Register an import module
    let (import_mod_id, _) = reg.module_registry.register(
        ModuleKind::Import,
        "imports/*",
        &crypto::sha256_hex(b"import-module-binary"),
        creator_id,
        &creator_key,
    );

    let _ = import_mod_id; // used by callers via module_registry

    (reg, creator_id, native_mod_id, ai_mod_id)
}
