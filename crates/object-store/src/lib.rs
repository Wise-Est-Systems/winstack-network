use canon_types::{AuditEvent, SealedObject};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("object not found: {0}")]
    NotFound(Uuid),
    #[error("object already exists: {0}")]
    AlreadyExists(Uuid),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("persistence failed: {0}")]
    PersistenceFailed(String),
}

pub struct ObjectStore {
    objects: HashMap<Uuid, SealedObject>,
    artifacts: HashMap<Uuid, Vec<u8>>,
    audit_log: Vec<AuditEvent>,
    base_path: Option<PathBuf>,
}

impl Default for ObjectStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectStore {
    pub fn new() -> Self {
        Self {
            objects: HashMap::new(),
            artifacts: HashMap::new(),
            audit_log: Vec::new(),
            base_path: None,
        }
    }

    pub fn with_path(path: &Path) -> Result<Self, StoreError> {
        let store_path = path.join("store");
        let artifacts_path = path.join("artifacts");
        fs::create_dir_all(&store_path)?;
        fs::create_dir_all(&artifacts_path)?;

        let mut store = Self {
            objects: HashMap::new(),
            artifacts: HashMap::new(),
            audit_log: Vec::new(),
            base_path: Some(path.to_path_buf()),
        };

        // Load existing objects from disk
        if store_path.exists() {
            for entry in fs::read_dir(&store_path)? {
                let entry = entry?;
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    let data = fs::read_to_string(&p)?;
                    let obj: SealedObject = serde_json::from_str(&data)?;
                    let oid = obj.object_id;
                    store.objects.insert(oid, obj);

                    let art_path = artifacts_path.join(oid.to_string());
                    if art_path.exists() {
                        let bytes = fs::read(&art_path)?;
                        store.artifacts.insert(oid, bytes);
                    }
                }
            }
        }

        Ok(store)
    }

    pub fn insert(
        &mut self,
        object: SealedObject,
        artifact_bytes: Vec<u8>,
    ) -> Result<(), StoreError> {
        let oid = object.object_id;
        if self.objects.contains_key(&oid) {
            return Err(StoreError::AlreadyExists(oid));
        }

        // Persist to disk if base_path is set
        if let Some(ref base) = self.base_path {
            let obj_path = base.join("store").join(format!("{}.json", oid));
            let art_path = base.join("artifacts").join(oid.to_string());

            let obj_json = serde_json::to_string_pretty(&object)?;

            // Write artifact first, then object, then commit marker
            fs::write(&art_path, &artifact_bytes)?;

            // fsync artifact
            let f = fs::File::open(&art_path)?;
            f.sync_all()?;

            fs::write(&obj_path, obj_json)?;

            // fsync object
            let f = fs::File::open(&obj_path)?;
            f.sync_all()?;
        }

        self.objects.insert(oid, object);
        self.artifacts.insert(oid, artifact_bytes);

        let audit = AuditEvent {
            event_id: Uuid::new_v4(),
            object_id: oid,
            action: "SEALED".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        self.audit_log.push(audit);

        Ok(())
    }

    pub fn get(&self, id: &Uuid) -> Option<&SealedObject> {
        self.objects.get(id)
    }

    pub fn get_artifact(&self, id: &Uuid) -> Option<&[u8]> {
        self.artifacts.get(id).map(|v| v.as_slice())
    }

    pub fn contains(&self, id: &Uuid) -> bool {
        self.objects.contains_key(id)
    }

    pub fn all_ids(&self) -> Vec<Uuid> {
        self.objects.keys().copied().collect()
    }

    pub fn audit_log(&self) -> &[AuditEvent] {
        &self.audit_log
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canon_types::*;

    fn dummy_object(id: Uuid) -> SealedObject {
        SealedObject {
            object_id: id,
            object_class: ObjectClass::Native,
            payload_hash: "abc".to_string(),
            artifact_size_bytes: 3,
            parent_ids: vec![],
            origin: OriginRecord {
                origin_record_id: Uuid::new_v4(),
                object_id: id,
                object_class: ObjectClass::Native,
                creator_identity_id: Uuid::new_v4(),
                module_identity_id: Uuid::new_v4(),
                time_authority_identity_id: Uuid::new_v4(),
                created_at: "t".to_string(),
                protocol: "V1".to_string(),
                foreign_source_uri: None,
                ai_model: None,
                signature: "sig".to_string(),
            },
            time_event: ChainedTimeEvent {
                time_event_id: Uuid::new_v4(),
                timestamp: "t".to_string(),
                time_authority_identity_id: Uuid::new_v4(),
                predecessor_event_id: None,
                predecessor_hash: None,
                payload_hash: "ph".to_string(),
                signature: "sig".to_string(),
                time_source: canon_types::TimeSource::Local,
                rfc3161_token: None,
                anchored_time: None,
            },
            policy_proof: PolicyProof {
                policy_proof_id: Uuid::new_v4(),
                decision: PolicyDecision::Permit,
                policy_version: 1,
                context_hash: "ch".to_string(),
                evaluator_identity_id: Uuid::new_v4(),
                evaluated_at: "t".to_string(),
                signature: "sig".to_string(),
            },
            ai_generation: None,
            import_declaration: None,
            object_signature: "sig".to_string(),
            protocol: "V1".to_string(),
            proof_chain: None,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut store = ObjectStore::new();
        let id = Uuid::new_v4();
        let obj = dummy_object(id);
        store.insert(obj, b"abc".to_vec()).unwrap();
        assert!(store.get(&id).is_some());
        assert_eq!(store.get_artifact(&id).unwrap(), b"abc");
    }

    #[test]
    fn duplicate_rejected() {
        let mut store = ObjectStore::new();
        let id = Uuid::new_v4();
        store.insert(dummy_object(id), b"a".to_vec()).unwrap();
        assert!(store.insert(dummy_object(id), b"b".to_vec()).is_err());
    }

    #[test]
    fn immutability() {
        let mut store = ObjectStore::new();
        let id = Uuid::new_v4();
        store.insert(dummy_object(id), b"data".to_vec()).unwrap();
        // No mutation API exists - object is immutable after insert
        assert!(store.contains(&id));
    }
}
