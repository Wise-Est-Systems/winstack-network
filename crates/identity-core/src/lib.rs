use canon_types::*;
use std::collections::HashMap;
use uuid::Uuid;
use winstack_crypto::{self as crypto, KeyPair};

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity not found: {0}")]
    NotFound(Uuid),
    #[error("identity not active: {0}")]
    NotActive(Uuid),
    #[error("duplicate identity: {0}")]
    Duplicate(Uuid),
    #[error("signature invalid")]
    SignatureInvalid,
    #[error("module not registered: {0}")]
    ModuleNotFound(Uuid),
    #[error("module scope mismatch")]
    ModuleScopeMismatch,
    #[error("module kind mismatch")]
    ModuleKindMismatch,
    #[error("module binary hash mismatch")]
    ModuleBinaryHashMismatch,
    #[error("session identity cannot create permanent native objects")]
    SessionCannotCreateNative,
}

pub struct IdentityStore {
    identities: HashMap<Uuid, IdentityRecord>,
    keys: HashMap<Uuid, KeyPair>,
}

impl Default for IdentityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityStore {
    pub fn new() -> Self {
        Self {
            identities: HashMap::new(),
            keys: HashMap::new(),
        }
    }

    pub fn create_identity(&mut self, kind: IdentityKind) -> (Uuid, IdentityRecord) {
        let kp = KeyPair::generate();
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().to_rfc3339();

        #[derive(serde::Serialize)]
        struct SignPayload<'a> {
            identity_id: &'a Uuid,
            kind: &'a IdentityKind,
            status: &'a IdentityStatus,
            public_key_hex: &'a str,
            created_at: &'a str,
        }

        let pk_hex = kp.public_key_hex();
        let payload = SignPayload {
            identity_id: &id,
            kind: &kind,
            status: &IdentityStatus::Active,
            public_key_hex: &pk_hex,
            created_at: &now,
        };
        let sig = kp.sign_json(&payload);

        let record = IdentityRecord {
            identity_id: id,
            kind,
            status: IdentityStatus::Active,
            public_key_hex: pk_hex,
            created_at: now,
            signature: sig,
        };

        self.identities.insert(id, record.clone());
        self.keys.insert(id, kp);
        (id, record)
    }

    pub fn get(&self, id: &Uuid) -> Option<&IdentityRecord> {
        self.identities.get(id)
    }

    pub fn get_key(&self, id: &Uuid) -> Option<&KeyPair> {
        self.keys.get(id)
    }

    pub fn validate_identity(&self, id: &Uuid) -> Result<&IdentityRecord, IdentityError> {
        let rec = self
            .identities
            .get(id)
            .ok_or(IdentityError::NotFound(*id))?;
        if rec.status != IdentityStatus::Active {
            return Err(IdentityError::NotActive(*id));
        }
        Ok(rec)
    }

    pub fn validate_creator_for_class(
        &self,
        creator_id: &Uuid,
        object_class: ObjectClass,
    ) -> Result<&IdentityRecord, IdentityError> {
        let rec = self.validate_identity(creator_id)?;
        if rec.kind == IdentityKind::Session
            && matches!(object_class, ObjectClass::Native | ObjectClass::AiGenerated)
        {
            return Err(IdentityError::SessionCannotCreateNative);
        }
        Ok(rec)
    }

    pub fn verify_identity_signature(&self, record: &IdentityRecord) -> Result<(), IdentityError> {
        #[derive(serde::Serialize)]
        struct SignPayload<'a> {
            identity_id: &'a Uuid,
            kind: &'a IdentityKind,
            status: &'a IdentityStatus,
            public_key_hex: &'a str,
            created_at: &'a str,
        }
        let payload = SignPayload {
            identity_id: &record.identity_id,
            kind: &record.kind,
            status: &record.status,
            public_key_hex: &record.public_key_hex,
            created_at: &record.created_at,
        };
        crypto::verify_json_signature(&record.public_key_hex, &payload, &record.signature)
            .map_err(|_| IdentityError::SignatureInvalid)
    }

    pub fn suspend(&mut self, id: &Uuid) -> Result<(), IdentityError> {
        let rec = self
            .identities
            .get_mut(id)
            .ok_or(IdentityError::NotFound(*id))?;
        rec.status = IdentityStatus::Suspended;
        Ok(())
    }

    pub fn revoke(&mut self, id: &Uuid) -> Result<(), IdentityError> {
        let rec = self
            .identities
            .get_mut(id)
            .ok_or(IdentityError::NotFound(*id))?;
        rec.status = IdentityStatus::Revoked;
        Ok(())
    }

    pub fn insert_identity(&mut self, record: IdentityRecord, kp: KeyPair) {
        let id = record.identity_id;
        self.identities.insert(id, record);
        self.keys.insert(id, kp);
    }
}

pub struct ModuleRegistry {
    modules: HashMap<Uuid, ModuleRegistration>,
}

impl Default for ModuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        kind: ModuleKind,
        scope: &str,
        binary_hash: &str,
        registrar_id: Uuid,
        registrar_key: &KeyPair,
    ) -> (Uuid, ModuleRegistration) {
        let id = Uuid::new_v4();

        #[derive(serde::Serialize)]
        struct SignPayload<'a> {
            module_id: &'a Uuid,
            kind: &'a ModuleKind,
            scope: &'a str,
            binary_hash: &'a str,
            registered_by: &'a Uuid,
        }

        let payload = SignPayload {
            module_id: &id,
            kind: &kind,
            scope,
            binary_hash,
            registered_by: &registrar_id,
        };
        let sig = registrar_key.sign_json(&payload);

        let reg = ModuleRegistration {
            module_id: id,
            kind,
            scope: scope.to_string(),
            binary_hash: binary_hash.to_string(),
            registered_by: registrar_id,
            signature: sig,
        };

        self.modules.insert(id, reg.clone());
        (id, reg)
    }

    pub fn get(&self, id: &Uuid) -> Option<&ModuleRegistration> {
        self.modules.get(id)
    }

    pub fn validate_module(
        &self,
        module_id: &Uuid,
        expected_kind: ModuleKind,
        _scope_context: &str,
    ) -> Result<&ModuleRegistration, IdentityError> {
        let reg = self
            .modules
            .get(module_id)
            .ok_or(IdentityError::ModuleNotFound(*module_id))?;
        if reg.kind != expected_kind {
            return Err(IdentityError::ModuleKindMismatch);
        }
        Ok(reg)
    }

    pub fn validate_module_for_object(
        &self,
        module_id: &Uuid,
        object_class: ObjectClass,
    ) -> Result<&ModuleRegistration, IdentityError> {
        let reg = self
            .modules
            .get(module_id)
            .ok_or(IdentityError::ModuleNotFound(*module_id))?;
        let expected = match object_class {
            ObjectClass::SealedImport => ModuleKind::Import,
            ObjectClass::AiGenerated => ModuleKind::AiGeneration,
            ObjectClass::Native => return Ok(reg),
        };
        if reg.kind != expected {
            return Err(IdentityError::ModuleKindMismatch);
        }
        Ok(reg)
    }

    pub fn insert_module(&mut self, reg: ModuleRegistration) {
        self.modules.insert(reg.module_id, reg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_identity() {
        let mut store = IdentityStore::new();
        let (id, _rec) = store.create_identity(IdentityKind::Personal);
        assert!(store.validate_identity(&id).is_ok());
    }

    #[test]
    fn suspended_identity_fails() {
        let mut store = IdentityStore::new();
        let (id, _rec) = store.create_identity(IdentityKind::Service);
        store.suspend(&id).unwrap();
        assert!(store.validate_identity(&id).is_err());
    }

    #[test]
    fn session_cannot_create_native() {
        let mut store = IdentityStore::new();
        let (id, _rec) = store.create_identity(IdentityKind::Session);
        let result = store.validate_creator_for_class(&id, ObjectClass::Native);
        assert!(matches!(
            result,
            Err(IdentityError::SessionCannotCreateNative)
        ));
    }

    #[test]
    fn register_and_validate_module() {
        let mut ids = IdentityStore::new();
        let (sid, _) = ids.create_identity(IdentityKind::Service);
        let key = ids.get_key(&sid).unwrap();

        let mut reg = ModuleRegistry::new();
        let (mid, _) = reg.register(ModuleKind::Import, "files/*", "abc123", sid, key);
        assert!(reg
            .validate_module(&mid, ModuleKind::Import, "files/test")
            .is_ok());
    }

    #[test]
    fn module_kind_mismatch() {
        let mut ids = IdentityStore::new();
        let (sid, _) = ids.create_identity(IdentityKind::Service);
        let key = ids.get_key(&sid).unwrap();

        let mut reg = ModuleRegistry::new();
        let (mid, _) = reg.register(ModuleKind::Import, "files/*", "abc123", sid, key);
        assert!(matches!(
            reg.validate_module(&mid, ModuleKind::AiGeneration, "files/test"),
            Err(IdentityError::ModuleKindMismatch)
        ));
    }
}
