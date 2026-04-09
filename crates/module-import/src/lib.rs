use canon_types::{ImportBirthProposal, ImportDeclaration};
use uuid::Uuid;
use winstack_crypto::KeyPair;

pub fn assemble_import_proposal(
    artifact_bytes: Vec<u8>,
    creator_identity_id: Uuid,
    module_id: Uuid,
    parent_ids: Vec<Uuid>,
    source_uri: &str,
    claimed_content_type: &str,
    reason: &str,
) -> ImportBirthProposal {
    ImportBirthProposal {
        artifact_bytes,
        creator_identity_id,
        module_id,
        parent_ids,
        source_uri: source_uri.to_string(),
        claimed_content_type: claimed_content_type.to_string(),
        reason: reason.to_string(),
        tsa_attachment: None,
    }
}

pub fn build_import_declaration(
    object_id: Uuid,
    source_uri: &str,
    claimed_content_type: &str,
    reason: &str,
    module_id: Uuid,
    creator_key: &KeyPair,
) -> ImportDeclaration {
    let decl = ImportDeclaration {
        import_id: Uuid::new_v4(),
        object_id,
        source_uri: source_uri.to_string(),
        claimed_content_type: claimed_content_type.to_string(),
        reason: reason.to_string(),
        module_id,
        signature: String::new(),
    };
    let sig = creator_key.sign_json(&decl);
    ImportDeclaration {
        signature: sig,
        ..decl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_proposal() {
        let p = assemble_import_proposal(
            b"data".to_vec(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec![],
            "https://example.com",
            "text/plain",
            "test import",
        );
        assert_eq!(p.source_uri, "https://example.com");
        assert_eq!(p.reason, "test import");
    }

    #[test]
    fn declaration_has_signature() {
        let kp = KeyPair::generate();
        let decl = build_import_declaration(
            Uuid::new_v4(),
            "https://example.com",
            "text/plain",
            "reason",
            Uuid::new_v4(),
            &kp,
        );
        assert!(!decl.signature.is_empty());
    }
}
