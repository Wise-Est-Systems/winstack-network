use canon_types::{AiBirthProposal, AiGenerationRecord, AiModelInfo};
use uuid::Uuid;
use winstack_crypto::{self as crypto, KeyPair};

pub fn assemble_ai_proposal(
    artifact_bytes: Vec<u8>,
    creator_identity_id: Uuid,
    module_id: Uuid,
    parent_ids: Vec<Uuid>,
    model_name: &str,
    model_version: &str,
    prompt: &[u8],
) -> AiBirthProposal {
    AiBirthProposal {
        artifact_bytes,
        creator_identity_id,
        module_id,
        parent_ids,
        model: AiModelInfo {
            model_name: model_name.to_string(),
            model_version: model_version.to_string(),
        },
        prompt_hash: crypto::sha256_hex(prompt),
        tsa_attachment: None,
    }
}

pub fn build_ai_generation_record(
    object_id: Uuid,
    model: AiModelInfo,
    prompt: &[u8],
    output: &[u8],
    module_id: Uuid,
    creator_key: &KeyPair,
) -> AiGenerationRecord {
    let rec = AiGenerationRecord {
        generation_id: Uuid::new_v4(),
        object_id,
        model,
        prompt_hash: crypto::sha256_hex(prompt),
        output_hash: crypto::sha256_hex(output),
        module_id,
        signature: String::new(),
    };
    let sig = creator_key.sign_json(&rec);
    AiGenerationRecord {
        signature: sig,
        ..rec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assemble_proposal() {
        let p = assemble_ai_proposal(
            b"output".to_vec(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            vec![],
            "gpt-4",
            "2024-01",
            b"prompt text",
        );
        assert_eq!(p.model.model_name, "gpt-4");
        assert!(!p.prompt_hash.is_empty());
    }

    #[test]
    fn generation_record_signed() {
        let kp = KeyPair::generate();
        let rec = build_ai_generation_record(
            Uuid::new_v4(),
            AiModelInfo {
                model_name: "m".into(),
                model_version: "1".into(),
            },
            b"prompt",
            b"output",
            Uuid::new_v4(),
            &kp,
        );
        assert!(!rec.signature.is_empty());
        assert_eq!(rec.output_hash, crypto::sha256_hex(b"output"));
    }
}
