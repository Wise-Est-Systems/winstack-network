use axum::{
    extract::{Multipart, Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use canon_types::*;
use registry_core::Registry;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

pub type SharedRegistry = Arc<Mutex<Registry>>;

/// Generate a cryptographically random session token (hex string).
pub fn generate_session_token() -> String {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

#[derive(Serialize)]
pub struct InspectionResponse {
    pub status: String,
    pub object_id: String,
    pub object_type: ObjectTypeInfo,
    pub trust_class: String,
    pub summary: SummaryInfo,
    pub integrity: IntegrityInfo,
    pub policy: PolicyInfo,
    pub lineage: LineageInfo,
    pub origin: OriginInfo,
    pub failures: Vec<FailureInfo>,
}

#[derive(Serialize)]
pub struct ObjectTypeInfo {
    pub object_class: String,
    pub foreign_source_uri: Option<String>,
    pub ai_model: Option<AiModelInfoResponse>,
}

#[derive(Serialize)]
pub struct AiModelInfoResponse {
    pub model_name: String,
    pub model_version: String,
}

#[derive(Serialize)]
pub struct SummaryInfo {
    pub creator: CreatorSummary,
    pub module: ModuleSummary,
    pub time: TimeSummary,
}

#[derive(Serialize)]
pub struct CreatorSummary {
    pub identity_id: String,
    pub identity_class: String,
    pub identity_status: String,
}

#[derive(Serialize)]
pub struct ModuleSummary {
    pub identity_id: String,
    pub kind: Option<String>,
    pub approved_binary_hash: Option<String>,
}

#[derive(Serialize)]
pub struct TimeSummary {
    pub time_event_id: String,
    pub timestamp: String,
    pub time_authority_identity_id: String,
    pub chain_linkage_status: String,
    pub signature_verified: bool,
    pub time_source: String,
}

#[derive(Serialize)]
pub struct IntegrityInfo {
    pub payload_hash: String,
    pub recomputed_hash_status: String,
    pub signature_status: String,
    pub artifact_size_bytes: u64,
}

#[derive(Serialize)]
pub struct PolicyInfo {
    pub decision: Option<String>,
    pub policy_version: Option<u64>,
    pub proof_status: String,
    pub evaluated_at: Option<String>,
    pub policy_proof_id: Option<String>,
}

#[derive(Serialize)]
pub struct LineageInfo {
    pub parent_ids: Vec<String>,
    pub parent_count: usize,
    pub child_count: usize,
    pub lineage_status: String,
}

#[derive(Serialize)]
pub struct OriginInfo {
    pub object_class: String,
    pub creator_identity_id: String,
    pub module_identity_id: String,
    pub time_authority_identity_id: String,
    pub origin_record_id: Option<String>,
    pub created_at: String,
    pub protocol: String,
}

#[derive(Serialize)]
pub struct FailureInfo {
    pub code: String,
    pub reason: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Serialize)]
pub struct ErrorDetail {
    pub message: String,
}

async fn inspect_object(
    State(registry): State<SharedRegistry>,
    Path(id_str): Path<String>,
) -> Result<Json<InspectionResponse>, (StatusCode, Json<ErrorResponse>)> {
    let id = Uuid::parse_str(&id_str).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("invalid uuid: {}", id_str),
                },
            }),
        )
    })?;

    let reg = registry.lock().unwrap();

    let obj = reg.object_store.get(&id).cloned().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("object not found: {}", id),
                },
            }),
        )
    })?;

    // Re-run verifier — no cached truth
    let verification = reg.verify_object(&id);
    let (status, failures) = match verification {
        Some(result) => {
            let s = match result.status {
                VerificationStatus::Verified => "Verified",
                VerificationStatus::Tampered => "Tampered",
                VerificationStatus::Invalid => "Invalid",
                // (Dying merged into Unrecognized),
            };
            let fs: Vec<FailureInfo> = result
                .failures
                .iter()
                .map(|f| FailureInfo {
                    code: format!("{:?}", f.code),
                    reason: f.reason.clone(),
                })
                .collect();
            (s.to_string(), fs)
        },
        None => (
            "Invalid".to_string(),
            vec![FailureInfo {
                code: "MISSING_DATA".into(),
                reason: "could not load all verification inputs".into(),
            }],
        ),
    };

    let trust_class = match obj.object_class.trust_class() {
        TrustClass::Native => "Native",
        TrustClass::NonNative => "Non-native",
    };

    // Creator summary
    let creator_summary = match reg.identity_store.get(&obj.origin.creator_identity_id) {
        Some(ident) => CreatorSummary {
            identity_id: ident.identity_id.to_string(),
            identity_class: format!("{:?}", ident.kind),
            identity_status: format!("{:?}", ident.status),
        },
        None => CreatorSummary {
            identity_id: obj.origin.creator_identity_id.to_string(),
            identity_class: "UNKNOWN".into(),
            identity_status: "UNKNOWN".into(),
        },
    };

    // Module summary
    let module_summary = match reg.module_registry.get(&obj.origin.module_identity_id) {
        Some(m) => ModuleSummary {
            identity_id: m.module_id.to_string(),
            kind: Some(format!("{:?}", m.kind)),
            approved_binary_hash: Some(m.binary_hash.clone()),
        },
        None => ModuleSummary {
            identity_id: obj.origin.module_identity_id.to_string(),
            kind: None,
            approved_binary_hash: None,
        },
    };

    // Time summary
    let time_sig_ok = if let Some(ta_ident) = reg
        .identity_store
        .get(&obj.origin.time_authority_identity_id)
    {
        time_core::verify_time_signature(&obj.time_event, &ta_ident.public_key_hex).is_ok()
    } else {
        false
    };

    let chain_status = if obj.time_event.is_genesis() {
        "GENESIS"
    } else if obj.time_event.predecessor_event_id.is_some() {
        "LINKED"
    } else {
        "PREDECESSOR_MISSING"
    };

    let time_summary = TimeSummary {
        time_event_id: obj.time_event.time_event_id.to_string(),
        timestamp: obj.time_event.timestamp.clone(),
        time_authority_identity_id: obj.time_event.time_authority_identity_id.to_string(),
        chain_linkage_status: chain_status.to_string(),
        signature_verified: time_sig_ok,
        time_source: format!("{:?}", obj.time_event.time_source),
    };

    // Integrity
    let artifact = reg.object_store.get_artifact(&id);
    let (hash_status, sig_status) = match artifact {
        Some(bytes) => {
            let computed = winstack_crypto::sha256_hex(bytes);
            let hash_ok = computed == obj.payload_hash;
            let sig_ok = if let Some(creator_ident) =
                reg.identity_store.get(&obj.origin.creator_identity_id)
            {
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
                let payload = ObjSignPayload {
                    object_id: &obj.object_id,
                    object_class: &obj.object_class,
                    payload_hash: &obj.payload_hash,
                    artifact_size_bytes: obj.artifact_size_bytes,
                    parent_ids: &obj.parent_ids,
                    protocol: &obj.protocol,
                    proof_chain: &obj.proof_chain,
                };
                winstack_crypto::verify_json_signature(
                    &creator_ident.public_key_hex,
                    &payload,
                    &obj.object_signature,
                )
                .is_ok()
            } else {
                false
            };
            (
                if hash_ok { "MATCH" } else { "MISMATCH" },
                if sig_ok { "VALID" } else { "INVALID" },
            )
        },
        None => ("MISMATCH", "UNVERIFIABLE"),
    };

    let integrity = IntegrityInfo {
        payload_hash: obj.payload_hash.clone(),
        recomputed_hash_status: hash_status.to_string(),
        signature_status: sig_status.to_string(),
        artifact_size_bytes: obj.artifact_size_bytes,
    };

    // Policy
    let policy = PolicyInfo {
        decision: Some(format!("{:?}", obj.policy_proof.decision)),
        policy_version: Some(obj.policy_proof.policy_version),
        proof_status: if status == "Verified" {
            "Verified".to_string()
        } else {
            let has_policy_failure = failures.iter().any(|f| f.code.starts_with("Policy"));
            if has_policy_failure {
                "Failed".to_string()
            } else {
                "Verified".to_string()
            }
        },
        evaluated_at: Some(obj.policy_proof.evaluated_at.clone()),
        policy_proof_id: Some(obj.policy_proof.policy_proof_id.to_string()),
    };

    // Lineage
    let child_count = reg.graph.child_count(id).unwrap_or(0);
    let parent_count = obj.parent_ids.len();

    let lineage_status = if failures.iter().any(|f| f.code.starts_with("Lineage")) {
        if failures.iter().any(|f| f.code == "LineageParentMissing") {
            "PARENT_MISSING"
        } else if failures.iter().any(|f| f.code == "LineageParentInvalid") {
            "PARENT_INVALID"
        } else if failures
            .iter()
            .any(|f| f.code == "LineageParentTimestampViolation")
        {
            "PARENT_TIMESTAMP_VIOLATION"
        } else if failures
            .iter()
            .any(|f| f.code == "LineageSelfCycle" || f.code == "LineageCycleDetected")
        {
            "CYCLE_DETECTED"
        } else {
            "PARENT_INVALID"
        }
    } else {
        "CLEAN"
    };

    let lineage = LineageInfo {
        parent_ids: obj.parent_ids.iter().map(|p| p.to_string()).collect(),
        parent_count,
        child_count,
        lineage_status: lineage_status.to_string(),
    };

    // Origin
    let origin = OriginInfo {
        object_class: format!("{:?}", obj.origin.object_class),
        creator_identity_id: obj.origin.creator_identity_id.to_string(),
        module_identity_id: obj.origin.module_identity_id.to_string(),
        time_authority_identity_id: obj.origin.time_authority_identity_id.to_string(),
        origin_record_id: Some(obj.origin.origin_record_id.to_string()),
        created_at: obj.origin.created_at.clone(),
        protocol: obj.origin.protocol.clone(),
    };

    // Object type
    let object_type = ObjectTypeInfo {
        object_class: format!("{:?}", obj.object_class),
        foreign_source_uri: obj.origin.foreign_source_uri.clone(),
        ai_model: obj.origin.ai_model.as_ref().map(|m| AiModelInfoResponse {
            model_name: m.model_name.clone(),
            model_version: m.model_version.clone(),
        }),
    };

    Ok(Json(InspectionResponse {
        status,
        object_id: id.to_string(),
        object_type,
        trust_class: trust_class.to_string(),
        summary: SummaryInfo {
            creator: creator_summary,
            module: module_summary,
            time: time_summary,
        },
        integrity,
        policy,
        lineage,
        origin,
        failures,
    }))
}

async fn export_object(
    State(registry): State<SharedRegistry>,
    Path(id_str): Path<String>,
) -> Result<
    (
        StatusCode,
        [(&'static str, String); 2],
        Json<canon_types::ProofBundle>,
    ),
    (StatusCode, Json<ErrorResponse>),
> {
    let id = Uuid::parse_str(&id_str).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("invalid uuid: {}", id_str),
                },
            }),
        )
    })?;

    let reg = registry.lock().unwrap();

    let bundle = reg.build_proof_bundle(&id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("object not found: {}", id),
                },
            }),
        )
    })?;

    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/json".to_string()),
            (
                "content-disposition",
                format!("attachment; filename=\"{}.proof.json\"", id),
            ),
        ],
        Json(bundle),
    ))
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub result: String,
    pub object_id: String,
    pub message: String,
    pub file_hash: String,
    pub expected_hash: String,
    pub failures: Vec<FailureInfo>,
    pub trust_class: String,
    pub object_class: String,
    pub created_at: String,
    pub payload_hash: String,
    pub time_source: String,
    pub anchored_time: Option<String>,
    pub chain_status: String,
    pub chain_depth: usize,
    pub creator_key: String,
}

async fn verify_upload(
    mut multipart: Multipart,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut proof_bytes: Option<Vec<u8>> = None;
    let mut field_count: usize = 0;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("multipart error: {}", e),
                },
            }),
        )
    })? {
        field_count += 1;
        if field_count > 2 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: "too many fields: expected 'file' and 'proof'".into(),
                    },
                }),
            ));
        }
        let name = field.name().unwrap_or("").to_string();
        let data = field.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!("read error: {}", e),
                    },
                }),
            )
        })?;
        match name.as_str() {
            "file" => file_bytes = Some(data.to_vec()),
            "proof" => proof_bytes = Some(data.to_vec()),
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: ErrorDetail {
                            message: format!(
                                "unexpected field '{}': expected 'file' or 'proof'",
                                name
                            ),
                        },
                    }),
                ));
            },
        }
    }

    let file_bytes = file_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: "missing 'file' field".into(),
                },
            }),
        )
    })?;

    let proof_bytes = proof_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: "missing 'proof' field".into(),
                },
            }),
        )
    })?;

    let bundle: ProofBundle = serde_json::from_slice(&proof_bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("invalid proof bundle: {}", e),
                },
            }),
        )
    })?;

    let file_hash = winstack_crypto::sha256_hex(&file_bytes);
    let expected_hash = bundle.object.payload_hash.clone();
    let object_id = bundle.object.object_id.to_string();
    let trust_class = format!("{:?}", bundle.object.object_class.trust_class());
    let object_class = format!("{:?}", bundle.object.object_class);
    let created_at = bundle.object.origin.created_at.clone();
    let payload_hash = bundle.object.payload_hash.clone();
    let time_source = format!("{:?}", bundle.object.time_event.time_source);
    let anchored_time = bundle.object.time_event.anchored_time.clone();
    let creator_key = bundle.creator_identity.public_key_hex.clone();

    // Determine chain status
    let (chain_status_str, chain_depth) = {
        let chain = &bundle.object.proof_chain;
        match chain {
            None => ("standalone".to_string(), 1),
            Some(c) if c.predecessor_proof_id.is_none() => ("origin".to_string(), 1),
            Some(_) => ("successor".to_string(), 1),
        }
    };

    // Check tamper first — file content vs name tag's recorded hash
    if file_hash != expected_hash {
        return Ok(Json(VerifyResponse {
            result: "Tampered".into(),
            object_id,
            message: "Tampered. This file was changed after it was sealed.".into(),
            file_hash,
            expected_hash,
            failures: vec![],
            trust_class,
            object_class,
            created_at,
            payload_hash,
            time_source,

            anchored_time,
            chain_status: chain_status_str.clone(),
            chain_depth,
            creator_key: creator_key.clone(),
        }));
    }

    // Run full verification from proof bundle
    let vr = verifier::verify_from_proof_bundle(&bundle, &file_bytes);
    let (result_str, message) = match vr.status {
        VerificationStatus::Verified => (
            "Verified",
            "Verified. This file matches the original — it hasn't been changed.",
        ),
        VerificationStatus::Tampered => (
            "Tampered",
            "Tampered. This file was changed after it was sealed.",
        ),
        VerificationStatus::Invalid => ("Invalid", "Invalid. We can't verify this file."),
    };
    let failures: Vec<FailureInfo> = if vr.status.is_verified() {
        vec![]
    } else {
        vr.failures
            .iter()
            .map(|f| FailureInfo {
                code: format!("{:?}", f.code),
                reason: f.reason.clone(),
            })
            .collect()
    };
    Ok(Json(VerifyResponse {
        result: result_str.into(),
        object_id,
        message: message.into(),
        file_hash,
        expected_hash,
        failures,
        trust_class,
        object_class,
        created_at,
        payload_hash,
        time_source,

        anchored_time,
        chain_status: chain_status_str,
        chain_depth,
        creator_key,
    }))
}

#[derive(Serialize)]
pub struct ProveResponse {
    pub result: String,
    pub object_id: String,
    pub payload_hash: String,
    pub created_at: String,
    pub time_source: String,
    pub message: String,
}

async fn prove_upload(
    axum::Extension(token): axum::Extension<Arc<Option<String>>>,
    headers: axum::http::HeaderMap,
    State(registry): State<SharedRegistry>,
    mut multipart: Multipart,
) -> Result<(StatusCode, [(&'static str, String); 2], Vec<u8>), (StatusCode, Json<ErrorResponse>)> {
    // Auth check — write endpoint requires session token
    if let Some(ref expected) = *token {
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if provided != Some(expected.as_str()) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: "unauthorized".into(),
                    },
                }),
            ));
        }
    }

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;
    let mut predecessor_bytes: Option<Vec<u8>> = None;
    let mut field_count: usize = 0;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("multipart error: {}", e),
                },
            }),
        )
    })? {
        field_count += 1;
        if field_count > 2 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: "too many fields: expected 'file' and optional 'predecessor'"
                            .into(),
                    },
                }),
            ));
        }
        let name = field.name().unwrap_or("").to_string();
        let fname = field.file_name().unwrap_or("").to_string();
        let data = field.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!("read error: {}", e),
                    },
                }),
            )
        })?;
        if name == "file" {
            file_name = Some(fname);
            file_bytes = Some(data.to_vec());
        } else if name == "predecessor" {
            predecessor_bytes = Some(data.to_vec());
        } else {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!(
                            "unexpected field '{}': expected 'file' or 'predecessor'",
                            name
                        ),
                    },
                }),
            ));
        }
    }

    let artifact_bytes = file_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: "missing 'file' field".into(),
                },
            }),
        )
    })?;

    let mut reg = registry.lock().unwrap();

    // Find the creator and module IDs from the identity store
    let all_ids = reg.identity_store.all_identity_ids();
    let creator_id = all_ids
        .iter()
        .find(|id| {
            reg.identity_store
                .get(id)
                .map(|r| r.kind == IdentityKind::Personal)
                .unwrap_or(false)
        })
        .copied()
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: "no creator identity found — run 'winstack prove' first to initialize the node".into(),
                    },
                }),
            )
        })?;

    let module_id = reg.module_registry.first_module_id().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message:
                        "no module registered — run 'winstack prove' first to initialize the node"
                            .into(),
                },
            }),
        )
    })?;

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes,
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: predecessor_bytes.and_then(|pb| {
                serde_json::from_slice::<ProofBundle>(&pb).ok().map(|pred| {
                    let lineage_id = pred
                        .object
                        .proof_chain
                        .as_ref()
                        .map(|c| c.lineage_id)
                        .unwrap_or(pred.object.object_id);
                    ProofChain {
                        lineage_id,
                        predecessor_proof_id: Some(pred.object.object_id),
                        predecessor_payload_hash: Some(pred.object.payload_hash.clone()),
                        key_delegation: None,
                    }
                })
            }),
        })
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!("sealing failed: {}", e),
                    },
                }),
            )
        })?;

    let bundle = reg.build_proof_bundle(&obj.object_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: "could not build proof bundle".into(),
                },
            }),
        )
    })?;

    let proof_json = serde_json::to_string_pretty(&bundle).unwrap();
    let download_name = file_name
        .map(|n| format!("{}.proof.json", n))
        .unwrap_or_else(|| format!("{}.proof.json", obj.object_id));

    // Auto-save to user's Downloads folder
    if let Ok(home) = std::env::var("HOME") {
        let downloads = std::path::Path::new(&home).join("Downloads");
        if downloads.exists() {
            let save_path = downloads.join(&download_name);
            let _ = std::fs::write(&save_path, &proof_json);
        }
    }

    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/json".to_string()),
            (
                "content-disposition",
                format!("attachment; filename=\"{}\"", download_name),
            ),
        ],
        proof_json.into_bytes(),
    ))
}

/// POST /seal — drop a file, get a .win bundle back (file + proof in one ZIP)
async fn seal_upload(
    axum::Extension(token): axum::Extension<Arc<Option<String>>>,
    headers: axum::http::HeaderMap,
    State(registry): State<SharedRegistry>,
    mut multipart: Multipart,
) -> Result<(StatusCode, [(&'static str, String); 2], Vec<u8>), (StatusCode, Json<ErrorResponse>)> {
    // Auth check
    if let Some(ref expected) = *token {
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if provided != Some(expected.as_str()) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: "unauthorized".into(),
                    },
                }),
            ));
        }
    }

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;
    let mut field_count: usize = 0;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("upload error: {}", e),
                },
            }),
        )
    })? {
        field_count += 1;
        if field_count > 1 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: "too many fields: expected single 'file' field".into(),
                    },
                }),
            ));
        }
        let name = field.name().unwrap_or("").to_string();
        if name != "file" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!("unexpected field '{}': expected 'file'", name),
                    },
                }),
            ));
        }
        let fname = field.file_name().unwrap_or("").to_string();
        let data = field.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!("read error: {}", e),
                    },
                }),
            )
        })?;
        file_name = Some(fname);
        file_bytes = Some(data.to_vec());
    }

    let artifact_bytes = file_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: "no file provided".into(),
                },
            }),
        )
    })?;
    let original_name = file_name.unwrap_or_else(|| "file".into());

    let mut reg = registry.lock().unwrap();

    let all_ids = reg.identity_store.all_identity_ids();
    let creator_id = all_ids
        .iter()
        .find(|id| {
            reg.identity_store
                .get(id)
                .map(|r| r.kind == IdentityKind::Personal)
                .unwrap_or(false)
        })
        .copied()
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: "node not initialized".into(),
                    },
                }),
            )
        })?;

    let module_id = reg.module_registry.first_module_id().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: "node not initialized".into(),
                },
            }),
        )
    })?;

    let obj = reg
        .seal_native(NativeBirthProposal {
            artifact_bytes: artifact_bytes.clone(),
            creator_identity_id: creator_id,
            module_id,
            parent_ids: vec![],
            tsa_attachment: None,
            proof_chain: None,
        })
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!("sealing failed: {}", e),
                    },
                }),
            )
        })?;

    let bundle = reg.build_proof_bundle(&obj.object_id).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: "could not build proof".into(),
                },
            }),
        )
    })?;

    let proof_json = serde_json::to_string_pretty(&bundle).unwrap();
    let win_bytes = win_format::pack(&original_name, &artifact_bytes, &proof_json);
    let win_name = format!("{}.win", original_name);

    // Auto-save
    if let Ok(home) = std::env::var("HOME") {
        let downloads = std::path::Path::new(&home).join("Downloads");
        if downloads.exists() {
            let _ = std::fs::write(downloads.join(&win_name), &win_bytes);
        }
    }

    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/octet-stream".to_string()),
            (
                "content-disposition",
                format!("attachment; filename=\"{}\"", win_name),
            ),
        ],
        win_bytes,
    ))
}

/// POST /check — drop a .win bundle, get verification result
async fn check_bundle(
    mut multipart: Multipart,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut bundle_bytes: Option<Vec<u8>> = None;
    let mut field_count: usize = 0;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("upload error: {}", e),
                },
            }),
        )
    })? {
        field_count += 1;
        if field_count > 1 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: "too many fields: expected single 'file' field".into(),
                    },
                }),
            ));
        }
        let name = field.name().unwrap_or("").to_string();
        if name != "file" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!("unexpected field '{}': expected 'file'", name),
                    },
                }),
            ));
        }
        let data = field.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!("read error: {}", e),
                    },
                }),
            )
        })?;
        bundle_bytes = Some(data.to_vec());
    }

    let data = bundle_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: "no file provided".into(),
                },
            }),
        )
    })?;

    let (_file_name, file_bytes, proof_text) = match win_format::unpack(&data) {
        Ok(v) => v,
        Err(e) => {
            return Ok(Json(VerifyResponse {
                result: "Invalid".into(),
                object_id: String::new(),
                message: format!("I can't read this name tag. {}", e),
                file_hash: String::new(),
                expected_hash: String::new(),
                failures: vec![],
                trust_class: String::new(),
                object_class: String::new(),
                created_at: String::new(),
                payload_hash: String::new(),
                time_source: String::new(),

                anchored_time: None,
                chain_status: String::new(),
                chain_depth: 0,
                creator_key: String::new(),
            }));
        },
    };

    let bundle: ProofBundle = match serde_json::from_str(&proof_text) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Json(VerifyResponse {
                result: "Invalid".into(),
                object_id: String::new(),
                message: format!(
                    "I can't read this name tag. Proof section is not valid: {}",
                    e
                ),
                file_hash: String::new(),
                expected_hash: String::new(),
                failures: vec![],
                trust_class: String::new(),
                object_class: String::new(),
                created_at: String::new(),
                payload_hash: String::new(),
                time_source: String::new(),

                anchored_time: None,
                chain_status: String::new(),
                chain_depth: 0,
                creator_key: String::new(),
            }));
        },
    };

    let file_hash = winstack_crypto::sha256_hex(&file_bytes);
    let expected_hash = bundle.object.payload_hash.clone();
    let object_id = bundle.object.object_id.to_string();
    let trust_class = format!("{:?}", bundle.object.object_class.trust_class());
    let object_class = format!("{:?}", bundle.object.object_class);
    let created_at = bundle.object.origin.created_at.clone();
    let payload_hash = bundle.object.payload_hash.clone();
    let time_source = format!("{:?}", bundle.object.time_event.time_source);
    let anchored_time = bundle.object.time_event.anchored_time.clone();
    let creator_key = bundle.creator_identity.public_key_hex.clone();
    let (chain_status_str, chain_depth) = match &bundle.object.proof_chain {
        None => ("standalone".to_string(), 1),
        Some(c) if c.predecessor_proof_id.is_none() => ("origin".to_string(), 1),
        Some(_) => ("successor".to_string(), 1),
    };

    if file_hash != expected_hash {
        return Ok(Json(VerifyResponse {
            result: "Tampered".into(),
            object_id,
            message: "Tampered. This file was changed after it was sealed.".into(),
            file_hash,
            expected_hash,
            failures: vec![],
            trust_class,
            object_class,
            created_at,
            payload_hash,
            time_source,

            anchored_time,
            chain_status: chain_status_str,
            chain_depth,
            creator_key: creator_key.clone(),
        }));
    }

    let vr = verifier::verify_from_proof_bundle(&bundle, &file_bytes);
    let (result_str, message) = match vr.status {
        VerificationStatus::Verified => (
            "Verified",
            "Verified. This file matches the original — it hasn't been changed.",
        ),
        VerificationStatus::Tampered => (
            "Tampered",
            "Tampered. This file was changed after it was sealed.",
        ),
        VerificationStatus::Invalid => ("Invalid", "I can't read this name tag."),
        // (Dying merged into Unrecognized.)
    };
    let failures: Vec<FailureInfo> = if vr.status.is_verified() {
        vec![]
    } else {
        vr.failures
            .iter()
            .map(|f| FailureInfo {
                code: format!("{:?}", f.code),
                reason: f.reason.clone(),
            })
            .collect()
    };
    Ok(Json(VerifyResponse {
        result: result_str.into(),
        object_id,
        message: message.into(),
        file_hash,
        expected_hash,
        failures,
        trust_class,
        object_class,
        created_at,
        payload_hash,
        time_source,

        anchored_time,
        chain_status: chain_status_str,
        chain_depth,
        creator_key,
    }))
}

/// POST /save-and-open — save file to Downloads and open with system default app
async fn save_and_open(
    axum::Extension(token): axum::Extension<Arc<Option<String>>>,
    headers: axum::http::HeaderMap,
    mut multipart: Multipart,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Auth check — requires session token
    if let Some(ref expected) = *token {
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if provided != Some(expected.as_str()) {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: "unauthorized".into(),
                    },
                }),
            ));
        }
    }

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: format!("upload error: {}", e),
                },
            }),
        )
    })? {
        let name = field.name().unwrap_or("").to_string();
        let fname = field.file_name().unwrap_or("").to_string();
        let data = field.bytes().await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: ErrorDetail {
                        message: format!("read error: {}", e),
                    },
                }),
            )
        })?;
        if name == "file" {
            file_name = Some(if fname.is_empty() {
                "file".into()
            } else {
                fname
            });
            file_bytes = Some(data.to_vec());
        }
    }

    let bytes = file_bytes.ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: ErrorDetail {
                    message: "no file provided".into(),
                },
            }),
        )
    })?;
    let raw_name = file_name.unwrap_or_else(|| "file".into());
    // Sanitize: strip path separators, reject null bytes
    let name: String = raw_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("file")
        .replace('\0', "")
        .chars()
        .take(255)
        .collect();
    let name = if name.is_empty() { "file".into() } else { name };

    // Save to Downloads
    if let Ok(home) = std::env::var("HOME") {
        let save_path = std::path::Path::new(&home).join("Downloads").join(&name);
        if std::fs::write(&save_path, &bytes).is_ok() {
            // Open with system default app
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("open").arg(&save_path).spawn();
            }
        }
    }

    Ok(StatusCode::OK)
}

/// Build router with session token auth on write endpoints.
/// Read-only endpoints (verify, check, inspect) require no token.
/// Write endpoints (prove, seal, save-and-open) require Bearer token.
pub fn build_router(registry: SharedRegistry, session_token: Option<String>) -> Router {
    let body_limit = axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024);
    let token: Arc<Option<String>> = Arc::new(session_token);

    Router::new()
        .route("/objects/:id", get(inspect_object))
        .route("/objects/:id/export", get(export_object))
        .route("/verify", post(verify_upload).layer(body_limit))
        .route("/check", post(check_bundle).layer(body_limit))
        .route("/prove", post(prove_upload).layer(body_limit))
        .route("/seal", post(seal_upload).layer(body_limit))
        .route("/save-and-open", post(save_and_open).layer(body_limit))
        .layer(axum::Extension(token))
        .layer({
            // Only allow requests from the Tauri app origin and localhost
            use axum::http::{HeaderValue, Method};
            use tower_http::cors::AllowOrigin;
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
                    let o = origin.to_str().unwrap_or("");
                    o.starts_with("http://127.0.0.1")
                        || o.starts_with("http://localhost")
                        || o.starts_with("tauri://")
                        || o.starts_with("https://tauri.")
                }))
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(tower_http::cors::Any)
        })
        .with_state(registry)
}

pub async fn serve(registry: SharedRegistry, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    serve_with_token(registry, addr, None).await
}

pub async fn serve_with_token(
    registry: SharedRegistry,
    addr: &str,
    token: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(registry, token);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
