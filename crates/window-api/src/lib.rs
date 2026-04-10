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
    pub time_trust: String,
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
                VerificationStatus::Verified => "VERIFIED",
                VerificationStatus::Invalid => "INVALID",
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
        }
        None => (
            "INVALID".to_string(),
            vec![FailureInfo {
                code: "MISSING_DATA".into(),
                reason: "could not load all verification inputs".into(),
            }],
        ),
    };

    let trust_class = match obj.object_class.trust_class() {
        TrustClass::Native => "NATIVE",
        TrustClass::Foreign => "FOREIGN",
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
        time_trust: "open".to_string(),
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
                }
                let payload = ObjSignPayload {
                    object_id: &obj.object_id,
                    object_class: &obj.object_class,
                    payload_hash: &obj.payload_hash,
                    artifact_size_bytes: obj.artifact_size_bytes,
                    parent_ids: &obj.parent_ids,
                    protocol: &obj.protocol,
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
        }
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
        proof_status: if status == "VERIFIED" {
            "VERIFIED".to_string()
        } else {
            let has_policy_failure = failures.iter().any(|f| f.code.starts_with("Policy"));
            if has_policy_failure {
                "FAILED".to_string()
            } else {
                "VERIFIED".to_string()
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
    pub time_trust: String,
    pub anchored_time: Option<String>,
}

async fn verify_upload(
    mut multipart: Multipart,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut proof_bytes: Option<Vec<u8>> = None;

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
            _ => {}
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

    // Check tamper first
    if file_hash != expected_hash {
        return Ok(Json(VerifyResponse {
            result: "TAMPERED".into(),
            object_id,
            message: "This file does not match the proof. It was either modified or you selected the wrong file.".into(),
            file_hash,
            expected_hash,
            failures: vec![],
            trust_class,
            object_class,
            created_at,
            payload_hash,
            time_source,
            time_trust: "open".to_string(),
            anchored_time,
        }));
    }

    // Run full verification from proof bundle
    let vr = verifier::verify_from_proof_bundle(&bundle, &file_bytes);
    match vr.status {
        VerificationStatus::Verified => Ok(Json(VerifyResponse {
            result: "VERIFIED".into(),
            object_id,
            message: "This file is authentic. It has not been changed since it was sealed.".into(),
            file_hash,
            expected_hash,
            failures: vec![],
            trust_class,
            object_class,
            created_at,
            payload_hash,
            time_source,
            time_trust: "open".to_string(),
            anchored_time,
        })),
        VerificationStatus::Invalid => {
            let failures: Vec<FailureInfo> = vr
                .failures
                .iter()
                .map(|f| FailureInfo {
                    code: format!("{:?}", f.code),
                    reason: f.reason.clone(),
                })
                .collect();
            Ok(Json(VerifyResponse {
                result: "INVALID".into(),
                object_id,
                message: "The proof bundle failed verification. The seal is broken or incomplete."
                    .into(),
                file_hash,
                expected_hash,
                failures,
                trust_class,
                object_class,
                created_at,
                payload_hash,
                time_source,
                time_trust: "open".to_string(),
                anchored_time,
            }))
        }
    }
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
    State(registry): State<SharedRegistry>,
    mut multipart: Multipart,
) -> Result<(StatusCode, [(&'static str, String); 2], Vec<u8>), (StatusCode, Json<ErrorResponse>)> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name: Option<String> = None;

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

pub fn build_router(registry: SharedRegistry) -> Router {
    Router::new()
        .route("/objects/:id", get(inspect_object))
        .route("/objects/:id/export", get(export_object))
        .route(
            "/verify",
            post(verify_upload).layer(axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024)),
        )
        .route(
            "/prove",
            post(prove_upload).layer(axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024)),
        )
        .layer(CorsLayer::permissive())
        .with_state(registry)
}

pub async fn serve(registry: SharedRegistry, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let app = build_router(registry);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
