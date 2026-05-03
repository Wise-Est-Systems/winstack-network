//! WASM bindings for the Wise verifier.
//!
//! One artifact, many surfaces. This crate compiles to a single `.wasm` module
//! that any browser, extension, or chat-app can call to verify a win tag.
//!
//! See `spec/grammar.md` § 3 for the three states this returns.
//!
//! Usage from JavaScript:
//!
//! ```js
//! import init, { recognize_win, recognize_bundle } from './verifier_wasm.js';
//! await init();
//! const reading = recognize_win(winFileBytes);
//! // reading.status is one of: "Verified", "Tampered", "Invalid"
//! ```
//!
//! (`recognize_*` is the public JS export name, kept stable for backwards
//! compatibility. Conceptually it is a verify call; the JS-facing name is
//! frozen on the wire and not user-visible.)
//!
//! The reading object structure is documented in `Reading` below — its JSON
//! shape is the contract every receiver-side surface relies on.

use canon_types::{
    ChainedTimeEvent, IdentityKind, ModuleKind, ObjectClass, OriginRecord, ProofBundle,
    ProofChain, SealedObject, TimeSource, VerificationStatus,
};
use identity_core::{IdentityStore, ModuleRegistry};
use policy_core::PolicyEvaluator;
use serde::Serialize;
use time_core::TimeAuthority;
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wise_crypto::KeyPair;

#[derive(Serialize)]
struct Reading {
    /// One of "Verified" | "Tampered" | "Invalid".
    status: &'static str,
    /// Signing-key identity classification — one of:
    ///   "Local"    — no display name, not in any trusted list
    ///   "Named"    — declares a display name (still up to receiver)
    ///   "Official" — fingerprint matches a receiver-side trusted list (not revoked)
    ///   "Unknown"  — we couldn't even read the signer (Invalid readings)
    /// This is the **trust class of the key**, not a claim about the
    /// real-world person behind it. The receiver decides what trust to
    /// extend; the verifier only reports what the .win itself declares.
    identity_class: &'static str,
    /// Plain-English summary of what `identity_class` proves and does not.
    /// Suitable for direct display next to the verdict.
    identity_explainer: &'static str,
    /// Witness on the win tag. None when we couldn't read the tag.
    witness: Option<Witness>,
    /// Creation date from the win tag's origin record. JSON key kept as
    /// `born` for wire compatibility; user-facing surfaces relabel to "Created".
    born: Option<String>,
    /// True iff anchored via RFC 3161; false for local-clock creation dates.
    anchored: bool,
    /// "Standalone" | "Origin" | "Successor" — lineage shape.
    lineage: &'static str,
    /// SHA-256 of the file as recorded on the win tag.
    payload_hash: Option<String>,
    /// File size as recorded.
    size_bytes: Option<u64>,
    /// Diagnostics. Engineering layer; receiver UI can ignore.
    failures: Vec<FailureInfo>,
    /// Human-readable explanation in grammar voice. Suitable for direct display.
    message: &'static str,
}

#[derive(Serialize)]
struct Witness {
    public_key_hex: String,
    /// `object_class` trust hint (Native / NonNative). NOT the same as
    /// `Reading.identity_class` — this describes whether the key claims
    /// to have made the file or to be attesting to one it didn't make.
    trust_class: String,
    /// Optional self-declared name from the proof's identity record.
    /// The signer chose this; the verifier surfaces it but does not validate it.
    display_name: Option<String>,
}

#[derive(Serialize)]
struct FailureInfo {
    code: String,
    reason: String,
}

fn lineage_str(bundle: &ProofBundle) -> &'static str {
    match &bundle.object.proof_chain {
        None => "Standalone",
        Some(c) if c.predecessor_proof_id.is_none() => "Origin",
        Some(_) => "Successor",
    }
}

fn message_for(status: VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Verified => {
            "The file matches the proof inside this .win container. No byte changes detected."
        },
        VerificationStatus::Tampered => {
            "The file no longer matches the proof inside this .win container. \
             At least one byte changed."
        },
        VerificationStatus::Invalid => "This .win container is not valid or cannot be verified.",
    }
}

/// Plain-English summary of what an identity class proves about the
/// real-world signer. The verifier surfaces this alongside the status.
fn identity_explainer_for(class: &str) -> &'static str {
    match class {
        "Local" => {
            "Sealed by a local key generated on the sealer's device. \
             This proves file integrity, not real-world identity."
        },
        "Named" => {
            "Sealed by a key that declares a display name. The receiver \
             decides whether to trust that name."
        },
        "Official" => {
            "Sealed by a key whose fingerprint matches an entry the \
             receiver has explicitly added to a local trusted list."
        },
        _ => {
            "Sealed by an unknown key. Valid signature, no further \
             trust signal."
        },
    }
}

/// Classify the signing key on a successfully-parsed proof bundle.
/// Receiver-side identity tier. Returns one of:
///   "Local"    — Personal-kind key, sealed on someone's own device
///   "Named"    — Organization or Service kind (declares a non-personal identity)
///   "Official" — never returned by this fn directly; the host elevates
///                Named → Official only after a trusted-list fingerprint match
///   "Unknown"  — only returned by `unrecognizable_reading` for Invalid bundles
///
/// The protocol does not let a signing key claim a real-world person
/// or company. "Named" only means the key was registered with an
/// IdentityKind of Organization or Service in its own creation record;
/// the receiver still decides whether to trust that claim.
fn identity_class_for(bundle: &ProofBundle) -> &'static str {
    use canon_types::IdentityKind;
    match bundle.creator_identity.kind {
        IdentityKind::Personal | IdentityKind::Session => "Local",
        IdentityKind::Organization | IdentityKind::Service => "Named",
    }
}

fn status_str(status: VerificationStatus) -> &'static str {
    match status {
        VerificationStatus::Verified => "Verified",
        VerificationStatus::Tampered => "Tampered",
        VerificationStatus::Invalid => "Invalid",
    }
}

/// Build a Reading for cases where we couldn't even parse the container or
/// proof. From the receiver's perspective, this is indistinguishable from
/// any other reason we can't verify the file — so we return Invalid.
fn unrecognizable_reading(reason: &str) -> Reading {
    Reading {
        status: "Invalid",
        identity_class: "Unknown",
        identity_explainer: identity_explainer_for("Unknown"),
        witness: None,
        born: None,
        anchored: false,
        lineage: "Unknown",
        payload_hash: None,
        size_bytes: None,
        failures: vec![FailureInfo {
            code: "ContainerMalformed".into(),
            reason: reason.into(),
        }],
        message: message_for(VerificationStatus::Invalid),
    }
}

fn build_reading(bundle: &ProofBundle, file_bytes: &[u8]) -> Reading {
    let id_class = identity_class_for(bundle);
    // File-vs-win-tag hash check first — the most actionable signal for the receiver.
    let computed = wise_crypto::sha256_hex(file_bytes);
    if computed != bundle.object.payload_hash {
        return Reading {
            status: status_str(VerificationStatus::Tampered),
            identity_class: id_class,
            identity_explainer: identity_explainer_for(id_class),
            witness: Some(Witness {
                public_key_hex: bundle.creator_identity.public_key_hex.clone(),
                trust_class: format!("{:?}", bundle.object.object_class.trust_class()),
                display_name: None,
            }),
            born: Some(bundle.object.origin.created_at.clone()),
            anchored: matches!(
                bundle.object.time_event.time_source,
                canon_types::TimeSource::External
            ),
            lineage: lineage_str(bundle),
            payload_hash: Some(bundle.object.payload_hash.clone()),
            size_bytes: Some(bundle.object.artifact_size_bytes),
            failures: vec![FailureInfo {
                code: "PayloadHashMismatch".into(),
                reason: format!(
                    "expected {}, computed {}",
                    bundle.object.payload_hash, computed
                ),
            }],
            message: message_for(VerificationStatus::Tampered),
        };
    }

    // Full structural verification.
    let result = verifier::verify_from_proof_bundle(bundle, file_bytes);
    Reading {
        status: status_str(result.status),
        identity_class: id_class,
        identity_explainer: identity_explainer_for(id_class),
        witness: Some(Witness {
            public_key_hex: bundle.creator_identity.public_key_hex.clone(),
            trust_class: format!("{:?}", bundle.object.object_class.trust_class()),
            display_name: None,
        }),
        born: Some(bundle.object.origin.created_at.clone()),
        anchored: matches!(
            bundle.object.time_event.time_source,
            canon_types::TimeSource::External
        ),
        lineage: lineage_str(bundle),
        payload_hash: Some(bundle.object.payload_hash.clone()),
        size_bytes: Some(bundle.object.artifact_size_bytes),
        failures: result
            .failures
            .iter()
            .map(|f| FailureInfo {
                code: format!("{:?}", f.code),
                reason: f.reason.clone(),
            })
            .collect(),
        message: message_for(result.status),
    }
}

/// Verify a `.win` container in one call.
///
/// Returns a `Reading` whose `status` is one of "Verified", "Tampered",
/// "Invalid". Throws only if serialization itself fails — malformed
/// containers produce an Invalid reading, not an exception.
#[wasm_bindgen]
pub fn recognize_win(win_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let reading = match win_format::unpack(win_bytes) {
        Ok((_name, file_bytes, proof_text)) => {
            match serde_json::from_str::<ProofBundle>(&proof_text) {
                Ok(bundle) => build_reading(&bundle, &file_bytes),
                Err(e) => unrecognizable_reading(&format!(
                    "win tag's proof section is not valid JSON: {}",
                    e
                )),
            }
        },
        Err(e) => unrecognizable_reading(&format!("{}", e)),
    };
    serde_wasm_bindgen::to_value(&reading).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify a file given its bytes plus a separately-supplied proof bundle JSON.
///
/// Use this when the win tag arrives separately from the file (legacy
/// `.proof.json` sidecar, URL-fetched proof bundle, etc).
#[wasm_bindgen]
pub fn recognize_bundle(proof_json: &str, file_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let reading = match serde_json::from_str::<ProofBundle>(proof_json) {
        Ok(bundle) => build_reading(&bundle, file_bytes),
        Err(e) => unrecognizable_reading(&format!("win tag is not valid JSON: {}", e)),
    };
    serde_wasm_bindgen::to_value(&reading).map_err(|e| JsValue::from_str(&e.to_string()))
}

// ---------------------------------------------------------------------------
// Browser sealing
// ---------------------------------------------------------------------------
//
// `seal_file` builds a real, verifier-accepted .win container in the browser.
//
// The witness keys (creator, time-authority, policy-evaluator) are generated
// fresh in the browser on each call. They are NOT the Wise.Est production
// witness key. The receiver-side trust class on the resulting .win is
// "browser-local" — recorded in the SealResult so the UI can label it
// honestly. The verifier still returns Verified for these files because the
// math is real; the trust story is what the UI must communicate.

/// Result of an in-browser seal call.
///
/// Returned to JavaScript. `win_bytes` is the binary .win payload the user
/// downloads. `verification_status` is the literal status the local verifier
/// returned when re-verifying the produced container — we never claim
/// "Verified" without re-running the verifier on the result.
#[derive(Serialize)]
struct SealResult {
    /// One of "Verified" | "Tampered" | "Invalid". This is the result of
    /// re-verifying the freshly-sealed container with the bundled verifier.
    /// The UI must not claim Verified unless this field says Verified.
    verification_status: &'static str,
    /// Raw bytes of the produced .win container, base64 is avoided —
    /// wasm-bindgen marshals Vec<u8> as Uint8Array which is what the
    /// browser needs to trigger a download.
    win_bytes: Vec<u8>,
    /// Filename to use when offering the download. Always
    /// "<original>.win".
    filename: String,
    /// SHA-256 of the file at the moment of sealing.
    payload_hash: String,
    /// Public key of the witness used for this seal. This is a fresh
    /// browser-generated key — not the Wise.Est production key.
    witness_public_key_hex: String,
    /// Trust label the UI must surface. Currently always
    /// "browser-local — not a Wise.Est production attestation".
    witness_trust: &'static str,
    /// ISO 8601 timestamp recorded on the seal.
    sealed_at: String,
    /// Whether the seal is anchored to an external time source. Always
    /// false for in-browser seals (no TSA call from the browser yet).
    anchored: bool,
}

#[derive(Serialize)]
struct SealError {
    reason: String,
}

/// Seal `file_bytes` into a `.win` container in the browser.
///
/// Generates fresh creator / time-authority / policy-evaluator keypairs on
/// each call, signs the proof bundle, packs it into a `.win`, and re-runs
/// the verifier on the produced bytes. The returned `verification_status`
/// is whatever the verifier said — the UI must reflect that literally.
///
/// `filename` is sanitized by `win_format::pack`; path separators and
/// other unsafe characters are stripped.
#[wasm_bindgen]
pub fn seal_file(filename: &str, file_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let outcome = seal_file_inner(filename, file_bytes);
    match outcome {
        Ok(result) => serde_wasm_bindgen::to_value(&result)
            .map_err(|e| JsValue::from_str(&e.to_string())),
        Err(reason) => {
            let err = SealError { reason };
            Err(serde_wasm_bindgen::to_value(&err)
                .unwrap_or_else(|_| JsValue::from_str("seal failed")))
        },
    }
}

fn seal_file_inner(filename: &str, file_bytes: &[u8]) -> Result<SealResult, String> {
    // 1. Identities. Three fresh keypairs, one per role. We mirror the CLI
    //    `ensure_node` flow — this is what the verifier expects to see.
    let mut identity_store = IdentityStore::new();
    let (creator_id, _) = identity_store.create_identity(IdentityKind::Personal);
    let (ta_id, _) = identity_store.create_identity(IdentityKind::Service);
    let (pe_id, _) = identity_store.create_identity(IdentityKind::Service);

    let ta_secret = identity_store
        .get_key(&ta_id)
        .ok_or_else(|| "time-authority key missing".to_string())?
        .secret_key_bytes();
    let pe_secret = identity_store
        .get_key(&pe_id)
        .ok_or_else(|| "policy-evaluator key missing".to_string())?
        .secret_key_bytes();
    let creator_secret = identity_store
        .get_key(&creator_id)
        .ok_or_else(|| "creator key missing".to_string())?
        .secret_key_bytes();

    let creator_pub_hex = identity_store
        .get(&creator_id)
        .map(|r| r.public_key_hex.clone())
        .ok_or_else(|| "creator identity record missing".to_string())?;

    let mut time_authority =
        TimeAuthority::new(ta_id, KeyPair::from_secret_bytes(&ta_secret));
    let policy_evaluator =
        PolicyEvaluator::new(pe_id, KeyPair::from_secret_bytes(&pe_secret));

    // 2. Module registration — mirror CLI's "wise-cli" but tag this one as
    //    "wise-web-browser" so audits can tell which surface produced it.
    let mut module_registry = ModuleRegistry::new();
    let module_hash = wise_crypto::sha256_hex(b"wise-web-browser");
    let mod_key = KeyPair::from_secret_bytes(&creator_secret);
    let (module_id, _) = module_registry.register(
        ModuleKind::Document,
        "*",
        &module_hash,
        creator_id,
        &mod_key,
    );

    // 3. Per-object work — payload hash, ids, time, policy.
    let object_id = Uuid::new_v4();
    let payload_hash = wise_crypto::sha256_hex(file_bytes);
    let artifact_size = file_bytes.len() as u64;

    let context_hash = wise_crypto::sha256_hex(
        format!("{}:{}:{}", object_id, payload_hash, creator_id).as_bytes(),
    );
    let policy_proof = policy_evaluator.permit(&context_hash);
    let time_event: ChainedTimeEvent = time_authority.attest_time(&payload_hash);

    // 4. Origin record — sign with creator key (signature field empty in payload).
    let now = chrono::Utc::now().to_rfc3339();
    let origin_unsigned = OriginRecord {
        origin_record_id: Uuid::new_v4(),
        object_id,
        object_class: ObjectClass::Native,
        creator_identity_id: creator_id,
        module_identity_id: module_id,
        time_authority_identity_id: time_authority.authority_id(),
        created_at: now.clone(),
        protocol: "V1".to_string(),
        foreign_source_uri: None,
        ai_model: None,
        signature: String::new(),
    };
    let creator_key = KeyPair::from_secret_bytes(&creator_secret);
    let origin_sig = creator_key.sign_json(&origin_unsigned);
    let origin = OriginRecord {
        signature: origin_sig,
        ..origin_unsigned
    };

    // 5. Object signature — must match exactly what the verifier checks.
    //    See verifier::verify_object's ObjSignPayload (crates/verifier).
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
    let parent_ids: Vec<Uuid> = vec![];
    let proof_chain: Option<ProofChain> = None;
    let sign_payload = ObjSignPayload {
        object_id: &object_id,
        object_class: &ObjectClass::Native,
        payload_hash: &payload_hash,
        artifact_size_bytes: artifact_size,
        parent_ids: &parent_ids,
        protocol: "V1",
        proof_chain: &proof_chain,
    };
    let object_signature = creator_key.sign_json(&sign_payload);

    // 6. SealedObject + ProofBundle.
    let sealed = SealedObject {
        object_id,
        object_class: ObjectClass::Native,
        payload_hash: payload_hash.clone(),
        artifact_size_bytes: artifact_size,
        parent_ids,
        origin,
        time_event,
        policy_proof,
        ai_generation: None,
        import_declaration: None,
        object_signature,
        protocol: "V1".to_string(),
        proof_chain,
    };

    let creator_identity = identity_store
        .get(&creator_id)
        .cloned()
        .ok_or_else(|| "creator identity missing post-build".to_string())?;
    let ta_identity = identity_store
        .get(&ta_id)
        .cloned()
        .ok_or_else(|| "time-authority identity missing post-build".to_string())?;
    let pe_identity = identity_store
        .get(&pe_id)
        .cloned()
        .ok_or_else(|| "policy-evaluator identity missing post-build".to_string())?;
    let module_registration = module_registry
        .get(&module_id)
        .cloned()
        .ok_or_else(|| "module registration missing post-build".to_string())?;

    let bundle = ProofBundle {
        object: sealed,
        creator_identity,
        module_registration,
        time_authority_identity: ta_identity,
        policy_evaluator_identity: pe_identity,
        predecessor_time_event: None,
        parent_objects: vec![],
        parent_proofs: vec![],
    };

    // 7. Re-verify the bundle we just produced. We never claim Verified
    //    without running the verifier on the result.
    let result = verifier::verify_from_proof_bundle(&bundle, file_bytes);
    let status = status_str(result.status);

    // 8. Pack into .win.
    let proof_json = serde_json::to_string(&bundle)
        .map_err(|e| format!("serializing proof bundle failed: {}", e))?;
    let win_bytes = win_format::pack(filename, file_bytes, &proof_json);

    let anchored = matches!(bundle.object.time_event.time_source, TimeSource::External);

    Ok(SealResult {
        verification_status: status,
        win_bytes,
        filename: format!("{}.win", filename),
        payload_hash,
        witness_public_key_hex: creator_pub_hex,
        witness_trust: "browser-local — not a Wise.Est production attestation",
        sealed_at: now,
        anchored,
    })
}
