//! WASM bindings for the Winstack verifier.
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

use canon_types::{ProofBundle, VerificationStatus};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct Reading {
    /// One of "Verified" | "Tampered" | "Invalid".
    status: &'static str,
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
    trust_class: String,
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
            "Verified. This file matches the original — it hasn't been changed."
        },
        VerificationStatus::Tampered => "Tampered. This file was changed after it was sealed.",
        VerificationStatus::Invalid => "Invalid. We can't verify this file.",
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
    // File-vs-win-tag hash check first — the most actionable signal for the receiver.
    let computed = winstack_crypto::sha256_hex(file_bytes);
    if computed != bundle.object.payload_hash {
        return Reading {
            status: status_str(VerificationStatus::Tampered),
            witness: Some(Witness {
                public_key_hex: bundle.creator_identity.public_key_hex.clone(),
                trust_class: format!("{:?}", bundle.object.object_class.trust_class()),
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
        witness: Some(Witness {
            public_key_hex: bundle.creator_identity.public_key_hex.clone(),
            trust_class: format!("{:?}", bundle.object.object_class.trust_class()),
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
