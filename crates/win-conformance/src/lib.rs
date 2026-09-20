//! W.I.N. Unified Transition Protocol — conformance suite.
//!
//! A set of frozen `.win` transition artifacts (`vectors/*.win`) plus a manifest
//! (`vectors/vectors.json`) declaring the exact verification result each one must
//! produce. An independent implementation proves compatibility by running its own
//! verifier over the same frozen bytes and matching every field.
//!
//! The runner here (`win-conformance`) reads only the frozen inputs and the
//! manifest — it does not regenerate anything, so a green run means the current
//! verifier still agrees with the frozen expectations.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use win_transition::verify_win;

/// The manifest of expected results, frozen alongside the fixtures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub protocol: String,
    pub artifact_format: String,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vector {
    pub id: String,
    pub description: String,
    pub file: String,
    pub expect: Expectation,
}

/// Expected verification outcome for one vector. Fields left `None` are not
/// asserted, so a vector can pin exactly the dimensions that matter for it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Expectation {
    /// Whether the bytes can be read into a proof at all (Ok vs damage/not-UTP).
    pub readable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_structure_valid: Option<bool>,
    /// One of `Valid` | `Mismatch` | `NotApplicable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_integrity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transition_valid: Option<bool>,
    /// `executed` | `refused`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_checks_pass: Option<bool>,
    /// Identity rung for the authorizer, verified with NO trust list:
    /// `not_established` | `consistent_actor` | `self_asserted` | `trusted`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorizer_identity: Option<String>,
}

/// The default vectors directory, resolved relative to this crate.
#[must_use]
pub fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

/// Load the frozen manifest from a vectors directory.
///
/// # Errors
/// Returns an error string if the manifest is missing or malformed.
pub fn load_manifest(dir: &Path) -> Result<Manifest, String> {
    let path = dir.join("vectors.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("malformed manifest: {e}"))
}

/// Result of checking one vector.
pub struct VectorOutcome {
    pub id: String,
    pub pass: bool,
    /// Empty when the vector passed; otherwise the mismatched dimensions.
    pub detail: String,
}

fn check<T: PartialEq + std::fmt::Debug>(
    label: &str,
    expected: &Option<T>,
    actual: T,
    out: &mut Vec<String>,
) {
    if let Some(exp) = expected {
        if *exp != actual {
            out.push(format!("{label}: expected {exp:?}, got {actual:?}"));
        }
    }
}

/// Run one vector against the current verifier and compare to its expectation.
#[must_use]
pub fn run_vector(dir: &Path, v: &Vector) -> VectorOutcome {
    let bytes = match std::fs::read(dir.join(&v.file)) {
        Ok(b) => b,
        Err(e) => {
            return VectorOutcome {
                id: v.id.clone(),
                pass: false,
                detail: format!("cannot read fixture {}: {e}", v.file),
            }
        }
    };

    let mut mism: Vec<String> = Vec::new();
    match verify_win(&bytes) {
        Ok(art) => {
            if !v.expect.readable {
                mism.push("expected unreadable (damaged/not-UTP), but it read".to_string());
            }
            check(
                "container_structure_valid",
                &v.expect.container_structure_valid,
                art.container_structure_valid,
                &mut mism,
            );
            check(
                "content_integrity",
                &v.expect.content_integrity,
                format!("{:?}", art.content_integrity),
                &mut mism,
            );
            check(
                "transition_valid",
                &v.expect.transition_valid,
                art.transition_valid,
                &mut mism,
            );
            check(
                "outcome",
                &v.expect.outcome,
                if art.was_executed { "executed" } else { "refused" }.to_string(),
                &mut mism,
            );
            let actual_reason = art.refusal_reason.map(|r| format!("{r:?}"));
            if v.expect.refusal_reason != actual_reason {
                mism.push(format!(
                    "refusal_reason: expected {:?}, got {:?}",
                    v.expect.refusal_reason, actual_reason
                ));
            }
            check(
                "all_checks_pass",
                &v.expect.all_checks_pass,
                art.all_checks_pass(),
                &mut mism,
            );
            let identity_kind = match art.authorizer_identity {
                win_transition::IdentityStatus::NotEstablished => "not_established",
                win_transition::IdentityStatus::ConsistentActor => "consistent_actor",
                win_transition::IdentityStatus::SelfAsserted { .. } => "self_asserted",
                win_transition::IdentityStatus::Trusted { .. } => "trusted",
            };
            check(
                "authorizer_identity",
                &v.expect.authorizer_identity,
                identity_kind.to_string(),
                &mut mism,
            );
        }
        Err(e) => {
            if v.expect.readable {
                mism.push(format!("expected readable, but it failed to open: {e}"));
            } else if let Some(sub) = &v.expect.error_contains {
                if !e.to_string().to_lowercase().contains(&sub.to_lowercase()) {
                    mism.push(format!("error should contain {sub:?}, got: {e}"));
                }
            }
        }
    }

    VectorOutcome {
        id: v.id.clone(),
        pass: mism.is_empty(),
        detail: mism.join("; "),
    }
}

/// Run every vector in the manifest at `dir`.
#[must_use]
pub fn run_all(dir: &Path) -> Vec<VectorOutcome> {
    match load_manifest(dir) {
        Ok(m) => m.vectors.iter().map(|v| run_vector(dir, v)).collect(),
        Err(e) => vec![VectorOutcome {
            id: "<manifest>".to_string(),
            pass: false,
            detail: e,
        }],
    }
}
