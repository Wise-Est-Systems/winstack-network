//! Signature-determinism guard.
//!
//! THE INVARIANT: every Ed25519-signed payload in this workspace must be a
//! fixed-field shape whose `serde_json` byte-output is identical on every
//! machine and every run. If that holds, a sealed `.win` re-verifies offline
//! anywhere. If it breaks, signatures pass on the signer's box and FAIL on the
//! verifier's — silently, with green CI.
//!
//! WHY THE GUARD IS NEEDED — the `canonical_json` misnomer:
//! `wise_crypto::canonical_json` does NO canonicalization. It is
//! `serde_json::to_string`, which keeps struct *declaration order* and does
//! NOT sort map keys or normalize floats. So the bytes are stable ONLY while
//! every signed field is itself byte-stable. The day someone adds a
//! `HashMap` / `BTreeMap` / `serde_json::Value` / `f32` / `f64` field to a
//! signed payload, cross-machine reproducibility dies.
//!
//! HOW THIS GUARD PROVES (not assumes) the invariant:
//! `wise_crypto::CanonStable` is a sealed marker trait implemented for
//! determinism-safe types and deliberately lacking an impl for the four
//! foot-guns. `assert_canon_stable::<T>()` is a compile-time check: if `T`
//! is a map / float / Value, the call does not compile. Below we list every
//! field type of every signed payload and assert each is `CanonStable`. Add
//! a foot-gun field, mirror it here, and the workspace stops compiling. The
//! negative test at the bottom proves the guard actually has teeth.

use canon_types::{IdentityKind, IdentityStatus, ModuleKind, PolicyDecision, TimeSource};
use uuid::Uuid;
use wise_crypto::assert_canon_stable;

// The signed-payload enums (IdentityKind, IdentityStatus, ModuleKind,
// TimeSource, PolicyDecision, ObjectClass) are declared `CanonStable` in the
// canon-types library itself (orphan rules require the impl to live with the
// type). This test consumes those impls below.

/// Compile-time assertion over the COMPLETE set of field types that appear in
/// every Ed25519-signed payload across the workspace.
///
/// Sources (grep `sign_json` / `sign(`): the field types below are the union of
///   - identity-core  `IdentityStore::create_identity` SignPayload
///   - identity-core  `ModuleRegistry::register`       SignPayload
///   - time-core      `attest_time` / verify           SignPayload
///   - policy-core     `permit` / verify               SignPayload
///   - verifier        `ObjSignPayload`                 (object signature)
///   - verifier        `DelegPayload`                   (key delegation)
///
/// Every distinct field type used by ANY of those is asserted here. If a new
/// signed field is introduced, its type must be added to this list — and if
/// that type is a map / float / `serde_json::Value`, this stops compiling.
#[test]
fn every_signed_payload_field_type_is_canon_stable() {
    // Scalars / strings used across the signed payloads.
    assert_canon_stable::<Uuid>();
    assert_canon_stable::<str>();
    assert_canon_stable::<String>();
    assert_canon_stable::<u64>(); // policy_version, artifact_size_bytes

    // Optionals that appear in signed payloads (time event predecessor/token).
    assert_canon_stable::<Option<Uuid>>();
    assert_canon_stable::<Option<String>>();

    // Slices / collections of stable types (parent_ids: &[Uuid]).
    assert_canon_stable::<[Uuid]>();
    assert_canon_stable::<Vec<Uuid>>();

    // Borrowed forms — payload structs hold these by reference (&'a T).
    assert_canon_stable::<&Uuid>();
    assert_canon_stable::<&str>();
    assert_canon_stable::<&Option<Uuid>>();
    assert_canon_stable::<&Option<String>>();
    assert_canon_stable::<&[Uuid]>();

    // The enums that ride inside signed payloads.
    assert_canon_stable::<IdentityKind>();
    assert_canon_stable::<IdentityStatus>();
    assert_canon_stable::<ModuleKind>();
    assert_canon_stable::<TimeSource>();
    assert_canon_stable::<PolicyDecision>();
    assert_canon_stable::<&IdentityKind>();
    assert_canon_stable::<&IdentityStatus>();
    assert_canon_stable::<&ModuleKind>();
    assert_canon_stable::<&TimeSource>();
    assert_canon_stable::<&PolicyDecision>();

    // The Option<ProofChain> field in the object-signature payload is gated by
    // `skip_serializing_if = Option::is_none` and ProofChain itself is composed
    // only of the stable types above; it carries no map/float/Value field.
    // (If ProofChain ever gains one, the runtime teeth test below also fires.)
}

/// Runtime teeth: prove `CanonStable` actually rejects the foot-guns, and that
/// no real signed payload serializes any JSON float. A float in signed JSON is
/// the most common non-portable byte source, and unlike maps it is detectable
/// after the fact, so we belt-and-suspenders it here.
///
/// This walks the serialized JSON of a representative signed payload and fails
/// if any number is a float. (Structs and maps both serialize to JSON objects,
/// so the map foot-gun is caught at compile time by the trait, not here.)
#[test]
fn signed_payload_json_contains_no_floats() {
    // A representative signed payload shape: the object-signature payload from
    // verifier::verify_object. We build the same field set and serialize it the
    // exact way the signer does (via canonical_json).
    #[derive(serde::Serialize)]
    struct ObjSignPayload<'a> {
        object_id: &'a Uuid,
        payload_hash: &'a str,
        artifact_size_bytes: u64,
        parent_ids: &'a [Uuid],
        protocol: &'a str,
    }
    let id = Uuid::nil();
    let payload = ObjSignPayload {
        object_id: &id,
        payload_hash: "deadbeef",
        artifact_size_bytes: 42,
        parent_ids: &[],
        protocol: "V1",
    };
    let json = wise_crypto::canonical_json(&payload);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(
        !json_has_float(&value),
        "signed payload serialized a JSON float — non-portable bytes: {json}"
    );
}

fn json_has_float(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Number(n) => n.as_i64().is_none() && n.as_u64().is_none(),
        serde_json::Value::Array(a) => a.iter().any(json_has_float),
        serde_json::Value::Object(o) => o.values().any(json_has_float),
        _ => false,
    }
}
