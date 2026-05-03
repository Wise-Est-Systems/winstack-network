//! HTTP `/check` endpoint state-classification regression.
//!
//! Drives the actual axum router built by `window_api::build_router`
//! and asserts that the JSON `result` field returns the same four
//! states the CLI and WASM verifier surface:
//!
//!   Verified  — bytes match, proof valid, signatures pass
//!   Tampered  — container readable, file bytes differ from proof
//!   Invalid   — container readable, proof itself broken/forged
//!   Damaged   — container itself unreadable (truncated, bad magic)
//!
//! These tests close the producer ↔ consumer parity gap that
//! previously existed between the desktop HTTP API and the rest of
//! the verification surfaces.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use registry_core::Registry;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// Minimal router exposing /check without auth — `/check` itself
/// requires no State or Bearer token, but `build_router` wires up
/// the full surface so we provide an empty in-memory Registry.
fn test_app() -> axum::Router {
    let reg = Arc::new(Mutex::new(Registry::new_in_memory()));
    window_api::build_router(reg, None)
}

/// Build a multipart/form-data body with one "file" field carrying
/// the given bytes. axum 0.7 accepts standard RFC 7578 multipart.
fn multipart_body(field_name: &str, content: &[u8]) -> (String, Vec<u8>) {
    let boundary = "----WiseTestBoundary7vN3kQ";
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{}\"; filename=\"x.win\"\r\n",
            field_name
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{}--\r\n", boundary).as_bytes());
    let content_type = format!("multipart/form-data; boundary={}", boundary);
    (content_type, body)
}

/// POST `bytes` as a single multipart "file" field to /check.
/// Returns the parsed JSON response.
async fn post_check_with(bytes: &[u8]) -> serde_json::Value {
    let app = test_app();
    let (ctype, body) = multipart_body("file", bytes);
    let req = Request::builder()
        .method("POST")
        .uri("/check")
        .header("content-type", ctype)
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "check expected 200");
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body_bytes).expect("response is valid JSON")
}

/// Build a minimal valid .win container with ANY proof JSON. The
/// proof_text we hand in does not need to verify; for these container-
/// level tests we only care about how unpack errors classify. For tests
/// that need a real proof, see the e2e_state_matrix in crates/cli.
fn valid_container_bytes() -> Vec<u8> {
    win_format::pack(
        "test.txt",
        b"hello",
        r#"{"object":{"payload_hash":"abc","kind":"test"},"signatures":[]}"#,
    )
}

// ─────────────────────────────────────────────────────────────────────
// DAMAGED — container itself unreadable
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn check_truncated_container_returns_damaged() {
    let full = valid_container_bytes();
    let truncated = &full[..full.len() / 2];
    let resp = post_check_with(truncated).await;
    assert_eq!(
        resp["result"], "Damaged",
        "truncated container must classify as Damaged, got: {}",
        resp
    );
    assert!(
        resp["message"]
            .as_str()
            .unwrap_or("")
            .contains("incomplete or corrupted"),
        "Damaged message must use spec wording: {}",
        resp["message"]
    );
}

#[tokio::test]
async fn check_bad_magic_container_returns_damaged() {
    let mut bytes = valid_container_bytes();
    bytes[0] ^= 0xFF; // wreck the magic byte
    let resp = post_check_with(&bytes).await;
    assert_eq!(
        resp["result"], "Damaged",
        "bad magic must classify as Damaged, got: {}",
        resp
    );
}

#[tokio::test]
async fn check_too_short_container_returns_damaged() {
    let resp = post_check_with(b"short").await;
    assert_eq!(resp["result"], "Damaged");
}

#[tokio::test]
async fn check_empty_body_returns_damaged() {
    let resp = post_check_with(b"").await;
    assert_eq!(resp["result"], "Damaged");
}

// ─────────────────────────────────────────────────────────────────────
// INVALID — container readable but proof JSON malformed
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn check_unparseable_proof_json_returns_invalid_not_damaged() {
    // Container is structurally valid (lengths balance, brackets count)
    // but the proof section is JSON that fails to parse as ProofBundle
    // (missing required fields like `object`).
    let bytes = win_format::pack("t.txt", b"x", "{}"); // empty proof object
    let resp = post_check_with(&bytes).await;
    assert_eq!(
        resp["result"], "Invalid",
        "container-OK + proof-not-a-ProofBundle must be Invalid, got: {}",
        resp
    );
    assert_ne!(
        resp["result"], "Damaged",
        "container that parsed cleanly must NOT be reported as Damaged"
    );
}

// ─────────────────────────────────────────────────────────────────────
// VERIFIED / TAMPERED — require a real CLI-produced .win.
//
// The /check endpoint only takes a .win — it doesn't have the keys to
// produce one. We borrow the CLI binary to produce a real seal, then
// post the bytes as-is for Verified, and with a flipped payload byte
// for Tampered.
// ─────────────────────────────────────────────────────────────────────

fn cli_seal(content: &[u8]) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("v.txt");
    std::fs::write(&src, content).unwrap();
    let win_bin = std::env::var("CARGO_BIN_EXE_win").unwrap_or_else(|_| {
        // Fallback: locate via target dir relative to manifest. This is
        // best-effort for invocations outside `cargo test -p cli`.
        let cwd = std::env::current_dir().unwrap();
        cwd.ancestors()
            .find_map(|a| {
                let p = a.join("target/debug/win");
                if p.exists() {
                    Some(p)
                } else {
                    None
                }
            })
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "win".into())
    });
    let status = std::process::Command::new(&win_bin)
        .arg("seal")
        .arg(&src)
        .arg("--private")
        .env("HOME", dir.path())
        .current_dir(dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("win seal");
    assert!(status.success(), "win seal must succeed for test fixture");
    std::fs::read(src.with_extension("win")).expect("read .win")
}

#[tokio::test]
async fn check_valid_win_returns_verified() {
    let bytes = cli_seal(b"verified through http");
    let resp = post_check_with(&bytes).await;
    assert_eq!(
        resp["result"], "Verified",
        "valid .win must return Verified, got: {}",
        resp
    );
}

#[tokio::test]
async fn check_payload_tampered_win_returns_tampered() {
    let mut bytes = cli_seal(b"to be tampered");
    // Flip a byte deep inside the payload region — past the magic,
    // past filename_len/filename, past file_len header, into the file
    // bytes themselves. (Container layout: 4 magic + 4 fname_len +
    // fname + 8 file_len + content + proof.)
    let i = 4 + 4 + b"v.txt".len() + 8 + 3;
    bytes[i] ^= 0xFF;
    let resp = post_check_with(&bytes).await;
    assert_eq!(
        resp["result"], "Tampered",
        "payload tamper must return Tampered, got: {}",
        resp
    );
    assert_ne!(
        resp["result"], "Damaged",
        "payload tamper must NOT be reported as Damaged"
    );
    assert_ne!(
        resp["result"], "Invalid",
        "payload tamper must NOT be reported as Invalid"
    );
}

/// Find a byte-pattern offset in a buffer (no UTF-8 conversion —
/// the .win contains binary data so indexing through a String
/// would shift offsets via lossy-replacement).
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[tokio::test]
async fn check_proof_signature_tampered_win_returns_invalid() {
    let mut bytes = cli_seal(b"sig tamper through http");
    // Find object_signature in the proof JSON region, then flip a
    // hex digit. A single hex-digit flip keeps the JSON brackets
    // balanced, so the container parses cleanly — exactly what we
    // need to distinguish "Invalid proof" from "Damaged container".
    // Proof JSON in this codebase is pretty-printed, so the field
    // name is followed by ": " (colon + space) before the opening
    // quote. Try compact form first, then pretty.
    let pretty = b"\"object_signature\": \"";
    let compact = b"\"object_signature\":\"";
    let (pos, len) = find_bytes(&bytes, pretty)
        .map(|p| (p, pretty.len()))
        .or_else(|| find_bytes(&bytes, compact).map(|p| (p, compact.len())))
        .expect("object_signature field present in seal output");
    let target = pos + len; // first hex char of the signature
    let cur = bytes[target];
    // Flip to a different lowercase hex digit so JSON stays valid.
    bytes[target] = match cur {
        b'a'..=b'e' => cur + 1,
        b'f' => b'0',
        b'0'..=b'8' => cur + 1,
        b'9' => b'a',
        _ => b'a',
    };
    assert_ne!(bytes[target], cur, "mutation must actually change a byte");

    let resp = post_check_with(&bytes).await;
    let result = resp["result"].as_str().unwrap_or("?");
    assert!(
        result == "Invalid",
        "proof-sig tamper must be Invalid — never Damaged or Verified. \
         got: {} (full: {})",
        result,
        resp
    );
    assert_ne!(
        result, "Damaged",
        "proof-sig tamper must NOT be reported as Damaged"
    );
    assert_ne!(
        result, "Verified",
        "proof-sig tamper must NOT be reported as Verified"
    );
}
