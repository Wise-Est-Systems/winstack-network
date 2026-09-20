//! HTTP regression for the governed-transition surface exposed to the desktop:
//!   POST /transition/summarize  → accepted transition, sealed .win
//!   POST /transition/publish    → refused (scope exceeded), no side effect
//!   POST /transition/verify     → per-dimension matrix
//!
//! Drives the real router from `window_api::build_router`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use http_body_util::BodyExt;
use registry_core::Registry;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn test_app() -> axum::Router {
    let reg = Arc::new(Mutex::new(Registry::new_in_memory()));
    window_api::build_router(reg, None)
}

/// Keep the persistent identity these handlers create out of the real node dir.
fn iso() {
    std::env::set_var("WISE_NODE_DIR", std::env::temp_dir().join("wise-txn-test"));
}

fn multipart_body(field_name: &str, filename: &str, content: &[u8]) -> (String, Vec<u8>) {
    let boundary = "----WiseTestBoundaryTx42";
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(content);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn post(uri: &str, filename: &str, content: &[u8]) -> serde_json::Value {
    let app = test_app();
    let (ctype, body) = multipart_body("file", filename, content);
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", ctype)
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{uri} expected 200");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("valid JSON")
}

#[tokio::test]
async fn propose_previews_without_side_effect() {
    let source = b"UNIQUETOKEN9 is the opening clause.\nSecond clause.\n";
    let v = post("/transition/propose", "doc.txt", source).await;
    assert_eq!(v["required_authority"], "LocalWrite");
    assert_eq!(v["external_actions"], "None");
    assert!(v["summary_text"].as_str().unwrap().contains("UNIQUETOKEN9"));
    assert!(v["subject_content_id"].as_str().unwrap().starts_with("sha256:"));
    // A preview carries no sealed artifact.
    assert!(v.get("win_base64").is_none());
}

#[tokio::test]
async fn summarize_then_verify_roundtrip() {
    iso();
    let source = b"UNIQUETOKEN9 is the opening clause.\nA second clause follows here.\n";
    let v = post("/transition/summarize", "doc.txt", source).await;

    assert_eq!(v["outcome"], "EXECUTED");
    assert_eq!(v["all_checks_pass"], true);
    assert!(v["summary_text"].as_str().unwrap().contains("UNIQUETOKEN9"));
    assert_eq!(v["win_filename"], "doc.txt.summary.win");

    // Decode the sealed .win and verify it through the verify endpoint.
    let win = base64::engine::general_purpose::STANDARD
        .decode(v["win_base64"].as_str().unwrap())
        .unwrap();
    let vv = post("/transition/verify", "doc.txt.summary.win", &win).await;
    assert_eq!(vv["ok"], true);
    assert_eq!(vv["all_checks_pass"], true);
    assert_eq!(vv["verification"]["content_integrity"], "Valid");
}

#[tokio::test]
async fn publish_is_refused_with_no_side_effect() {
    iso();
    let source = b"A confidential internal memo.\n";
    let v = post("/transition/publish", "memo.txt", source).await;

    assert_eq!(v["outcome"], "REFUSED");
    assert_eq!(v["refusal_reason"], "AuthorizationScopeExceeded");
    // A refusal is a valid, verifiable record.
    assert_eq!(v["all_checks_pass"], true);
    assert_eq!(v["verification"]["execution_receipt_present"], false);
}

#[tokio::test]
async fn tampered_artifact_fails_verify() {
    iso();
    let source = b"UNIQUETOKEN9 is the opening clause.\nSecond clause.\n";
    let v = post("/transition/summarize", "doc.txt", source).await;
    let mut win = base64::engine::general_purpose::STANDARD
        .decode(v["win_base64"].as_str().unwrap())
        .unwrap();

    // Flip a byte of the carried summary content.
    let needle = b"UNIQUETOKEN9";
    let idx = win
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("lead token present in sealed content");
    win[idx] ^= 0xFF;

    let vv = post("/transition/verify", "doc.txt.summary.win", &win).await;
    assert_eq!(vv["ok"], true);
    assert_eq!(vv["all_checks_pass"], false);
    assert_eq!(vv["verification"]["content_integrity"], "Mismatch");
}
