//! HTTP regression for the desktop identity + trust endpoints.
//! Isolated to a temp node dir via WISE_NODE_DIR so the real one is untouched.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use registry_core::Registry;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn app() -> axum::Router {
    let reg = Arc::new(Mutex::new(Registry::new_in_memory()));
    window_api::build_router(reg, None)
}

async fn get(uri: &str) -> serde_json::Value {
    let resp = app()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{uri} GET expected 200");
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&b).unwrap()
}

async fn post(uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let resp = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&b).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn identity_and_trust_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("WISE_NODE_DIR", dir.path());

    // Identity is created on first read and has a public key.
    let id = get("/identity").await;
    let key = id["public_key"].as_str().unwrap().to_string();
    assert_eq!(key.len(), 64, "authorizer public key is 64-hex");

    // Set a self-asserted name/context; it round-trips.
    let (st, set) = post(
        "/identity",
        serde_json::json!({"name": "Acme Ops", "context": "acme.co"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(set["name"], "Acme Ops");
    assert_eq!(set["context"], "acme.co");
    // The key is stable across reads (persistent).
    assert_eq!(get("/identity").await["public_key"], key);
    assert_eq!(get("/identity").await["name"], "Acme Ops");

    // Trust list starts empty, then a valid key can be trusted.
    assert!(get("/trust").await.as_array().unwrap().is_empty());
    let good = "ab".repeat(32);
    let (st, keys) = post(
        "/trust",
        serde_json::json!({"key": good, "label": "A partner"}),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(keys.as_array().unwrap().len(), 1);
    assert_eq!(keys[0]["label"], "A partner");

    // A malformed key is rejected.
    let (st, _) = post("/trust", serde_json::json!({"key": "not-hex", "label": null})).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Remove it.
    let (_, after) = post("/trust/remove", serde_json::json!({"key": good})).await;
    assert!(after.as_array().unwrap().is_empty());
}
