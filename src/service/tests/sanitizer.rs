//! Push notification payload sanitizer — forbidden plaintext fields.
//!
//! Spec B4 hardening: `binding_proof.signature`, `subject_proof.signature`,
//! `expected_previous_generation`, and `attestation_evidence` MUST be
//! rejected as forbidden plaintext fields regardless of profile.

use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;

#[tokio::test]
async fn sanitizer_rejects_binding_proof_signature() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["notification"]["binding_proof"] = json!({
        "signature": "deadbeef",
    });

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["error"]["code"], json!("schema_violation"));
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("binding_proof.signature")
    );
}

#[tokio::test]
async fn sanitizer_rejects_subject_proof_signature() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["notification"]["subject_proof"] = json!({
        "signature": "deadbeef",
    });

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sanitizer_rejects_expected_previous_generation() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["expected_previous_generation"] = json!(7);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sanitizer_rejects_attestation_evidence() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut body = payload(vec![device("com.example.app", "x-token")]);
    body["notification"]["attestation_evidence"] = json!({
        "tee_quote": "deadbeef",
    });

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}
