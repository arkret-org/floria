//! Push notification payload sanitizer — proof signature plaintext fields.
//!
//! Spec B4 hardening: `binding_proof.signature`, `subject_proof.signature`,
//! MUST be rejected as forbidden plaintext fields regardless of profile.

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

    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["error"]["code"], json!("schema_violation"));
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

    let response = TestClient::post("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}
