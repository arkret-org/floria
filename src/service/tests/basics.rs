use std::sync::Arc;

use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;

#[tokio::test]
async fn accepted_devices_are_not_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, 1, vec![], 0).await;
}

#[tokio::test]
async fn notify_endpoint_accepts_active_payload_shape() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, 1, vec![], 0).await;
}

#[tokio::test]
async fn describe_endpoint_advertises_gateway_profile() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::get("http://127.0.0.1/api/v1/push/describe")
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["operation_id"], json!(NOTIFY_OPERATION_ID));
    assert_eq!(
        body["supported_profiles"],
        json!(["cx.profile.push_gateway.v1"])
    );
    assert_eq!(body["supported_providers"], json!(["com.example.app"]));
    assert_eq!(
        body["plaintext_visibility_class"],
        json!("blind-wakeup-only")
    );
    assert_eq!(body["auth_modes"], json!(["anonymous"]));
    assert_eq!(
        body["limits"]["max_request_size_bytes"],
        json!(MAX_REQUEST_SIZE)
    );
}

#[tokio::test]
async fn integration_describe_lists_operational_surfaces() {
    let service = test_service(vec![]);

    let mut response = TestClient::get("http://127.0.0.1/api/v1/integration/describe")
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["version"], json!("2026-05-07"));

    let surfaces = body["surfaces"].as_array().expect("surfaces array");
    let surface_names = surfaces
        .iter()
        .filter_map(|surface| surface["name"].as_str())
        .collect::<Vec<_>>();
    assert!(surface_names.contains(&"push_bridge"));
    assert!(surface_names.contains(&"push_notify"));
    assert!(surface_names.contains(&"gateway_describe"));
    assert!(surface_names.contains(&"health"));
    assert!(surface_names.contains(&"ready"));
    assert!(surface_names.contains(&"metrics"));

    let metrics_surface = surfaces
        .iter()
        .find(|surface| surface["name"] == json!("metrics"))
        .expect("metrics surface");
    assert_eq!(metrics_surface["path"], json!("/metrics"));
    assert_eq!(metrics_surface["contract"], json!("prometheus.text.0.0.4"));
}

#[tokio::test]
async fn bridge_describe_lists_failure_codes() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::get("http://127.0.0.1/api/v1/push/bridge/describe")
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<Value>().await.unwrap();
    let failure_codes = body["failure_codes"]
        .as_array()
        .expect("failure_codes array");
    assert!(
        failure_codes
            .iter()
            .any(|entry| entry["code"] == json!("capability_denied")
                && entry["http_status"] == json!(403)
                && entry["retryable"] == json!(false))
    );
    assert!(
        failure_codes
            .iter()
            .any(|entry| entry["code"] == json!("rate_limited")
                && entry["http_status"] == json!(429)
                && entry["retryable"] == json!(true))
    );
    assert!(
        failure_codes
            .iter()
            .any(|entry| entry["code"] == json!("temporarily_unavailable")
                && entry["http_status"] == json!(503)
                && entry["retryable"] == json!(true))
    );
}

#[tokio::test]
async fn bridge_describe_exposes_provider_capability_matrix() {
    let pushkin =
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept).with_kind("fcm"));
    let service = test_service(vec![("com.example.app", pushkin as Arc<dyn Pushkin>)]);

    let mut response = TestClient::get("http://127.0.0.1/api/v1/push/bridge/describe")
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<Value>().await.unwrap();
    let capabilities = body["provider_capabilities"]
        .as_array()
        .expect("provider_capabilities must be an array");
    assert_eq!(capabilities.len(), 1);
    let entry = &capabilities[0];
    assert_eq!(entry["name"], json!("com.example.app"));
    assert_eq!(entry["kind"], json!("fcm"));
    assert_eq!(entry["batch"], json!("multicast"));
    assert_eq!(entry["supports_collapse"], json!(true));
    assert_eq!(entry["supports_badge"], json!(true));
    assert_eq!(entry["default_payload_shape"], json!("data_only_blind_wakeup"));
    assert_eq!(entry["credential_kinds"], json!(["service_account_v1"]));
    assert_eq!(
        entry["credential_rotation"],
        json!("rotate_service_account_yearly_or_on_compromise")
    );
    assert_eq!(entry["blind_wakeup_required"], json!(true));
    assert!(entry.get("notes").is_none());
    assert_eq!(
        body["provider_capabilities_version"],
        json!(crate::pushkin::PROVIDER_CAPABILITIES_VERSION)
    );
}

#[tokio::test]
async fn bridge_describe_omits_unknown_provider_kinds() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::get("http://127.0.0.1/api/v1/push/bridge/describe")
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["provider_capabilities"], json!([]));
}

#[tokio::test]
async fn notify_response_includes_delivery_receipts_without_plaintext_tokens() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<NotifyResponse>().await.unwrap();
    assert_eq!(body.accepted, 1);
    assert_eq!(body.delivery_receipts.len(), 1);
    let receipt = &body.delivery_receipts[0];
    assert_eq!(receipt.provider.as_deref(), Some("com.example.app"));
    assert_eq!(receipt.status.as_deref(), Some("accepted"));
    assert!(
        receipt
            .push_key_hash
            .as_deref()
            .is_some_and(|value| value.starts_with("pkh_"))
    );
    assert_ne!(receipt.push_key_hash.as_deref(), Some("accept"));
    assert_eq!(
        receipt.request_id.as_deref(),
        Some(body.request_id.as_str())
    );
}

#[tokio::test]
async fn notify_rejects_non_canonical_operation_id() {
    let service = test_service(vec![]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&with_operation_id(
            payload(vec![device("com.example.app", "one")]),
            "cx.push.register_device",
        ))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "unsupported_feature", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("operation_id must be cx.push.notify")
    );
}

#[tokio::test]
async fn notify_method_not_allowed_returns_standard_error_envelope() {
    let service = test_service(vec![]);

    let mut get_response = TestClient::get("http://127.0.0.1/api/v1/push/notify")
        .send(&service)
        .await;
    assert_eq!(
        get_response.status_code.unwrap(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        get_response
            .headers()
            .get("allow")
            .and_then(|value| value.to_str().ok()),
        Some("POST")
    );
    assert_notify_error(&mut get_response, "method_not_allowed", false).await;

    let mut put_response = TestClient::put("http://127.0.0.1/api/v1/push/notify")
        .send(&service)
        .await;
    assert_eq!(
        put_response.status_code.unwrap(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_notify_error(&mut put_response, "method_not_allowed", false).await;

    let mut delete_response = TestClient::delete("http://127.0.0.1/api/v1/push/notify")
        .send(&service)
        .await;
    assert_eq!(
        delete_response.status_code.unwrap(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_notify_error(&mut delete_response, "method_not_allowed", false).await;
}

#[tokio::test]
async fn ready_endpoint_returns_ok() {
    let service = test_service(vec![]);

    let mut response = TestClient::get("http://127.0.0.1/ready")
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_eq!(response.take_string().await.unwrap(), "ok");
}
