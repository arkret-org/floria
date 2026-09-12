use std::sync::Arc;

use arkret_wire::ServiceOperationId;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;

#[tokio::test]
async fn accepted_devices_are_not_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device(
            "com.example.app",
            "plaintext-token-should-not-leak",
        )]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, vec![]).await;
}

#[tokio::test]
async fn notify_endpoint_accepts_active_payload_shape() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, vec![]).await;
}

#[tokio::test]
async fn describe_endpoint_advertises_gateway_profile() {
    let service = describe_test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::get("http://127.0.0.1/_arkret/describe")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            true,
        )
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<Value>().await.unwrap();
    // FLORIA-01 — canonical ServiceDescribe shape. The push-gateway
    // matrix (operation id, providers, plaintext class, auth modes) is
    // folded into `limits` under `x_floria_*` extension keys.
    assert_eq!(body["service_kind"], json!("push_gateway"));
    assert_eq!(
        body["limits"]["x_floria_operation_id"],
        json!(ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1)
    );
    // The mandatory blind-wakeup baseline is always advertised alongside
    // the base profile; the visible-notification profile is only added
    // when a plaintext-eligible surface is configured (not here).
    assert_eq!(
        body["supported_profiles"],
        json!([
            "ak.profile.push_gateway.v1",
            "ak.profile.push_gateway.blind_wakeup.v1"
        ])
    );
    assert_eq!(
        body["limits"]["x_floria_supported_providers"],
        json!(["com.example.app"])
    );
    assert_eq!(
        body["limits"]["x_floria_plaintext_visibility_class"],
        json!("blind-wakeup-only")
    );
    assert_eq!(body["limits"]["x_floria_auth_modes"], json!(["service-id"]));
    assert_eq!(
        body["limits"]["max_request_size_bytes"],
        json!(MAX_REQUEST_SIZE)
    );
    assert_eq!(
        body["supported_operation_bundles"],
        json!([
            "ak.operation_bundle.push_gateway.describe.v1",
            "ak.operation_bundle.push_gateway.http_notify.v1"
        ])
    );
    assert_eq!(body["transport_bindings"][0]["kind"], "http_json");
    assert_eq!(
        body["transport_bindings"][0]["base_url"],
        "http://127.0.0.1:5000/"
    );
    assert_eq!(
        body["supported_features"],
        json!(["ak.feature.notifications.v1"])
    );
}

#[tokio::test]
async fn describe_fails_closed_when_gateway_service_did_is_missing() {
    let service = test_service_with_auth(vec![], NotifyAuthConfig::default());
    let mut response = TestClient::get("http://127.0.0.1/_arkret/describe")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            true,
        )
        .send(&service)
        .await;

    assert_eq!(
        response.status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(
        body["type"],
        json!(format!(
            "https://arkret.org/problems/{}",
            arkret_wire::ErrorCode::INTERNAL_ERROR
        ))
    );
    assert_eq!(
        body["detail"],
        json!("gateway service resolution is not configured")
    );
}

#[tokio::test]
async fn describe_fails_closed_when_gateway_service_did_is_invalid() {
    let mut auth = NotifyAuthConfig::default();
    auth.gateway_service_did = Some("not-a-did".to_owned());
    let service = test_service_with_auth(vec![], auth);
    let mut response = TestClient::get("http://127.0.0.1/_arkret/describe")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            true,
        )
        .send(&service)
        .await;

    assert_eq!(
        response.status_code,
        Some(StatusCode::INTERNAL_SERVER_ERROR)
    );
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(
        body["type"],
        json!(format!(
            "https://arkret.org/problems/{}",
            arkret_wire::ErrorCode::INTERNAL_ERROR
        ))
    );
    assert_eq!(
        body["detail"],
        json!("gateway service resolution is not configured")
    );
}

#[tokio::test]
async fn operation_selector_is_required_and_route_bound_before_handlers() {
    let service = describe_test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut missing = TestClient::get("http://127.0.0.1/_arkret/describe")
        .send(&service)
        .await;
    assert_eq!(missing.status_code, Some(StatusCode::BAD_REQUEST));
    let missing_body = missing.take_json::<Value>().await.unwrap();
    assert_eq!(
        missing_body["type"],
        json!(format!(
            "https://arkret.org/problems/{}",
            arkret_wire::ErrorCode::OPERATION_SELECTOR_REQUIRED
        ))
    );

    let mut mismatch = TestClient::get("http://127.0.0.1/_arkret/describe")
        .add_header(
            "Arkret-Operation",
            ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .send(&service)
        .await;
    assert_eq!(mismatch.status_code, Some(StatusCode::UNPROCESSABLE_ENTITY));
    let mismatch_body = mismatch.take_json::<Value>().await.unwrap();
    assert_eq!(
        mismatch_body["type"],
        json!(format!(
            "https://arkret.org/problems/{}",
            arkret_wire::ErrorCode::UNSUPPORTED_OPERATION_VERSION
        ))
    );
}

#[tokio::test]
async fn describe_separates_claim_levels() {
    // T6.1 — push gateway describe response MUST partition into
    // wire-callable operations + claim-level arrays. floria has no
    // production posture is explicit, so the default service is described as
    // development-mode; the invariant (development_mode=true =>
    // verified_profiles=[]) is exercised directly — an empty list means no
    // cotest_verified entry can leak into a dev posture.
    let service = describe_test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::get("http://127.0.0.1/_arkret/describe")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            true,
        )
        .send(&service)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<Value>().await.unwrap();

    let verified = body["verified_profiles"]
        .as_array()
        .expect("verified_profiles present");
    assert!(
        verified.is_empty(),
        "floria has no cotest verifier wired in; verified_profiles MUST stay empty"
    );

    assert!(
        body["supported_profiles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|profile| profile == "ak.profile.push_gateway.v1")
    );
    assert!(body.get("claimed_profiles").is_none());

    for surface in body["interop_surfaces"]
        .as_array()
        .expect("interop_surfaces present")
    {
        let kind = surface["kind"].as_str().expect("interop surface kind");
        assert!(matches!(
            kind,
            "matrix_passthrough" | "mimi_passthrough" | "delegated_resolver" | "external_interop"
        ));
    }

    assert!(body["development_mode"].is_boolean());
}

#[tokio::test]
async fn describe_does_not_advertise_media_token_self_issue() {
    let service = describe_test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::get("http://127.0.0.1/_arkret/describe")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            true,
        )
        .send(&service)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<Value>().await.unwrap();

    for field in [
        "supported_operation_bundles",
        "supported_features",
        "interop_surfaces",
    ] {
        let encoded = serde_json::to_string(&body[field]).unwrap();
        assert!(
            !encoded.contains("rtc")
                && !encoded.contains("media.token")
                && !encoded.contains("self_issue"),
            "{field} must not expose floria media-token self-issue surfaces: {encoded}"
        );
    }
}

#[tokio::test]
async fn describe_omits_bearer_mode_when_production_disables_bearer_fallback() {
    let mut auth = production_notify_auth_config();
    auth.service_principals
        .get_mut("ak:did_core:web:sync.example.com")
        .unwrap()
        .bearer_token_hashes = vec![crate::auth::bearer_token_sha256_hex("fallback-token")];
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        auth,
    );

    let mut response = TestClient::get("http://127.0.0.1/_arkret/describe")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            true,
        )
        .send(&service)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response.take_json::<Value>().await.unwrap();
    let modes = body["limits"]["x_floria_auth_modes"]
        .as_array()
        .expect("x_floria_auth_modes array");

    assert!(!modes.contains(&json!("bearer")));
    assert!(modes.contains(&json!("http-message-signature")));
    assert!(modes.contains(&json!("service-id")));
}

#[tokio::test]
async fn gateway_describe_lives_at_root_meta_position() {
    // The gateway profile advertisement lives only at the root meta
    // position GET /_arkret/describe (openapi: "advertisement lives at
    // the root meta position /_arkret/describe"). There is no
    // protocol-surface push-specific describe operation.
    let service = describe_test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut server_response = TestClient::get("http://127.0.0.1/_arkret/describe")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            true,
        )
        .send(&service)
        .await;
    assert_eq!(server_response.status_code.unwrap(), StatusCode::OK);
    let server_body = server_response.take_json::<Value>().await.unwrap();
    assert_eq!(server_body["service_kind"], json!("push_gateway"));
    assert_eq!(
        server_body["limits"]["x_floria_operation_id"],
        json!(ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1)
    );

    // The self-made /_arkret/edge/push/describe path MUST NOT exist;
    // ak.edge.push.* registers only register/unregister/notify.
    let push_describe = TestClient::get("http://127.0.0.1/_arkret/edge/push/describe")
        .send(&service)
        .await;
    assert_eq!(push_describe.status_code.unwrap(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn integration_describe_lists_operational_surfaces() {
    let service = test_service(vec![]);

    let mut response = TestClient::get("http://127.0.0.1/_floria/integration/describe")
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
    assert!(!surface_names.contains(&"push_bridge"));
    assert!(surface_names.contains(&"push_notify"));
    assert!(surface_names.contains(&"gateway_describe"));
    assert!(surface_names.contains(&"ready"));
    assert!(surface_names.contains(&"readyz"));
    assert!(surface_names.contains(&"metrics"));
    assert!(body.get("dependencies").is_none());

    let removed_private_describe = TestClient::get("http://127.0.0.1/_floria/push/bridge/describe")
        .send(&service)
        .await;
    assert_eq!(
        removed_private_describe.status_code.unwrap(),
        StatusCode::NOT_FOUND
    );

    let push_notify_surface = surfaces
        .iter()
        .find(|surface| surface["name"] == json!("push_notify"))
        .expect("push_notify surface");
    assert_eq!(
        push_notify_surface["path"],
        json!("/_arkret/edge/push/notify")
    );
    assert_eq!(
        push_notify_surface["contract"],
        json!("ak.edge.push.command.notify.v1")
    );

    let metrics_surface = surfaces
        .iter()
        .find(|surface| surface["name"] == json!("metrics"))
        .expect("metrics surface");
    assert_eq!(metrics_surface["path"], json!("/metrics"));
    assert_eq!(metrics_surface["contract"], json!("prometheus.text.0.0.4"));
}

#[tokio::test]
async fn notify_response_uses_standard_outcome_without_plaintext_tokens() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(body.outcomes.len(), 1);
    assert_eq!(
        body.outcomes[0].gateway_status,
        arkret_models_integration::PushNotifyGatewayStatus::Accepted
    );
    let encoded = serde_json::to_string(&body).unwrap();
    assert!(!encoded.contains("plaintext-token-should-not-leak"));
    for forbidden in [
        "push_key",
        "app_id",
        "provider_message_id",
        "push_key_hash",
        "rejected",
        "provider_retries",
        "delivery_receipts",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "notify response must not contain `{forbidden}`, got: {encoded}"
        );
    }
}

#[tokio::test]
async fn notify_response_conserves_every_requested_device_id() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let devices = vec![
        device("com.example.app", "token-a"),
        device("com.example.app", "token-b"),
    ];
    let requested_device_ids = devices
        .iter()
        .map(|device| device["device_id"].as_str().unwrap().to_owned())
        .collect::<std::collections::HashSet<_>>();

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(devices))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    let outcome_device_ids = body
        .outcomes
        .iter()
        .map(|outcome| outcome.device_id.as_str().to_owned())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(outcome_device_ids, requested_device_ids);
    assert_eq!(body.outcomes.len(), requested_device_ids.len());
}

#[tokio::test]
async fn notify_rejects_operation_id_in_body() {
    // The push notify endpoint schema determines `operation_id` from the URL; it is no
    // longer a body field. A caller that still puts it in the body is
    // rejected as an unknown field (deny_unknown_fields), not validated.
    let service = test_service(vec![]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&with_operation_id(
            payload(vec![device("com.example.app", "one")]),
            "ak.edge.push.command.notify.v1",
        ))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    assert_notify_error(&mut response, "schema_violation", true).await;
}

#[tokio::test]
async fn notify_method_not_allowed_returns_problem_details() {
    let service = test_service(vec![]);

    let mut get_response = TestClient::get("http://127.0.0.1/_arkret/edge/push/notify")
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
    assert_notify_error(&mut get_response, "method_not_allowed", true).await;

    let mut put_response = TestClient::put("http://127.0.0.1/_arkret/edge/push/notify")
        .send(&service)
        .await;
    assert_eq!(
        put_response.status_code.unwrap(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_notify_error(&mut put_response, "method_not_allowed", true).await;

    let mut delete_response = TestClient::delete("http://127.0.0.1/_arkret/edge/push/notify")
        .send(&service)
        .await;
    assert_eq!(
        delete_response.status_code.unwrap(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_notify_error(&mut delete_response, "method_not_allowed", true).await;
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

#[tokio::test]
async fn readyz_endpoint_returns_ok_for_configured_registry() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::get("http://127.0.0.1/readyz")
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["service"], "floria");
    assert_eq!(body["ok"], true);
    assert_eq!(body["checks"]["provider_registry"]["ok"], true);
    assert_eq!(body["checks"]["provider_registry"]["count"], json!(1));
    assert_eq!(
        body["checks"]["provider_registry"]["providers"],
        json!(["com.example.app"])
    );
    let dependencies = body["checks"]["dependencies"]
        .as_array()
        .expect("dependency checks");
    assert!(dependencies.iter().all(|check| check["ok"] == json!(true)));
}

#[tokio::test]
async fn readyz_endpoint_fails_when_registry_is_empty() {
    let service = test_service(vec![]);

    let mut response = TestClient::get("http://127.0.0.1/readyz")
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["service"], "floria");
    assert_eq!(body["ok"], false);
    assert_eq!(body["checks"]["provider_registry"]["ok"], false);
    assert_eq!(body["checks"]["provider_registry"]["count"], json!(0));
}

/// T8.3 — `/health` MUST return a JSON body with a `hardening` block
/// (production deployment checklist snapshot) so the sodmin
/// `/hardening` dashboard can aggregate it.
#[tokio::test]
async fn healthz_exposes_hardening_status() {
    let service = test_service(vec![]);

    let mut response = TestClient::get("http://127.0.0.1/health")
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body: Value = response.take_json().await.unwrap();
    assert_eq!(body["service"], "floria");
    assert_eq!(body["ok"], true);
    let hardening = &body["hardening"];
    assert!(hardening.is_object(), "hardening block must be present");
    assert!(hardening["checklist_max"].as_u64().unwrap() >= 8);
    let admin_auth_mode = hardening["admin_auth_mode"].as_str().unwrap();
    assert!(
        admin_auth_mode == "closed"
            || admin_auth_mode == "development"
            || admin_auth_mode == "production"
    );
}
