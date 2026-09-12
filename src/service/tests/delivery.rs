use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use salvo::test::TestClient;

use super::*;

#[tokio::test]
async fn rejected_devices_are_reported() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
    )]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.app", "reject")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![rejected(Some("com.example.app"), "reject")],
    )
    .await;
}

#[tokio::test]
async fn ambiguous_app_ids_are_rejected() {
    let service = test_service(vec![
        (
            "*.example.*",
            Arc::new(TestPushkin::new("*.example.*", TestBehavior::Accept)),
        ),
        (
            "com.example.a*",
            Arc::new(TestPushkin::new("com.example.a*", TestBehavior::Accept)),
        ),
    ]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.app", "spqr")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![rejected(Some("com.example.app"), "spqr")],
    )
    .await;
}

#[tokio::test]
async fn remote_provider_errors_are_not_reported_as_accepted() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::RemoteError,
        )),
    )]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.app", "remote")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(
        body.outcomes[0].gateway_status,
        arkret_models_integration::PushNotifyGatewayStatus::Rejected
    );
    assert_eq!(
        body.outcomes[0].reason_code,
        Some(arkret_models_integration::PushNotifyReasonCode::PushGatewayUnreachable)
    );
}

#[tokio::test]
async fn internal_gateway_errors_return_caller_retryable_outcome() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::InternalError,
        )),
    )]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.app", "boom")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![rejected(Some("com.example.app"), "boom")],
    )
    .await;
}

#[tokio::test]
async fn temporary_errors_without_durable_retry_return_per_device_backoff() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::TemporaryError,
        )),
    )]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.app", "retry")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(
        body.outcomes[0].gateway_status,
        arkret_models_integration::PushNotifyGatewayStatus::Rejected
    );
    assert_eq!(
        body.outcomes[0].reason_code,
        Some(arkret_models_integration::PushNotifyReasonCode::PushGatewayUnreachable)
    );
    assert_eq!(body.outcomes[0].retry_after_ms, Some(7_000));
}

#[tokio::test]
async fn oversized_requests_are_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .text("x".repeat(MAX_REQUEST_SIZE + 1))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn per_pushkin_concurrency_limit_does_not_leak_provider_state() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::with_limit(
            "com.example.app",
            TestBehavior::SlowAccept,
            1,
        )),
    )]);

    let request_a = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service);
    let request_b = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service);

    let (response_a, response_b) = tokio::join!(request_a, request_b);
    let statuses = [
        response_a.status_code.unwrap(),
        response_b.status_code.unwrap(),
    ];

    assert_eq!(statuses, [StatusCode::OK, StatusCode::OK]);
}

#[tokio::test]
async fn duplicate_device_ids_are_rejected_at_ingress() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
    )]);

    let response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![
            device("com.example.app", "dup"),
            device("com.example.app", "dup"),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn distinct_device_ids_are_not_deduplicated_within_one_request() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );
    let first = device("com.example.app", "shared-route");
    let second = crate::registrations::test_support::device(
        "com.example.app",
        "shared-route",
        "ak:device:0196419b-0000-7000-8000-000000000099",
    );

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![first, second]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, vec![]).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn unknown_device_registration_is_rejected_without_dispatch() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);
    let unknown = json!({"device_id": "ak:device:0196419b-0000-7000-8000-ffffffffffff"});
    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![unknown.clone()]))
        .send(&service)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(body.outcomes.len(), 1);
    assert_eq!(
        body.outcomes[0].device_id.as_str(),
        unknown["device_id"].as_str().unwrap()
    );
    assert_eq!(
        body.outcomes[0].gateway_status,
        arkret_models_integration::PushNotifyGatewayStatus::Rejected
    );
    assert_eq!(
        body.outcomes[0].reason_code,
        Some(arkret_models_integration::PushNotifyReasonCode::PushTargetUnknown)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_device_identity_is_rejected_before_registration_lookup() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);
    for device in [
        json!({}),
        json!({"device_id": null}),
        json!({"device_id": ""}),
        json!({"device_id": "   "}),
    ] {
        let mut response =
            authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
                .add_header(
                    "Arkret-Operation",
                    arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
                    true,
                )
                .json(&payload(vec![device]))
                .send(&service)
                .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
        assert_notify_error(&mut response, "schema_violation", true).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn notify_cannot_supply_or_override_registration_routing_fields() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);
    let registered = device("com.example.app", "registered-route-only");
    for base in [
        registered,
        json!({"device_id": "ak:device:0196419b-0000-7000-8000-fffffffffffe"}),
    ] {
        for (field, value) in [
            ("app_id", json!("com.attacker.app")),
            ("push_key", json!("unregistered-provider-token")),
            ("platform", json!("apns")),
            ("visible_notification_opt_in", json!(true)),
        ] {
            let mut candidate = base.clone();
            candidate[field] = value;
            let mut response =
                authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
                    .add_header(
                        "Arkret-Operation",
                        arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
                        true,
                    )
                    .json(&payload(vec![candidate]))
                    .send(&service)
                    .await;
            assert_eq!(
                response.status_code.unwrap(),
                StatusCode::BAD_REQUEST,
                "notify accepted {field}"
            );
            assert_notify_error(&mut response, "schema_violation", true).await;
        }
    }
    for removed_field in [
        "timing_profile_hint",
        "mention_redirect_target_route_tokens",
    ] {
        let mut body = payload(vec![device("com.example.app", "registered-route-only")]);
        if removed_field == "timing_profile_hint" {
            body["notification"][removed_field] = json!("immediate");
        } else {
            body["notification"]["route_tokens"][removed_field] = json!([]);
        }
        let mut response =
            authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
                .add_header(
                    "Arkret-Operation",
                    arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
                    true,
                )
                .json(&body)
                .send(&service)
                .await;
        assert_eq!(
            response.status_code.unwrap(),
            StatusCode::BAD_REQUEST,
            "notify accepted {removed_field}"
        );
        assert_notify_error(&mut response, "schema_violation", true).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn registered_blank_provider_app_is_rejected_without_dispatch() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service(vec![("com.example.app", pushkin)]);
    // Invalid routing belongs to retained registration state. The wire carrier
    // still contains only a typed device identity.
    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("   ", "blank-registered-app")]))
        .send(&service)
        .await;
    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    let body = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(
        body.outcomes[0].reason_code,
        Some(arkret_models_integration::PushNotifyReasonCode::PushTokenInvalid)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn mixed_success_and_temporary_failure_returns_200() {
    let service = test_service(vec![
        (
            "com.example.ok",
            Arc::new(TestPushkin::new("com.example.ok", TestBehavior::Accept)),
        ),
        (
            "com.example.retry",
            Arc::new(TestPushkin::new(
                "com.example.retry",
                TestBehavior::TemporaryError,
            )),
        ),
    ]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![
            device("com.example.ok", "ok"),
            device("com.example.retry", "retry"),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![rejected(Some("com.example.retry"), "retry")],
    )
    .await;
}

#[tokio::test]
async fn all_temporary_failures_return_conserved_rejections() {
    let service = test_service(vec![(
        "com.example.retry",
        Arc::new(TestPushkin::new(
            "com.example.retry",
            TestBehavior::TemporaryError,
        )),
    )]);

    let mut response = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&payload(vec![device("com.example.retry", "retry")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        vec![rejected(Some("com.example.retry"), "retry")],
    )
    .await;
}

#[tokio::test]
async fn exact_replay_returns_the_original_per_device_outcomes() {
    let success_pushkin = Arc::new(TestPushkin::new("com.example.ok", TestBehavior::Accept));
    let success_calls = success_pushkin.calls.clone();
    let retry_pushkin = Arc::new(TestPushkin::new(
        "com.example.retry",
        TestBehavior::TemporaryError,
    ));
    let retry_calls = retry_pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![
            ("com.example.ok", success_pushkin as Arc<dyn Pushkin>),
            ("com.example.retry", retry_pushkin as Arc<dyn Pushkin>),
        ],
        Duration::from_secs(60),
    );
    let request_body = payload(vec![
        device("com.example.ok", "ok"),
        device("com.example.retry", "retry"),
    ]);

    let first = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&request_body)
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let second = authenticated_notify_request("http://127.0.0.1/_arkret/edge/push/notify")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1,
            true,
        )
        .json(&request_body)
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::OK);

    assert_eq!(success_calls.load(Ordering::SeqCst), 1);
    assert_eq!(retry_calls.load(Ordering::SeqCst), 1);
}
