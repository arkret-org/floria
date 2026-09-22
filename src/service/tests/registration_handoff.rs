use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;

fn handoff_test_service() -> Service {
    let registry = PushkinRegistry::new(HashMap::new());
    Service::new(build_router(Arc::new(AppState::new(Arc::new(registry)))))
}

fn body() -> Value {
    json!({
        "registration_id": "registration_0123456789abcdef",
        "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
        "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
        "state": "active",
        "push_key": "provider-secret",
        "app_id": "org.arkret.fixture",
        "visible_notification_opt_in": false
    })
}

#[tokio::test]
async fn handoff_requires_its_registered_operation_selector() {
    let service = handoff_test_service();
    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/registrations:apply")
        .json(&body())
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let problem = response.take_json::<Value>().await.unwrap();
    assert!(
        problem.to_string().contains("operation_selector_required"),
        "unexpected problem body: {problem}"
    );
}

#[tokio::test]
async fn handoff_never_accepts_an_unsigned_request() {
    let service = handoff_test_service();
    let mut response = TestClient::post("http://127.0.0.1/_arkret/edge/push/registrations:apply")
        .add_header(
            "Arkret-Operation",
            arkret_wire::ServiceOperationId::EDGE_PUSH_COMMAND_APPLY_REGISTRATION_V1,
            true,
        )
        .add_header(
            SOURCE_SERVICE_ID_HEADER,
            "ak:did_core:web:station.example",
            true,
        )
        .add_header(
            DESTINATION_SERVICE_ID_HEADER,
            "ak:did_core:web:push.example",
            true,
        )
        .json(&body())
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let problem = response.take_json::<Value>().await.unwrap();
    assert!(
        problem.to_string().contains("unauthenticated"),
        "unexpected problem body: {problem}"
    );
}
