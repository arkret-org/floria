use std::sync::Arc;

use salvo::test::{ResponseExt, TestClient};
use serde_json::json;

use super::*;

#[tokio::test]
async fn notify_payload_with_message_body_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["content"] = json!({
        "msgtype": "m.text",
        "body": "hello"
    });

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("Contrix blind wakeup payloads must not include sensitive field `content.body`")
    );
}

#[tokio::test]
async fn notify_payload_with_provider_preview_smuggling_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["content"] = json!({
        "provider_payload": {
            "aps": {
                "alert": {
                    "title": "Secret Project",
                    "body": "hello"
                }
            }
        }
    });

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!(
            "Contrix blind wakeup payloads must not include sensitive field `content.provider_payload`"
        )
    );
}

#[tokio::test]
async fn notify_payload_with_structured_preview_hint_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["push_hint"] = json!(r#"{"title":"Secret Project"}"#);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!(
            "Contrix blind wakeup push_hint must not contain plaintext preview or call setup material"
        )
    );
}

#[tokio::test]
async fn notify_payload_with_legacy_room_field_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["room_id"] = json!("!room:example.com");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("legacy notify contract field `notification.room_id` is not supported")
    );
}

#[tokio::test]
async fn notify_payload_with_legacy_card_id_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["card_id"] = json!("cx:card:legacy-card");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("legacy notify contract field `notification.card_id` is not supported")
    );
}

#[tokio::test]
async fn notify_payload_with_legacy_subject_id_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["subject_id"] = json!("cx:subject:legacy-subject");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("legacy notify contract field `notification.subject_id` is not supported")
    );
}

#[tokio::test]
async fn notify_payload_with_legacy_typed_id_value_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["flow_id"] = json!("cx:card:legacy-card");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("legacy notify contract value `notification.flow_id` is not supported")
    );
}

#[tokio::test]
async fn notify_payload_with_legacy_event_type_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["type"] = json!("m.room.message");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("legacy notify contract value `notification.type` is not supported")
    );
}

#[tokio::test]
async fn notify_payload_with_legacy_only_last_per_room_flag_is_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["devices"][0]["data"] = json!({
        "only_last_per_room": true
    });

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!(
            "legacy notify contract field `notification.devices[0].data.only_last_per_room` is not supported"
        )
    );
}
