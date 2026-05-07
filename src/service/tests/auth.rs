use std::sync::Arc;

use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};

use super::*;

#[tokio::test]
async fn notify_accepts_authenticated_allowlisted_service() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        notify_auth_config(),
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, 1, vec![], 0).await;
}

#[tokio::test]
async fn notify_requires_bearer_token_when_auth_enabled() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        notify_auth_config(),
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body = assert_notify_error(&mut response, "unauthenticated", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("missing bearer service token")
    );
}

#[tokio::test]
async fn notify_rejects_invalid_bearer_token() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        notify_auth_config(),
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer wrong-token", true)
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body = assert_notify_error(&mut response, "unauthenticated", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("invalid bearer service token")
    );
}

#[tokio::test]
async fn notify_accepts_hashed_bearer_token() {
    let mut config = notify_auth_config();
    config.bearer_tokens.clear();
    config.bearer_token_hashes = vec![crate::auth::bearer_token_sha256_hex("secret-token")];
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        config,
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, 1, vec![], 0).await;
}

#[tokio::test]
async fn notify_rejects_query_string_auth_material() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        notify_auth_config(),
    );

    let mut response =
        TestClient::post("http://127.0.0.1/api/v1/push/notify?access_token=secret-token")
            .add_header("authorization", "Bearer secret-token", true)
            .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
            .add_header(
                DESTINATION_SERVICE_DID_HEADER,
                "did:web:push.example.com",
                true,
            )
            .json(&payload(vec![device("com.example.app", "accept")]))
            .send(&service)
            .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("query string authentication is not allowed")
    );
}

#[tokio::test]
async fn notify_rejects_bearer_without_origin_service_did() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        notify_auth_config(),
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("origin service DID is required")
    );
}

#[tokio::test]
async fn notify_rejects_non_allowlisted_origin_service_did() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        notify_auth_config(),
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:rogue.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("origin service DID is not allowlisted")
    );
}

#[tokio::test]
async fn notify_rejects_plaintext_metadata_for_unauthorized_service() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        restricted_notify_auth_config(),
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("caller is not authorized to send sender_display_name or flow/space name metadata")
    );
}

#[tokio::test]
async fn notify_rejects_sender_identity_for_unauthorized_service() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        restricted_notify_auth_config(),
    );
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["flow_name"] = Value::Null;
    request_body["notification"]["space_name"] = Value::Null;
    request_body["notification"]["sender_display_name"] = Value::Null;
    request_body["notification"]["sender"] = json!("@alice:example.com");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!(
            "caller is not authorized to send plaintext identity metadata in `notification.sender`"
        )
    );
}

#[tokio::test]
async fn notify_rejects_target_did_for_unauthorized_service() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        restricted_notify_auth_config(),
    );
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["flow_name"] = Value::Null;
    request_body["notification"]["space_name"] = Value::Null;
    request_body["notification"]["sender_display_name"] = Value::Null;
    request_body["notification"]["sender"] = Value::Null;
    request_body["notification"]["content"] = json!({
        "target_did": "did:web:bob.example.com"
    });

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!(
            "caller is not authorized to send plaintext identity metadata in `notification.content.target_did`"
        )
    );
}

#[tokio::test]
async fn notify_rejects_nested_did_literal_for_unauthorized_service() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        restricted_notify_auth_config(),
    );
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["notification"]["flow_name"] = Value::Null;
    request_body["notification"]["space_name"] = Value::Null;
    request_body["notification"]["sender_display_name"] = Value::Null;
    request_body["notification"]["sender"] = Value::Null;
    request_body["notification"]["content"] = json!({
        "call_wakeup": {
            "relay_username": "did:web:relay.example.com"
        }
    });

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!(
            "caller is not authorized to send DID literal in `notification.content.call_wakeup.relay_username`"
        )
    );
}

#[tokio::test]
async fn notify_rejects_mismatched_origin_service_did() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        notify_auth_config(),
    );
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["origin_service_did"] = json!("did:web:other.example.com");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("origin service DID does not match the authenticated caller")
    );
}

#[tokio::test]
async fn notify_rejects_mismatched_destination_service_did() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        notify_auth_config(),
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:other-gateway.example.com",
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("destination service DID does not match this gateway")
    );
}

#[tokio::test]
async fn notify_rejects_body_destination_service_did_mismatch() {
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        notify_auth_config(),
    );
    let mut request_body = payload(vec![device("com.example.app", "accept")]);
    request_body["destination_service_did"] = json!("did:web:other-gateway.example.com");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer secret-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("destination_service_did does not match the authenticated destination")
    );
}

#[tokio::test]
async fn production_mode_rejects_anonymous_requests() {
    let mut config = NotifyAuthConfig::default();
    config.production_mode = true;
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        config,
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body = assert_notify_error(&mut response, "unauthenticated", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("anonymous /notify is disabled in production mode")
    );
}

#[tokio::test]
async fn production_mode_rejects_bearer_only_principal() {
    use crate::config::NotifyServicePrincipalConfig;
    let mut config = production_notify_auth_config();
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.bearer_tokens = vec!["principal-token".to_owned()];
    config
        .service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        config,
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer principal-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body = assert_notify_error(&mut response, "unauthenticated", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("production mode requires HTTP Message Signature or mTLS")
    );
}

#[tokio::test]
async fn production_mode_rejects_unknown_origin_with_gateway_bearer() {
    let mut config = production_notify_auth_config();
    config.bearer_tokens = vec!["gateway-token".to_owned()];
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        config,
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer gateway-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:rogue.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
    let body = assert_notify_error(&mut response, "unauthenticated", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("production mode requires a configured service principal")
    );
}

#[tokio::test]
async fn principal_plaintext_policy_requires_eligible_service_kind() {
    use crate::config::NotifyServicePrincipalConfig;
    let mut config = NotifyAuthConfig::default();
    config.gateway_service_did = Some("did:web:push.example.com".to_owned());
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.bearer_tokens = vec!["principal-token".to_owned()];
    principal.allow_plaintext_metadata = true;
    // `push` is a delegated push service (so the request is accepted)
    // but is NOT plaintext-eligible (so plaintext metadata is rejected).
    principal.service_type = Some("push".to_owned());
    config
        .service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);
    let service = test_service_with_auth(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        config,
    );

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("authorization", "Bearer principal-token", true)
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .add_header(
            DESTINATION_SERVICE_DID_HEADER,
            "did:web:push.example.com",
            true,
        )
        .json(&payload(vec![device("com.example.app", "accept")]))
        .send(&service)
        .await;

    // The principal is allowed to push, but its declared service_type is not in
    // the plaintext-eligible kind list, so the plaintext metadata in the
    // payload (sender_display_name etc.) is rejected.
    assert_eq!(response.status_code.unwrap(), StatusCode::FORBIDDEN);
    let body = assert_notify_error(&mut response, "capability_denied", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("caller is not authorized to send sender_display_name or flow/space name metadata")
    );
}
