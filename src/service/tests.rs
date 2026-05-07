use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use salvo::test::{ResponseExt, TestClient};
use serde_json::json;
use tokio::time::sleep;

use super::*;
use crate::config::{NotifyAuthConfig, NotifyRateLimitConfig};
use crate::dedup::NotifyDeduplicator;
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext, NotifyResponse, RejectedDevice};
use crate::pushkin::{AppMatcher, ConcurrencyGate, Pushkin, PushkinRegistry};
use crate::rate_limit::NotifyRateLimiter;

#[derive(Debug, Clone)]
enum TestBehavior {
    Accept,
    Reject,
    RemoteError,
    TemporaryError,
    InternalError,
    SlowAccept,
}

struct TestPushkin {
    matcher: AppMatcher,
    gate: Option<ConcurrencyGate>,
    behavior: TestBehavior,
    calls: Arc<AtomicUsize>,
    kind: &'static str,
}

impl TestPushkin {
    fn new(name: &str, behavior: TestBehavior) -> Self {
        Self {
            matcher: AppMatcher::new(name.to_owned()).unwrap(),
            gate: None,
            behavior,
            calls: Arc::new(AtomicUsize::new(0)),
            kind: "test",
        }
    }

    fn with_limit(name: &str, behavior: TestBehavior, limit: usize) -> Self {
        Self {
            matcher: AppMatcher::new(name.to_owned()).unwrap(),
            gate: Some(ConcurrencyGate::new(limit)),
            behavior,
            calls: Arc::new(AtomicUsize::new(0)),
            kind: "test",
        }
    }

    fn with_kind(mut self, kind: &'static str) -> Self {
        self.kind = kind;
        self
    }
}

#[async_trait]
impl Pushkin for TestPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        self.kind
    }

    fn handles_appid(&self, appid: &str) -> bool {
        self.matcher.handles_appid(appid)
    }

    async fn dispatch_notification(
        &self,
        _notification: &Notification,
        device: &Device,
        _context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _permit = self
            .gate
            .as_ref()
            .map(|gate| gate.acquire(self.name()))
            .transpose()?;

        match self.behavior {
            TestBehavior::Accept => Ok(vec![]),
            TestBehavior::Reject => Ok(vec![device.pushkey.clone()]),
            TestBehavior::RemoteError => Err(DispatchError::remote("synthetic remote failure")),
            TestBehavior::TemporaryError => Err(DispatchError::temporary(
                "synthetic temporary failure",
                Some(Duration::from_secs(7)),
            )),
            TestBehavior::InternalError => {
                Err(DispatchError::internal("synthetic internal failure"))
            }
            TestBehavior::SlowAccept => {
                sleep(Duration::from_millis(100)).await;
                Ok(vec![])
            }
        }
    }
}

fn test_service(pushkins: Vec<(&str, Arc<dyn Pushkin>)>) -> Service {
    let registry = PushkinRegistry::new(
        pushkins
            .into_iter()
            .map(|(name, pushkin)| (name.to_owned(), pushkin))
            .collect::<HashMap<_, _>>(),
    );
    let state = Arc::new(AppState::new(Arc::new(registry)));
    Service::new(build_router(state))
}

fn test_service_with_dedup(
    pushkins: Vec<(&str, Arc<dyn Pushkin>)>,
    dedup_ttl: Duration,
) -> Service {
    let registry = PushkinRegistry::new(
        pushkins
            .into_iter()
            .map(|(name, pushkin)| (name.to_owned(), pushkin))
            .collect::<HashMap<_, _>>(),
    );
    let state = Arc::new(AppState::with_notify_deduplicator(
        Arc::new(registry),
        Arc::new(NotifyDeduplicator::new(dedup_ttl)),
    ));
    Service::new(build_router(state))
}

fn test_service_with_rate_limits(
    pushkins: Vec<(&str, Arc<dyn Pushkin>)>,
    notify_rate_limits: NotifyRateLimitConfig,
) -> Service {
    let registry = PushkinRegistry::new(
        pushkins
            .into_iter()
            .map(|(name, pushkin)| (name.to_owned(), pushkin))
            .collect::<HashMap<_, _>>(),
    );
    let mut state = AppState::new(Arc::new(registry));
    state.notify_rate_limiter = Some(Arc::new(NotifyRateLimiter::new(notify_rate_limits)));
    Service::new(build_router(Arc::new(state)))
}

fn test_service_with_dedup_and_rate_limits(
    pushkins: Vec<(&str, Arc<dyn Pushkin>)>,
    dedup_ttl: Duration,
    notify_rate_limits: NotifyRateLimitConfig,
) -> Service {
    let registry = PushkinRegistry::new(
        pushkins
            .into_iter()
            .map(|(name, pushkin)| (name.to_owned(), pushkin))
            .collect::<HashMap<_, _>>(),
    );
    let mut state = AppState::with_notify_deduplicator(
        Arc::new(registry),
        Arc::new(NotifyDeduplicator::new(dedup_ttl)),
    );
    state.notify_rate_limiter = Some(Arc::new(NotifyRateLimiter::new(notify_rate_limits)));
    Service::new(build_router(Arc::new(state)))
}

fn test_service_with_auth(
    pushkins: Vec<(&str, Arc<dyn Pushkin>)>,
    notify_auth: NotifyAuthConfig,
) -> Service {
    let registry = PushkinRegistry::new(
        pushkins
            .into_iter()
            .map(|(name, pushkin)| (name.to_owned(), pushkin))
            .collect::<HashMap<_, _>>(),
    );
    let mut state = AppState::new(Arc::new(registry));
    state.notify_auth = notify_auth;
    Service::new(build_router(Arc::new(state)))
}

fn notify_auth_config() -> NotifyAuthConfig {
    let mut config = NotifyAuthConfig::default();
    config.bearer_tokens = vec!["secret-token".to_owned()];
    config.trusted_service_dids = vec!["did:web:sync.example.com".to_owned()];
    config.plaintext_metadata_service_dids = vec!["did:web:sync.example.com".to_owned()];
    config.gateway_service_did = Some("did:web:push.example.com".to_owned());
    config
}

fn restricted_notify_auth_config() -> NotifyAuthConfig {
    let mut config = notify_auth_config();
    config.plaintext_metadata_service_dids.clear();
    config
}

fn production_notify_auth_config() -> NotifyAuthConfig {
    use crate::config::NotifyServicePrincipalConfig;
    let mut config = NotifyAuthConfig::default();
    config.gateway_service_did = Some("did:web:push.example.com".to_owned());
    config.production_mode = true;
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
    principal.signature_public_key_hex = Some(
        "deadbeef".repeat(8),
    );
    principal.service_type = Some("sync".to_owned());
    config
        .service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);
    config
}

fn payload(devices: Vec<Value>) -> Value {
    json!({
        "operation_id": NOTIFY_OPERATION_ID,
        "origin_service_did": "did:web:sync.example.com",
        "notification": {
            "event_id": "cx:event:01JS0EV000000000000000000",
            "message_id": "cx:message:01JS0MSG0000000000000000",
            "flow_id": "cx:flow:01JS0FLOW000000000000000",
            "space_id": "cx:space:01JS0SP000000000000000000",
            "flow_name": "Engineering",
            "sender": "did:web:alice.example.com",
            "sender_display_name": "Alice",
            "type": "cx.message.create",
            "push_hint": "New message",
            "devices": devices
        }
    })
}

fn with_idempotency_key(mut request_body: Value, idempotency_key: &str) -> Value {
    request_body["idempotency_key"] = Value::String(idempotency_key.to_owned());
    request_body
}

fn with_operation_id(mut request_body: Value, operation_id: &str) -> Value {
    request_body["operation_id"] = Value::String(operation_id.to_owned());
    request_body
}

fn device(app_id: &str, pushkey: &str) -> Value {
    json!({
        "app_id": app_id,
        "pushkey": pushkey,
        "pushkey_ts": 42
    })
}

fn rejected(app_id: Option<&str>, push_key: &str) -> RejectedDevice {
    RejectedDevice::new(app_id, push_key)
}

async fn assert_notify_error<T: ResponseExt + ?Sized>(
    response: &mut T,
    code: &str,
    expect_request_id: bool,
) -> Value {
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(body["ok"], json!(false));
    assert_eq!(body["error"]["code"], json!(code));
    match (expect_request_id, body.get("request_id")) {
        (true, Some(Value::String(request_id))) => assert!(!request_id.is_empty()),
        (true, _) => panic!("expected request_id in error response"),
        (false, None) => {}
        (false, Some(Value::Null)) => {}
        (false, Some(_)) => panic!("did not expect request_id in error response"),
    }
    body
}

async fn assert_notify_ok<T: ResponseExt + ?Sized>(
    response: &mut T,
    accepted: usize,
    rejected_devices: Vec<RejectedDevice>,
    provider_retries: usize,
) {
    let body = response.take_json::<NotifyResponse>().await.unwrap();
    assert!(!body.request_id.is_empty());
    assert_eq!(body.accepted, accepted);
    assert_eq!(body.rejected, rejected_devices);
    assert_eq!(body.provider_retries.len(), provider_retries);
}

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

#[tokio::test]
async fn rejected_devices_are_reported() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "reject")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        0,
        vec![rejected(Some("com.example.app"), "reject")],
        0,
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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "spqr")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        0,
        vec![rejected(Some("com.example.app"), "spqr")],
        0,
    )
    .await;
}

#[tokio::test]
async fn remote_errors_map_to_502() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::RemoteError,
        )),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "remote")]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn internal_errors_map_to_500() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::InternalError,
        )),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "boom")]))
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn temporary_errors_map_to_503_with_retry_after() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new(
            "com.example.app",
            TestBehavior::TemporaryError,
        )),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "retry")]))
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("7")
    );
}

#[tokio::test]
async fn oversized_requests_are_rejected() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .text("x".repeat(MAX_REQUEST_SIZE + 1))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn per_pushkin_concurrency_limit_returns_502() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::with_limit(
            "com.example.app",
            TestBehavior::SlowAccept,
            1,
        )),
    )]);

    let request_a = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service);
    let request_b = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service);

    let (response_a, response_b) = tokio::join!(request_a, request_b);
    let statuses = [
        response_a.status_code.unwrap(),
        response_b.status_code.unwrap(),
    ];

    assert!(statuses.contains(&StatusCode::OK));
    assert!(statuses.contains(&StatusCode::BAD_GATEWAY));
}

#[tokio::test]
async fn duplicate_devices_are_dispatched_only_once() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Reject)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![
            device("com.example.app", "dup"),
            device("com.example.app", "dup"),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        0,
        vec![rejected(Some("com.example.app"), "dup")],
        0,
    )
    .await;
}

#[tokio::test]
async fn blank_device_fields_are_rejected_without_dispatch() {
    let service = test_service(vec![(
        "com.example.app",
        Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
    )]);

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![
            device("   ", "blank-app"),
            device("com.example.app", "   "),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(
        &mut response,
        0,
        vec![
            rejected(None, "blank-app"),
            rejected(Some("com.example.app"), "   "),
        ],
        0,
    )
    .await;
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

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![
            device("com.example.ok", "ok"),
            device("com.example.retry", "retry"),
        ]))
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    assert_notify_ok(&mut response, 1, vec![], 1).await;
}

#[tokio::test]
async fn all_temporary_failures_still_return_503() {
    let service = test_service(vec![(
        "com.example.retry",
        Arc::new(TestPushkin::new(
            "com.example.retry",
            TestBehavior::TemporaryError,
        )),
    )]);

    let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.retry", "retry")]))
        .send(&service)
        .await;

    assert_eq!(
        response.status_code.unwrap(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("7")
    );
}

#[tokio::test]
async fn notify_rate_limit_returns_429_with_retry_after() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_origin_service = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        second
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|value| value >= 1)
    );
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for origin_service")
    );
    assert!(
        body["error"]["retry_after_ms"]
            .as_u64()
            .is_some_and(|value| value >= 1000)
    );
}

#[tokio::test]
async fn notify_rate_limit_can_apply_per_app_id() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_app_id = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for app_id")
    );
}

#[tokio::test]
async fn notify_rate_limit_can_apply_per_provider() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_provider = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for provider")
    );
}

#[tokio::test]
async fn notify_rate_limit_can_apply_per_push_key_hash() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_push_key_hash = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "same-push-key")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "same-push-key")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for push_key_hash")
    );
}

#[tokio::test]
async fn notify_rate_limit_can_apply_per_endpoint() {
    let service = test_service_with_rate_limits(
        vec![(
            "com.example.app",
            Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept)),
        )],
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_endpoint = Some(1);
            config
        },
    );

    let first = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::TOO_MANY_REQUESTS);
    let body = assert_notify_error(&mut second, "rate_limited", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("notify rate limit exceeded for endpoint")
    );
}

#[tokio::test]
async fn dedup_replay_bypasses_rate_limit() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup_and_rate_limits(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
        {
            let mut config = NotifyRateLimitConfig::default();
            config.window_seconds = 60;
            config.per_origin_service = Some(1);
            config
        },
    );
    let request_body = payload(vec![device("com.example.app", "cached")]);

    for _ in 0..2 {
        let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
            .add_header("idempotency-key", "notify-123", true)
            .json(&request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn notify_supports_header_idempotency_key_replay() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );
    let request_body = payload(vec![device("com.example.app", "cached")]);

    for _ in 0..2 {
        let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("idempotency-key", "notify-123", true)
            .json(&request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn notify_duplicate_idempotency_key_with_different_body_returns_conflict() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );

    let first = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("idempotency-key", "notify-123", true)
        .json(&payload(vec![device("com.example.app", "one")]))
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let mut second = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("idempotency-key", "notify-123", true)
        .json(&payload(vec![device("com.example.app", "two")]))
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::CONFLICT);
    let body = assert_notify_error(&mut second, "duplicate_conflict", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("same idempotency key maps to different canonical request body")
    );

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn notify_rejects_mismatched_header_and_body_idempotency_keys() {
    let service = test_service_with_dedup(vec![], Duration::from_secs(60));
    let request_body =
        with_idempotency_key(payload(vec![device("com.example.app", "one")]), "body-key");

    let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .add_header("idempotency-key", "header-key", true)
        .json(&request_body)
        .send(&service)
        .await;

    assert_eq!(response.status_code.unwrap(), StatusCode::BAD_REQUEST);
    let body = assert_notify_error(&mut response, "schema_violation", true).await;
    assert_eq!(
        body["error"]["message"],
        json!("Idempotency-Key header does not match body idempotency_key")
    );
}

#[tokio::test]
async fn notify_dedup_cache_serves_repeated_success_without_redispatch() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );
    let request_body = payload(vec![device("com.example.app", "cached")]);

    for _ in 0..2 {
        let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .json(&request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn notify_dedup_cache_matches_reordered_equivalent_payloads() {
    let pushkin = Arc::new(TestPushkin::new("com.example.app", TestBehavior::Accept));
    let calls = pushkin.calls.clone();
    let service = test_service_with_dedup(
        vec![("com.example.app", pushkin as Arc<dyn Pushkin>)],
        Duration::from_secs(60),
    );

    let first = r#"{
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "message_id": "cx:message:01JS0MSG0000000000000000",
                "flow_id": "cx:flow:01JS0FLOW000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "sender": "did:web:alice.example.com",
                "sender_display_name": "Alice",
                "type": "cx.message.create",
                "push_hint": "New message",
                "devices": [
                    {"app_id": "com.example.app", "pushkey": "cached", "pushkey_ts": 42},
                    {"app_id": "com.example.app", "pushkey": "cached", "pushkey_ts": 42}
                ]
            }
        }"#;
    let second = r#"{
            "notification": {
                "devices": [
                    {"pushkey_ts": 42, "pushkey": "cached", "app_id": "com.example.app"}
                ],
                "push_hint": "New message",
                "type": "cx.message.create",
                "sender_display_name": "Alice",
                "sender": "did:web:alice.example.com",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "flow_id": "cx:flow:01JS0FLOW000000000000000",
                "message_id": "cx:message:01JS0MSG0000000000000000",
                "event_id": "cx:event:01JS0EV000000000000000000"
            }
        }"#;

    for request_body in [first, second] {
        let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("content-type", "application/json", true)
            .text(request_body)
            .send(&service)
            .await;
        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    assert_eq!(calls.load(Ordering::SeqCst), 1);
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

#[tokio::test]
async fn partial_success_retries_only_failed_devices() {
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

    let first = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;
    assert_eq!(first.status_code.unwrap(), StatusCode::OK);

    let second = TestClient::post("http://127.0.0.1/api/v1/push/notify")
        .json(&request_body)
        .send(&service)
        .await;
    assert_eq!(second.status_code.unwrap(), StatusCode::SERVICE_UNAVAILABLE);

    assert_eq!(success_calls.load(Ordering::SeqCst), 1);
    assert_eq!(retry_calls.load(Ordering::SeqCst), 2);
}
