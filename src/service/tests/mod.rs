use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arkret_models_integration::{PushNotificationEnvelope, PushRegistrationRecord};
use async_trait::async_trait;
use salvo::test::ResponseExt;
use serde_json::{Value, json};
use tokio::time::sleep;

use super::*;
use crate::config::{NotifyAuthConfig, NotifyRateLimitConfig};
use crate::dedup::NotifyDeduplicator;
use crate::error::DispatchError;
use crate::models::{DeviceExt, NotificationContext, RejectedDevice};
use crate::pushkin::{AppMatcher, ConcurrencyGate, Pushkin, PushkinRegistry};
use crate::rate_limit::NotifyRateLimiter;

mod agent_routing;
mod auth;
mod basics;
mod dedup;
mod delivery;
mod internal;
mod rate_limit;
mod registration_handoff;
mod sanitizer;

#[derive(Debug, Clone)]
pub(super) enum TestBehavior {
    Accept,
    Reject,
    RemoteError,
    TemporaryError,
    InternalError,
    SlowAccept,
}

pub(super) struct TestPushkin {
    matcher: AppMatcher,
    gate: Option<ConcurrencyGate>,
    behavior: TestBehavior,
    pub(super) calls: Arc<AtomicUsize>,
}

impl TestPushkin {
    pub(super) fn new(name: &str, behavior: TestBehavior) -> Self {
        Self {
            matcher: AppMatcher::new(name.to_owned()).unwrap(),
            gate: None,
            behavior,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) fn with_limit(name: &str, behavior: TestBehavior, limit: usize) -> Self {
        Self {
            matcher: AppMatcher::new(name.to_owned()).unwrap(),
            gate: Some(ConcurrencyGate::new(limit)),
            behavior,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl Pushkin for TestPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn handles_app_id(&self, app_id: &str) -> bool {
        self.matcher.handles_app_id(app_id)
    }

    async fn dispatch_notification(
        &self,
        _notification: &PushNotificationEnvelope,
        device: &PushRegistrationRecord,
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
            TestBehavior::Reject => Ok(vec![device.push_key().unwrap_or_default().to_owned()]),
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

pub(super) fn test_service(pushkins: Vec<(&str, Arc<dyn Pushkin>)>) -> Service {
    let registry = PushkinRegistry::new(
        pushkins
            .into_iter()
            .map(|(name, pushkin)| (name.to_owned(), pushkin))
            .collect::<HashMap<_, _>>(),
    );
    let mut state = AppState::new(Arc::new(registry));
    state.notify_auth = notify_auth_config();
    state.registrations = Arc::new(crate::registrations::test_support::directory());
    Service::new(build_router(Arc::new(state)))
}

pub(super) fn test_service_with_dedup(
    pushkins: Vec<(&str, Arc<dyn Pushkin>)>,
    dedup_ttl: Duration,
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
    state.notify_auth = notify_auth_config();
    state.registrations = Arc::new(crate::registrations::test_support::directory());
    Service::new(build_router(Arc::new(state)))
}

pub(super) fn test_service_with_rate_limits(
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
    state.notify_auth = notify_auth_config();
    state.registrations = Arc::new(crate::registrations::test_support::directory());
    Service::new(build_router(Arc::new(state)))
}

pub(super) fn test_service_with_dedup_and_rate_limits(
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
    state.notify_auth = notify_auth_config();
    state.registrations = Arc::new(crate::registrations::test_support::directory());
    Service::new(build_router(Arc::new(state)))
}

pub(super) fn test_service_with_auth(
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
    state.registrations = Arc::new(crate::registrations::test_support::directory());
    Service::new(build_router(Arc::new(state)))
}

pub(super) fn describe_test_service(pushkins: Vec<(&str, Arc<dyn Pushkin>)>) -> Service {
    let mut notify_auth = NotifyAuthConfig::default();
    notify_auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
    test_service_with_auth(pushkins, notify_auth)
}

pub(super) fn notify_auth_config() -> NotifyAuthConfig {
    let mut config = NotifyAuthConfig::default();
    config.bearer_tokens = vec!["secret-token".to_owned()];
    config.trusted_service_ids = vec!["ak:did_core:web:sync.example.com".to_owned()];
    config.plaintext_metadata_service_ids = vec!["ak:did_core:web:sync.example.com".to_owned()];
    config.gateway_service_did = Some("did:web:push.example.com".to_owned());
    config
}

pub(super) fn restricted_notify_auth_config() -> NotifyAuthConfig {
    let mut config = notify_auth_config();
    config.plaintext_metadata_service_ids.clear();
    config
}

pub(super) fn production_notify_auth_config() -> NotifyAuthConfig {
    use crate::config::NotifyServicePrincipalConfig;
    let mut config = NotifyAuthConfig::default();
    config.gateway_service_did = Some("did:web:push.example.com".to_owned());
    config.gateway_service_method_history_head = Some("fixture-head".to_owned());
    config.gateway_service_version_id = Some("fixture-v1".to_owned());
    config.production_mode = true;
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_verification_method = Some("did:web:sync.example.com#push".to_owned());
    principal.signature_public_key_hex = Some("deadbeef".repeat(8));
    principal.service_kind = Some("sync".to_owned());
    config
        .service_principals
        .insert("ak:did_core:web:sync.example.com".to_owned(), principal);
    config
}

pub(super) fn payload(devices: Vec<Value>) -> Value {
    // The push notify endpoint schema keeps transport fields (operation_id / origin_id /
    // destination_id / idempotency_key) ride HTTP headers, not the
    // body. Gateway-internal routing ids (realm_id / circle_id / ...) live
    // under notification.route_tokens.
    json!({
        "notification": {
            "event_id": "ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
            "message_id": "ak:message:AevYtAp_mjd9pPNtsNoiquL8rnoJUC0S0gYtV6_SwmD1",
            "strand_id": "ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD",
            "route_tokens": {
                "realm_route_token": "realm_route_token_000000001"
            },
            "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
            "wakeup_kind": "message",

            "push_hint": "new_message",
            "devices": devices
        }
    })
}

pub(super) fn visible_payload(devices: Vec<Value>) -> Value {
    let mut body = payload(devices);
    body["notification"]["strand_title"] = json!("Engineering");
    body["notification"]["sender_actor_display_name"] = json!("Alice");
    body
}

pub(super) fn with_idempotency_key(mut request_body: Value, idempotency_key: &str) -> Value {
    request_body["idempotency_key"] = Value::String(idempotency_key.to_owned());
    request_body
}

pub(super) fn with_operation_id(mut request_body: Value, operation_id: &str) -> Value {
    request_body["operation_id"] = Value::String(operation_id.to_owned());
    request_body
}

pub(super) fn device(app_id: &str, push_key: &str) -> Value {
    use std::hash::{DefaultHasher, Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    (app_id, push_key).hash(&mut hasher);
    let suffix = hasher.finish() & 0x0000_ffff_ffff_ffff;
    crate::registrations::test_support::device(
        app_id,
        push_key,
        &format!("ak:device:0196419b-0000-7000-8000-{suffix:012x}"),
    )
}

pub(super) fn rejected(app_id: Option<&str>, push_key: &str) -> RejectedDevice {
    RejectedDevice::new(app_id, push_key)
}

pub(super) async fn assert_notify_error<T: ResponseExt + ?Sized>(
    response: &mut T,
    code: &str,
    expect_request_id: bool,
) -> Value {
    let body = response.take_json::<Value>().await.unwrap();
    assert_eq!(
        body["type"],
        json!(format!("https://arkret.org/problems/{code}"))
    );
    assert!(body["status"].as_u64().is_some_and(|status| status >= 400));
    assert!(
        body["detail"]
            .as_str()
            .is_some_and(|detail| !detail.is_empty())
    );
    match (expect_request_id, body.get("instance")) {
        (true, Some(Value::String(request_id))) => assert!(!request_id.is_empty()),
        (true, _) => panic!("expected instance in problem response"),
        (false, None) => {}
        (false, Some(Value::Null)) => {}
        (false, Some(_)) => panic!("did not expect instance in problem response"),
    }
    // Preserve the older assertion helper projection for detailed tests while
    // validating the actual wire object above as RFC 9457.
    let core = ["type", "title", "status", "detail", "instance"];
    let details = body
        .as_object()
        .into_iter()
        .flat_map(|object| object.iter())
        .filter(|(key, _)| !core.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<serde_json::Map<_, _>>();
    json!({
        "ok": false,
        "error": {
            "code": code,
            "message": body["detail"].clone(),
            "details": details,
        },
        "request_id": body.get("instance").cloned().unwrap_or(Value::Null),
    })
}

pub(super) async fn assert_notify_ok<T: ResponseExt + ?Sized>(
    response: &mut T,
    rejected_devices: Vec<RejectedDevice>,
) {
    let body = response
        .take_json::<arkret_models_integration::PushNotifyOutcome>()
        .await
        .unwrap();
    assert_eq!(
        body.push_target_id.as_str(),
        "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8"
    );
    assert!(!body.outcomes.is_empty());
    assert_eq!(
        body.outcomes
            .iter()
            .filter(|outcome| {
                outcome.gateway_status
                    == arkret_models_integration::PushNotifyGatewayStatus::Rejected
            })
            .count(),
        rejected_devices.len()
    );
    let unique_device_ids = body
        .outcomes
        .iter()
        .map(|outcome| outcome.device_id.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(unique_device_ids.len(), body.outcomes.len());
    let encoded = serde_json::to_string(&body).unwrap();
    for rejected in rejected_devices {
        assert!(!encoded.contains(&rejected.push_key));
    }
    assert!(!encoded.contains("provider_retries"));
    assert!(!encoded.contains("delivery_receipts"));
}

pub(super) fn authenticated_notify_request(url: &str) -> salvo::test::RequestBuilder {
    salvo::test::TestClient::post(url)
        .bearer_auth("secret-token")
        .add_header("Idempotency-Key", "fixture", true)
        .add_header(
            "Source-Service-ID",
            crate::registrations::test_support::SOURCE,
            true,
        )
        .add_header(
            "Destination-Service-ID",
            "ak:did_core:web:push.example.com",
            true,
        )
}
