#![allow(unused_imports)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use salvo::test::{ResponseExt, TestClient};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio::time::sleep;

use super::*;
use crate::audit::{AuditEvent, AuditSink};
use crate::config::{NotifyAuthConfig, NotifyRateLimitConfig};
use crate::dedup::NotifyDeduplicator;
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext, NotifyResponse, RejectedDevice};
use crate::pushkin::{AppMatcher, ConcurrencyGate, Pushkin, PushkinRegistry};
use crate::rate_limit::NotifyRateLimiter;

mod auth;
mod basics;
mod dedup;
mod delivery;
mod internal;
mod phase_p2;
mod push_decision;
mod rate_limit;
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
    kind: &'static str,
}

impl TestPushkin {
    pub(super) fn new(name: &str, behavior: TestBehavior) -> Self {
        Self {
            matcher: AppMatcher::new(name.to_owned()).unwrap(),
            gate: None,
            behavior,
            calls: Arc::new(AtomicUsize::new(0)),
            kind: "test",
        }
    }

    pub(super) fn with_limit(name: &str, behavior: TestBehavior, limit: usize) -> Self {
        Self {
            matcher: AppMatcher::new(name.to_owned()).unwrap(),
            gate: Some(ConcurrencyGate::new(limit)),
            behavior,
            calls: Arc::new(AtomicUsize::new(0)),
            kind: "test",
        }
    }

    pub(super) fn with_kind(mut self, kind: &'static str) -> Self {
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
            TestBehavior::Reject => Ok(vec![device.push_key.clone()]),
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

pub(super) struct RecordingAuditSink {
    events: Arc<Mutex<Vec<AuditEvent>>>,
}

#[async_trait]
impl AuditSink for RecordingAuditSink {
    async fn record(&self, event: &AuditEvent) -> anyhow::Result<()> {
        self.events.lock().await.push(event.clone());
        Ok(())
    }
}

pub(super) fn recording_audit_sink() -> (Arc<Mutex<Vec<AuditEvent>>>, Arc<dyn AuditSink>) {
    let events = Arc::new(Mutex::new(Vec::new()));
    (events.clone(), Arc::new(RecordingAuditSink { events }))
}

pub(super) fn test_service(pushkins: Vec<(&str, Arc<dyn Pushkin>)>) -> Service {
    let registry = PushkinRegistry::new(
        pushkins
            .into_iter()
            .map(|(name, pushkin)| (name.to_owned(), pushkin))
            .collect::<HashMap<_, _>>(),
    );
    let state = Arc::new(AppState::new(Arc::new(registry)));
    Service::new(build_router(state))
}

pub(super) fn test_service_with_audit_sink(
    pushkins: Vec<(&str, Arc<dyn Pushkin>)>,
    audit_sink: Arc<dyn AuditSink>,
) -> Service {
    let registry = PushkinRegistry::new(
        pushkins
            .into_iter()
            .map(|(name, pushkin)| (name.to_owned(), pushkin))
            .collect::<HashMap<_, _>>(),
    );
    let mut state = AppState::new(Arc::new(registry));
    state.audit_sink = Some(audit_sink);
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
    let state = Arc::new(AppState::with_notify_deduplicator(
        Arc::new(registry),
        Arc::new(NotifyDeduplicator::new(dedup_ttl)),
    ));
    Service::new(build_router(state))
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
    Service::new(build_router(Arc::new(state)))
}

pub(super) fn notify_auth_config() -> NotifyAuthConfig {
    let mut config = NotifyAuthConfig::default();
    config.bearer_tokens = vec!["secret-token".to_owned()];
    config.trusted_service_dids = vec!["did:web:sync.example.com".to_owned()];
    config.plaintext_metadata_service_dids = vec!["did:web:sync.example.com".to_owned()];
    config.gateway_service_did = Some("did:web:push.example.com".to_owned());
    config
}

pub(super) fn restricted_notify_auth_config() -> NotifyAuthConfig {
    let mut config = notify_auth_config();
    config.plaintext_metadata_service_dids.clear();
    config
}

pub(super) fn production_notify_auth_config() -> NotifyAuthConfig {
    use crate::config::NotifyServicePrincipalConfig;
    let mut config = NotifyAuthConfig::default();
    config.gateway_service_did = Some("did:web:push.example.com".to_owned());
    config.production_mode = true;
    let mut principal = NotifyServicePrincipalConfig::default();
    principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
    principal.signature_public_key_hex = Some("deadbeef".repeat(8));
    principal.service_type = Some("sync".to_owned());
    config
        .service_principals
        .insert("did:web:sync.example.com".to_owned(), principal);
    config
}

pub(super) fn payload(devices: Vec<Value>) -> Value {
    json!({
        "operation_id": NOTIFY_OPERATION_ID,
        "origin_service_did": "did:web:sync.example.com",
        "notification": {
            "event_id": "ck:event:01JS0EV000000000000000000",
            "message_id": "ck:message:01JS0MSG0000000000000000",
            "flow_id": "ck:flow:01JS0FLOW000000000000000",
            "realm_id": "ck:realm:01JS0SP000000000000000000",
            "push_target_id": "ck:pseudonym:push:01HYZ8Z000000000000000",
            "wakeup_kind": "message",
            "push_hint": "new_message",
            "devices": devices
        }
    })
}

pub(super) fn visible_payload(devices: Vec<Value>) -> Value {
    let mut body = payload(devices);
    body["notification"]["flow_title"] = json!("Engineering");
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
    json!({
        "app_id": app_id,
        "push_key": push_key
    })
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

pub(super) async fn assert_notify_ok<T: ResponseExt + ?Sized>(
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
