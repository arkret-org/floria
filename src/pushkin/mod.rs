mod android;
mod apns;
mod custom;
mod fcm;
mod honor;
mod huawei;
mod jpush;
mod oppo;
mod reqwest_support;
mod vivo;
#[cfg(feature = "webpush-provider")]
mod webpush;
mod xiaomi;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
use cokret::push_gateway_api::ProviderCapabilityDescriptor;
use globset::{Glob, GlobMatcher};
use prometheus::register_int_counter_vec;
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext};

static INFLIGHT_LIMIT_DROP: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_inflight_request_limit_drop",
        "Number of notifications dropped because the number of inflight requests exceeded the configured inflight_request_limit",
        &["pushkin"]
    )
    .expect("register floria_inflight_request_limit_drop")
});

pub use apns::ApnsPushkin;
pub use custom::CustomPushkin;
pub use fcm::FcmPushkin;
pub use honor::HonorPushkin;
pub use huawei::HuaweiPushkin;
pub use jpush::JpushPushkin;
pub use oppo::OppoPushkin;
pub use vivo::VivoPushkin;
#[cfg(feature = "webpush-provider")]
pub use webpush::WebpushPushkin;
pub use xiaomi::XiaomiPushkin;

pub const DEFAULT_INFLIGHT_REQUEST_LIMIT: usize = 512;
pub const DEFAULT_MAX_CONNECTIONS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchTarget {
    pub push_key: String,
    pub app_id: String,
}

/// Unified result of a single pushkin dispatch attempt.
///
/// Surfaces both happy-path (`accepted`) and partial-failure
/// (`rejected`) outcomes alongside the retry hint that drives the
/// retry queue + dead-letter ring (see [`crate::retry_queue`]). The
/// `dedup_binding` field carries any provider-emitted message id so
/// downstream observers can match the gateway delivery receipt to the
/// upstream provider record.
#[derive(Debug, Clone, Default)]
pub struct DispatchOutcome {
    pub accepted: Vec<DispatchTarget>,
    pub rejected: Vec<String>,
    pub retry_after: Option<std::time::Duration>,
    pub dedup_binding: Vec<(String, String)>,
}

impl DispatchOutcome {
    pub fn from_rejected_tokens(targets: &[DispatchTarget], rejected: Vec<String>) -> Self {
        let rejected_set: std::collections::HashSet<&str> =
            rejected.iter().map(String::as_str).collect();
        let accepted = targets
            .iter()
            .filter(|target| !rejected_set.contains(target.push_key.as_str()))
            .cloned()
            .collect();
        Self {
            accepted,
            rejected,
            retry_after: None,
            dedup_binding: Vec::new(),
        }
    }
}

#[async_trait]
pub trait Pushkin: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    fn handles_appid(&self, appid: &str) -> bool;
    fn dispatch_targets(
        &self,
        _notification: &Notification,
        device: &Device,
    ) -> Vec<DispatchTarget> {
        vec![DispatchTarget {
            app_id: device.app_id.clone(),
            push_key: device.push_key.clone(),
        }]
    }
    async fn dispatch_notification(
        &self,
        notification: &Notification,
        device: &Device,
        context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError>;

    /// Unified dispatch entry point. The default implementation wraps
    /// [`Self::dispatch_notification`] so existing pushkins keep
    /// working unchanged. Implementations that can return per-target
    /// provider message IDs should override this method to surface a
    /// richer [`DispatchOutcome`].
    async fn dispatch_outcome(
        &self,
        notification: &Notification,
        device: &Device,
        context: &NotificationContext,
    ) -> Result<DispatchOutcome, DispatchError> {
        let targets = self.dispatch_targets(notification, device);
        let rejected = self
            .dispatch_notification(notification, device, context)
            .await?;
        Ok(DispatchOutcome::from_rejected_tokens(&targets, rejected))
    }
}

/// Frozen capability snapshot for a provider kind, surfaced through
/// `bridge/describe` so principal servers (soland, chime SDK) and
/// cotest matrices can plan payload shape, TTL caps, and credential
/// rotation without per-provider knowledge.
///
/// Values describe the *kind* (apns, fcm, ...) — per-app overrides
/// (e.g. tighter admin TTL caps) are intentionally not included here.
///
/// Contract version is exposed as `PROVIDER_CAPABILITIES_VERSION`;
/// bumping it signals downstream snapshots (soland drift detection,
/// chime typed DTO, cotest push matrix) that the matrix changed and
/// they must refresh.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderCapabilities {
    /// Stable provider kind, e.g. `"apns"`, `"fcm"`, `"oppo"`.
    pub kind: &'static str,
    /// Multi-recipient send shape: `"none"`, `"multicast"`, or `"topic"`.
    pub batch: &'static str,
    /// Maximum TTL in seconds the upstream provider accepts, or `None`
    /// when the provider does not document a hard cap.
    pub ttl_seconds_max: Option<u64>,
    /// Whether the provider supports a collapse / replace key.
    pub supports_collapse: bool,
    /// Whether the provider has first-class badge / unread count support.
    pub supports_badge: bool,
    /// Default outbound payload shape — informs blind-wakeup vs.
    /// service-visible plaintext defaults.
    pub default_payload_shape: &'static str,
    /// Credential material this provider expects.
    pub credential_kinds: &'static [&'static str],
    /// Documented credential rotation cadence for this provider kind.
    pub credential_rotation: &'static str,
    /// Whether the provider can carry an encrypted body that the
    /// gateway must NOT inspect (controls plaintext-policy gating).
    pub blind_wakeup_required: bool,
}

/// Contract version for the frozen `provider_capabilities` matrix.
///
/// Bump on any field/value change so soland drift detection, chime
/// typed DTOs, and cotest push matrices know to refresh.
pub const PROVIDER_CAPABILITIES_VERSION: &str = "2026-05-07";

pub fn provider_kind_capabilities(kind: &str) -> Option<ProviderCapabilities> {
    let kind = match kind {
        "apns" => ProviderCapabilities {
            kind: "apns",
            batch: "none",
            ttl_seconds_max: Some(28 * 24 * 60 * 60),
            supports_collapse: true,
            supports_badge: true,
            default_payload_shape: "encrypted_or_blind_wakeup",
            credential_kinds: &["jwt_p8", "cert_p12"],
            credential_rotation: "rotate_jwt_p8_yearly_cert_p12_per_apple_lifecycle",
            blind_wakeup_required: true,
        },
        "fcm" => ProviderCapabilities {
            kind: "fcm",
            batch: "multicast",
            ttl_seconds_max: Some(28 * 24 * 60 * 60),
            supports_collapse: true,
            supports_badge: true,
            default_payload_shape: "data_only_blind_wakeup",
            credential_kinds: &["service_account_v1"],
            credential_rotation: "rotate_service_account_yearly_or_on_compromise",
            blind_wakeup_required: true,
        },
        "webpush" => ProviderCapabilities {
            kind: "webpush",
            batch: "none",
            ttl_seconds_max: None,
            supports_collapse: true,
            supports_badge: false,
            default_payload_shape: "encrypted_aes128gcm",
            credential_kinds: &["vapid_keypair"],
            credential_rotation: "rotate_vapid_keypair_quarterly",
            blind_wakeup_required: true,
        },
        "honor" => ProviderCapabilities {
            kind: "honor",
            batch: "none",
            ttl_seconds_max: None,
            supports_collapse: true,
            supports_badge: true,
            default_payload_shape: "rich_android",
            credential_kinds: &["client_id_secret"],
            credential_rotation: "rotate_client_secret_yearly",
            blind_wakeup_required: false,
        },
        "huawei" => ProviderCapabilities {
            kind: "huawei",
            batch: "multicast",
            ttl_seconds_max: Some(15 * 24 * 60 * 60),
            supports_collapse: true,
            supports_badge: true,
            default_payload_shape: "rich_android",
            credential_kinds: &["client_id_secret"],
            credential_rotation: "rotate_client_secret_yearly",
            blind_wakeup_required: false,
        },
        "jpush" => ProviderCapabilities {
            kind: "jpush",
            batch: "multicast",
            ttl_seconds_max: None,
            supports_collapse: true,
            supports_badge: true,
            default_payload_shape: "rich_android",
            credential_kinds: &["app_key_master_secret"],
            credential_rotation: "rotate_master_secret_quarterly",
            blind_wakeup_required: false,
        },
        "oppo" => ProviderCapabilities {
            kind: "oppo",
            batch: "none",
            ttl_seconds_max: None,
            supports_collapse: true,
            supports_badge: true,
            default_payload_shape: "rich_android",
            credential_kinds: &["app_key_master_secret"],
            credential_rotation: "rotate_master_secret_yearly",
            blind_wakeup_required: false,
        },
        "oneplus" => ProviderCapabilities {
            kind: "oneplus",
            batch: "none",
            ttl_seconds_max: None,
            supports_collapse: true,
            supports_badge: true,
            default_payload_shape: "rich_android",
            credential_kinds: &["app_key_master_secret"],
            credential_rotation: "rotate_master_secret_yearly",
            blind_wakeup_required: false,
        },
        "vivo" => ProviderCapabilities {
            kind: "vivo",
            batch: "none",
            ttl_seconds_max: None,
            supports_collapse: true,
            supports_badge: true,
            default_payload_shape: "rich_android",
            credential_kinds: &["app_id_app_key"],
            credential_rotation: "rotate_app_key_yearly",
            blind_wakeup_required: false,
        },
        "xiaomi" => ProviderCapabilities {
            kind: "xiaomi",
            batch: "multicast",
            ttl_seconds_max: None,
            supports_collapse: true,
            supports_badge: true,
            default_payload_shape: "rich_android",
            credential_kinds: &["app_secret"],
            credential_rotation: "rotate_app_secret_yearly",
            blind_wakeup_required: false,
        },
        "custom" => ProviderCapabilities {
            kind: "custom",
            batch: "none",
            ttl_seconds_max: None,
            supports_collapse: false,
            supports_badge: false,
            default_payload_shape: "operator_defined",
            credential_kinds: &["bearer_token", "hmac_secret", "client_certificate"],
            credential_rotation: "operator_defined",
            blind_wakeup_required: true,
        },
        _ => return None,
    };
    Some(kind)
}

#[derive(Clone)]
pub struct PushkinRegistry {
    pushkins: HashMap<String, Arc<dyn Pushkin>>,
}

impl PushkinRegistry {
    pub fn from_config(config: &Config) -> Result<Self> {
        let base_dir = std::env::var("FLORIA_CONF")
            .ok()
            .and_then(|path| {
                std::path::PathBuf::from(path)
                    .parent()
                    .map(Path::to_path_buf)
            })
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

        let mut pushkins = HashMap::<String, Arc<dyn Pushkin>>::new();
        for (name, app) in &config.apps {
            let pushkin = create_pushkin(name.clone(), app, config, &base_dir)?;
            pushkins.insert(name.clone(), pushkin);
        }

        Ok(Self { pushkins })
    }

    pub fn new(pushkins: HashMap<String, Arc<dyn Pushkin>>) -> Self {
        Self { pushkins }
    }

    pub fn is_empty(&self) -> bool {
        self.pushkins.is_empty()
    }

    pub fn provider_names(&self) -> Vec<String> {
        let mut names = self.pushkins.keys().cloned().collect::<Vec<_>>();
        names.sort_unstable();
        names
    }

    pub fn provider_capabilities(&self) -> Vec<ProviderCapabilityDescriptor> {
        let mut out = self
            .pushkins
            .iter()
            .filter_map(|(name, pushkin)| {
                provider_kind_capabilities(pushkin.kind()).map(|capabilities| {
                    ProviderCapabilityDescriptor {
                        name: name.clone(),
                        kind: capabilities.kind.to_owned(),
                        batch: capabilities.batch.to_owned(),
                        ttl_seconds_max: capabilities.ttl_seconds_max,
                        supports_collapse: capabilities.supports_collapse,
                        supports_badge: capabilities.supports_badge,
                        default_payload_shape: capabilities.default_payload_shape.to_owned(),
                        credential_kinds: capabilities
                            .credential_kinds
                            .iter()
                            .map(|kind| (*kind).to_owned())
                            .collect(),
                        credential_rotation: capabilities.credential_rotation.to_owned(),
                        blind_wakeup_required: capabilities.blind_wakeup_required,
                    }
                })
            })
            .collect::<Vec<_>>();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn find_pushkins(&self, appid: &str) -> Vec<Arc<dyn Pushkin>> {
        if let Some(pushkin) = self.pushkins.get(appid) {
            return vec![pushkin.clone()];
        }

        self.pushkins
            .values()
            .filter(|pushkin| pushkin.handles_appid(appid))
            .cloned()
            .collect()
    }
}

fn create_pushkin(
    name: String,
    app: &AppConfig,
    config: &Config,
    base_dir: &Path,
) -> Result<Arc<dyn Pushkin>> {
    match app.require_kind()? {
        "apns" => Ok(Arc::new(ApnsPushkin::new(name, app, config, base_dir)?)),
        "custom" => Ok(Arc::new(CustomPushkin::new(name, app, config, base_dir)?)),
        "fcm" => Ok(Arc::new(FcmPushkin::new(name, app, config, base_dir)?)),
        "honor" => Ok(Arc::new(HonorPushkin::new(name, app, config)?)),
        "huawei" => Ok(Arc::new(HuaweiPushkin::new(name, app, config)?)),
        "jpush" => Ok(Arc::new(JpushPushkin::new(name, app, config)?)),
        "oppo" => Ok(Arc::new(OppoPushkin::new(name, app, config)?)),
        "oneplus" => Ok(Arc::new(OppoPushkin::new_oneplus(name, app, config)?)),
        "vivo" => Ok(Arc::new(VivoPushkin::new(name, app, config)?)),
        "webpush" => create_webpush_pushkin(name, app, config, base_dir),
        "xiaomi" => Ok(Arc::new(XiaomiPushkin::new(name, app, config)?)),
        other => bail!("unsupported pushkin type `{other}`"),
    }
}

#[cfg(feature = "webpush-provider")]
fn create_webpush_pushkin(
    name: String,
    app: &AppConfig,
    config: &Config,
    base_dir: &Path,
) -> Result<Arc<dyn Pushkin>> {
    Ok(Arc::new(WebpushPushkin::new(name, app, config, base_dir)?))
}

#[cfg(not(feature = "webpush-provider"))]
fn create_webpush_pushkin(
    _name: String,
    _app: &AppConfig,
    _config: &Config,
    _base_dir: &Path,
) -> Result<Arc<dyn Pushkin>> {
    bail!("webpush pushkin requires the `webpush-provider` cargo feature")
}

#[derive(Debug)]
pub struct AppMatcher {
    name: String,
    glob: GlobMatcher,
}

impl AppMatcher {
    pub fn new(name: String) -> Result<Self> {
        let glob = Glob::new(&name)
            .map_err(|error| anyhow!("invalid app id matcher `{name}`: {error}"))?
            .compile_matcher();
        Ok(Self { name, glob })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn handles_appid(&self, appid: &str) -> bool {
        self.name == appid || self.glob.is_match(appid)
    }
}

#[derive(Debug, Clone)]
pub struct ConcurrencyGate {
    semaphore: Arc<Semaphore>,
}

impl ConcurrencyGate {
    pub fn new(limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(limit.max(1))),
        }
    }

    pub fn acquire(&self, pushkin_name: &str) -> Result<OwnedSemaphorePermit, DispatchError> {
        self.semaphore.clone().try_acquire_owned().map_err(|_| {
            INFLIGHT_LIMIT_DROP.with_label_values(&[pushkin_name]).inc();
            DispatchError::remote(format!("too many in-flight requests for `{pushkin_name}`"))
        })
    }
}

pub fn inflight_limit(app: &AppConfig) -> Result<usize> {
    Ok(app
        .get_u64("inflight_request_limit")?
        .unwrap_or(DEFAULT_INFLIGHT_REQUEST_LIMIT as u64) as usize)
}

pub fn max_connections(app: &AppConfig) -> Result<usize> {
    Ok(app
        .get_u64("max_connections")?
        .unwrap_or(DEFAULT_MAX_CONNECTIONS as u64) as usize)
}

pub fn truncate_str(input: &str, max_bytes: usize) -> (String, bool) {
    let bytes = input.as_bytes();
    if bytes.len() <= max_bytes {
        return (input.to_owned(), false);
    }

    let limit = max_bytes.saturating_sub(3);
    match std::str::from_utf8(&bytes[..limit]) {
        Ok(prefix) => (format!("{prefix}..."), true),
        Err(error) => {
            let safe = &bytes[..error.valid_up_to()];
            (format!("{}...", String::from_utf8_lossy(safe)), true)
        }
    }
}

// ---------------------------------------------------------------------------
// T4.3 — provider-side sanitization
//
// Final builder for the blind-wakeup payload that goes on the wire to a
// downstream push provider (APNS, FCM, WebPush, Chinese OEM, custom).
// Adapters must call [`sanitized_provider_payload`] *just before* they
// hand the JSON off to the provider so that any forbidden key that
// slipped past the notify ingress validators (stale call sites, future
// builder bugs, …) is stripped before fan-out.
//
// `sanitize_blind_payload_strict` from the SDK is the last line of
// defence; if it rejects, the dispatcher must drop the device rather
// than send a leaky payload.
// ---------------------------------------------------------------------------

use serde_json::Map;

/// Sanitize a fully-built provider payload tree just before it leaves
/// the gateway. Removes any forbidden top-level key, recursively scans
/// nested objects for the same, then runs the SDK
/// `sanitize_blind_payload_strict` validator wrapped in a synthetic
/// envelope so we don't have to require `push_target_id` / `wakeup_kind`
/// at the top level of provider-shaped data.
///
/// On success returns the sanitized payload. On rejection the caller
/// must treat this as a hard drop (rejected token) rather than fall
/// through to a leaky send.
pub fn sanitized_provider_payload(
    mut payload: Map<String, serde_json::Value>,
) -> Result<Map<String, serde_json::Value>, ProviderPayloadRejection> {
    strip_forbidden_recursive(&mut payload);
    let envelope = serde_json::json!({
        "notification": {
            "push_target_id": "ck:pseudonym:push:0000000000000000000000",
            "wakeup_kind": "message",
        },
        "provider_payload_under_review": serde_json::Value::Object(payload.clone()),
    });
    if let Err(err) = cokret::blind_payload_sanitizer::sanitize_blind_payload_strict(&envelope) {
        return Err(ProviderPayloadRejection {
            field_path: err.field_path,
            reason_code: err.reason_code.as_str().to_owned(),
        });
    }
    Ok(payload)
}

/// Rejection emitted by [`sanitized_provider_payload`] when the SDK
/// sanitizer refuses the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderPayloadRejection {
    pub field_path: String,
    pub reason_code: String,
}

impl std::fmt::Display for ProviderPayloadRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "provider payload sanitizer rejected `{}` ({})",
            self.field_path, self.reason_code,
        )
    }
}

fn strip_forbidden_recursive(map: &mut Map<String, serde_json::Value>) {
    // Drop forbidden top-level keys. We do *not* touch keys that are
    // provider-defined wrappers like `aps`, `android`, `notification`,
    // `payload` — those are themselves on the SDK forbidden list when
    // they appear in the blind-wakeup contract, so anything that gets
    // here with one of those keys gets stripped.
    //
    // SDK's `is_forbidden_payload_key` covers `realm_id` (the renamed
    // security-boundary id) AND the renamed container `space_id`. The
    // shared `crate::sanitize::is_forbidden_egress_key` adds floria's
    // provider-egress routing/audit fields on top.
    map.retain(|key, _| !crate::sanitize::is_forbidden_egress_key(key));
    for value in map.values_mut() {
        strip_value_recursive(value);
    }
}

fn strip_value_recursive(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => strip_forbidden_recursive(map),
        serde_json::Value::Array(values) => {
            for nested in values {
                strip_value_recursive(nested);
            }
        }
        _ => {}
    }
}

/// Build a base data map from a [`Notification`] using only the
/// SDK-allowed blind-wakeup fields. Adapters that want a blind-only
/// payload (FCM, WebPush blind path, Chinese OEM blind path) can start
/// from this and append their own provider-specific wrappers — they
/// still MUST run [`sanitized_provider_payload`] before sending.
///
/// This intentionally drops every potentially-correlating identifier
/// (`event_id`, `message_id`, `strand_id`, `realm_id`, sender, names,
/// body, push_hint when it carries an l10n token, etc.). The only
/// fields that survive are:
///   * `push_target_id` (opaque pseudonym)
///   * `wakeup_kind` (closed enum)
///   * `push_hint` ONLY when it's an allow-listed literal (not l10n_key)
///   * `badge` / `unread_count` (clamped at SDK MAX_COUNT_VALUE)
pub fn build_blind_routing_data(notification: &Notification) -> Map<String, serde_json::Value> {
    use cokret::blind_payload_sanitizer as sdk;

    let mut data = Map::new();
    if let Some(push_target_id) = notification.push_target_id.as_deref()
        && sdk::is_valid_push_target_id(push_target_id)
    {
        data.insert(
            "push_target_id".to_owned(),
            serde_json::Value::String(push_target_id.to_owned()),
        );
    }
    if let Some(wakeup_kind) = notification.wakeup_kind()
        && sdk::is_valid_wakeup_kind(wakeup_kind)
    {
        data.insert(
            "wakeup_kind".to_owned(),
            serde_json::Value::String(wakeup_kind.to_owned()),
        );
    }
    if let Some(push_hint) = notification.push_hint.as_deref()
        && sdk::is_valid_push_hint(push_hint)
    {
        data.insert(
            "push_hint".to_owned(),
            serde_json::Value::String(push_hint.to_owned()),
        );
    }
    data
}

pub fn build_blind_provider_data(notification: &Notification) -> Map<String, serde_json::Value> {
    let mut data = build_blind_routing_data(notification);

    // §5.1 — the absolute unread count is an activity side channel.
    // Bucket it (0 / 1 / 2-5 / 6+) before it reaches the provider so it
    // can't be used to rebuild a cumulative per-`push_target_id`
    // activity profile. `bucket_count` also clamps below MAX_COUNT_VALUE.
    if let Some(unread) = notification.counts.unread {
        data.insert(
            "unread_count".to_owned(),
            serde_json::Value::Number(crate::sanitize::bucket_count(unread).into()),
        );
    }
    data
}

/// Generate a fresh random base64url collapse_key. Used by WebPush /
/// any provider that previously derived its collapse / topic from a
/// stable `realm_id` / `strand_id`. The blake2-of-scope-id form was
/// non-reversible but still acted as a stable per-conversation tag
/// that an observer could correlate across pushes; a per-message
/// random key removes that.
pub fn random_collapse_key() -> String {
    use base64::Engine;
    let bytes: [u8; 16] = uuid::Uuid::new_v4().into_bytes();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod sanitize_tests {
    use serde_json::json;

    use super::*;
    use crate::models::RoutingMetadata;

    #[test]
    fn sanitized_provider_payload_strips_event_id() {
        let payload = json!({
            "client": "android",
            "event_id": "ck:event:01JS0EV000000000000000000",
            "wakeup_kind": "message",
        })
        .as_object()
        .unwrap()
        .clone();
        let out = sanitized_provider_payload(payload).unwrap();
        assert!(!out.contains_key("event_id"));
        assert_eq!(out.get("client"), Some(&json!("android")));
    }

    #[test]
    fn sanitized_provider_payload_strips_audience_mention_expansion_metadata() {
        let payload = json!({
            "client": "android",
            "wakeup_kind": "mention",
            "audience": "strand_engaged",
            "audience_mentions": [{ "audience": "strand_watchers" }],
            "audience_mention_routing_hint": { "recipient_count": 2 },
            "recipient_count": 2,
        })
        .as_object()
        .unwrap()
        .clone();
        let out = sanitized_provider_payload(payload).unwrap();
        for forbidden in [
            "audience",
            "audience_mentions",
            "audience_mention_routing_hint",
            "recipient_count",
        ] {
            assert!(
                out.get(forbidden).is_none(),
                "audience mention expansion field `{forbidden}` survived sanitization"
            );
        }
        assert_eq!(out.get("wakeup_kind"), Some(&json!("mention")));
    }

    /// Round R2/R3 (T07/T10/T06) — the appeal / attestation / audit /
    /// policy-frontier-hash / trust-domain / reset-event-id field names
    /// added by rounds 2+3 MUST be stripped from any provider payload
    /// before it leaves floria. They are all stable correlators that
    /// would let an observer link the push back to a moderation appeal,
    /// audit agent, or cross-signing reset.
    #[test]
    fn sanitized_provider_payload_strips_forbidden_fields() {
        // We stage values that are safe (no `did:` / `ck:` literals)
        // so the sanitizer doesn't reject for `sensitive_literal`; the
        // only assertion is "key was removed from the output map".
        let payload = json!({
            "client": "android",
            "wakeup_kind": "message",
            "appeal_id": "01904100-0000-7000-8000-000000000001",
            "attestation_evidence": "evidence-blob-ref",
            "audit_purpose": "compliance_lawful_access",
            "attestation_chain": ["chain-item-0", "chain-item-1"],
            "audit_policy_version_digest": "a".repeat(64),
            "policy_frontier_digest": "b".repeat(64),
            "trust_domain": "example.net",
            "reset_event_id": "01904100-0000-7000-8000-000000000002",
        })
        .as_object()
        .unwrap()
        .clone();
        let out = sanitized_provider_payload(payload).unwrap();
        for forbidden in [
            "appeal_id",
            "attestation_evidence",
            "audit_purpose",
            "attestation_chain",
            "audit_policy_version_digest",
            "policy_frontier_digest",
            "trust_domain",
            "reset_event_id",
        ] {
            assert!(
                out.get(forbidden).is_none(),
                "round R2/R3 forbidden field `{forbidden}` survived sanitization"
            );
        }
        assert_eq!(out.get("client"), Some(&json!("android")));
        assert_eq!(out.get("wakeup_kind"), Some(&json!("message")));
    }

    /// Round R2/R3 — the same field names buried inside a nested object
    /// are also stripped by the recursive sweep.
    #[test]
    fn sanitized_provider_payload_strips_forbidden_fields_when_nested() {
        let payload = json!({
            "client": "ios",
            "wakeup_kind": "message",
            "nested": {
                "deep": {
                    "appeal_id": "01904100-0000-7000-8000-000000000001",
                    "trust_domain": "example.net",
                    "ok_key": "value"
                }
            }
        })
        .as_object()
        .unwrap()
        .clone();
        let out = sanitized_provider_payload(payload).unwrap();
        // Serialize back to JSON and assert none of the names survive.
        let encoded = serde_json::to_string(&out).unwrap();
        for forbidden in ["appeal_id", "trust_domain"] {
            assert!(
                !encoded.contains(forbidden),
                "nested round R2/R3 forbidden field `{forbidden}` survived: {encoded}"
            );
        }
        assert!(encoded.contains("ok_key"));
    }

    #[test]
    fn sanitized_provider_payload_rejects_did_literal() {
        let payload = json!({
            "client": "did:web:alice.example.com",
        })
        .as_object()
        .unwrap()
        .clone();
        let err = sanitized_provider_payload(payload).unwrap_err();
        assert_eq!(err.reason_code, "sensitive_literal");
    }

    #[test]
    fn build_blind_provider_data_keeps_only_allowed_fields() {
        let notification = Notification {
            strand_title: Some("Mission Control".to_owned()),
            realm_title: None,
            priority: None,
            membership: None,
            sender_actor_display_name: Some("Major Tom".to_owned()),
            content: None,
            event_id: Some("ck:event:01JS0EV000000000000000000".to_owned()),
            message_id: Some("ck:message:01JS0MSG0000000000000000".to_owned()),
            strand_id: Some("ck:strand:019640f9-8000-7000-8000-000000000000".to_owned()),
            routing_metadata: Some(RoutingMetadata {
                realm_id: Some("ck:realm:01JS0SP000000000000000000".to_owned()),
                ..Default::default()
            }),
            user_is_target: None,
            push_target_id: Some("ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            wakeup_kind: Some("message".to_owned()),
            push_hint: Some("new_message".to_owned()),
            devices: vec![],
            counts: crate::models::Counts {
                unread: Some(3),
                missed_calls: None,
                highlight_count: None,
            },
            ..Default::default()
        };
        let data = build_blind_provider_data(&notification);
        assert!(data.contains_key("push_target_id"));
        assert!(data.contains_key("wakeup_kind"));
        assert!(data.contains_key("push_hint"));
        assert!(data.contains_key("unread_count"));
        assert!(!data.contains_key("event_id"));
        assert!(!data.contains_key("sender"));
        assert!(!data.contains_key("strand_title"));
        assert!(!data.contains_key("strand_id"));
    }

    #[test]
    fn random_collapse_key_does_not_leak_scope() {
        let a = random_collapse_key();
        let b = random_collapse_key();
        assert_ne!(a, b);
        assert!(!a.contains("ck:"));
    }
}
