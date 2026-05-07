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
mod webpush;
mod xiaomi;

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, LazyLock};

use anyhow::{Result, anyhow, bail};
use async_trait::async_trait;
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
pub use webpush::WebpushPushkin;
pub use xiaomi::XiaomiPushkin;

pub const DEFAULT_INFLIGHT_REQUEST_LIMIT: usize = 512;
pub const DEFAULT_MAX_CONNECTIONS: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchTarget {
    pub app_id: String,
    pub pushkey: String,
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
    pub fn from_legacy(targets: &[DispatchTarget], rejected: Vec<String>) -> Self {
        let rejected_set: std::collections::HashSet<&str> =
            rejected.iter().map(String::as_str).collect();
        let accepted = targets
            .iter()
            .filter(|target| !rejected_set.contains(target.pushkey.as_str()))
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
            pushkey: device.pushkey.clone(),
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
        Ok(DispatchOutcome::from_legacy(&targets, rejected))
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

#[derive(Debug, Clone, Serialize)]
pub struct ProviderCapabilityDescriptor {
    /// Configured app name as known to the registry.
    pub name: String,
    #[serde(flatten)]
    pub capabilities: ProviderCapabilities,
}

#[derive(Clone)]
pub struct PushkinRegistry {
    pushkins: HashMap<String, Arc<dyn Pushkin>>,
}

impl PushkinRegistry {
    pub async fn from_config(config: &Config) -> Result<Self> {
        let base_dir = std::env::var("SOFLARE_CONF")
            .ok()
            .and_then(|path| {
                std::path::PathBuf::from(path)
                    .parent()
                    .map(Path::to_path_buf)
            })
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

        let mut pushkins = HashMap::<String, Arc<dyn Pushkin>>::new();
        for (name, app) in &config.apps {
            let pushkin = create_pushkin(name.clone(), app, config, &base_dir).await?;
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
                        capabilities,
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

async fn create_pushkin(
    name: String,
    app: &AppConfig,
    config: &Config,
    base_dir: &Path,
) -> Result<Arc<dyn Pushkin>> {
    match app.require_kind()? {
        "apns" => Ok(Arc::new(ApnsPushkin::new(name, app, config, base_dir)?)),
        "custom" => Ok(Arc::new(CustomPushkin::new(name, app, config, base_dir)?)),
        "fcm" => Ok(Arc::new(
            FcmPushkin::new(name, app, config, base_dir).await?,
        )),
        "honor" => Ok(Arc::new(HonorPushkin::new(name, app, config)?)),
        "huawei" => Ok(Arc::new(HuaweiPushkin::new(name, app, config)?)),
        "jpush" => Ok(Arc::new(JpushPushkin::new(name, app, config)?)),
        "oppo" => Ok(Arc::new(OppoPushkin::new(name, app, config)?)),
        "oneplus" => Ok(Arc::new(OppoPushkin::new_oneplus(name, app, config)?)),
        "vivo" => Ok(Arc::new(VivoPushkin::new(name, app, config)?)),
        "webpush" => Ok(Arc::new(WebpushPushkin::new(name, app, config, base_dir)?)),
        "xiaomi" => Ok(Arc::new(XiaomiPushkin::new(name, app, config)?)),
        other => bail!("unsupported pushkin type `{other}`"),
    }
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
