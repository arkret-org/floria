mod android;
mod apns;
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

#[async_trait]
pub trait Pushkin: Send + Sync {
    fn name(&self) -> &str;
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
        "gcm" | "fcm" => Ok(Arc::new(
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
