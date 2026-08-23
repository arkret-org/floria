use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_integration::{PushDeviceRoute, PushNotificationEnvelope};
use async_trait::async_trait;
use prometheus::{
    Histogram, IntGauge, register_histogram, register_int_counter_vec, register_int_gauge,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::Semaphore;
use tokio::time::sleep;

use super::android::{AndroidNotificationPayload, build_android_notification_payload};
use super::reqwest_support::{build_reqwest_client, parse_retry_after};
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{DeviceExt, NotificationContext};

static JPUSH_QUEUE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_jpush_queue_time",
        "Time taken waiting for a JPush request slot"
    )
    .expect("register floria_jpush_queue_time")
});

static JPUSH_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_jpush_request_time",
        "Time taken to send HTTP request to JPush"
    )
    .expect("register floria_jpush_request_time")
});

static JPUSH_PENDING_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_pending_jpush_requests",
        "Number of JPush requests waiting for a connection"
    )
    .expect("register floria_pending_jpush_requests")
});

static JPUSH_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_jpush_requests",
        "Number of JPush requests in flight"
    )
    .expect("register floria_active_jpush_requests")
});

static JPUSH_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_jpush_status_codes",
        "Number of HTTP response status codes received from JPush",
        &["pushkin", "code"]
    )
    .expect("register floria_jpush_status_codes")
});

static JPUSH_DISPATCH_BY_CHANNEL: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_jpush_dispatch_by_channel_total",
        "Per-third-party-channel JPush dispatch outcome (channels are joined alphabetically; `default` when no third_party_channel is configured)",
        &["pushkin", "channel_label", "outcome"]
    )
    .expect("register floria_jpush_dispatch_by_channel_total")
});

const JPUSH_URL: &str = "https://api.jpush.cn/v3/push";
const JPUSH_MAX_TRIES: usize = 3;
const JPUSH_RETRY_DELAY_BASE_SECS: u64 = 10;

pub struct JpushPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: Client,
    authorization: HeaderValue,
    config: JpushConfig,
    /// Stable label that tracks the configured third_party_channel
    /// vendors (alphabetically joined; `default` when no channel is
    /// configured). Used both for retry log fields and for the
    /// `floria_jpush_dispatch_by_channel_total` metric so operators
    /// can see how each channel mix is performing.
    channel_label: String,
}

#[derive(Debug, Clone)]
struct JpushConfig {
    platforms: Vec<String>,
    time_to_live: Option<u64>,
    apns_production: Option<bool>,
    builder_id: Option<u64>,
    large_icon: Option<String>,
    intent: Option<String>,
    uri_activity: Option<String>,
    options: Map<String, Value>,
    android_notification: Map<String, Value>,
    hmos_notification: Map<String, Value>,
    third_party_channel: Option<Map<String, Value>>,
    send_badge_counts: bool,
}

impl JpushPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "app_key",
                "master_secret",
                "platforms",
                "time_to_live",
                "apns_production",
                "builder_id",
                "large_icon",
                "intent",
                "uri_activity",
                "options",
                "android_notification",
                "hmos_notification",
                "third_party_channel",
                "send_badge_counts",
                "max_connections",
                "inflight_request_limit",
            ],
        );

        let app_key = app
            .get_string("app_key")?
            .context("JPush config requires app_key")?;
        let master_secret = app
            .get_string("master_secret")?
            .context("JPush config requires master_secret")?;
        let platforms = parse_platforms(app.get_string_list("platforms")?)?;
        let authorization = basic_authorization(&app_key, &master_secret)?;
        let matcher = AppMatcher::new(name)?;
        let gate = ConcurrencyGate::new(inflight_limit(app)?);
        let connection_semaphore = Arc::new(Semaphore::new(max_connections(app)?.max(1)));
        let client = build_reqwest_client(config, "floria")?;
        let third_party_channel = app
            .get_object("third_party_channel")?
            .map(validate_third_party_channel)
            .transpose()?;

        let channel_label = third_party_channel
            .as_ref()
            .map(|channel| {
                let mut vendors = channel.keys().cloned().collect::<Vec<_>>();
                vendors.sort_unstable();
                if vendors.is_empty() {
                    "default".to_owned()
                } else {
                    vendors.join("+")
                }
            })
            .unwrap_or_else(|| "default".to_owned());

        Ok(Self {
            matcher,
            gate,
            connection_semaphore,
            client,
            authorization,
            config: JpushConfig {
                platforms,
                time_to_live: app.get_u64("time_to_live")?,
                apns_production: app.get_bool("apns_production")?,
                builder_id: app.get_u64("builder_id")?,
                large_icon: app.get_string("large_icon")?,
                intent: app.get_string("intent")?,
                uri_activity: app.get_string("uri_activity")?,
                options: app.get_object("options")?.unwrap_or_default(),
                android_notification: app.get_object("android_notification")?.unwrap_or_default(),
                hmos_notification: app.get_object("hmos_notification")?.unwrap_or_default(),
                third_party_channel,
                send_badge_counts: app.get_bool("send_badge_counts")?.unwrap_or(true),
            },
            channel_label,
        })
    }

    pub fn channel_label(&self) -> &str {
        &self.channel_label
    }

    fn build_request_body(
        &self,
        notification: &PushNotificationEnvelope,
        device: &PushDeviceRoute,
        payload: AndroidNotificationPayload,
    ) -> Map<String, Value> {
        let mut body = Map::new();
        body.insert(
            "platform".to_owned(),
            Value::Array(
                self.config
                    .platforms
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
        body.insert(
            "audience".to_owned(),
            json!({ "registration_id": [device.push_key().unwrap_or_default()] }),
        );

        if let Some(alert) = payload.body.as_ref() {
            let mut notification_object = Map::new();
            notification_object.insert("alert".to_owned(), Value::String(alert.clone()));
            if self
                .config
                .platforms
                .iter()
                .any(|platform| platform == "android")
            {
                notification_object.insert(
                    "android".to_owned(),
                    Value::Object(self.android_notification(&payload)),
                );
            }
            if self
                .config
                .platforms
                .iter()
                .any(|platform| platform == "hmos")
            {
                notification_object.insert(
                    "hmos".to_owned(),
                    Value::Object(self.hmos_notification(&payload)),
                );
            }
            body.insert(
                "notification".to_owned(),
                Value::Object(notification_object),
            );
        } else {
            body.insert(
                "message".to_owned(),
                json!({
                    "msg_content": "blind_wakeup",
                    "extras": jpush_extras(&payload.data),
                }),
            );
        }

        let options = self.options(notification);
        if !options.is_empty() {
            body.insert("options".to_owned(), Value::Object(options));
        }
        if let Some(third_party_channel) = &self.config.third_party_channel {
            body.insert(
                "third_party_channel".to_owned(),
                Value::Object(third_party_channel.clone()),
            );
        }

        body
    }

    fn android_notification(&self, payload: &AndroidNotificationPayload) -> Map<String, Value> {
        let mut android = self.config.android_notification.clone();
        if let Some(title) = &payload.title {
            android.insert("title".to_owned(), Value::String(title.clone()));
        }
        if let Some(body) = &payload.body {
            android.insert("alert".to_owned(), Value::String(body.clone()));
        }
        android.insert(
            "extras".to_owned(),
            Value::Object(jpush_extras(&payload.data)),
        );

        if let Some(builder_id) = self.config.builder_id {
            android.insert("builder_id".to_owned(), Value::Number(builder_id.into()));
        }
        if let Some(large_icon) = &self.config.large_icon {
            android.insert("large_icon".to_owned(), Value::String(large_icon.clone()));
        }
        if let Some(intent) = &self.config.intent {
            android.insert("intent".to_owned(), Value::String(intent.clone()));
        }
        if let Some(uri_activity) = &self.config.uri_activity {
            android.insert(
                "uri_activity".to_owned(),
                Value::String(uri_activity.clone()),
            );
        }

        android
    }

    fn hmos_notification(&self, payload: &AndroidNotificationPayload) -> Map<String, Value> {
        let mut hmos = self.config.hmos_notification.clone();
        if let Some(title) = &payload.title {
            hmos.insert("title".to_owned(), Value::String(title.clone()));
        }
        hmos.insert(
            "extras".to_owned(),
            Value::Object(jpush_extras(&payload.data)),
        );
        hmos
    }

    fn options(&self, payload: &PushNotificationEnvelope) -> Map<String, Value> {
        let mut options = self.config.options.clone();
        if let Some(time_to_live) = self.config.time_to_live {
            options.insert(
                "time_to_live".to_owned(),
                Value::Number(time_to_live.into()),
            );
        }
        if let Some(apns_production) = self.config.apns_production {
            options.insert("apns_production".to_owned(), Value::Bool(apns_production));
        }
        options.insert(
            "priority".to_owned(),
            Value::Number(
                match payload.priority.as_deref() {
                    Some("low") => 0_u64,
                    _ => 1_u64,
                }
                .into(),
            ),
        );
        options
    }

    async fn send_once(
        &self,
        notification: &PushNotificationEnvelope,
        device: &PushDeviceRoute,
        payload: AndroidNotificationPayload,
    ) -> Result<Vec<String>, DispatchError> {
        let body = self.build_request_body(notification, device, payload);

        JPUSH_PENDING_REQUESTS.inc();
        let queue_started = Instant::now();
        let _connection_permit = self
            .connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                JPUSH_PENDING_REQUESTS.dec();
                DispatchError::internal("JPush connection semaphore closed")
            })?;
        JPUSH_PENDING_REQUESTS.dec();
        JPUSH_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.authorization.clone());
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        JPUSH_ACTIVE_REQUESTS.inc();
        let request_started = Instant::now();
        let response = self
            .client
            .post(JPUSH_URL)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                JPUSH_ACTIVE_REQUESTS.dec();
                JPUSH_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                DispatchError::temporary(format!("JPush request failed: {error}"), None)
            })?;
        JPUSH_ACTIVE_REQUESTS.dec();
        JPUSH_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());

        let status = response.status();
        JPUSH_STATUS_CODES
            .with_label_values(&[self.name(), &status.as_u16().to_string()])
            .inc();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read JPush response: {error}"))
        })?;
        self.handle_response(status, retry_after, &body, device)
    }

    fn handle_response(
        &self,
        status: StatusCode,
        retry_after: Option<Duration>,
        body: &str,
        device: &PushDeviceRoute,
    ) -> Result<Vec<String>, DispatchError> {
        match status.as_u16() {
            200..=299 => Ok(vec![]),
            429 => Err(DispatchError::temporary(
                jpush_error_message(body, status),
                retry_after.or(Some(Duration::from_secs(JPUSH_RETRY_DELAY_BASE_SECS))),
            )),
            500..=599 => Err(DispatchError::temporary(
                jpush_error_message(body, status),
                retry_after,
            )),
            400 if body.contains("registration_id") && body.contains("invalid") => {
                Ok(vec![device.push_key().unwrap_or_default().to_owned()])
            }
            _ => Err(DispatchError::remote(jpush_error_message(body, status))),
        }
    }
}

#[async_trait]
impl Pushkin for JpushPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        "jpush"
    }

    fn handles_app_id(&self, app_id: &str) -> bool {
        self.matcher.handles_app_id(app_id)
    }

    async fn dispatch_notification(
        &self,
        notification: &PushNotificationEnvelope,
        device: &PushDeviceRoute,
        context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        let _permit = self.gate.acquire(self.name())?;

        if device.push_key().is_none() {
            tracing::warn!("rejecting JPush device due to empty registration_id");
            return Ok(vec![device.push_key().unwrap_or_default().to_owned()]);
        }

        let Some(payload) = build_android_notification_payload(
            notification,
            Map::new(),
            context.allow_plaintext_metadata && device.visible_notification_opt_in(),
            self.config.send_badge_counts,
        ) else {
            return Ok(vec![]);
        };

        for attempt in 0..JPUSH_MAX_TRIES {
            let result = self.send_once(notification, device, payload.clone()).await;
            let outcome = match &result {
                Ok(rejected) if rejected.is_empty() => "accepted",
                Ok(_) => "partial",
                Err(error) if error.is_temporary() => "retryable",
                Err(error) if error.is_remote() => "remote_error",
                Err(_) => "internal_error",
            };
            JPUSH_DISPATCH_BY_CHANNEL
                .with_label_values(&[self.name(), self.channel_label(), outcome])
                .inc();
            match result {
                Ok(result) => return Ok(result),
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < JPUSH_MAX_TRIES => {
                    // Channels with stricter rate limits (huawei,
                    // xiaomi) historically need longer waits; bump
                    // the base when they are configured. operators
                    // can disable this by setting third_party_channel
                    // to the looser vendors only.
                    let stricter =
                        self.config
                            .third_party_channel
                            .as_ref()
                            .is_some_and(|channel| {
                                channel.contains_key("huawei") || channel.contains_key("xiaomi")
                            });
                    let multiplier = if stricter { 2 } else { 1 };
                    let retry_after = error.retry_after().unwrap_or_else(|| {
                        Duration::from_secs(
                            JPUSH_RETRY_DELAY_BASE_SECS * multiplier * (1_u64 << attempt),
                        )
                    });
                    tracing::warn!(
                        pushkin = %self.name(),
                        channel = %self.channel_label(),
                        attempt = attempt + 1,
                        retry_after_secs = retry_after.as_secs(),
                        "JPush temporary failure; backing off before retry"
                    );
                    sleep(retry_after).await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(DispatchError::remote("JPush retried too many times"))
    }
}

fn parse_platforms(platforms: Option<Vec<String>>) -> Result<Vec<String>> {
    let platforms = platforms.unwrap_or_else(|| vec!["android".to_owned()]);
    if platforms.is_empty() {
        bail!("JPush platforms must contain at least one platform");
    }

    let supported = ["android", "hmos"];
    for platform in &platforms {
        if !supported.contains(&platform.as_str()) {
            bail!(
                "unsupported JPush platform `{platform}`; supported values are {:?}",
                supported
            );
        }
    }

    Ok(platforms)
}

fn basic_authorization(app_key: &str, master_secret: &str) -> Result<HeaderValue> {
    let credentials = format!("{app_key}:{master_secret}");
    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        credentials.as_bytes(),
    );
    HeaderValue::from_str(&format!("Basic {encoded}"))
        .map_err(|error| anyhow!("invalid JPush authorization header: {error}"))
}

fn validate_third_party_channel(mut channel: Map<String, Value>) -> Result<Map<String, Value>> {
    let supported = [
        "xiaomi", "huawei", "oppo", "vivo", "honor", "hmos", "meizu", "fcm",
    ];
    for (vendor, value) in &channel {
        if !supported.contains(&vendor.as_str()) {
            bail!("unsupported JPush third_party_channel vendor `{vendor}`");
        }
        let Some(object) = value.as_object() else {
            bail!("JPush third_party_channel.{vendor} must be an object");
        };
        if let Some(distribution) = object.get("distribution")
            && !distribution.is_string()
        {
            bail!("JPush third_party_channel.{vendor}.distribution must be a string");
        }
    }

    if let Some(Value::Object(hmos)) = channel.get_mut("hmos")
        && (hmos.len() > 1 || hmos.get("distribution").is_none())
    {
        tracing::warn!(
            "JPush third_party_channel.hmos officially only supports the distribution field"
        );
    }

    Ok(channel)
}

fn jpush_extras(data: &Map<String, Value>) -> Map<String, Value> {
    data.iter()
        .filter_map(|(key, value)| match value {
            Value::Null => None,
            Value::Bool(_) | Value::Number(_) | Value::String(_) => {
                Some((key.clone(), value.clone()))
            }
            Value::Array(_) | Value::Object(_) => Some((
                key.clone(),
                Value::String(serde_json::to_string(value).unwrap_or_default()),
            )),
        })
        .collect()
}

fn jpush_error_message(body: &str, status: StatusCode) -> String {
    serde_json::from_str::<JpushErrorResponse>(body)
        .ok()
        .map(|response| {
            format!(
                "JPush rejected request: {} {}",
                response.error.code, response.error.message
            )
        })
        .unwrap_or_else(|| format!("JPush rejected request: {status} {body}"))
}

#[derive(Debug, Deserialize)]
struct JpushErrorResponse {
    error: JpushErrorBody,
}

#[derive(Debug, Deserialize)]
struct JpushErrorBody {
    code: i64,
    message: String,
}

#[cfg(test)]
mod tests {
    use arkret_models_integration::{
        PushCounts, PushDeviceRoute, PushNotificationEnvelope, PushRouteTokens,
    };

    use super::*;

    fn device() -> PushDeviceRoute {
        PushDeviceRoute {
            device_id: arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            app_id: Some("com.example.jpush".to_owned()),
            push_key: Some(arkret_models_integration::PushKey::new("regid").unwrap()),
            platform: None,
            target_route_token: None,
            visible_notification_opt_in: false,
        }
    }

    fn notification() -> PushNotificationEnvelope {
        PushNotificationEnvelope {
            strand_title: Some("Mission Control".to_owned()),
            realm_title: None,
            priority: None,
            membership: None,
            sender_actor_display_name: Some("Major Tom".to_owned()),
            event_id: Some(
                arkret_wire::EventId::new("ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS")
                    .unwrap(),
            ),
            message_id: Some(
                arkret_wire::MessageId::new(
                    "ak:message:AevYtAp_mjd9pPNtsNoiquL8rnoJUC0S0gYtV6_SwmD1",
                )
                .unwrap(),
            ),
            strand_id: Some(
                arkret_wire::StrandId::new(
                    "ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD",
                )
                .unwrap(),
            ),
            route_tokens: Some(PushRouteTokens {
                realm_route_token: Some(
                    arkret_models_integration::PushRouteToken::new("realm_route_token_000000001")
                        .unwrap(),
                ),
                ..Default::default()
            }),
            user_is_target: Some(true),
            push_target_id: Some(
                arkret_wire::PushTargetId::new(
                    "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                )
                .unwrap(),
            ),
            wakeup_kind: Some("message".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Some(PushCounts {
                badge: Some(arkret_models_integration::PushCountIndicator::Bucket(
                    "2-5".to_owned(),
                )),
                unread_increment: Some(2),
                missed_call: Some(arkret_models_integration::PushCountIndicator::Present(true)),
            }),
            ..Default::default()
        }
    }

    fn pushkin() -> JpushPushkin {
        JpushPushkin {
            matcher: AppMatcher::new("com.example.jpush".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client: Client::builder().build().unwrap(),
            authorization: HeaderValue::from_static("Basic abc"),
            config: JpushConfig {
                platforms: vec!["android".to_owned()],
                time_to_live: Some(3600),
                apns_production: Some(true),
                builder_id: Some(1),
                large_icon: Some("https://example.com/icon.png".to_owned()),
                intent: Some("intent:#Intent;end".to_owned()),
                uri_activity: None,
                options: Map::new(),
                android_notification: Map::new(),
                hmos_notification: Map::new(),
                third_party_channel: Some(
                    json!({
                        "xiaomi": {
                            "distribution": "jpush"
                        },
                        "vivo": {
                            "distribution": "jpush",
                            "classification": 0
                        }
                    })
                    .as_object()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .collect(),
                ),
                send_badge_counts: true,
            },
            channel_label: "vivo+xiaomi".to_owned(),
        }
    }

    #[test]
    fn builds_request_body_with_extras_and_third_party_channel() {
        let device = device();
        let payload =
            build_android_notification_payload(&notification(), Map::new(), true, true).unwrap();
        let body = pushkin().build_request_body(&notification(), &device, payload);
        let body = Value::Object(body);

        assert_eq!(
            body.get("audience"),
            Some(&json!({ "registration_id": ["regid"] }))
        );
        assert_eq!(
            body.pointer("/notification/android/title"),
            Some(&Value::String("Mission Control".to_owned()))
        );
        assert!(
            body.pointer("/notification/android/extras/client")
                .is_none()
        );
        assert_eq!(
            body.pointer("/third_party_channel/vivo/classification"),
            Some(&Value::Number(0.into()))
        );
        assert_eq!(
            body.pointer("/options/time_to_live"),
            Some(&Value::Number(3600.into()))
        );
    }

    #[test]
    fn invalid_registration_response_rejects_push_key() {
        let result = pushkin()
            .handle_response(
                StatusCode::BAD_REQUEST,
                None,
                r#"{"error":{"code":1008,"message":"invalid registration_id"}}"#,
                &device(),
            )
            .unwrap();

        assert_eq!(result, vec!["regid".to_owned()]);
    }

    #[test]
    fn hmos_validation_warns_only_distribution() {
        let channel = validate_third_party_channel(
            json!({
                "hmos": {
                    "distribution": "jpush"
                }
            })
            .as_object()
            .unwrap()
            .clone()
            .into_iter()
            .collect(),
        )
        .unwrap();
        let channel = Value::Object(channel);
        assert_eq!(
            channel.pointer("/hmos/distribution"),
            Some(&Value::String("jpush".to_owned()))
        );
    }
}
