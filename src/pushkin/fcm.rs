use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use prometheus::{
    Histogram, IntGauge, register_histogram, register_int_counter_vec, register_int_gauge,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;

use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext};

use super::reqwest_support::{header_value, parse_retry_after};
use super::{
    AppMatcher, ConcurrencyGate, DispatchTarget, Pushkin, inflight_limit, max_connections,
    truncate_str,
};

static GCM_QUEUE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_gcm_queue_time",
        "Time taken waiting for a connection to GCM"
    )
    .expect("register floria_gcm_queue_time")
});

static GCM_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_gcm_request_time",
        "Time taken to send HTTP request to GCM"
    )
    .expect("register floria_gcm_request_time")
});

static GCM_PENDING_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_pending_gcm_requests",
        "Number of GCM requests waiting for a connection"
    )
    .expect("register floria_pending_gcm_requests")
});

static GCM_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_gcm_requests",
        "Number of GCM requests in flight"
    )
    .expect("register floria_active_gcm_requests")
});

static GCM_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_gcm_status_codes",
        "Number of HTTP response status codes received from GCM",
        &["pushkin", "code"]
    )
    .expect("register floria_gcm_status_codes")
});

const FCM_MAX_TRIES: usize = 3;
const FCM_RETRY_DELAY_BASE_SECS: u64 = 10;
const FCM_RETRY_DELAY_QUOTA_SECS: u64 = 60;
const FCM_MAX_BYTES_PER_FIELD: usize = 1024;
const FCM_MAX_FIREBASE_MESSAGE_SIZE: usize = 4096;
const FCM_MAX_OVERFLOW_FIELDS: usize = FCM_MAX_FIREBASE_MESSAGE_SIZE / FCM_MAX_BYTES_PER_FIELD - 1;
const FCM_URL_LEGACY: &str = "https://fcm.googleapis.com/fcm/send";
const GOOGLE_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

pub struct FcmPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: Client,
    api_version: ApiVersion,
    auth: FcmAuth,
    base_request_body: Map<String, Value>,
    send_badge_counts: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiVersion {
    Legacy,
    V1,
}

enum FcmAuth {
    Legacy {
        api_key: String,
    },
    V1 {
        project_id: String,
        service_account: ServiceAccountSigner,
    },
}

struct ServiceAccountSigner {
    client_email: String,
    private_key: EncodingKey,
    token_uri: String,
    cache: Mutex<Option<CachedAccessToken>>,
}

struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

struct LegacyDispatchOutcome {
    rejected: Vec<String>,
    retry_pushkeys: Vec<String>,
}

impl FcmPushkin {
    pub async fn new(
        name: String,
        app: &AppConfig,
        config: &Config,
        base_dir: &Path,
    ) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "api_key",
                "api_version",
                "fcm_options",
                "max_connections",
                "project_id",
                "service_account_file",
                "send_badge_counts",
                "inflight_request_limit",
            ],
        );
        let matcher = AppMatcher::new(name)?;
        let gate = ConcurrencyGate::new(inflight_limit(app)?);
        let connection_semaphore = Arc::new(Semaphore::new(max_connections(app)?.max(1)));
        let api_version = match app.get_string("api_version")?.as_deref() {
            Some("v1") => ApiVersion::V1,
            Some("legacy") | None => ApiVersion::Legacy,
            Some(other) => bail!("invalid FCM api_version `{other}`"),
        };
        let send_badge_counts = app.get_bool("send_badge_counts")?.unwrap_or(true);
        let base_request_body = app.get_object("fcm_options")?.unwrap_or_default();

        let mut client_builder = Client::builder().user_agent("floria");
        if let Some(proxy) = config.outbound_proxy() {
            client_builder = client_builder
                .proxy(Proxy::all(proxy).with_context(|| format!("invalid proxy URL `{proxy}`"))?);
        }
        let client = client_builder
            .build()
            .context("failed to build FCM client")?;

        let auth = match api_version {
            ApiVersion::Legacy => {
                let api_key = app
                    .get_string("api_key")?
                    .context("legacy FCM config requires api_key")?;
                FcmAuth::Legacy { api_key }
            }
            ApiVersion::V1 => {
                let project_id = app
                    .get_string("project_id")?
                    .context("FCM v1 config requires project_id")?;
                let service_account_file = app
                    .require_existing_file(base_dir, "service_account_file")?
                    .context("FCM v1 config requires service_account_file")?;
                let content =
                    std::fs::read_to_string(&service_account_file).with_context(|| {
                        format!("failed to read {}", service_account_file.display())
                    })?;
                let key: ServiceAccountKey =
                    serde_json::from_str(&content).context("invalid service account JSON")?;
                let private_key = EncodingKey::from_rsa_pem(key.private_key.as_bytes())
                    .context("invalid service account private key")?;
                FcmAuth::V1 {
                    project_id,
                    service_account: ServiceAccountSigner {
                        client_email: key.client_email,
                        private_key,
                        token_uri: key.token_uri,
                        cache: Mutex::new(None),
                    },
                }
            }
        };

        Ok(Self {
            matcher,
            gate,
            connection_semaphore,
            client,
            api_version,
            auth,
            base_request_body,
            send_badge_counts,
        })
    }

    async fn dispatch_legacy(
        &self,
        notification: &Notification,
        pushkeys: Vec<String>,
        data: Map<String, Value>,
    ) -> Result<Vec<String>, DispatchError> {
        let FcmAuth::Legacy { api_key } = &self.auth else {
            return Err(DispatchError::internal("invalid FCM auth configuration"));
        };

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, header_value(&format!("key={api_key}"))?);
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let mut rejected = Vec::new();
        let mut pending_pushkeys = pushkeys;

        for attempt in 0..FCM_MAX_TRIES {
            let body = self.build_legacy_request_body(notification, &pending_pushkeys, &data);
            GCM_PENDING_REQUESTS.inc();
            let queue_started = Instant::now();
            let _connection_permit = self
                .connection_semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| {
                    GCM_PENDING_REQUESTS.dec();
                    DispatchError::internal("FCM connection semaphore closed")
                })?;
            GCM_PENDING_REQUESTS.dec();
            GCM_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

            GCM_ACTIVE_REQUESTS.inc();
            let request_started = Instant::now();
            let response = self
                .client
                .post(FCM_URL_LEGACY)
                .headers(headers.clone())
                .json(&body)
                .send()
                .await
                .map_err(|error| {
                    GCM_ACTIVE_REQUESTS.dec();
                    GCM_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                    DispatchError::temporary(format!("FCM legacy request failed: {error}"), None)
                });

            match response {
                Ok(response) => {
                    GCM_ACTIVE_REQUESTS.dec();
                    GCM_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                    GCM_STATUS_CODES
                        .with_label_values(&[self.name(), &response.status().as_u16().to_string()])
                        .inc();
                    match self
                        .handle_legacy_response(response, &pending_pushkeys)
                        .await
                    {
                        Ok(outcome) => {
                            rejected.extend(outcome.rejected);
                            if outcome.retry_pushkeys.is_empty() {
                                return Ok(rejected);
                            }
                            if attempt + 1 >= FCM_MAX_TRIES {
                                tracing::info!(
                                    pushkin = self.name(),
                                    retry_pushkey_hashes =
                                        ?crate::models::redact_push_tokens(&outcome.retry_pushkeys),
                                    "giving up retrying individual legacy FCM pushkeys"
                                );
                                return Ok(rejected);
                            }
                            pending_pushkeys = outcome.retry_pushkeys;
                        }
                        Err(error @ DispatchError::Temporary { .. })
                            if attempt + 1 < FCM_MAX_TRIES =>
                        {
                            let retry_after = error.retry_after().unwrap_or_else(|| {
                                Duration::from_secs(FCM_RETRY_DELAY_BASE_SECS * (1_u64 << attempt))
                            });
                            sleep(retry_after).await;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < FCM_MAX_TRIES => {
                    let retry_after = error.retry_after().unwrap_or_else(|| {
                        Duration::from_secs(FCM_RETRY_DELAY_BASE_SECS * (1_u64 << attempt))
                    });
                    sleep(retry_after).await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(DispatchError::remote("FCM legacy retried too many times"))
    }

    async fn dispatch_v1(
        &self,
        notification: &Notification,
        device: &Device,
        data: Map<String, Value>,
    ) -> Result<Vec<String>, DispatchError> {
        let FcmAuth::V1 {
            project_id,
            service_account,
        } = &self.auth
        else {
            return Err(DispatchError::internal("invalid FCM auth configuration"));
        };

        let token = service_account.access_token(&self.client).await?;
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, header_value(&format!("Bearer {token}"))?);
        headers.insert("content-type", HeaderValue::from_static("application/json"));

        let mut message = self.base_request_body.clone();
        let mut data_strings = Map::new();
        for (key, value) in data {
            let string_value = match value {
                Value::String(value) => value,
                other => serde_json::to_string(&other).map_err(|error| {
                    DispatchError::internal(format!("failed to serialize FCM v1 value: {error}"))
                })?,
            };
            data_strings.insert(key, Value::String(string_value));
        }
        message.insert("data".to_owned(), Value::Object(data_strings));
        message.insert("token".to_owned(), Value::String(device.pushkey.clone()));

        let priority = Value::String(if notification.prio.as_deref() == Some("low") {
            "normal".to_owned()
        } else {
            "high".to_owned()
        });
        if let Some(android) = message.get_mut("android").and_then(Value::as_object_mut) {
            android.insert("priority".to_owned(), priority);
        } else {
            message.insert("android".to_owned(), json!({ "priority": priority }));
        }

        let body = json!({ "message": message });
        let url = format!("https://fcm.googleapis.com/v1/projects/{project_id}/messages:send");

        for attempt in 0..FCM_MAX_TRIES {
            GCM_PENDING_REQUESTS.inc();
            let queue_started = Instant::now();
            let _connection_permit = self
                .connection_semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| {
                    GCM_PENDING_REQUESTS.dec();
                    DispatchError::internal("FCM connection semaphore closed")
                })?;
            GCM_PENDING_REQUESTS.dec();
            GCM_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

            GCM_ACTIVE_REQUESTS.inc();
            let request_started = Instant::now();
            let response = self
                .client
                .post(&url)
                .headers(headers.clone())
                .json(&body)
                .send()
                .await
                .map_err(|error| {
                    GCM_ACTIVE_REQUESTS.dec();
                    GCM_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                    DispatchError::temporary(format!("FCM v1 request failed: {error}"), None)
                });

            match response {
                Ok(response) => {
                    GCM_ACTIVE_REQUESTS.dec();
                    GCM_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                    GCM_STATUS_CODES
                        .with_label_values(&[self.name(), &response.status().as_u16().to_string()])
                        .inc();
                    match self.handle_v1_response(response, &device.pushkey).await {
                        Ok(result) => return Ok(result),
                        Err(error @ DispatchError::Temporary { .. })
                            if attempt + 1 < FCM_MAX_TRIES =>
                        {
                            let fallback =
                                Duration::from_secs(FCM_RETRY_DELAY_BASE_SECS * (1_u64 << attempt));
                            sleep(error.retry_after().unwrap_or(fallback)).await;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < FCM_MAX_TRIES => {
                    let fallback =
                        Duration::from_secs(FCM_RETRY_DELAY_BASE_SECS * (1_u64 << attempt));
                    sleep(error.retry_after().unwrap_or(fallback)).await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(DispatchError::remote("FCM v1 retried too many times"))
    }

    async fn handle_legacy_response(
        &self,
        response: reqwest::Response,
        pushkeys: &[String],
    ) -> Result<LegacyDispatchOutcome, DispatchError> {
        let status = response.status();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read FCM response: {error}"))
        })?;

        match status.as_u16() {
            500..=599 => Err(DispatchError::temporary(
                format!("FCM server error: {status}"),
                retry_after,
            )),
            400 => Err(DispatchError::remote(format!(
                "invalid FCM request: {body}"
            ))),
            401 => Err(DispatchError::remote(format!(
                "FCM authorization failed: {body}"
            ))),
            429 => Err(DispatchError::temporary(
                "FCM message quota exceeded".to_owned(),
                retry_after.or(Some(Duration::from_secs(FCM_RETRY_DELAY_QUOTA_SECS))),
            )),
            404 => Ok(LegacyDispatchOutcome {
                rejected: pushkeys.to_vec(),
                retry_pushkeys: vec![],
            }),
            200..=299 => {
                let parsed: LegacyFcmResponse = serde_json::from_str(&body)
                    .map_err(|error| DispatchError::remote(format!("invalid FCM JSON: {error}")))?;

                if parsed.results.len() < pushkeys.len() {
                    tracing::error!(
                        pushkin = self.name(),
                        sent = pushkeys.len(),
                        received = parsed.results.len(),
                        "sent {} notifications but only got {} results",
                        pushkeys.len(),
                        parsed.results.len()
                    );
                }

                let mut rejected = Vec::new();
                let mut retry_pushkeys = Vec::new();

                for (pushkey, result) in pushkeys.iter().zip(parsed.results) {
                    match result.error {
                        Some(error) if is_bad_pushkey_error(&error) => {
                            rejected.push(pushkey.clone());
                        }
                        Some(error) if is_bad_message_error(&error) => {}
                        Some(_) => retry_pushkeys.push(pushkey.clone()),
                        None => {}
                    }
                }

                if !retry_pushkeys.is_empty() && retry_after.is_some() {
                    return Err(DispatchError::temporary(
                        "FCM temporary device failure".to_owned(),
                        retry_after,
                    ));
                }

                Ok(LegacyDispatchOutcome {
                    rejected,
                    retry_pushkeys,
                })
            }
            _ => Err(DispatchError::remote(format!(
                "unexpected FCM status: {status}"
            ))),
        }
    }

    async fn handle_v1_response(
        &self,
        response: reqwest::Response,
        pushkey: &str,
    ) -> Result<Vec<String>, DispatchError> {
        let status = response.status();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read FCM response: {error}"))
        })?;

        match status.as_u16() {
            500..=599 => Err(DispatchError::temporary(
                format!("FCM server error: {status}"),
                retry_after,
            )),
            400 => Err(DispatchError::remote(format!(
                "invalid FCM v1 request: {body}"
            ))),
            401 => Err(DispatchError::remote(format!(
                "FCM v1 authorization failed: {body}"
            ))),
            403 => Err(DispatchError::remote(format!(
                "FCM sender mismatch: {body}"
            ))),
            404 => Ok(vec![pushkey.to_owned()]),
            429 => Err(DispatchError::temporary(
                "FCM message quota exceeded".to_owned(),
                retry_after.or(Some(Duration::from_secs(FCM_RETRY_DELAY_QUOTA_SECS))),
            )),
            200..=299 => Ok(vec![]),
            _ => Err(DispatchError::remote(format!(
                "unexpected FCM v1 status: {status}"
            ))),
        }
    }

    fn build_data(
        &self,
        notification: &Notification,
        default_payload: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, DispatchError> {
        let mut data = default_payload;
        let mut overflow_fields: usize = 0;

        for (attr, value) in [
            ("event_id", notification.event_id.as_deref()),
            ("type", notification.event_kind()),
            ("sender", notification.sender.as_deref()),
            ("space_name", notification.scope_name()),
            ("room_name", notification.scope_name()),
            ("room_alias", notification.room_alias.as_deref()),
            ("membership", notification.membership.as_deref()),
            (
                "sender_display_name",
                notification.sender_display_name.as_deref(),
            ),
            ("space_id", notification.scope_id()),
            ("room_id", notification.scope_id()),
            ("push_hint", notification.push_hint.as_deref()),
        ] {
            if let Some(value) = value {
                let (value, truncated) = truncate_str(value, FCM_MAX_BYTES_PER_FIELD);
                if truncated {
                    overflow_fields += 1;
                }
                data.insert(attr.to_owned(), Value::String(value));
            }
        }

        if let Some(content) = &notification.content {
            if self.api_version == ApiVersion::V1 {
                for (key, value) in content {
                    let string_value = if let Some(s) = value.as_str() {
                        s.to_owned()
                    } else {
                        serde_json::to_string(value).unwrap_or_default()
                    };
                    let (string_value, truncated) =
                        truncate_str(&string_value, FCM_MAX_BYTES_PER_FIELD);
                    if truncated {
                        overflow_fields += 1;
                    }
                    data.insert(format!("content_{key}"), Value::String(string_value));
                }
            } else {
                data.insert("content".to_owned(), Value::Object(content.clone()));
            }
        }

        data.insert(
            "prio".to_owned(),
            Value::String(if notification.prio.as_deref() == Some("low") {
                "normal".to_owned()
            } else {
                "high".to_owned()
            }),
        );

        let mut counts = Map::new();
        if self.send_badge_counts {
            if let Some(unread) = notification.counts.unread
                && unread > 0
            {
                counts.insert(
                    "unread".to_owned(),
                    if self.api_version == ApiVersion::V1 {
                        Value::String(unread.to_string())
                    } else {
                        Value::Number(unread.into())
                    },
                );
            }
            if let Some(missed_calls) = notification.counts.missed_calls
                && missed_calls > 0
            {
                counts.insert(
                    "missed_calls".to_owned(),
                    if self.api_version == ApiVersion::V1 {
                        Value::String(missed_calls.to_string())
                    } else {
                        Value::Number(missed_calls.into())
                    },
                );
            }
            if let Some(highlight_count) = notification.counts.highlight_count
                && highlight_count > 0
            {
                counts.insert(
                    "highlight_count".to_owned(),
                    if self.api_version == ApiVersion::V1 {
                        Value::String(highlight_count.to_string())
                    } else {
                        Value::Number(highlight_count.into())
                    },
                );
            }
        }

        let has_routable_context = data.contains_key("space_id")
            || data.contains_key("room_id")
            || data.contains_key("event_id")
            || data.contains_key("push_hint");
        if !has_routable_context && counts.is_empty() {
            return Ok(None);
        }

        data.extend(counts);

        if overflow_fields > FCM_MAX_OVERFLOW_FIELDS {
            tracing::warn!(
                pushkin = self.name(),
                overflow_fields,
                "payload contains too many overflowing fields; notification likely to be rejected by Firebase"
            );
        }

        Ok(Some(data))
    }

    fn legacy_pushkeys_for_notification(
        &self,
        notification: &Notification,
        device: &Device,
    ) -> Option<Vec<String>> {
        let pushkeys = notification
            .devices
            .iter()
            .filter(|candidate| self.handles_appid(&candidate.app_id))
            .map(|candidate| candidate.pushkey.clone())
            .collect::<Vec<_>>();

        if pushkeys
            .first()
            .is_none_or(|pushkey| pushkey != &device.pushkey)
        {
            return None;
        }

        Some(pushkeys)
    }

    fn build_legacy_request_body(
        &self,
        notification: &Notification,
        pushkeys: &[String],
        data: &Map<String, Value>,
    ) -> Map<String, Value> {
        let mut body = self.base_request_body.clone();
        body.insert("data".to_owned(), Value::Object(data.clone()));
        body.insert(
            "priority".to_owned(),
            Value::String(if notification.prio.as_deref() == Some("low") {
                "normal".to_owned()
            } else {
                "high".to_owned()
            }),
        );

        if pushkeys.len() == 1 {
            body.insert("to".to_owned(), Value::String(pushkeys[0].clone()));
        } else {
            body.insert(
                "registration_ids".to_owned(),
                Value::Array(pushkeys.iter().cloned().map(Value::String).collect()),
            );
        }

        body
    }
}

#[async_trait]
impl Pushkin for FcmPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn handles_appid(&self, appid: &str) -> bool {
        self.matcher.handles_appid(appid)
    }

    fn dispatch_targets(
        &self,
        notification: &Notification,
        device: &Device,
    ) -> Vec<DispatchTarget> {
        match self.api_version {
            ApiVersion::Legacy => {
                let Some(pushkeys) = self.legacy_pushkeys_for_notification(notification, device)
                else {
                    return vec![];
                };
                notification
                    .devices
                    .iter()
                    .filter(|candidate| {
                        self.handles_appid(&candidate.app_id)
                            && pushkeys.iter().any(|pushkey| pushkey == &candidate.pushkey)
                    })
                    .map(|candidate| DispatchTarget {
                        app_id: candidate.app_id.clone(),
                        pushkey: candidate.pushkey.clone(),
                    })
                    .collect()
            }
            ApiVersion::V1 => vec![DispatchTarget {
                app_id: device.app_id.clone(),
                pushkey: device.pushkey.clone(),
            }],
        }
    }

    async fn dispatch_notification(
        &self,
        notification: &Notification,
        device: &Device,
        _context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        let _permit = self.gate.acquire(self.name())?;

        match self.api_version {
            ApiVersion::Legacy => {
                let Some(pushkeys) = self.legacy_pushkeys_for_notification(notification, device)
                else {
                    return Ok(vec![]);
                };
                let default_payload = match device.default_payload() {
                    Ok(default_payload) => default_payload,
                    Err(_) => {
                        tracing::warn!(
                            pushkey_hashes = ?crate::models::redact_push_tokens(&pushkeys),
                            "rejecting legacy FCM pushkeys due to invalid default_payload"
                        );
                        return Ok(pushkeys);
                    }
                };
                let Some(data) = self.build_data(notification, default_payload)? else {
                    return Ok(vec![]);
                };
                self.dispatch_legacy(notification, pushkeys, data).await
            }
            ApiVersion::V1 => {
                let default_payload = match device.default_payload() {
                    Ok(default_payload) => default_payload,
                    Err(_) => {
                        tracing::warn!(
                            pushkey_hash = %device.redacted_pushkey(),
                            "rejecting FCM pushkey due to invalid default_payload"
                        );
                        return Ok(vec![device.pushkey.clone()]);
                    }
                };
                let Some(data) = self.build_data(notification, default_payload)? else {
                    return Ok(vec![]);
                };
                self.dispatch_v1(notification, device, data).await
            }
        }
    }
}

impl ServiceAccountSigner {
    async fn access_token(&self, client: &Client) -> Result<String, DispatchError> {
        {
            let cache = self.cache.lock().await;
            if let Some(token) = cache.as_ref()
                && token.expires_at > Instant::now() + Duration::from_secs(30)
            {
                return Ok(token.token.clone());
            }
        }

        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            scope: &'a str,
            aud: &'a str,
            exp: u64,
            iat: u64,
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let jwt = encode(
            &Header::new(Algorithm::RS256),
            &Claims {
                iss: &self.client_email,
                scope: GOOGLE_OAUTH_SCOPE,
                aud: &self.token_uri,
                exp: now + 3600,
                iat: now,
            },
            &self.private_key,
        )
        .map_err(|error| DispatchError::internal(format!("failed to sign Google JWT: {error}")))?;

        let token: AccessTokenResponse = client
            .post(&self.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt.as_str()),
            ])
            .send()
            .await
            .map_err(|error| {
                DispatchError::temporary(
                    format!("failed to fetch Google access token: {error}"),
                    None,
                )
            })?
            .error_for_status()
            .map_err(|error| {
                DispatchError::remote(format!("Google token endpoint rejected request: {error}"))
            })?
            .json()
            .await
            .map_err(|error| {
                DispatchError::remote(format!("failed to parse Google access token: {error}"))
            })?;

        let mut cache = self.cache.lock().await;
        *cache = Some(CachedAccessToken {
            token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(token.expires_in.max(60)),
        });
        Ok(token.access_token)
    }
}

#[derive(Debug, Deserialize)]
struct LegacyFcmResponse {
    #[serde(default)]
    results: Vec<LegacyFcmResult>,
}

#[derive(Debug, Deserialize)]
struct LegacyFcmResult {
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    #[serde(default = "default_token_uri")]
    token_uri: String,
}

fn default_token_uri() -> String {
    GOOGLE_TOKEN_URI.to_owned()
}

fn is_bad_pushkey_error(error: &str) -> bool {
    matches!(
        error,
        "MissingRegistration"
            | "InvalidRegistration"
            | "NotRegistered"
            | "InvalidPackageName"
            | "MismatchSenderId"
    )
}

fn is_bad_message_error(error: &str) -> bool {
    matches!(error, "MessageTooBig" | "InvalidDataKey" | "InvalidTtl")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::models::{Counts, Device, Notification, Tweaks};

    fn pushkin(api_version: ApiVersion) -> FcmPushkin {
        FcmPushkin {
            matcher: AppMatcher::new("com.example.gcm".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client: Client::builder().build().unwrap(),
            api_version,
            auth: FcmAuth::Legacy {
                api_key: "key".to_owned(),
            },
            base_request_body: Map::new(),
            send_badge_counts: true,
        }
    }

    fn device() -> Device {
        device_with_pushkey("spqr")
    }

    fn device_with_pushkey(pushkey: &str) -> Device {
        Device {
            app_id: "com.example.gcm".to_owned(),
            pushkey: pushkey.to_owned(),
            pushkey_ts: 42,
            data: None,
            tweaks: Tweaks::default(),
        }
    }

    #[test]
    fn builds_legacy_data_payload() {
        let pushkin = pushkin(ApiVersion::Legacy);
        let notification = Notification {
            room_name: Some("Mission Control".to_owned()),
            room_alias: None,
            space_name: None,
            prio: None,
            membership: None,
            sender_display_name: Some("Major Tom".to_owned()),
            content: Some(
                json!({
                    "msgtype": "m.text",
                    "body": "I'm floating in a most peculiar way."
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            event_id: Some("$event".to_owned()),
            room_id: Some("!room:example.com".to_owned()),
            space_id: None,
            user_is_target: None,
            r#type: Some("m.room.message".to_owned()),
            sender: Some("@major:example.com".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
                highlight_count: Some(1),
            },
        };

        let payload = pushkin
            .build_data(&notification, Map::new())
            .unwrap()
            .unwrap();
        assert_eq!(
            payload,
            json!({
                "event_id": "$event",
                "type": "m.room.message",
                "sender": "@major:example.com",
                "space_name": "Mission Control",
                "room_name": "Mission Control",
                "sender_display_name": "Major Tom",
                "space_id": "!room:example.com",
                "room_id": "!room:example.com",
                "content": {
                    "msgtype": "m.text",
                    "body": "I'm floating in a most peculiar way."
                },
                "prio": "high",
                "unread": 2,
                "missed_calls": 1,
                "highlight_count": 1
            })
            .as_object()
            .unwrap()
            .clone()
        );
    }

    #[test]
    fn builds_v1_data_payload() {
        let pushkin = pushkin(ApiVersion::V1);
        let notification = Notification {
            room_name: Some("Mission Control".to_owned()),
            room_alias: None,
            space_name: None,
            prio: Some("low".to_owned()),
            membership: None,
            sender_display_name: Some("Major Tom".to_owned()),
            content: Some(
                json!({
                    "msgtype": "m.text",
                    "body": "I'm floating in a most peculiar way."
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            event_id: Some("$event".to_owned()),
            room_id: Some("!room:example.com".to_owned()),
            space_id: None,
            user_is_target: None,
            r#type: Some("m.room.message".to_owned()),
            sender: Some("@major:example.com".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
                highlight_count: Some(1),
            },
        };

        let payload = pushkin
            .build_data(&notification, Map::new())
            .unwrap()
            .unwrap();
        assert_eq!(
            payload,
            json!({
                "event_id": "$event",
                "type": "m.room.message",
                "sender": "@major:example.com",
                "space_name": "Mission Control",
                "room_name": "Mission Control",
                "sender_display_name": "Major Tom",
                "space_id": "!room:example.com",
                "room_id": "!room:example.com",
                "content_msgtype": "m.text",
                "content_body": "I'm floating in a most peculiar way.",
                "prio": "normal",
                "unread": "2",
                "missed_calls": "1",
                "highlight_count": "1"
            })
            .as_object()
            .unwrap()
            .clone()
        );
    }

    #[test]
    fn legacy_batching_only_dispatches_from_first_matching_device() {
        let pushkin = pushkin(ApiVersion::Legacy);
        let first = device_with_pushkey("spqr");
        let second = device_with_pushkey("spqr2");
        let notification = Notification {
            room_name: None,
            room_alias: None,
            space_name: None,
            prio: None,
            membership: None,
            sender_display_name: None,
            content: None,
            event_id: Some("$event".to_owned()),
            room_id: Some("!room:example.com".to_owned()),
            space_id: None,
            user_is_target: None,
            r#type: None,
            sender: None,
            push_hint: None,
            devices: vec![first.clone(), second.clone()],
            counts: Counts::default(),
        };

        assert_eq!(
            pushkin.legacy_pushkeys_for_notification(&notification, &first),
            Some(vec!["spqr".to_owned(), "spqr2".to_owned()])
        );
        assert_eq!(
            pushkin.legacy_pushkeys_for_notification(&notification, &second),
            None
        );
    }

    #[test]
    fn legacy_batch_request_uses_registration_ids() {
        let pushkin = pushkin(ApiVersion::Legacy);
        let notification = Notification {
            room_name: None,
            room_alias: None,
            space_name: None,
            prio: None,
            membership: None,
            sender_display_name: None,
            content: None,
            event_id: Some("$event".to_owned()),
            room_id: Some("!room:example.com".to_owned()),
            space_id: None,
            user_is_target: None,
            r#type: None,
            sender: None,
            push_hint: None,
            devices: vec![device()],
            counts: Counts::default(),
        };

        let body = pushkin.build_legacy_request_body(
            &notification,
            &["spqr".to_owned(), "spqr2".to_owned()],
            &json!({
                "event_id": "$event",
                "room_id": "!room:example.com",
                "prio": "high"
            })
            .as_object()
            .unwrap()
            .clone(),
        );

        assert_eq!(
            body.get("registration_ids"),
            Some(&json!(["spqr", "spqr2"]))
        );
        assert!(body.get("to").is_none());
    }

    #[test]
    fn zero_badge_counts_are_dropped() {
        let pushkin = pushkin(ApiVersion::Legacy);
        let notification = Notification {
            room_name: None,
            room_alias: None,
            space_name: None,
            prio: None,
            membership: None,
            sender_display_name: None,
            content: None,
            event_id: None,
            room_id: None,
            space_id: None,
            user_is_target: None,
            r#type: None,
            sender: None,
            push_hint: None,
            devices: vec![device()],
            counts: Counts {
                unread: Some(0),
                missed_calls: Some(0),
                highlight_count: Some(0),
            },
        };

        assert_eq!(pushkin.build_data(&notification, Map::new()).unwrap(), None);
    }
}
