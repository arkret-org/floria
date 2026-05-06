use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
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

use crate::auth::redact_url_credentials;
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext};

use super::reqwest_support::{header_value, parse_retry_after};
use super::{
    AppMatcher, ConcurrencyGate, DispatchTarget, Pushkin, inflight_limit, max_connections,
    truncate_str,
};

static FCM_QUEUE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_fcm_queue_time",
        "Time taken waiting for a connection to FCM"
    )
    .expect("register floria_fcm_queue_time")
});

static FCM_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_fcm_request_time",
        "Time taken to send HTTP request to FCM"
    )
    .expect("register floria_fcm_request_time")
});

static FCM_PENDING_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_pending_fcm_requests",
        "Number of FCM requests waiting for a connection"
    )
    .expect("register floria_pending_fcm_requests")
});

static FCM_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_fcm_requests",
        "Number of FCM requests in flight"
    )
    .expect("register floria_active_fcm_requests")
});

static FCM_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_fcm_status_codes",
        "Number of HTTP response status codes received from FCM",
        &["pushkin", "code"]
    )
    .expect("register floria_fcm_status_codes")
});

const FCM_MAX_TRIES: usize = 3;
const FCM_RETRY_DELAY_BASE_SECS: u64 = 10;
const FCM_RETRY_DELAY_QUOTA_SECS: u64 = 60;
const FCM_MAX_BYTES_PER_FIELD: usize = 1024;
const FCM_MAX_FIREBASE_MESSAGE_SIZE: usize = 4096;
const FCM_MAX_OVERFLOW_FIELDS: usize = FCM_MAX_FIREBASE_MESSAGE_SIZE / FCM_MAX_BYTES_PER_FIELD - 1;
const GOOGLE_OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const GOOGLE_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

pub struct FcmPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: Client,
    auth: FcmAuth,
    base_request_body: Map<String, Value>,
    send_badge_counts: bool,
}

struct FcmAuth {
    project_id: String,
    service_account: Option<ServiceAccountSigner>,
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
        let send_badge_counts = app.get_bool("send_badge_counts")?.unwrap_or(true);
        let base_request_body = app.get_object("fcm_options")?.unwrap_or_default();

        let mut client_builder = Client::builder().user_agent("floria");
        if let Some(proxy) = config.outbound_proxy() {
            client_builder = client_builder.proxy(Proxy::all(proxy).with_context(|| {
                format!("invalid proxy URL `{}`", redact_url_credentials(proxy))
            })?);
        }
        let client = client_builder
            .build()
            .context("failed to build FCM client")?;

        let project_id = app
            .get_string("project_id")?
            .context("FCM config requires project_id")?;
        let service_account_file = app
            .require_existing_file(base_dir, "service_account_file")?
            .context("FCM config requires service_account_file")?;
        let content = std::fs::read_to_string(&service_account_file)
            .with_context(|| format!("failed to read {}", service_account_file.display()))?;
        let key: ServiceAccountKey =
            serde_json::from_str(&content).context("invalid service account JSON")?;
        let private_key = EncodingKey::from_rsa_pem(key.private_key.as_bytes())
            .context("invalid service account private key")?;

        Ok(Self {
            matcher,
            gate,
            connection_semaphore,
            client,
            auth: FcmAuth {
                project_id,
                service_account: Some(ServiceAccountSigner {
                    client_email: key.client_email,
                    private_key,
                    token_uri: key.token_uri,
                    cache: Mutex::new(None),
                }),
            },
            base_request_body,
            send_badge_counts,
        })
    }

    async fn dispatch_v1(
        &self,
        notification: &Notification,
        device: &Device,
        data: Map<String, Value>,
    ) -> Result<Vec<String>, DispatchError> {
        let service_account = self
            .auth
            .service_account
            .as_ref()
            .ok_or_else(|| DispatchError::internal("invalid FCM auth configuration"))?;
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
                    DispatchError::internal(format!("failed to serialize FCM value: {error}"))
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
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.auth.project_id
        );

        for attempt in 0..FCM_MAX_TRIES {
            FCM_PENDING_REQUESTS.inc();
            let queue_started = Instant::now();
            let _connection_permit = self
                .connection_semaphore
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| {
                    FCM_PENDING_REQUESTS.dec();
                    DispatchError::internal("FCM connection semaphore closed")
                })?;
            FCM_PENDING_REQUESTS.dec();
            FCM_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

            FCM_ACTIVE_REQUESTS.inc();
            let request_started = Instant::now();
            let response = self
                .client
                .post(&url)
                .headers(headers.clone())
                .json(&body)
                .send()
                .await
                .map_err(|error| {
                    FCM_ACTIVE_REQUESTS.dec();
                    FCM_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                    DispatchError::temporary(format!("FCM request failed: {error}"), None)
                });

            match response {
                Ok(response) => {
                    FCM_ACTIVE_REQUESTS.dec();
                    FCM_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                    FCM_STATUS_CODES
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

        Err(DispatchError::remote("FCM retried too many times"))
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

        classify_fcm_v1_response(status.as_u16(), retry_after, &body, pushkey)
    }

    fn build_data(
        &self,
        notification: &Notification,
        default_payload: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, DispatchError> {
        let mut data = default_payload;
        let mut overflow_fields = 0usize;

        for (attr, value) in [
            ("event_id", notification.event_id.as_deref()),
            ("message_id", notification.message_id()),
            ("type", notification.event_kind()),
            ("sender", notification.sender.as_deref()),
            ("flow_name", notification.flow_name()),
            ("space_name", notification.space_name()),
            ("membership", notification.membership.as_deref()),
            (
                "sender_display_name",
                notification.sender_display_name.as_deref(),
            ),
            ("flow_id", notification.flow_id()),
            ("space_id", notification.space_id()),
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
                counts.insert("unread".to_owned(), Value::String(unread.to_string()));
            }
            if let Some(missed_calls) = notification.counts.missed_calls
                && missed_calls > 0
            {
                counts.insert(
                    "missed_calls".to_owned(),
                    Value::String(missed_calls.to_string()),
                );
            }
            if let Some(highlight_count) = notification.counts.highlight_count
                && highlight_count > 0
            {
                counts.insert(
                    "highlight_count".to_owned(),
                    Value::String(highlight_count.to_string()),
                );
            }
        }

        let has_routable_context = data.contains_key("flow_id")
            || data.contains_key("space_id")
            || data.contains_key("event_id")
            || data.contains_key("message_id")
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
}

#[async_trait]
impl Pushkin for FcmPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        "fcm"
    }

    fn handles_appid(&self, appid: &str) -> bool {
        self.matcher.handles_appid(appid)
    }

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
        _context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        let _permit = self.gate.acquire(self.name())?;

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

fn classify_fcm_v1_response(
    status: u16,
    retry_after: Option<Duration>,
    body: &str,
    pushkey: &str,
) -> Result<Vec<String>, DispatchError> {
    match status {
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
            "unexpected FCM status: {}",
            reqwest::StatusCode::from_u16(status)
                .map(|status| status.to_string())
                .unwrap_or_else(|_| status.to_string())
        ))),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::models::{Counts, Device, Notification, Tweaks};

    fn pushkin() -> FcmPushkin {
        FcmPushkin {
            matcher: AppMatcher::new("com.example.fcm".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client: Client::builder().build().unwrap(),
            auth: FcmAuth {
                project_id: "example-project".to_owned(),
                service_account: None,
            },
            base_request_body: Map::new(),
            send_badge_counts: true,
        }
    }

    fn device() -> Device {
        Device {
            app_id: "com.example.fcm".to_owned(),
            pushkey: "spqr".to_owned(),
            pushkey_ts: 42,
            data: None,
            tweaks: Tweaks::default(),
        }
    }

    fn notification() -> Notification {
        Notification {
            flow_name: Some("Mission Control".to_owned()),
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
            event_id: Some("cx:event:01JS0EV000000000000000000".to_owned()),
            message_id: Some("cx:message:01JS0MSG0000000000000000".to_owned()),
            flow_id: Some("cx:flow:01JS0FLOW000000000000000".to_owned()),
            space_id: Some("cx:space:01JS0SP000000000000000000".to_owned()),
            user_is_target: None,
            r#type: Some("cx.message.create".to_owned()),
            sender: Some("@major:example.com".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
                highlight_count: Some(1),
            },
        }
    }

    #[test]
    fn builds_v1_data_payload() {
        let payload = pushkin()
            .build_data(&notification(), Map::new())
            .unwrap()
            .unwrap();

        assert_eq!(
            payload,
            json!({
                "event_id": "cx:event:01JS0EV000000000000000000",
                "message_id": "cx:message:01JS0MSG0000000000000000",
                "flow_id": "cx:flow:01JS0FLOW000000000000000",
                "type": "cx.message.create",
                "sender": "@major:example.com",
                "flow_name": "Mission Control",
                "sender_display_name": "Major Tom",
                "space_id": "cx:space:01JS0SP000000000000000000",
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
    fn dispatch_targets_include_only_the_current_device() {
        let pushkin = pushkin();
        let primary = device();
        let secondary = Device {
            app_id: "com.example.fcm".to_owned(),
            pushkey: "spqr2".to_owned(),
            pushkey_ts: 43,
            data: None,
            tweaks: Tweaks::default(),
        };
        let mut notification = notification();
        notification.devices = vec![primary.clone(), secondary];

        assert_eq!(
            pushkin.dispatch_targets(&notification, &primary),
            vec![DispatchTarget {
                app_id: "com.example.fcm".to_owned(),
                pushkey: "spqr".to_owned(),
            }]
        );
    }

    #[test]
    fn zero_badge_counts_are_dropped() {
        let notification = Notification {
            flow_name: None,
            space_name: None,
            prio: None,
            membership: None,
            sender_display_name: None,
            content: None,
            event_id: None,
            message_id: None,
            flow_id: None,
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

        assert_eq!(
            pushkin().build_data(&notification, Map::new()).unwrap(),
            None
        );
    }

    #[test]
    fn v1_not_found_rejects_pushkey() {
        let rejected = classify_fcm_v1_response(404, None, "", "spqr").unwrap();

        assert_eq!(rejected, vec!["spqr".to_owned()]);
    }

    #[test]
    fn fcm_quota_errors_are_temporary() {
        let error = classify_fcm_v1_response(429, None, "", "spqr").unwrap_err();

        assert!(error.is_temporary());
        assert_eq!(
            error.retry_after(),
            Some(Duration::from_secs(FCM_RETRY_DELAY_QUOTA_SECS))
        );
        assert_eq!(error.to_string(), "FCM message quota exceeded");
    }
}
