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

use super::reqwest_support::{header_value, parse_retry_after};
use super::{
    AppMatcher, ConcurrencyGate, DispatchTarget, Pushkin, build_blind_routing_data, inflight_limit,
    max_connections, notification_badge_count, notification_unread_increment,
    sanitized_provider_payload,
};
use crate::auth::redact_url_credentials;
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, DeviceExt, Notification, NotificationContext, NotificationExt};

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

static FCM_BATCH_SIZE: LazyLock<prometheus::HistogramVec> = LazyLock::new(|| {
    prometheus::register_histogram_vec!(
        "floria_fcm_batch_size",
        "Batch size observed when FCM multicast dispatch is invoked",
        &["pushkin"],
        vec![1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 500.0]
    )
    .expect("register floria_fcm_batch_size")
});

static FCM_BATCH_OUTCOMES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_fcm_batch_dispatched_total",
        "Per-message outcome of FCM multicast dispatch",
        &["pushkin", "outcome"]
    )
    .expect("register floria_fcm_batch_dispatched_total")
});

const FCM_MAX_TRIES: usize = 3;
const FCM_RETRY_DELAY_BASE_SECS: u64 = 10;
const FCM_RETRY_DELAY_QUOTA_SECS: u64 = 60;
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
    pub fn new(name: String, app: &AppConfig, config: &Config, base_dir: &Path) -> Result<Self> {
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

        // FCM v1 multicast = many concurrent /messages:send calls
        // sharing one HTTP/2 connection. ALPN handles the upgrade
        // over TLS; adaptive_window lets reqwest grow the receive
        // window as throughput climbs so per-stream pacing stays
        // pipeline-bound rather than window-bound.
        let mut client_builder = Client::builder()
            .user_agent("floria")
            .connect_timeout(super::reqwest_support::CONNECT_TIMEOUT)
            .timeout(super::reqwest_support::REQUEST_TIMEOUT)
            .dns_resolver(crate::egress::EgressGuardResolver::from_env())
            .http2_adaptive_window(true);
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
        message.insert(
            "token".to_owned(),
            Value::String(device.push_key().unwrap_or_default().to_owned()),
        );

        let priority = Value::String(if notification.is_low_priority() {
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
                    match self
                        .handle_v1_response(response, device.push_key().unwrap_or_default())
                        .await
                    {
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
        push_key: &str,
    ) -> Result<Vec<String>, DispatchError> {
        let status = response.status();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read FCM response: {error}"))
        })?;

        classify_fcm_v1_response(status.as_u16(), retry_after, &body, push_key)
    }

    fn build_data(
        &self,
        notification: &Notification,
    ) -> Result<Option<Map<String, Value>>, DispatchError> {
        // T4.3 — the FCM data dictionary used to auto-copy event_id /
        // message_id / strand_id / realm_id / sender / names / push_hint
        // / content_*. None of those survive on the wire any more:
        //
        //   * The client decrypts a server-side e2ee envelope to learn event/space/sender/body —
        //     the provider wire format only needs to carry the opaque push_target_id + wakeup_kind
        //     so the client knows it has work to pick up.
        //   * `push_hint` survives ONLY when it's one of the SDK's allow-listed literals (no
        //     l10n_key:* form that could embed a stable token).
        //   * Counts are bucketed (0 / 1 / 2-5 / 6+) per §5.1 so the absolute figure can't ride the
        //     wire as a per-`push_target_id` activity correlator.
        //
        let mut data = Map::new();

        data.extend(build_blind_routing_data(notification));

        data.insert(
            "priority".to_owned(),
            Value::String(if notification.is_low_priority() {
                "normal".to_owned()
            } else {
                "high".to_owned()
            }),
        );

        let mut emitted_count = false;
        if self.send_badge_counts {
            if let Some(unread_increment) = notification_unread_increment(notification)
                && unread_increment > 0
            {
                data.insert(
                    "unread_count".to_owned(),
                    Value::String(unread_increment.to_string()),
                );
                emitted_count = true;
            }
            if let Some(badge) = notification_badge_count(notification)
                && badge > 0
            {
                data.insert("badge".to_owned(), Value::String(badge.to_string()));
                emitted_count = true;
            }
        }

        // We still want to drop the dispatch entirely when the caller
        // gave us nothing routable: no push_target_id + wakeup_kind,
        // no counts. The old "has_routable_context" check used
        // strand_id/realm_id/event_id/message_id — none of those are
        // emitted any more, so the check is on the blind fields.
        let has_routable_context = data.contains_key("push_target_id")
            || data.contains_key("wakeup_kind")
            || data.contains_key("push_hint")
            || emitted_count;
        if !has_routable_context {
            return Ok(None);
        }

        let data = sanitized_provider_payload(data).map_err(|rejection| {
            tracing::warn!(
                pushkin = self.name(),
                rejection = %rejection,
                "rejecting FCM dispatch due to provider sanitizer rejection"
            );
            DispatchError::remote(format!("FCM payload sanitizer rejected: {rejection}"))
        })?;

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

    fn handles_app_id(&self, app_id: &str) -> bool {
        self.matcher.handles_app_id(app_id)
    }

    fn dispatch_targets(
        &self,
        _notification: &Notification,
        device: &Device,
    ) -> Vec<DispatchTarget> {
        let (Some(app_id), Some(push_key)) = (device.app_id(), device.push_key()) else {
            return Vec::new();
        };
        vec![DispatchTarget {
            app_id: app_id.to_owned(),
            push_key: push_key.to_owned(),
        }]
    }

    async fn dispatch_notification(
        &self,
        notification: &Notification,
        device: &Device,
        _context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        let _permit = self.gate.acquire(self.name())?;

        let Some(data) = self.build_data(notification)? else {
            return Ok(vec![]);
        };
        self.dispatch_v1(notification, device, data).await
    }
}

impl FcmPushkin {
    /// Dispatch a multicast batch. FCM v1 deprecated `batchSend`, so
    /// the batched form is many concurrent `/messages:send` calls
    /// sharing one access token and one HTTP/2 connection. The
    /// `connection_semaphore` already bounds outbound concurrency;
    /// this method just `tokio::join!`s the per-device dispatches so
    /// the caller does not have to do it manually.
    pub async fn dispatch_batch(
        &self,
        notification: &Notification,
        devices: &[Device],
        context: &NotificationContext,
    ) -> Vec<Result<Vec<String>, DispatchError>> {
        FCM_BATCH_SIZE
            .with_label_values(&[self.name()])
            .observe(devices.len() as f64);

        let mut futures = Vec::with_capacity(devices.len());
        for device in devices {
            futures.push(self.dispatch_notification(notification, device, context));
        }
        let results = futures::future::join_all(futures).await;

        for result in &results {
            let outcome = match result {
                Ok(rejected) if rejected.is_empty() => "accepted",
                Ok(_) => "partial",
                Err(error) if error.is_temporary() => "retryable",
                Err(error) if error.is_remote() => "remote_error",
                Err(_) => "internal_error",
            };
            FCM_BATCH_OUTCOMES
                .with_label_values(&[self.name(), outcome])
                .inc();
        }
        results
    }
}

impl ServiceAccountSigner {
    async fn access_token(&self, client: &Client) -> Result<String, DispatchError> {
        {
            let cache = self.cache.lock().await;
            if let Some(token) = cache.as_ref()
                && token.expires_at > Instant::now() + super::reqwest_support::TOKEN_REFRESH_SKEW
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
    push_key: &str,
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
        404 => Ok(vec![push_key.to_owned()]),
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
    use super::*;
    use crate::models::{Counts, Device, Notification, RoutingMetadata};

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
            device_id: cokret::DeviceId::new("ck:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            app_id: Some("com.example.fcm".to_owned()),
            push_key: Some("spqr".to_owned()),
            platform: None,
            target_actor_id: None,
        }
    }

    fn notification() -> Notification {
        Notification {
            strand_title: Some("Mission Control".to_owned()),
            realm_title: None,
            priority: Some("low".to_owned()),
            membership: None,
            sender_actor_display_name: Some("Major Tom".to_owned()),
            event_id: Some(
                cokret::EventId::new("ck:event:0196419b-0000-7000-8000-000000000001").unwrap(),
            ),
            message_id: Some(
                cokret::MessageId::new("ck:message:0196419b-0000-7000-8000-000000000002").unwrap(),
            ),
            strand_id: Some(
                cokret::StrandId::new("ck:strand:019640f9-8000-7000-8000-000000000000").unwrap(),
            ),
            routing_metadata: Some(RoutingMetadata {
                realm_id: Some(
                    cokret::RealmId::new("ck:realm:0196419b-0000-7000-8000-000000000003").unwrap(),
                ),
                ..Default::default()
            }),
            user_is_target: None,
            push_target_id: Some("ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            wakeup_kind: Some("message".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Some(Counts {
                badge: Some(serde_json::json!("2-5")),
                unread_increment: Some(2),
                missed_call: Some(1),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn builds_v1_data_payload() {
        let payload = pushkin().build_data(&notification()).unwrap().unwrap();

        // T4.3 — provider payload now carries only allowed blind
        // fields. event_id / message_id / strand_id / realm_id /
        // sender / strand_title / sender_actor_display_name / content_* are
        // all stripped at the gateway.
        assert_eq!(
            payload.get("push_target_id"),
            Some(&Value::String(
                "ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()
            ))
        );
        assert_eq!(
            payload.get("wakeup_kind"),
            Some(&Value::String("message".to_owned()))
        );
        assert_eq!(
            payload.get("priority"),
            Some(&Value::String("normal".to_owned()))
        );
        // unread_increment travels as a bounded delta; badge keeps the
        // bucket representative for the SDK badge field.
        assert_eq!(
            payload.get("unread_count"),
            Some(&Value::String("2".to_owned()))
        );
        assert_eq!(payload.get("badge"), Some(&Value::String("5".to_owned())));

        for forbidden in [
            "event_id",
            "message_id",
            "strand_id",
            "realm_id",
            // SDK + local R23 sanitizers strip both the renamed
            // security id (`realm_id`) AND the renamed container id
            // (`space_id`).
            "space_id",
            // CKP-0007 — Circle routing identifiers MUST NOT reach
            // the provider plaintext payload.
            "circle_id",
            "effective_scope",
            "scope_circle_id",
            "sender",
            "sender_actor_display_name",
            "strand_title",
            "realm_title",
            "content_body",
            "content_msgtype",
            "highlight_count",
        ] {
            assert!(
                payload.get(forbidden).is_none(),
                "forbidden field `{forbidden}` should have been stripped, got: {payload:?}"
            );
        }
    }

    #[test]
    fn dispatch_targets_include_only_the_current_device() {
        let pushkin = pushkin();
        let primary = device();
        let secondary = Device {
            device_id: cokret::DeviceId::new("ck:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            app_id: Some("com.example.fcm".to_owned()),
            push_key: Some("spqr2".to_owned()),
            platform: None,
            target_actor_id: None,
        };
        let mut notification = notification();
        notification.devices = vec![primary.clone(), secondary];

        assert_eq!(
            pushkin.dispatch_targets(&notification, &primary),
            vec![DispatchTarget {
                app_id: "com.example.fcm".to_owned(),
                push_key: "spqr".to_owned(),
            }]
        );
    }

    #[test]
    fn zero_badge_counts_are_dropped() {
        // T4.3 — "no routable context" now means none of the
        // SDK-allowed blind fields (push_target_id, wakeup_kind,
        // push_hint) AND no nonzero counts. Without push_target_id the
        // dispatch is dropped entirely.
        let notification = Notification {
            strand_title: None,
            realm_title: None,
            priority: None,
            membership: None,
            sender_actor_display_name: None,
            event_id: None,
            message_id: None,
            strand_id: None,
            user_is_target: None,
            push_target_id: None,
            wakeup_kind: None,
            push_hint: None,
            devices: vec![device()],
            counts: Some(Counts {
                badge: None,
                unread_increment: None,
                missed_call: None,
            }),
            ..Default::default()
        };

        assert_eq!(pushkin().build_data(&notification).unwrap(), None);
    }

    #[test]
    fn v1_not_found_rejects_push_key() {
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
