use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use arkret_models_integration::{PushDeviceRoute, PushNotificationEnvelope};
use async_trait::async_trait;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use prometheus::{
    Histogram, IntGauge, register_histogram, register_int_counter_vec, register_int_gauge,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, Identity, Proxy};
use serde::Serialize;
use serde_json::{Map, Value};
use tokio::sync::Mutex;
use tokio::time::sleep;
use uuid::Uuid;

use super::reqwest_support::header_value;
use super::{
    AppMatcher, ConcurrencyGate, Pushkin, build_blind_routing_data, inflight_limit,
    notification_badge_count, sanitized_provider_payload,
};
use crate::auth::redact_url_credentials;
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{DeviceExt, NotificationContext, NotificationExt};

static APNS_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_apns_request_time",
        "Time taken to send HTTP request to APNS"
    )
    .expect("register floria_apns_request_time")
});

static APNS_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_apns_requests",
        "Number of APNS requests in flight"
    )
    .expect("register floria_active_apns_requests")
});

static APNS_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_apns_status_codes",
        "Number of HTTP response status codes received from APNS",
        &["pushkin", "code"]
    )
    .expect("register floria_apns_status_codes")
});

static CLIENT_CERT_EXPIRY: LazyLock<prometheus::GaugeVec> = LazyLock::new(|| {
    prometheus::register_gauge_vec!(
        "floria_client_cert_expiry",
        "The expiry date of the client certificate in seconds since the epoch",
        &["pushkin"]
    )
    .expect("register floria_client_cert_expiry")
});

static APNS_JWT_ROTATIONS: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_apns_jwt_rotations_total",
        "Number of fresh APNS JWTs minted by the gateway, by pushkin and reason",
        &["pushkin", "reason"]
    )
    .expect("register floria_apns_jwt_rotations_total")
});

static APNS_TOKEN_AUTH_FAILURES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_apns_token_auth_failures_total",
        "APNS rejections that point at the provider token, by pushkin and reason",
        &["pushkin", "reason"]
    )
    .expect("register floria_apns_token_auth_failures_total")
});

const APNS_MAX_TRIES: usize = 3;
const APNS_RETRY_DELAY_BASE_SECS: u64 = 10;
const APNS_MAX_FIELD_LENGTH: usize = 1024;
const APNS_MAX_JSON_BODY_SIZE: usize = 4096;
const APNS_TOKEN_TTL_SECS: u64 = 50 * 60;
const APNS_TOKEN_REFRESH_SAFETY_SECS: u64 = 30;
const APNS_URL_PRODUCTION: &str = "https://api.push.apple.com/3/device";
const APNS_URL_SANDBOX: &str = "https://api.sandbox.push.apple.com/3/device";
const APNS_PUSH_TYPES: &[&str] = &[
    "alert",
    "background",
    "voip",
    "complication",
    "fileprovider",
    "mdm",
];

pub struct ApnsPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    client: Client,
    auth: ApnsAuth,
    use_sandbox: bool,
    push_type: Option<String>,
    convert_device_token_to_hex: bool,
    send_badge_counts: bool,
}

enum ApnsAuth {
    Certificate {
        topic: Option<String>,
    },
    Token {
        topic: String,
        signer: ApnsTokenSigner,
    },
}

struct ApnsTokenSigner {
    pushkin_name: String,
    team_id: String,
    key_id: String,
    key: EncodingKey,
    token_ttl: Duration,
    cache: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    value: String,
    expires_at: u64,
}

impl ApnsPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config, base_dir: &Path) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "platform",
                "certfile",
                "team_id",
                "key_id",
                "keyfile",
                "topic",
                "push_type",
                "convert_device_token_to_hex",
                "send_badge_counts",
                "inflight_request_limit",
                "token_ttl_seconds",
            ],
        );
        let pushkin_name = name.clone();
        let matcher = AppMatcher::new(name)?;
        let gate = ConcurrencyGate::new(inflight_limit(app)?);

        let platform = app.get_string("platform")?;
        let use_sandbox = matches!(platform.as_deref(), Some("sandbox"));
        if let Some(platform) = platform.as_deref()
            && platform != "sandbox"
            && platform != "production"
            && platform != "prod"
        {
            bail!("invalid APNS platform `{platform}`");
        }

        let certfile = app.require_existing_file(base_dir, "certfile")?;
        let keyfile = app.require_existing_file(base_dir, "keyfile")?;
        if certfile.is_none() && keyfile.is_none() {
            bail!("APNS config must define either certfile or keyfile");
        }

        let push_type = app.get_string("push_type")?;
        if let Some(push_type) = push_type.as_deref()
            && !APNS_PUSH_TYPES.contains(&push_type)
        {
            bail!("invalid APNS push_type `{push_type}`");
        }
        let convert_device_token_to_hex =
            app.get_bool("convert_device_token_to_hex")?.unwrap_or(true);
        let send_badge_counts = app.get_bool("send_badge_counts")?.unwrap_or(true);

        let client = build_http_client(config.outbound_proxy(), certfile.as_deref())?;

        if let Some(certfile) = certfile.as_deref() {
            report_certificate_expiration(&pushkin_name, certfile);
        }

        let token_ttl_seconds = app
            .get_u64("token_ttl_seconds")?
            .unwrap_or(APNS_TOKEN_TTL_SECS);
        if token_ttl_seconds == 0 || token_ttl_seconds > 60 * 60 {
            bail!("APNS token_ttl_seconds must be between 1 and 3600");
        }

        let auth = if let Some(keyfile) = keyfile {
            let team_id = app
                .get_string("team_id")?
                .context("APNS token auth requires team_id")?;
            let key_id = app
                .get_string("key_id")?
                .context("APNS token auth requires key_id")?;
            let topic = app
                .get_string("topic")?
                .context("APNS token auth requires topic")?;
            let pem = std::fs::read(&keyfile)
                .with_context(|| format!("failed to read {}", keyfile.display()))?;
            let key = EncodingKey::from_ec_pem(&pem).context("invalid APNS p8 key")?;
            ApnsAuth::Token {
                topic,
                signer: ApnsTokenSigner {
                    pushkin_name,
                    team_id,
                    key_id,
                    key,
                    token_ttl: Duration::from_secs(token_ttl_seconds),
                    cache: Mutex::new(None),
                },
            }
        } else {
            ApnsAuth::Certificate {
                topic: app.get_string("topic")?,
            }
        };

        Ok(Self {
            matcher,
            gate,
            client,
            auth,
            use_sandbox,
            push_type,
            convert_device_token_to_hex,
            send_badge_counts,
        })
    }

    async fn send_once(
        &self,
        device: &PushDeviceRoute,
        payload: &Value,
        priority: u8,
    ) -> Result<Vec<String>, DispatchError> {
        let device_token = self.device_token(device)?;
        let url = format!("{}/{device_token}", self.base_url());

        let notif_id = Uuid::new_v4().to_string();

        let mut headers = HeaderMap::new();
        // `HeaderValue: From<u16>` is infallible — no hot-path unwrap.
        headers.insert("apns-priority", HeaderValue::from(u16::from(priority)));
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("apns-id", header_value(&notif_id)?);

        match &self.auth {
            ApnsAuth::Certificate { topic } => {
                if let Some(topic) = topic {
                    headers.insert("apns-topic", header_value(topic)?);
                }
            }
            ApnsAuth::Token { topic, signer } => {
                headers.insert("apns-topic", header_value(topic)?);
                let token = signer.jwt().await?;
                headers.insert(AUTHORIZATION, header_value(&format!("bearer {token}"))?);
            }
        }

        if let Some(push_type) = &self.push_type {
            headers.insert("apns-push-type", header_value(push_type)?);
        }

        APNS_ACTIVE_REQUESTS.inc();
        let started = Instant::now();
        let response = self
            .client
            .post(url)
            .headers(headers)
            .json(payload)
            .send()
            .await
            .map_err(|error| {
                APNS_ACTIVE_REQUESTS.dec();
                APNS_REQUEST_TIME.observe(started.elapsed().as_secs_f64());
                DispatchError::temporary(format!("APNS request failed: {error}"), None)
            })?;
        APNS_ACTIVE_REQUESTS.dec();
        APNS_REQUEST_TIME.observe(started.elapsed().as_secs_f64());

        let status = response.status().as_u16();
        APNS_STATUS_CODES
            .with_label_values(&[self.name(), &status.to_string()])
            .inc();

        if response.status().is_success() {
            return Ok(vec![]);
        }

        let body = response.text().await.unwrap_or_default();
        let reason = serde_json::from_str::<ApnsErrorBody>(&body)
            .ok()
            .and_then(|body| body.reason)
            .unwrap_or_else(|| body.clone());

        classify_apns_response(status, &reason, device.push_key().unwrap_or_default())
    }

    fn device_token(&self, device: &PushDeviceRoute) -> Result<String, DispatchError> {
        let push_key = device.push_key().unwrap_or_default();
        if !self.convert_device_token_to_hex {
            return Ok(push_key.to_owned());
        }

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(push_key)
            .map_err(|error| {
                DispatchError::remote(format!("invalid APNS device token: {error}"))
            })?;
        Ok(hex::encode(bytes))
    }

    fn base_url(&self) -> &'static str {
        if self.use_sandbox {
            APNS_URL_SANDBOX
        } else {
            APNS_URL_PRODUCTION
        }
    }

    fn build_payload(
        &self,
        notification: &PushNotificationEnvelope,
        provider_payload: Map<String, Value>,
        allow_visible_notification: bool,
    ) -> Result<Option<Value>, DispatchError> {
        Ok(self.payload_full(notification, provider_payload, allow_visible_notification))
    }

    fn payload_full(
        &self,
        notification: &PushNotificationEnvelope,
        mut provider_payload: Map<String, Value>,
        allow_visible_notification: bool,
    ) -> Option<Value> {
        let from_display = notification
            .sender_label()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| " ".to_owned());
        let from_display = trim_chars(&from_display, APNS_MAX_FIELD_LENGTH);

        let mut loc_key = None;
        let mut loc_args: Vec<String> = Vec::new();

        if allow_visible_notification {
            match notification.wakeup_kind.as_deref() {
                Some("message") => {
                    let scope_display = notification
                        .scope_title()
                        .map(|value| trim_chars(value, APNS_MAX_FIELD_LENGTH));

                    if let Some(scope_display) = scope_display {
                        loc_key = Some("MSG_FROM_USER_IN_ROOM");
                        loc_args = vec![from_display, scope_display];
                    } else {
                        loc_key = Some("MSG_FROM_USER");
                        loc_args = vec![from_display];
                    }
                }
                Some("incoming_call") => {
                    if let Some(push_hint) = notification.push_hint_text() {
                        loc_key = Some("MSG_FROM_USER_WITH_CONTENT");
                        loc_args = vec![from_display, trim_chars(push_hint, APNS_MAX_FIELD_LENGTH)];
                    } else {
                        loc_key = Some("VOICE_CALL_FROM_USER");
                        loc_args = vec![from_display];
                    }
                }
                Some("member")
                    if notification.user_is_target == Some(true)
                        && notification.membership.as_deref() == Some("invite") =>
                {
                    if let Some(scope_title) = notification.scope_title() {
                        loc_key = Some("USER_INVITE_TO_NAMED_ROOM");
                        loc_args =
                            vec![from_display, trim_chars(scope_title, APNS_MAX_FIELD_LENGTH)];
                    } else {
                        loc_key = Some("USER_INVITE_TO_CHAT");
                        loc_args = vec![from_display];
                    }
                }
                Some(_) => {
                    if let Some(scope_title) = notification.scope_title() {
                        loc_key = Some("MSG_FROM_USER_IN_ROOM");
                        loc_args =
                            vec![from_display, trim_chars(scope_title, APNS_MAX_FIELD_LENGTH)];
                    } else {
                        loc_key = Some("MSG_FROM_USER");
                        loc_args = vec![from_display];
                    }
                }
                None => {}
            }
        }

        let badge = if self.send_badge_counts {
            notification_badge_count(notification)
        } else {
            None
        };

        if allow_visible_notification && loc_key.is_none() && badge.is_none() {
            return None;
        }

        let aps = provider_payload
            .entry("aps")
            .or_insert_with(|| Value::Object(Map::new()));
        let aps_object = aps.as_object_mut()?;

        if !allow_visible_notification {
            aps_object.insert("content-available".to_owned(), Value::Number(1.into()));
        }
        if let Some(loc_key) = loc_key {
            let alert = aps_object
                .entry("alert")
                .or_insert_with(|| Value::Object(Map::new()));
            let alert_object = alert.as_object_mut()?;
            alert_object.insert("loc-key".to_owned(), Value::String(loc_key.to_owned()));
            if !loc_args.is_empty() {
                alert_object.insert(
                    "loc-args".to_owned(),
                    Value::Array(loc_args.into_iter().map(Value::String).collect()),
                );
            }
        }
        if let Some(badge) = badge {
            aps_object.insert("badge".to_owned(), Value::Number(badge.into()));
        }

        // T4.3 — stable correlation identifiers must not be copied onto
        // the APNS payload alongside the `aps` notification block. The
        // client decrypts an e2ee envelope keyed on `push_target_id` to
        // recover them.
        //
        // Allowed blind-wakeup fields are emitted alongside `aps` so
        // service extensions can still detect the wakeup kind and pull
        // the matching server-side record.
        provider_payload.extend(build_blind_routing_data(notification));

        // Final defence - strip anything forbidden that a future builder
        // bug tries to add. Note `aps` IS on the SDK forbidden list because it's a provider
        // escape hatch — for APNS we explicitly extract it, run the
        // sanitizer on the rest, then put `aps` back. This keeps the
        // allow-list strict for the freeform extension keys while
        // still letting the gateway emit a legitimate `aps` block.
        let aps_block = provider_payload.remove("aps");
        let mut payload_map = match sanitized_provider_payload(provider_payload) {
            Ok(map) => map,
            Err(rejection) => {
                tracing::warn!(
                    rejection = %rejection,
                    "dropping APNS payload because the provider sanitizer rejected a forbidden field"
                );
                return None;
            }
        };
        if let Some(aps) = aps_block {
            payload_map.insert("aps".to_owned(), aps);
        }

        let mut payload = Value::Object(payload_map);
        trim_apns_payload(&mut payload, APNS_MAX_JSON_BODY_SIZE);
        Some(payload)
    }
}

#[async_trait]
impl Pushkin for ApnsPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        "apns"
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

        let Some(payload) = self.build_payload(
            notification,
            Map::new(),
            context.allow_plaintext_metadata && device.visible_notification_opt_in(),
        )?
        else {
            return Ok(vec![]);
        };
        let priority = if notification.is_low_priority() {
            5
        } else {
            10
        };

        for attempt in 0..APNS_MAX_TRIES {
            match self.send_once(device, &payload, priority).await {
                Ok(result) => return Ok(result),
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < APNS_MAX_TRIES => {
                    if let Some(reason) = is_provider_token_failure(&error) {
                        APNS_TOKEN_AUTH_FAILURES
                            .with_label_values(&[self.name(), reason])
                            .inc();
                        if let ApnsAuth::Token { signer, .. } = &self.auth {
                            signer.invalidate().await;
                            // Pre-mint a fresh token for the retry so
                            // the next send_once doesn't race other
                            // dispatchers that also tripped the same
                            // expiry.
                            let _ = signer.jwt_with_reason("forced_rotation").await;
                        }
                    }
                    let retry_after = error.retry_after().unwrap_or_else(|| {
                        Duration::from_secs(APNS_RETRY_DELAY_BASE_SECS * (1_u64 << attempt))
                    });
                    sleep(retry_after).await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(DispatchError::remote("APNS retried too many times"))
    }
}

impl ApnsTokenSigner {
    async fn jwt(&self) -> Result<String, DispatchError> {
        self.jwt_with_reason("scheduled").await
    }

    /// Force the next call to `jwt()` to mint a fresh token. Use this
    /// when APNS has rejected the current token (`InvalidProviderToken`,
    /// `ExpiredProviderToken`) so we can rotate immediately rather
    /// than wait for the TTL.
    async fn invalidate(&self) {
        let mut cache = self.cache.lock().await;
        *cache = None;
    }

    async fn jwt_with_reason(&self, reason: &'static str) -> Result<String, DispatchError> {
        let now = epoch_now();
        {
            let cache = self.cache.lock().await;
            if let Some(cache) = cache.as_ref()
                && cache.expires_at > now + APNS_TOKEN_REFRESH_SAFETY_SECS
            {
                return Ok(cache.value.clone());
            }
        }

        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            iat: u64,
        }

        let header = Header {
            alg: Algorithm::ES256,
            kid: Some(self.key_id.clone()),
            ..Header::default()
        };
        let token = encode(
            &header,
            &Claims {
                iss: &self.team_id,
                iat: now,
            },
            &self.key,
        )
        .map_err(|error| DispatchError::internal(format!("failed to sign APNS JWT: {error}")))?;

        let mut cache = self.cache.lock().await;
        *cache = Some(CachedToken {
            value: token.clone(),
            expires_at: now + self.token_ttl.as_secs(),
        });
        APNS_JWT_ROTATIONS
            .with_label_values(&[self.pushkin_name.as_str(), reason])
            .inc();
        tracing::debug!(
            pushkin = %self.pushkin_name,
            reason,
            ttl_secs = self.token_ttl.as_secs(),
            "minted fresh APNS provider token"
        );
        Ok(token)
    }
}

#[derive(Debug, serde::Deserialize)]
struct ApnsErrorBody {
    #[serde(default)]
    reason: Option<String>,
}

fn classify_apns_response(
    status: u16,
    reason: &str,
    push_key: &str,
) -> Result<Vec<String>, DispatchError> {
    match (status, reason) {
        (400, "BadDeviceToken")
        | (400, "DeviceTokenNotForTopic")
        | (400, "TopicDisallowed")
        | (410, "Unregistered") => Ok(vec![push_key.to_owned()]),
        (403, "InvalidProviderToken")
        | (403, "MissingProviderToken")
        | (403, "ExpiredProviderToken") => Err(DispatchError::temporary(
            format!("APNS provider token rejected: {status} {reason}"),
            None,
        )),
        (500..=599, _) => Err(DispatchError::temporary(
            format!("APNS temporary failure: {status} {reason}"),
            None,
        )),
        _ => Err(DispatchError::remote(format!(
            "APNS rejected request: {status} {reason}"
        ))),
    }
}

fn is_provider_token_failure(error: &DispatchError) -> Option<&'static str> {
    match error {
        DispatchError::Temporary { message, .. } => {
            if message.contains("InvalidProviderToken") {
                Some("invalid_provider_token")
            } else if message.contains("ExpiredProviderToken") {
                Some("expired_provider_token")
            } else if message.contains("MissingProviderToken") {
                Some("missing_provider_token")
            } else {
                None
            }
        }
        _ => None,
    }
}

fn build_http_client(proxy: Option<&str>, identity_path: Option<&Path>) -> Result<Client> {
    let mut builder = Client::builder()
        .https_only(true)
        .tls_backend_rustls()
        .connect_timeout(super::reqwest_support::CONNECT_TIMEOUT)
        .timeout(super::reqwest_support::REQUEST_TIMEOUT)
        .dns_resolver(crate::egress::dns_resolver())
        .redirect(reqwest::redirect::Policy::none())
        .http2_adaptive_window(true);
    if let Some(proxy) = proxy {
        builder =
            builder.proxy(Proxy::all(proxy).with_context(|| {
                format!("invalid proxy URL `{}`", redact_url_credentials(proxy))
            })?);
    }
    if let Some(identity_path) = identity_path {
        let pem = std::fs::read(identity_path)
            .with_context(|| format!("failed to read {}", identity_path.display()))?;
        let identity = Identity::from_pem(&pem).context("invalid PEM certificate bundle")?;
        builder = builder.identity(identity);
    }
    builder.build().context("failed to build APNS HTTP client")
}

fn trim_chars(input: &str, max: usize) -> String {
    input.chars().take(max).collect()
}

fn trim_apns_payload(payload: &mut Value, max_bytes: usize) {
    loop {
        let encoded = serde_json::to_vec(payload).unwrap_or_default();
        if encoded.len() <= max_bytes {
            break;
        }

        let body = if let Some(body) = payload.pointer_mut("/aps/alert/loc-args/2") {
            body
        } else if let Some(body) = payload.pointer_mut("/aps/alert/loc-args/1") {
            body
        } else if let Some(body) = payload.pointer_mut("/aps/alert/loc-args/0") {
            body
        } else {
            break;
        };

        let Some(text) = body.as_str() else {
            break;
        };
        if text.len() <= 8 {
            break;
        }
        let reduced = text
            .chars()
            .take(text.chars().count().saturating_sub(16))
            .collect::<String>();
        *body = Value::String(format!("{reduced}..."));
    }
}

fn report_certificate_expiration(pushkin_name: &str, certfile: &Path) {
    match std::fs::read(certfile) {
        Ok(pem_data) => {
            for pem in x509_parser::pem::Pem::iter_from_buffer(&pem_data) {
                let Ok(pem) = pem else {
                    continue;
                };
                if let Ok(cert) = pem.parse_x509() {
                    let expiry = cert.validity().not_after.timestamp();
                    CLIENT_CERT_EXPIRY
                        .with_label_values(&[pushkin_name])
                        .set(expiry as f64);
                    return;
                }
            }
            tracing::warn!(
                pushkin = pushkin_name,
                "could not parse any X.509 certificate from PEM file"
            );
        }
        Err(error) => {
            tracing::warn!(
                pushkin = pushkin_name,
                error = %error,
                "failed to read certificate file for expiry monitoring"
            );
        }
    }
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use arkret_models_integration::{
        PushCounts, PushDeviceRoute, PushNotificationEnvelope, PushRouteTokens,
    };
    use serde_json::json;

    use super::*;

    fn device() -> PushDeviceRoute {
        PushDeviceRoute {
            device_id: arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            app_id: Some("com.example.apns".to_owned()),
            push_key: Some(arkret_models_integration::PushKey::new("spqr").unwrap()),
            platform: None,
            target_route_token: None,
            visible_notification_opt_in: false,
        }
    }

    fn pushkin() -> ApnsPushkin {
        ApnsPushkin {
            matcher: AppMatcher::new("com.example.apns".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            client: Client::builder().build().unwrap(),
            auth: ApnsAuth::Certificate { topic: None },
            use_sandbox: false,
            push_type: None,
            convert_device_token_to_hex: false,
            send_badge_counts: true,
        }
    }

    #[test]
    fn builds_message_payload() {
        let pushkin = pushkin();
        let notification = PushNotificationEnvelope {
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
            user_is_target: None,
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
        };

        let payload = pushkin
            .build_payload(&notification, Map::new(), true)
            .unwrap()
            .unwrap();

        // T4.3 — stable correlation identifiers are stripped. The
        // visible alert still renders from allowed labels in `aps.alert`,
        // but message content is ignored and the freeform extension keys
        // only carry the SDK-allowed blind fields.
        assert_eq!(
            payload,
            json!({
                "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                "wakeup_kind": "message",
                "aps": {
                    "alert": {
                        "loc-key": "MSG_FROM_USER_IN_ROOM",
                        "loc-args": [
                            "Major Tom",
                            "Mission Control"
                        ]
                    },
                    // Blind wakeups expose only a boolean unread badge.
                    "badge": 1
                }
            })
        );
    }

    #[test]
    fn builds_event_id_only_payload() {
        let pushkin = pushkin();
        let device = device();
        let notification = PushNotificationEnvelope {
            strand_title: None,
            realm_title: None,
            priority: None,
            membership: None,
            sender_actor_display_name: None,
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
            user_is_target: None,
            push_target_id: Some(
                arkret_wire::PushTargetId::new(
                    "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                )
                .unwrap(),
            ),
            wakeup_kind: None,
            push_hint: None,
            devices: vec![device.clone()],
            counts: Some(PushCounts {
                badge: None,
                unread_increment: None,
                missed_call: None,
            }),
            ..Default::default()
        };

        let payload = pushkin
            .build_payload(&notification, Map::new(), false)
            .unwrap()
            .unwrap();

        assert_eq!(
            payload,
            json!({
                "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                "aps": {
                    "content-available": 1
                }
            })
        );
    }

    #[test]
    fn invalid_apns_token_is_rejected() {
        let result = classify_apns_response(410, "Unregistered", "spqr").unwrap();

        assert_eq!(result, vec!["spqr".to_owned()]);
    }

    #[test]
    fn apns_server_errors_are_temporary() {
        let error = classify_apns_response(503, "ServiceUnavailable", "spqr").unwrap_err();

        assert!(error.is_temporary());
        assert_eq!(
            error.to_string(),
            "APNS temporary failure: 503 ServiceUnavailable"
        );
    }
}
