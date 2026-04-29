use std::path::Path;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
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

use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext};

use super::reqwest_support::header_value;
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit};

static APNS_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "soflare_apns_request_time",
        "Time taken to send HTTP request to APNS"
    )
    .expect("register soflare_apns_request_time")
});

static APNS_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "soflare_active_apns_requests",
        "Number of APNS requests in flight"
    )
    .expect("register soflare_active_apns_requests")
});

static APNS_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "soflare_apns_status_codes",
        "Number of HTTP response status codes received from APNS",
        &["pushkin", "code"]
    )
    .expect("register soflare_apns_status_codes")
});

static CLIENT_CERT_EXPIRY: LazyLock<prometheus::GaugeVec> = LazyLock::new(|| {
    prometheus::register_gauge_vec!(
        "soflare_client_cert_expiry",
        "The expiry date of the client certificate in seconds since the epoch",
        &["pushkin"]
    )
    .expect("register soflare_client_cert_expiry")
});

const APNS_MAX_TRIES: usize = 3;
const APNS_RETRY_DELAY_BASE_SECS: u64 = 10;
const APNS_MAX_FIELD_LENGTH: usize = 1024;
const APNS_MAX_JSON_BODY_SIZE: usize = 4096;
const APNS_TOKEN_TTL_SECS: u64 = 50 * 60;
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
    team_id: String,
    key_id: String,
    key: EncodingKey,
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
                    team_id,
                    key_id,
                    key,
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
        device: &Device,
        payload: &Value,
        priority: u8,
    ) -> Result<Vec<String>, DispatchError> {
        let device_token = self.device_token(device)?;
        let url = format!("{}/{device_token}", self.base_url());

        let notif_id = Uuid::new_v4().to_string();

        let mut headers = HeaderMap::new();
        headers.insert(
            "apns-priority",
            HeaderValue::from_str(&priority.to_string()).unwrap(),
        );
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

        match (status, reason.as_str()) {
            (400, "BadDeviceToken")
            | (400, "DeviceTokenNotForTopic")
            | (400, "TopicDisallowed")
            | (410, "Unregistered") => Ok(vec![device.pushkey.clone()]),
            (500..=599, _) => Err(DispatchError::temporary(
                format!("APNS temporary failure: {status} {reason}"),
                None,
            )),
            _ => Err(DispatchError::remote(format!(
                "APNS rejected request: {status} {reason}"
            ))),
        }
    }

    fn device_token(&self, device: &Device) -> Result<String, DispatchError> {
        if !self.convert_device_token_to_hex {
            return Ok(device.pushkey.clone());
        }

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&device.pushkey)
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
        notification: &Notification,
        default_payload: Map<String, Value>,
    ) -> Result<Option<Value>, DispatchError> {
        if notification.event_id.is_some() && notification.r#type.is_none() {
            return Ok(Some(
                self.payload_event_id_only(notification, default_payload),
            ));
        }

        Ok(self.payload_full(notification, default_payload))
    }

    fn payload_event_id_only(
        &self,
        notification: &Notification,
        default_payload: Map<String, Value>,
    ) -> Value {
        let mut payload = default_payload;
        if let Some(room_id) = &notification.room_id {
            payload.insert("room_id".to_owned(), Value::String(room_id.clone()));
        }
        if let Some(event_id) = &notification.event_id {
            payload.insert("event_id".to_owned(), Value::String(event_id.clone()));
        }
        if self.send_badge_counts {
            if let Some(unread) = notification.counts.unread {
                payload.insert("unread_count".to_owned(), Value::Number(unread.into()));
            }
            if let Some(missed_calls) = notification.counts.missed_calls {
                payload.insert(
                    "missed_calls".to_owned(),
                    Value::Number(missed_calls.into()),
                );
            }
        }
        Value::Object(payload)
    }

    fn payload_full(
        &self,
        notification: &Notification,
        mut default_payload: Map<String, Value>,
    ) -> Option<Value> {
        let from_display = notification
            .sender_display_name
            .clone()
            .or_else(|| notification.sender.clone())
            .unwrap_or_else(|| " ".to_owned());
        let from_display = trim_chars(&from_display, APNS_MAX_FIELD_LENGTH);

        let mut loc_key = None;
        let mut loc_args: Vec<String> = Vec::new();

        match notification.r#type.as_deref() {
            Some("m.room.message") | Some("m.room.encrypted") => {
                let room_display = notification
                    .room_name
                    .as_ref()
                    .or(notification.room_alias.as_ref())
                    .map(|value| trim_chars(value, APNS_MAX_FIELD_LENGTH));
                let msgtype = notification
                    .content
                    .as_ref()
                    .and_then(|content| content.get("msgtype"))
                    .and_then(Value::as_str);
                let body = notification
                    .content
                    .as_ref()
                    .and_then(|content| content.get("body"))
                    .and_then(Value::as_str);
                let content_display = body.map(|body| trim_chars(body, APNS_MAX_FIELD_LENGTH));
                let action_display = if msgtype == Some("m.emote") {
                    content_display.clone()
                } else {
                    None
                };
                let is_image = msgtype == Some("m.image");

                if let Some(room_display) = room_display {
                    match (is_image, content_display.clone(), action_display.clone()) {
                        (true, content, _) => {
                            loc_key = Some("IMAGE_FROM_USER_IN_ROOM");
                            loc_args = vec![
                                from_display.clone(),
                                content.unwrap_or_default(),
                                room_display,
                            ];
                        }
                        (false, Some(content), _) if msgtype != Some("m.emote") => {
                            loc_key = Some("MSG_FROM_USER_IN_ROOM_WITH_CONTENT");
                            loc_args = vec![from_display.clone(), room_display, content];
                        }
                        (false, _, Some(action)) => {
                            loc_key = Some("ACTION_FROM_USER_IN_ROOM");
                            loc_args = vec![room_display, from_display.clone(), action];
                        }
                        _ => {
                            loc_key = Some("MSG_FROM_USER_IN_ROOM");
                            loc_args = vec![from_display.clone(), room_display];
                        }
                    }
                } else {
                    match (is_image, content_display.clone(), action_display.clone()) {
                        (true, content, _) => {
                            loc_key = Some("IMAGE_FROM_USER");
                            loc_args = vec![from_display.clone(), content.unwrap_or_default()];
                        }
                        (false, Some(content), _) if msgtype != Some("m.emote") => {
                            loc_key = Some("MSG_FROM_USER_WITH_CONTENT");
                            loc_args = vec![from_display.clone(), content];
                        }
                        (false, _, Some(action)) => {
                            loc_key = Some("ACTION_FROM_USER");
                            loc_args = vec![from_display.clone(), action];
                        }
                        _ => {
                            loc_key = Some("MSG_FROM_USER");
                            loc_args = vec![from_display.clone()];
                        }
                    }
                }
            }
            Some("m.call.invite") => {
                let is_video = notification
                    .content
                    .as_ref()
                    .and_then(|content| content.get("offer"))
                    .and_then(Value::as_object)
                    .and_then(|offer| offer.get("sdp"))
                    .and_then(Value::as_str)
                    .map(|sdp| sdp.contains("m=video"))
                    .unwrap_or(false);
                loc_key = Some(if is_video {
                    "VIDEO_CALL_FROM_USER"
                } else {
                    "VOICE_CALL_FROM_USER"
                });
                loc_args = vec![from_display.clone()];
            }
            Some("m.room.member")
                if notification.user_is_target == Some(true)
                    && notification.membership.as_deref() == Some("invite") =>
            {
                if let Some(room_name) = notification
                    .room_name
                    .as_ref()
                    .or(notification.room_alias.as_ref())
                {
                    loc_key = Some("USER_INVITE_TO_NAMED_ROOM");
                    loc_args = vec![
                        from_display.clone(),
                        trim_chars(room_name, APNS_MAX_FIELD_LENGTH),
                    ];
                } else {
                    loc_key = Some("USER_INVITE_TO_CHAT");
                    loc_args = vec![from_display.clone()];
                }
            }
            Some(_) => {
                loc_key = Some("MSG_FROM_USER");
                loc_args = vec![from_display.clone()];
            }
            None => {}
        }

        let badge = if self.send_badge_counts {
            let mut badge = notification.counts.unread.unwrap_or(0);
            if let Some(missed_calls) = notification.counts.missed_calls {
                badge += missed_calls;
            }
            if badge == 0
                && notification.counts.unread.is_none()
                && notification.counts.missed_calls.is_none()
            {
                None
            } else {
                Some(badge)
            }
        } else {
            None
        };

        if loc_key.is_none() && badge.is_none() {
            return None;
        }

        let aps = default_payload
            .entry("aps")
            .or_insert_with(|| Value::Object(Map::new()));
        let aps_object = aps.as_object_mut()?;

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

        if loc_key.is_some() {
            if let Some(room_id) = &notification.room_id {
                default_payload.insert("room_id".to_owned(), Value::String(room_id.clone()));
            }
            if let Some(event_id) = &notification.event_id {
                default_payload.insert("event_id".to_owned(), Value::String(event_id.clone()));
            }
        }

        let mut payload = Value::Object(default_payload);
        trim_apns_payload(&mut payload, APNS_MAX_JSON_BODY_SIZE);
        Some(payload)
    }
}

#[async_trait]
impl Pushkin for ApnsPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn handles_appid(&self, appid: &str) -> bool {
        self.matcher.handles_appid(appid)
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
                tracing::warn!(pushkey = %device.pushkey, "rejecting APNS pushkey due to invalid default_payload");
                return Ok(vec![device.pushkey.clone()]);
            }
        };

        let Some(payload) = self.build_payload(notification, default_payload)? else {
            return Ok(vec![]);
        };
        let priority = if notification.prio.as_deref() == Some("low") {
            5
        } else {
            10
        };

        for attempt in 0..APNS_MAX_TRIES {
            match self.send_once(device, &payload, priority).await {
                Ok(result) => return Ok(result),
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < APNS_MAX_TRIES => {
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
        let now = epoch_now();
        {
            let cache = self.cache.lock().await;
            if let Some(cache) = cache.as_ref()
                && cache.expires_at > now + 5
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
            expires_at: now + APNS_TOKEN_TTL_SECS,
        });
        Ok(token)
    }
}

#[derive(Debug, serde::Deserialize)]
struct ApnsErrorBody {
    #[serde(default)]
    reason: Option<String>,
}

fn build_http_client(proxy: Option<&str>, identity_path: Option<&Path>) -> Result<Client> {
    let mut builder = Client::builder()
        .tls_backend_native()
        .http2_adaptive_window(true);
    if let Some(proxy) = proxy {
        builder = builder
            .proxy(Proxy::all(proxy).with_context(|| format!("invalid proxy URL `{proxy}`"))?);
    }
    if let Some(identity_path) = identity_path {
        let pem = std::fs::read(identity_path)
            .with_context(|| format!("failed to read {}", identity_path.display()))?;
        let (cert, key) = split_identity_pem(&pem)?;
        let identity =
            Identity::from_pkcs8_pem(&cert, &key).context("invalid PEM certificate bundle")?;
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

fn split_identity_pem(pem: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let pem = String::from_utf8_lossy(pem);

    let cert = collect_pem_blocks(&pem, "CERTIFICATE");
    if cert.is_empty() {
        bail!("certificate PEM does not contain any CERTIFICATE blocks");
    }

    for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"] {
        if let Some(key) = first_pem_block(&pem, label) {
            return Ok((cert.into_bytes(), key.into_bytes()));
        }
    }

    bail!("certificate PEM does not contain a supported private key block")
}

fn collect_pem_blocks(pem: &str, label: &str) -> String {
    let mut blocks = String::new();
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut start = 0usize;

    while let Some(begin_index) = pem[start..].find(&begin) {
        let block_start = start + begin_index;
        let Some(end_index) = pem[block_start..].find(&end) else {
            break;
        };
        let block_end = block_start + end_index + end.len();
        blocks.push_str(&pem[block_start..block_end]);
        blocks.push('\n');
        start = block_end;
    }

    blocks
}

fn first_pem_block(pem: &str, label: &str) -> Option<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin)?;
    let end_index = pem[start..].find(&end)?;
    let block_end = start + end_index + end.len();
    Some(format!("{}\n", &pem[start..block_end]))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::models::{Counts, Device, Notification, Tweaks};

    fn device() -> Device {
        Device {
            app_id: "com.example.apns".to_owned(),
            pushkey: "spqr".to_owned(),
            pushkey_ts: 42,
            data: None,
            tweaks: Tweaks::default(),
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
        let notification = Notification {
            room_name: Some("Mission Control".to_owned()),
            room_alias: None,
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
            user_is_target: None,
            r#type: Some("m.room.message".to_owned()),
            sender: Some("@major:example.com".to_owned()),
            devices: vec![device()],
            counts: Counts {
                unread: Some(3),
                missed_calls: None,
            },
        };

        let payload = pushkin
            .build_payload(&notification, Map::new())
            .unwrap()
            .unwrap();

        assert_eq!(
            payload,
            json!({
                "room_id": "!room:example.com",
                "event_id": "$event",
                "aps": {
                    "alert": {
                        "loc-key": "MSG_FROM_USER_IN_ROOM_WITH_CONTENT",
                        "loc-args": [
                            "Major Tom",
                            "Mission Control",
                            "I'm floating in a most peculiar way."
                        ]
                    },
                    "badge": 3
                }
            })
        );
    }

    #[test]
    fn builds_event_id_only_payload() {
        let pushkin = pushkin();
        let mut device = device();
        device.data = Some(
            json!({
                "default_payload": {
                    "aps": {
                        "mutable-content": 1,
                        "alert": {
                            "loc-key": "SINGLE_UNREAD",
                            "loc-args": []
                        }
                    }
                }
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let notification = Notification {
            room_name: None,
            room_alias: None,
            prio: None,
            membership: None,
            sender_display_name: None,
            content: None,
            event_id: Some("$event".to_owned()),
            room_id: Some("!room:example.com".to_owned()),
            user_is_target: None,
            r#type: None,
            sender: None,
            devices: vec![device.clone()],
            counts: Counts {
                unread: Some(2),
                missed_calls: None,
            },
        };

        let payload = pushkin
            .build_payload(&notification, device.default_payload().unwrap())
            .unwrap()
            .unwrap();

        assert_eq!(
            payload,
            json!({
                "room_id": "!room:example.com",
                "event_id": "$event",
                "unread_count": 2,
                "aps": {
                    "mutable-content": 1,
                    "alert": {
                        "loc-key": "SINGLE_UNREAD",
                        "loc-args": []
                    }
                }
            })
        );
    }
}
