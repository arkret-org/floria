//! Custom URL pushkin.
//!
//! Routes notifications to an arbitrary HTTPS endpoint chosen by the
//! operator. Supports three outbound authentication modes that can be
//! mixed and matched: Bearer token, HMAC-SHA256 signature header, and
//! mTLS client certificate. The endpoint URL may include a
//! `{push_key}` template variable that the gateway substitutes at
//! dispatch time so the same pushkin can fan out to per-user webhooks.

use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use prometheus::{Histogram, register_histogram, register_int_counter_vec};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, Identity, Proxy};
use serde_json::{Map, Value, json};
use sha2::Sha256;
use tokio::sync::Semaphore;
use tokio::time::sleep;

use super::reqwest_support::{header_value, parse_retry_after};
use super::{
    AppMatcher, ConcurrencyGate, Pushkin, build_blind_routing_data, inflight_limit,
    max_connections, sanitized_provider_payload,
};
use crate::auth::redact_url_credentials;
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, DeviceExt, Notification, NotificationContext};

static CUSTOM_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_custom_request_time",
        "Time taken for an outbound request to a custom URL pushkin"
    )
    .expect("register floria_custom_request_time")
});

static CUSTOM_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_custom_status_codes",
        "HTTP response status codes received from custom URL pushkins",
        &["pushkin", "code"]
    )
    .expect("register floria_custom_status_codes")
});

const PUSH_KEY_PLACEHOLDER: &str = "{push_key}";
const CUSTOM_MAX_TRIES: usize = 3;
const CUSTOM_RETRY_DELAY_BASE_SECS: u64 = 5;

pub struct CustomPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    _connection_semaphore: Arc<Semaphore>,
    client: Client,
    url_template: String,
    auth: CustomAuth,
}

enum CustomAuth {
    None,
    Bearer {
        token: String,
    },
    Hmac {
        key_id: String,
        secret: Vec<u8>,
        header: String,
    },
}

impl CustomPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config, base_dir: &Path) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "url",
                "auth",
                "bearer_token",
                "hmac_key_id",
                "hmac_secret",
                "hmac_header",
                "client_certfile",
                "max_connections",
                "inflight_request_limit",
            ],
        );
        let matcher = AppMatcher::new(name)?;
        let gate = ConcurrencyGate::new(inflight_limit(app)?);
        let connection_semaphore = Arc::new(Semaphore::new(max_connections(app)?.max(1)));

        let url = app
            .get_string("url")?
            .context("custom pushkin requires url")?;
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            bail!("custom pushkin url must be http(s): `{url}`");
        }
        let validation_url = url.replace(PUSH_KEY_PLACEHOLDER, "probe");
        crate::egress::validate_http_url_for_egress(&validation_url, "custom pushkin url")
            .map_err(anyhow::Error::msg)?;

        let auth_kind = app.get_string("auth")?.unwrap_or_else(|| "none".to_owned());
        let auth = match auth_kind.as_str() {
            "none" => CustomAuth::None,
            "bearer" => {
                let token = app
                    .get_string("bearer_token")?
                    .context("custom pushkin auth=bearer requires bearer_token")?;
                CustomAuth::Bearer { token }
            }
            "hmac" => {
                let key_id = app
                    .get_string("hmac_key_id")?
                    .context("custom pushkin auth=hmac requires hmac_key_id")?;
                let secret = app
                    .get_string("hmac_secret")?
                    .context("custom pushkin auth=hmac requires hmac_secret")?;
                let header = app
                    .get_string("hmac_header")?
                    .unwrap_or_else(|| "x-floria-signature".to_owned());
                CustomAuth::Hmac {
                    key_id,
                    secret: secret.into_bytes(),
                    header,
                }
            }
            other => bail!("custom pushkin auth must be one of: none, bearer, hmac; got `{other}`"),
        };

        let identity_path = app.require_existing_file(base_dir, "client_certfile")?;
        let client = build_http_client(config.outbound_proxy(), identity_path.as_deref())?;

        Ok(Self {
            matcher,
            gate,
            _connection_semaphore: connection_semaphore,
            client,
            url_template: url,
            auth,
        })
    }

    fn resolve_url(&self, device: &Device) -> Result<String, DispatchError> {
        if !self.url_template.contains(PUSH_KEY_PLACEHOLDER) {
            return Ok(self.url_template.clone());
        }
        let escaped = urlencoding_encode(device.push_key().unwrap_or_default());
        Ok(self.url_template.replace(PUSH_KEY_PLACEHOLDER, &escaped))
    }

    fn build_body(
        &self,
        notification: &Notification,
        device: &Device,
    ) -> Result<Map<String, Value>, DispatchError> {
        // T4.3 — the custom-URL pushkin used to forward `event_id` /
        // `message_id` to the operator's webhook. Both are stable
        // correlation identifiers and must not leave the gateway.
        // What survives:
        //   * `delivered_at`     — wall-clock for the operator's logs
        //   * `app_id`           — routing key the webhook keys on
        //   * `push_key_hash`    — already a blake2 truncation
        //   * `wakeup_kind`      — closed enum, validated by the SDK
        //   * `push_hint`        — only when SDK-validated literal
        //   * `push_target_id`   — opaque pseudonym
        let mut payload = Map::new();
        payload.insert(
            "delivered_at".to_owned(),
            json!(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            ),
        );
        payload.insert(
            "app_id".to_owned(),
            Value::String(device.app_id().unwrap_or_default().to_owned()),
        );
        payload.insert(
            "push_key_hash".to_owned(),
            Value::String(device.redacted_push_key()),
        );
        payload.extend(build_blind_routing_data(notification));
        sanitized_provider_payload(payload).map_err(|rejection| {
            DispatchError::remote(format!("custom pushkin payload rejected: {rejection}"))
        })
    }

    async fn send_once(
        &self,
        notification: &Notification,
        device: &Device,
    ) -> Result<Vec<String>, DispatchError> {
        let url = self.resolve_url(device)?;
        let parsed_url =
            crate::egress::validate_http_url_for_egress(&url, "custom pushkin request")
                .map_err(DispatchError::remote)?;
        let body = self.build_body(notification, device)?;
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|error| DispatchError::internal(format!("failed to encode body: {error}")))?;

        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        match &self.auth {
            CustomAuth::None => {}
            CustomAuth::Bearer { token } => {
                headers.insert(AUTHORIZATION, header_value(&format!("Bearer {token}"))?);
            }
            CustomAuth::Hmac {
                key_id,
                secret,
                header,
            } => {
                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(secret).map_err(|error| {
                    DispatchError::internal(format!("invalid hmac secret: {error}"))
                })?;
                mac.update(&body_bytes);
                let signature = mac.finalize().into_bytes();
                let value = format!(
                    "keyId=\"{key_id}\";alg=\"hmac-sha256\";signature=\"{}\"",
                    base64::engine::general_purpose::STANDARD.encode(signature)
                );
                let header_name: reqwest::header::HeaderName = header.parse().map_err(|error| {
                    DispatchError::internal(format!("invalid hmac header: {error}"))
                })?;
                headers.insert(header_name, header_value(&value)?);
            }
        }

        let started = Instant::now();
        let response = self
            .client
            .post(parsed_url)
            .headers(headers)
            .body(body_bytes)
            .send()
            .await
            .map_err(|error| {
                CUSTOM_REQUEST_TIME.observe(started.elapsed().as_secs_f64());
                DispatchError::temporary(format!("custom pushkin request failed: {error}"), None)
            })?;
        CUSTOM_REQUEST_TIME.observe(started.elapsed().as_secs_f64());

        let status = response.status();
        CUSTOM_STATUS_CODES
            .with_label_values(&[self.name(), &status.as_u16().to_string()])
            .inc();
        let retry_after = parse_retry_after(response.headers());
        let body_text = response.text().await.unwrap_or_default();
        match status.as_u16() {
            200..=299 => Ok(vec![]),
            410 | 404 => Ok(vec![device.push_key().unwrap_or_default().to_owned()]),
            429 | 500..=599 => Err(DispatchError::temporary(
                format!(
                    "custom pushkin {} responded {status}: {body_text}",
                    redact_url_credentials(&url)
                ),
                retry_after,
            )),
            _ => Err(DispatchError::remote(format!(
                "custom pushkin {} rejected: {status} {body_text}",
                redact_url_credentials(&url)
            ))),
        }
    }
}

#[async_trait]
impl Pushkin for CustomPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        "custom"
    }

    fn handles_app_id(&self, app_id: &str) -> bool {
        self.matcher.handles_app_id(app_id)
    }

    async fn dispatch_notification(
        &self,
        notification: &Notification,
        device: &Device,
        _context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        let _permit = self.gate.acquire(self.name())?;
        if device.push_key().is_none() {
            return Ok(vec![device.push_key().unwrap_or_default().to_owned()]);
        }

        for attempt in 0..CUSTOM_MAX_TRIES {
            match self.send_once(notification, device).await {
                Ok(rejected) => return Ok(rejected),
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < CUSTOM_MAX_TRIES => {
                    let retry_after = error.retry_after().unwrap_or_else(|| {
                        Duration::from_secs(CUSTOM_RETRY_DELAY_BASE_SECS * (1_u64 << attempt))
                    });
                    sleep(retry_after).await;
                }
                Err(error) => return Err(error),
            }
        }
        Err(DispatchError::remote(
            "custom pushkin retried too many times",
        ))
    }
}

fn build_http_client(proxy: Option<&str>, identity_path: Option<&Path>) -> Result<Client> {
    let mut builder = Client::builder()
        .user_agent("floria")
        .connect_timeout(super::reqwest_support::CONNECT_TIMEOUT)
        .timeout(super::reqwest_support::REQUEST_TIMEOUT)
        .dns_resolver(crate::egress::EgressGuardResolver::from_env())
        .http2_adaptive_window(true)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(proxy) = proxy {
        builder =
            builder.proxy(Proxy::all(proxy).with_context(|| {
                format!("invalid proxy URL `{}`", redact_url_credentials(proxy))
            })?);
    }
    if let Some(path) = identity_path {
        let pem =
            std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        let identity = Identity::from_pem(&pem).context("invalid client certificate bundle")?;
        builder = builder.identity(identity);
    }
    builder
        .build()
        .context("failed to build custom HTTP client")
}

fn urlencoding_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_template_substitutes_push_key() {
        let pushkin = CustomPushkin {
            matcher: AppMatcher::new("com.example.custom".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            _connection_semaphore: Arc::new(Semaphore::new(1)),
            client: Client::builder().build().unwrap(),
            url_template: "https://example.com/notify/{push_key}".to_owned(),
            auth: CustomAuth::None,
        };
        let device = Device {
            device_id: cokret::DeviceId::new("ck:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            app_id: Some("com.example.custom".to_owned()),
            push_key: Some("user/abc".to_owned()),
            platform: None,
            target_actor_id: None,
            visible_notification_opt_in: false,
        };
        let url = pushkin.resolve_url(&device).unwrap();
        assert_eq!(url, "https://example.com/notify/user%2Fabc");
    }
}
