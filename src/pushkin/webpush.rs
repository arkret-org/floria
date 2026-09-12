use std::fmt;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use anyhow::{Context, Result, anyhow};
use arkret_models_integration::{PushNotificationEnvelope, PushRegistrationRecord};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use blake2::digest::Digest;
use globset::{Glob, GlobMatcher};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::Generate;
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::DecodePrivateKey;
use p256::{PublicKey, SecretKey};
use prometheus::{Histogram, IntGauge, register_histogram, register_int_gauge};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::Sha256;
use tokio::sync::Semaphore;

use super::{
    AppMatcher, ConcurrencyGate, Pushkin, build_blind_routing_data, inflight_limit,
    max_connections, notification_badge_count, notification_unread_increment,
    sanitized_provider_payload,
};
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{DeviceExt, NotificationContext, NotificationExt};

static WEBPUSH_QUEUE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_webpush_queue_time",
        "Time taken waiting for a connection to WebPush endpoint"
    )
    .expect("register floria_webpush_queue_time")
});

static WEBPUSH_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_webpush_request_time",
        "Time taken to send HTTP request to WebPush endpoint"
    )
    .expect("register floria_webpush_request_time")
});

static WEBPUSH_PENDING_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_pending_webpush_requests",
        "Number of WebPush requests waiting for a connection"
    )
    .expect("register floria_pending_webpush_requests")
});

static WEBPUSH_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_webpush_requests",
        "Number of WebPush requests in flight"
    )
    .expect("register floria_active_webpush_requests")
});

static WEBPUSH_VAPID_ACTIVE_KEY: LazyLock<prometheus::IntGaugeVec> = LazyLock::new(|| {
    prometheus::register_int_gauge_vec!(
        "floria_webpush_vapid_active_key",
        "Active VAPID key per pushkin. The label `key_fingerprint` is a SHA-256 truncated hash of the on-disk private key; gauge value is the unix timestamp when the gateway loaded it.",
        &["pushkin", "key_fingerprint", "key_id"]
    )
    .expect("register floria_webpush_vapid_active_key")
});

const DEFAULT_WEBPUSH_TTL_SECS: u32 = 15 * 60;
const WEBPUSH_MAX_RESPONSE_SIZE: usize = 64 * 1024;
const WEBPUSH_MAX_PLAINTEXT_SIZE: usize = 3052;
const ECE_AES_KEY_LENGTH: usize = 16;
const ECE_AUTH_SECRET_LENGTH: usize = 16;
const ECE_DEFAULT_PADDING_BLOCK_SIZE: usize = 128;
const ECE_DEFAULT_RS: u32 = 4096;
const ECE_KEY_ID_LENGTH: u8 = 65;
const ECE_NONCE_LENGTH: usize = 12;
const ECE_PUBLIC_KEY_LENGTH: usize = 65;
const ECE_SALT_LENGTH: usize = 16;
#[cfg(test)]
const MAX_BODY_LENGTH: usize = 1000;

pub struct WebpushPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: Client,
    vapid_key: VapidKeyMaterial,
    vapid_contact_email: String,
    allowed_endpoints: Option<Vec<GlobMatcher>>,
    ttl: u32,
}

struct VapidKeyMaterial {
    signing_key: SigningKey,
    public_key: Vec<u8>,
}

impl VapidKeyMaterial {
    fn from_pem(bytes: &[u8]) -> Result<Self> {
        let pem = std::str::from_utf8(bytes).context("VAPID private key must be UTF-8 PEM")?;
        let secret_key = SecretKey::from_sec1_pem(pem)
            .or_else(|_| SecretKey::from_pkcs8_pem(pem))
            .context("VAPID private key must be a P-256 PEM key")?;
        Ok(Self::from_signing_key(SigningKey::from(secret_key)))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let public_key = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        Self {
            signing_key,
            public_key,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SubscriptionInfo {
    endpoint: String,
    keys: SubscriptionKeys,
}

#[derive(Debug, Deserialize)]
struct SubscriptionKeys {
    p256dh: String,
    auth: String,
}

#[derive(Debug, Clone, Copy)]
enum Urgency {
    Low,
    Normal,
}

impl Urgency {
    fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
        }
    }
}

struct WebpushMessage {
    endpoint: String,
    ttl: u32,
    urgency: Urgency,
    authorization: String,
    body: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct WebpushErrorInfo {
    #[serde(default)]
    code: u16,
    #[serde(default)]
    errno: u16,
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: String,
}

impl fmt::Display for WebpushErrorInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(
                formatter,
                "{} (code {}, errno {})",
                self.error, self.code, self.errno
            )
        } else {
            write!(
                formatter,
                "{} (code {}, errno {}): {}",
                self.error, self.code, self.errno, self.message
            )
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum WebpushError {
    #[error("webpush request failed")]
    Unspecified,
    #[error("invalid webpush endpoint URI")]
    InvalidUri,
    #[error("missing webpush crypto keys")]
    MissingCryptoKeys,
    #[error("invalid webpush crypto keys")]
    InvalidCryptoKeys,
    #[error("invalid VAPID claims")]
    InvalidClaims,
    #[error("webpush payload is too large")]
    PayloadTooLarge,
    #[error("webpush response exceeded size limit")]
    ResponseTooLarge,
    #[error("webpush unauthorized: {0}")]
    Unauthorized(WebpushErrorInfo),
    #[error("webpush bad request: {0}")]
    BadRequest(WebpushErrorInfo),
    #[error("webpush endpoint not found: {0}")]
    EndpointNotFound(WebpushErrorInfo),
    #[error("webpush endpoint not valid: {0}")]
    EndpointNotValid(WebpushErrorInfo),
    #[error("webpush server error: {info}")]
    ServerError {
        retry_after: Option<Duration>,
        info: WebpushErrorInfo,
    },
    #[error("webpush endpoint error: {0}")]
    Other(WebpushErrorInfo),
}

impl WebpushPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config, base_dir: &Path) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "max_connections",
                "vapid_private_key",
                "vapid_contact_email",
                "vapid_key_id",
                "allowed_endpoints",
                "ttl",
                "inflight_request_limit",
            ],
        );
        let matcher = AppMatcher::new(name)?;
        let gate = ConcurrencyGate::new(inflight_limit(app)?);
        let max_connections = max_connections(app)?.max(1);
        let connection_semaphore = Arc::new(Semaphore::new(max_connections));
        let client = super::reqwest_support::build_reqwest_client(config, "floria")
            .context("failed to build webpush HTTP client")?;

        let vapid_private_key = app
            .require_existing_file(base_dir, "vapid_private_key")?
            .context("webpush config requires vapid_private_key")?;
        let vapid_contact_email = app
            .get_string("vapid_contact_email")?
            .context("webpush config requires vapid_contact_email")?;
        let ttl = app
            .get_u64("ttl")?
            .unwrap_or(DEFAULT_WEBPUSH_TTL_SECS as u64)
            .try_into()
            .map_err(|_| anyhow!("ttl must fit into an unsigned 32-bit integer"))?;

        let allowed_endpoints = app
            .get_string_list("allowed_endpoints")?
            .map(|patterns| {
                patterns
                    .into_iter()
                    .map(|pattern| {
                        Glob::new(&pattern)
                            .with_context(|| {
                                format!("invalid webpush allowed_endpoints glob `{pattern}`")
                            })
                            .map(|glob| glob.compile_matcher())
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?;

        let key_bytes = std::fs::read(&vapid_private_key).with_context(|| {
            format!(
                "failed to read VAPID private key {}",
                vapid_private_key.display()
            )
        })?;
        let vapid_key =
            VapidKeyMaterial::from_pem(&key_bytes).context("invalid VAPID private key")?;
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(&key_bytes);
        let vapid_key_fingerprint = hex::encode(hasher.finalize());
        let vapid_key_fingerprint = vapid_key_fingerprint[..16].to_owned();
        let vapid_key_id = app
            .get_string("vapid_key_id")?
            .unwrap_or_else(|| vapid_key_fingerprint.clone());

        let loaded_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        WEBPUSH_VAPID_ACTIVE_KEY
            .with_label_values(&[
                matcher.name(),
                vapid_key_fingerprint.as_str(),
                vapid_key_id.as_str(),
            ])
            .set(loaded_at_unix);

        Ok(Self {
            matcher,
            gate,
            connection_semaphore,
            client,
            vapid_key,
            vapid_contact_email,
            allowed_endpoints,
            ttl,
        })
    }

    /// Build the WebPush JSON payload that goes into the encrypted
    /// `aes128gcm` body. Only SDK-allowed blind-wakeup fields survive
    /// on the provider wire.
    fn build_payload(
        notification: &PushNotificationEnvelope,
        device: &PushRegistrationRecord,
    ) -> Map<String, Value> {
        let _ = device;
        let mut payload = Map::new();

        payload.extend(build_blind_routing_data(notification));
        if let Some(unread_increment) = notification_unread_increment(notification) {
            payload.insert(
                "unread_count".to_owned(),
                Value::Number(unread_increment.into()),
            );
        }
        if let Some(badge) = notification_badge_count(notification) {
            payload.insert("badge".to_owned(), Value::Number(badge.into()));
        }

        match sanitized_provider_payload(payload) {
            Ok(sanitized) => sanitized,
            Err(rejection) => {
                tracing::warn!(
                    rejection = %rejection,
                    "webpush provider payload contained forbidden field, falling back to minimal payload"
                );
                build_blind_routing_data(notification)
            }
        }
    }

    fn endpoint_domain(endpoint: &str) -> Result<String, DispatchError> {
        let url = Url::parse(endpoint)
            .map_err(|error| DispatchError::remote(format!("invalid webpush endpoint: {error}")))?;
        if url.query().is_some() {
            return Err(DispatchError::remote(
                "invalid webpush endpoint: query string is not allowed",
            ));
        }
        let Some(host) = url.host_str() else {
            return Err(DispatchError::remote(
                "invalid webpush endpoint: missing host",
            ));
        };
        Ok(host.to_owned())
    }

    fn allows_endpoint(&self, endpoint_domain: &str) -> bool {
        endpoint_allowed(self.allowed_endpoints.as_deref(), endpoint_domain)
    }

    /// Validate the endpoint against the egress blocklist before building
    /// the request. The shared reqwest client also installs
    /// the shared guarded DNS resolver, so every connection re-applies the same
    /// blocklist at dial time and closes the DNS-rebinding gap.
    fn validate_endpoint_for_egress(&self, endpoint: &str) -> Result<(), String> {
        let url = Url::parse(endpoint)
            .map_err(|error| format!("webpush endpoint: invalid URL: {error}"))?;
        crate::egress::validate_url_for_egress(&url, "webpush endpoint")
    }

    fn subscription_from_device(
        &self,
        device: &PushRegistrationRecord,
    ) -> Result<SubscriptionInfo, DispatchError> {
        let push_key = device
            .push_key()
            .ok_or_else(|| DispatchError::remote("webpush device is missing push_key"))?;
        serde_json::from_str(push_key).map_err(|error| {
            DispatchError::remote(format!("invalid webpush subscription in push_key: {error}"))
        })
    }

    fn vapid_authorization(&self, subscription: &SubscriptionInfo) -> Result<String, WebpushError> {
        #[derive(Serialize)]
        struct VapidHeader<'a> {
            typ: &'a str,
            alg: &'a str,
        }

        #[derive(Serialize)]
        struct VapidClaims<'a> {
            aud: &'a str,
            exp: u64,
            sub: String,
        }

        let endpoint = Url::parse(&subscription.endpoint).map_err(|_| WebpushError::InvalidUri)?;
        let audience = endpoint.origin().ascii_serialization();
        if audience == "null" {
            return Err(WebpushError::InvalidUri);
        }

        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WebpushError::InvalidClaims)?
            .as_secs()
            + 12 * 60 * 60;
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&VapidHeader {
                typ: "JWT",
                alg: "ES256",
            })
            .map_err(|_| WebpushError::InvalidClaims)?,
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&VapidClaims {
                aud: &audience,
                exp: expires_at,
                sub: format!("mailto:{}", self.vapid_contact_email),
            })
            .map_err(|_| WebpushError::InvalidClaims)?,
        );
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = self.vapid_key.signing_key.sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        Ok(format!(
            "vapid t={token}, k={}",
            URL_SAFE_NO_PAD.encode(&self.vapid_key.public_key)
        ))
    }

    fn build_message(
        &self,
        subscription: &SubscriptionInfo,
        payload: &[u8],
        urgency: Urgency,
    ) -> Result<WebpushMessage, WebpushError> {
        let body = encrypt_webpush_payload(subscription, payload)?;
        let authorization = self.vapid_authorization(subscription)?;
        Ok(WebpushMessage {
            endpoint: subscription.endpoint.clone(),
            ttl: self.ttl,
            urgency,
            authorization,
            body,
        })
    }

    async fn send_message(
        &self,
        subscription: &SubscriptionInfo,
        notification: &PushNotificationEnvelope,
        device: &PushRegistrationRecord,
    ) -> Result<Vec<String>, DispatchError> {
        let payload =
            serde_json::to_vec(&Self::build_payload(notification, device)).map_err(|error| {
                DispatchError::internal(format!("failed to encode webpush payload: {error}"))
            })?;
        let urgency = if notification.is_low_priority() {
            Urgency::Low
        } else {
            Urgency::Normal
        };

        let message = match self.build_message(subscription, &payload, urgency) {
            Ok(message) => message,
            Err(WebpushError::InvalidUri)
            | Err(WebpushError::MissingCryptoKeys)
            | Err(WebpushError::InvalidCryptoKeys) => {
                tracing::warn!(
                    push_key_hash = %device.redacted_push_key(),
                    "rejecting invalid webpush crypto material"
                );
                return Ok(vec![device.push_key().unwrap_or_default().to_owned()]);
            }
            Err(WebpushError::InvalidClaims) => {
                return Err(DispatchError::internal(
                    "failed to build webpush request".to_owned(),
                ));
            }
            Err(error) => {
                return Err(DispatchError::remote(format!(
                    "failed to build webpush request: {error}"
                )));
            }
        };
        WEBPUSH_PENDING_REQUESTS.inc();
        let queue_started = Instant::now();
        let _connection_permit = self
            .connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                WEBPUSH_PENDING_REQUESTS.dec();
                DispatchError::internal("webpush connection semaphore closed")
            })?;
        WEBPUSH_PENDING_REQUESTS.dec();
        WEBPUSH_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

        WEBPUSH_ACTIVE_REQUESTS.inc();
        let request_started = Instant::now();
        let result = self.send_webpush_message(message).await;
        WEBPUSH_ACTIVE_REQUESTS.dec();
        WEBPUSH_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());

        classify_webpush_result(result, device.push_key().unwrap_or_default())
    }

    async fn send_webpush_message(&self, message: WebpushMessage) -> Result<(), WebpushError> {
        let request = self.client.post(&message.endpoint);
        let content_length = message.body.len().to_string();
        let mut response = request
            .header("TTL", message.ttl.to_string())
            .header("Urgency", message.urgency.as_str())
            .header(reqwest::header::AUTHORIZATION, message.authorization)
            .header(reqwest::header::CONTENT_ENCODING, "aes128gcm")
            .header(reqwest::header::CONTENT_LENGTH, content_length)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(message.body)
            .send()
            .await
            .map_err(|_| WebpushError::Unspecified)?;
        let retry_after = super::reqwest_support::parse_retry_after(response.headers());
        let status = response.status();

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| WebpushError::Unspecified)?
        {
            body.extend_from_slice(&chunk);
            if body.len() > WEBPUSH_MAX_RESPONSE_SIZE {
                return Err(WebpushError::ResponseTooLarge);
            }
        }

        parse_webpush_response(status, body, retry_after)
    }
}

#[async_trait]
impl Pushkin for WebpushPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn handles_app_id(&self, app_id: &str) -> bool {
        self.matcher.handles_app_id(app_id)
    }

    async fn dispatch_notification(
        &self,
        notification: &PushNotificationEnvelope,
        device: &PushRegistrationRecord,
        _context: &NotificationContext,
    ) -> Result<Vec<String>, DispatchError> {
        let _permit = self.gate.acquire(self.name())?;

        let subscription = match self.subscription_from_device(device) {
            Ok(subscription) => subscription,
            Err(error) => {
                tracing::warn!(
                    push_key_hash = %device.redacted_push_key(),
                    error = %error,
                    "rejecting invalid webpush subscription"
                );
                return Ok(vec![device.push_key().unwrap_or_default().to_owned()]);
            }
        };

        let endpoint_domain = match Self::endpoint_domain(&subscription.endpoint) {
            Ok(endpoint_domain) => endpoint_domain,
            Err(error) => {
                tracing::warn!(
                    push_key_hash = %device.redacted_push_key(),
                    error = %error,
                    "rejecting invalid webpush endpoint"
                );
                return Ok(vec![device.push_key().unwrap_or_default().to_owned()]);
            }
        };

        // Both guards below fail the dispatch rather than returning
        // `Ok(vec![])`. An empty reject list means "delivered, no devices to
        // unregister", so reporting it here would book a withheld push as a
        // success: the caller could neither retry nor count it, and an
        // unconfigured `allowed_endpoints` (fail-closed by design — see
        // docs/en/configuration.md) would silently blackhole every WebPush.
        // These are policy decisions, not provider faults, so they are
        // permanent (`remote`) rather than retryable.
        if !self.allows_endpoint(&endpoint_domain) {
            tracing::error!(
                push_key_hash = %device.redacted_push_key(),
                endpoint = %endpoint_domain,
                "webpush endpoint not allowed by configuration"
            );
            return Err(DispatchError::remote(format!(
                "webpush endpoint {endpoint_domain} is not permitted by allowed_endpoints"
            )));
        }

        if let Err(error) = self.validate_endpoint_for_egress(&subscription.endpoint) {
            tracing::error!(
                push_key_hash = %device.redacted_push_key(),
                endpoint = %endpoint_domain,
                error = %error,
                "webpush endpoint rejected by egress policy"
            );
            return Err(DispatchError::remote(format!(
                "webpush endpoint {endpoint_domain} rejected by egress policy: {error}"
            )));
        }

        self.send_message(&subscription, notification, device).await
    }
}

fn decode_webpush_key(raw: &str) -> Result<Vec<u8>, WebpushError> {
    if raw.is_empty() {
        return Err(WebpushError::MissingCryptoKeys);
    }
    URL_SAFE_NO_PAD
        .decode(raw)
        .or_else(|_| URL_SAFE.decode(raw))
        .map_err(|_| WebpushError::InvalidCryptoKeys)
}

fn encrypt_webpush_payload(
    subscription: &SubscriptionInfo,
    plaintext: &[u8],
) -> Result<Vec<u8>, WebpushError> {
    if plaintext.is_empty() {
        return Err(WebpushError::InvalidCryptoKeys);
    }
    if plaintext.len() > WEBPUSH_MAX_PLAINTEXT_SIZE {
        return Err(WebpushError::PayloadTooLarge);
    }

    let receiver_public = decode_webpush_key(&subscription.keys.p256dh)?;
    let auth_secret = decode_webpush_key(&subscription.keys.auth)?;
    if receiver_public.len() != ECE_PUBLIC_KEY_LENGTH || auth_secret.len() != ECE_AUTH_SECRET_LENGTH
    {
        return Err(WebpushError::InvalidCryptoKeys);
    }

    let receiver_public = PublicKey::from_sec1_bytes(&receiver_public)
        .map_err(|_| WebpushError::InvalidCryptoKeys)?;
    let mut salt = [0u8; ECE_SALT_LENGTH];
    getrandom::fill(&mut salt).map_err(|_| WebpushError::Unspecified)?;
    let sender_secret = EphemeralSecret::generate();
    let sender_public = sender_secret
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec();
    if sender_public.len() != ECE_PUBLIC_KEY_LENGTH {
        return Err(WebpushError::InvalidCryptoKeys);
    }

    let shared_secret = sender_secret.diffie_hellman(&receiver_public);
    let ikm_info = webpush_ikm_info(
        receiver_public.to_sec1_point(false).as_bytes(),
        &sender_public,
    )?;
    let auth_hkdf = Hkdf::<Sha256>::new(Some(&auth_secret), shared_secret.raw_secret_bytes());
    let mut ikm = [0u8; 32];
    auth_hkdf
        .expand(&ikm_info, &mut ikm)
        .map_err(|_| WebpushError::InvalidCryptoKeys)?;

    let salt_hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut key = [0u8; ECE_AES_KEY_LENGTH];
    salt_hkdf
        .expand(b"Content-Encoding: aes128gcm\0", &mut key)
        .map_err(|_| WebpushError::InvalidCryptoKeys)?;
    let mut nonce = [0u8; ECE_NONCE_LENGTH];
    salt_hkdf
        .expand(b"Content-Encoding: nonce\0", &mut nonce)
        .map_err(|_| WebpushError::InvalidCryptoKeys)?;

    let padding_length =
        ECE_DEFAULT_PADDING_BLOCK_SIZE - (plaintext.len() % ECE_DEFAULT_PADDING_BLOCK_SIZE);
    let record_len = plaintext.len() + padding_length;
    if record_len + 16 > ECE_DEFAULT_RS as usize {
        return Err(WebpushError::PayloadTooLarge);
    }
    let mut padded = Vec::with_capacity(record_len);
    padded.extend_from_slice(plaintext);
    padded.push(2);
    padded.resize(record_len, 0);

    let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| WebpushError::InvalidCryptoKeys)?;
    let nonce = Nonce::from(nonce);
    let ciphertext = cipher
        .encrypt(&nonce, padded.as_slice())
        .map_err(|_| WebpushError::InvalidCryptoKeys)?;

    let mut body =
        Vec::with_capacity(ECE_SALT_LENGTH + 4 + 1 + ECE_PUBLIC_KEY_LENGTH + ciphertext.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&ECE_DEFAULT_RS.to_be_bytes());
    body.push(ECE_KEY_ID_LENGTH);
    body.extend_from_slice(&sender_public);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

fn webpush_ikm_info(receiver_public: &[u8], sender_public: &[u8]) -> Result<Vec<u8>, WebpushError> {
    if receiver_public.len() != ECE_PUBLIC_KEY_LENGTH
        || sender_public.len() != ECE_PUBLIC_KEY_LENGTH
    {
        return Err(WebpushError::InvalidCryptoKeys);
    }
    let mut info = Vec::with_capacity("WebPush: info\0".len() + ECE_PUBLIC_KEY_LENGTH * 2);
    info.extend_from_slice(b"WebPush: info\0");
    info.extend_from_slice(receiver_public);
    info.extend_from_slice(sender_public);
    Ok(info)
}

fn parse_webpush_response(
    status: StatusCode,
    body: Vec<u8>,
    retry_after: Option<Duration>,
) -> Result<(), WebpushError> {
    if status.is_success() {
        return Ok(());
    }

    let info = webpush_error_info(status, body);
    match status {
        StatusCode::UNAUTHORIZED => Err(WebpushError::Unauthorized(info)),
        StatusCode::GONE => Err(WebpushError::EndpointNotValid(info)),
        StatusCode::NOT_FOUND => Err(WebpushError::EndpointNotFound(info)),
        StatusCode::PAYLOAD_TOO_LARGE => Err(WebpushError::PayloadTooLarge),
        StatusCode::BAD_REQUEST => Err(WebpushError::BadRequest(info)),
        status if status.is_server_error() => Err(WebpushError::ServerError { retry_after, info }),
        _ => Err(WebpushError::Other(info)),
    }
}

fn webpush_error_info(status: StatusCode, body: Vec<u8>) -> WebpushErrorInfo {
    serde_json::from_slice(&body).unwrap_or_else(|_| WebpushErrorInfo {
        code: status.as_u16(),
        errno: 999,
        error: "unknown error".to_owned(),
        message: String::from_utf8(body).unwrap_or_else(|_| "-".to_owned()),
    })
}

fn endpoint_allowed(allowed_endpoints: Option<&[GlobMatcher]>, endpoint_domain: &str) -> bool {
    allowed_endpoints.is_some_and(|patterns| {
        patterns
            .iter()
            .any(|pattern| pattern.is_match(endpoint_domain))
    })
}

fn classify_webpush_result(
    result: Result<(), WebpushError>,
    push_key: &str,
) -> Result<Vec<String>, DispatchError> {
    match result {
        Ok(()) => Ok(vec![]),
        Err(WebpushError::EndpointNotFound(_) | WebpushError::EndpointNotValid(_)) => {
            Ok(vec![push_key.to_owned()])
        }
        Err(WebpushError::ServerError { retry_after, info }) => Err(DispatchError::temporary(
            format!("webpush server error: {info}"),
            retry_after,
        )),
        Err(WebpushError::Unauthorized(info)) => Err(DispatchError::remote(format!(
            "webpush unauthorized: {info}"
        ))),
        Err(WebpushError::BadRequest(info)) => Err(DispatchError::remote(format!(
            "webpush bad request: {info}"
        ))),
        Err(WebpushError::Other(info)) => Err(DispatchError::remote(format!(
            "webpush endpoint error: {info}"
        ))),
        Err(WebpushError::Unspecified) => Err(DispatchError::temporary(
            "webpush request failed".to_owned(),
            None,
        )),
        Err(error) => Err(DispatchError::remote(format!(
            "webpush request failed: {error}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use arkret_models_integration::{PushCounts, PushRouteTokens};
    use serde_json::json;

    use super::*;
    use crate::config::{AppConfig, Config};

    fn device() -> PushRegistrationRecord {
        crate::pushkin::test_fixtures::device("com.example.web", "p256dh-key")
    }

    fn subscription_push_key(endpoint: &str) -> String {
        json!({
            "endpoint": endpoint,
            "keys": {
                "p256dh": "BH1HTeKM7-NwaLGHEqxeu2IamQaVVLkcsFHPIHmsCnqxcBHPQBprF41bEMOr3O1hUQ2jU1opNEm1F_lZV_sxMP8",
                "auth": "sBXU5_tIYz-5w7G2B25BEw"
            }
        })
        .to_string()
    }

    fn network_device(endpoint: &str) -> PushRegistrationRecord {
        crate::pushkin::test_fixtures::device("com.example.web", &subscription_push_key(endpoint))
    }

    fn pushkin_with_allowed_endpoints(
        allowed_endpoints: Option<Vec<GlobMatcher>>,
    ) -> WebpushPushkin {
        WebpushPushkin {
            matcher: AppMatcher::new("com.example.web".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client: super::super::reqwest_support::build_reqwest_client(
                &Config::default(),
                "floria",
            )
            .unwrap(),
            vapid_key: VapidKeyMaterial::from_signing_key(SigningKey::generate()),
            vapid_contact_email: "push@example.com".to_owned(),
            allowed_endpoints,
            ttl: DEFAULT_WEBPUSH_TTL_SECS,
        }
    }

    fn notification(_body: &str) -> PushNotificationEnvelope {
        PushNotificationEnvelope {
            strand_title: Some("Mission Control".to_owned()),
            realm_title: None,
            priority: Some("low".to_owned()),
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
            devices: vec![arkret_models_integration::PushDeviceRoute {
                device_id: device().device_id,
            }],
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

    #[test]
    fn builds_webpush_payload() {
        let payload = WebpushPushkin::build_payload(
            &notification(&"x".repeat(MAX_BODY_LENGTH + 20)),
            &device(),
        );

        assert!(payload.get("client").is_none());
        // T4.3 — allowed blind-wakeup fields survive.
        assert_eq!(
            payload.get("push_target_id"),
            Some(&Value::String(
                "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8".to_owned()
            ))
        );
        assert_eq!(
            payload.get("wakeup_kind"),
            Some(&Value::String("message".to_owned()))
        );
        // unread_increment travels as a bounded delta; badge is reduced
        // to a boolean unread indicator.
        assert_eq!(payload.get("unread_count"), Some(&Value::Number(5.into())));
        assert_eq!(payload.get("badge"), Some(&Value::Number(1.into())));

        // T4.3 — stable correlation identifiers are stripped.
        for forbidden in [
            "strand_id",
            "realm_id",
            // Both the renamed security id (`realm_id`) AND the
            // renamed container id (`space_id`) are off-wire — SDK
            // sanitizer covers both since spec 59ac1d4.
            "space_id",
            // `push-notifications.md` §5.1/§6.2 — Circle routing identifiers MUST NOT surface
            // on the webpush plaintext envelope.
            "circle_id",
            "effective_scope",
            "scope_circle_id",
            "event_id",
            "message_id",
            "sender",
            "sender_actor_display_name",
            "strand_title",
            "realm_title",
            "content",
            "highlight_count",
            "missed_calls",
            "user_is_target",
        ] {
            assert!(
                payload.get(forbidden).is_none(),
                "forbidden field `{forbidden}` should not appear in webpush payload"
            );
        }
    }

    #[test]
    fn build_payload_keeps_only_current_blind_fields() {
        let device = device();
        let payload = WebpushPushkin::build_payload(&notification("hello"), &device);
        assert!(payload.get("client").is_none());
        // T4.3 - event_id is no longer copied onto the wire. The
        // surviving routing hook is `push_target_id`.
        assert!(payload.get("event_id").is_none());
        assert_eq!(
            payload.get("push_target_id"),
            Some(&Value::String(
                "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8".to_owned()
            ))
        );
    }

    #[test]
    fn webpush_endpoint_rejects_query_string() {
        let error = WebpushPushkin::endpoint_domain("https://push.example.test/send?token=secret")
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid webpush endpoint: query string is not allowed"
        );
    }

    #[test]
    fn webpush_endpoint_allowlist_matches_domain() {
        let patterns = vec![Glob::new("*.push.example.test").unwrap().compile_matcher()];

        assert!(!endpoint_allowed(None, "updates.push.example.test"));
        assert!(endpoint_allowed(
            Some(&patterns),
            "updates.push.example.test"
        ));
        assert!(!endpoint_allowed(Some(&patterns), "fcm.googleapis.com"));
    }

    fn dispatch_context() -> NotificationContext {
        NotificationContext {
            request_id: "test".to_owned(),
            start_time: Instant::now(),
            allow_plaintext_metadata: false,
        }
    }

    #[tokio::test]
    async fn webpush_dispatch_blocks_private_endpoint_even_when_allowlisted() {
        let patterns = vec![Glob::new("*").unwrap().compile_matcher()];
        let pushkin = pushkin_with_allowed_endpoints(Some(patterns));
        let device = network_device("http://127.0.0.1/push");

        let error = pushkin
            .dispatch_notification(&notification("hello"), &device, &dispatch_context())
            .await
            .expect_err("a blocked endpoint must fail the dispatch, not report success");

        assert!(
            error.to_string().contains("egress policy"),
            "unexpected error: {error}"
        );
    }

    /// `allowed_endpoints` is fail-closed when unset (docs/en/configuration.md).
    /// Withholding every push is intended; booking it as a delivered push is
    /// not — the caller would see neither an error nor a rejected device.
    #[tokio::test]
    async fn webpush_dispatch_fails_when_the_endpoint_allowlist_is_unconfigured() {
        let pushkin = pushkin_with_allowed_endpoints(None);
        let device = network_device("https://updates.push.example.test/push");

        let error = pushkin
            .dispatch_notification(&notification("hello"), &device, &dispatch_context())
            .await
            .expect_err("an unconfigured allowlist must fail the dispatch, not silently drop it");

        assert!(
            error.to_string().contains("allowed_endpoints"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn invalid_vapid_private_key_is_rejected_at_startup() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("floria-webpush-{unique}"));
        fs::create_dir_all(&temp_dir).unwrap();
        let key_path = temp_dir.join("bad.pem");
        fs::write(&key_path, "not a private key").unwrap();

        let app = AppConfig {
            kind: "webpush".to_owned(),
            extra: json!({
                "vapid_private_key": key_path.file_name().unwrap().to_string_lossy(),
                "vapid_contact_email": "push@example.com"
            })
            .as_object()
            .unwrap()
            .clone()
            .into_iter()
            .collect(),
        };

        let error = match WebpushPushkin::new(
            "com.example.web".to_owned(),
            &app,
            &Config::default(),
            &temp_dir,
        ) {
            Ok(_) => panic!("expected invalid VAPID private key to be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("invalid VAPID private key"));

        let _ = fs::remove_file(key_path);
        let _ = fs::remove_dir(temp_dir);
    }

    #[test]
    fn webpush_gone_response_rejects_push_key() {
        let body =
            br#"{"code":410,"errno":1,"error":"gone","message":"subscription expired"}"#.to_vec();
        let result = parse_webpush_response(StatusCode::GONE, body, None);
        let rejected = classify_webpush_result(result, "expired-push-key").unwrap();

        assert_eq!(rejected, vec!["expired-push-key"]);
    }

    #[test]
    fn webpush_egress_validation_rejects_private_targets() {
        let pushkin =
            pushkin_with_allowed_endpoints(Some(vec![Glob::new("*").unwrap().compile_matcher()]));

        for (blocked, expected_reason) in [
            ("https://169.254.169.254/push", "link-local"),
            ("https://10.0.0.5/push", "private"),
            ("https://[::1]/push", "loopback"),
        ] {
            let error = match pushkin.validate_endpoint_for_egress(blocked) {
                Ok(_) => panic!("expected egress validation to reject {blocked}"),
                Err(error) => error,
            };
            assert!(
                error.contains(expected_reason),
                "unexpected error for {blocked}: {error}"
            );
        }
    }
}
