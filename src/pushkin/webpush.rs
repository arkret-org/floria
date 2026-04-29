use std::fs::File;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use base64::Engine;
use blake2::Blake2s256;
use blake2::digest::Digest;
use globset::{Glob, GlobMatcher};
use isahc::HttpClient;
use isahc::config::Configurable;
use prometheus::{Histogram, IntGauge, register_histogram, register_int_gauge};
use reqwest::Url;
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use web_push::{
    ContentEncoding, IsahcWebPushClient, PartialVapidSignatureBuilder, SubscriptionInfo, Urgency,
    VapidSignatureBuilder, WebPushClient, WebPushError, WebPushMessageBuilder,
};

use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext};

use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};

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

const DEFAULT_WEBPUSH_TTL_SECS: u32 = 15 * 60;
const MAX_BODY_LENGTH: usize = 1000;
const MAX_CIPHERTEXT_LENGTH: usize = 2000;

pub struct WebpushPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: IsahcWebPushClient,
    vapid_builder: PartialVapidSignatureBuilder,
    vapid_contact_email: String,
    allowed_endpoints: Option<Vec<GlobMatcher>>,
    ttl: u32,
}

impl WebpushPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config, base_dir: &Path) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "max_connections",
                "vapid_private_key",
                "vapid_contact_email",
                "allowed_endpoints",
                "ttl",
                "inflight_request_limit",
            ],
        );
        let matcher = AppMatcher::new(name)?;
        let gate = ConcurrencyGate::new(inflight_limit(app)?);
        let max_connections = max_connections(app)?.max(1);
        let connection_semaphore = Arc::new(Semaphore::new(max_connections));

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

        let mut client_builder = HttpClient::builder()
            .max_connections(max_connections)
            .default_header("user-agent", "floria");
        if let Some(proxy) = config.outbound_proxy() {
            client_builder = client_builder.proxy(Some(
                proxy
                    .parse::<isahc::http::Uri>()
                    .with_context(|| format!("invalid proxy URL `{proxy}`"))?,
            ));
        }
        let client = IsahcWebPushClient::from(
            client_builder
                .build()
                .context("failed to build webpush HTTP client")?,
        );

        let vapid_builder = VapidSignatureBuilder::from_pem_no_sub(
            File::open(&vapid_private_key)
                .with_context(|| format!("failed to read {}", vapid_private_key.display()))?,
        )
        .context("invalid VAPID private key")?;

        Ok(Self {
            matcher,
            gate,
            connection_semaphore,
            client,
            vapid_builder,
            vapid_contact_email,
            allowed_endpoints,
            ttl,
        })
    }

    fn build_payload(notification: &Notification, device: &Device) -> Map<String, Value> {
        let mut payload = device.default_payload_lossy();

        for (key, value) in [
            ("space_id", notification.scope_id()),
            ("room_id", notification.scope_id()),
            ("space_name", notification.scope_name()),
            ("room_name", notification.scope_name()),
            ("room_alias", notification.room_alias.as_ref()),
            ("membership", notification.membership.as_ref()),
            ("event_id", notification.event_id.as_ref()),
            ("sender", notification.sender.as_ref()),
            (
                "sender_display_name",
                notification.sender_display_name.as_ref(),
            ),
            ("type", notification.r#type.as_ref()),
            ("push_hint", notification.push_hint.as_ref()),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                payload.insert(key.to_owned(), Value::String(value.clone()));
            }
        }

        if notification.user_is_target == Some(true) {
            payload.insert("user_is_target".to_owned(), Value::Bool(true));
        }

        if let Some(unread) = notification.counts.unread {
            payload.insert("unread".to_owned(), Value::Number(unread.into()));
        }
        if let Some(missed_calls) = notification.counts.missed_calls {
            payload.insert(
                "missed_calls".to_owned(),
                Value::Number(missed_calls.into()),
            );
        }

        if let Some(content) = &notification.content {
            let mut content = content.clone();
            content.remove("formatted_body");
            if let Some(body) = content.get_mut("body")
                && let Some(text) = body.as_str()
            {
                let truncated = truncate_chars(text, MAX_BODY_LENGTH);
                *body = Value::String(truncated);
            }
            let drop_ciphertext = content
                .get("ciphertext")
                .and_then(Value::as_str)
                .is_some_and(|ciphertext| ciphertext.chars().count() > MAX_CIPHERTEXT_LENGTH);
            if drop_ciphertext {
                content.remove("ciphertext");
            }
            payload.insert("content".to_owned(), Value::Object(content));
        } else if let Some(push_hint) = notification.push_hint_text() {
            payload.insert(
                "content".to_owned(),
                Value::Object(Map::from_iter([(
                    "body".to_owned(),
                    Value::String(push_hint.to_owned()),
                )])),
            );
        }

        payload
    }

    fn scope_topic(scope_id: &str) -> String {
        let mut hasher = Blake2s256::new();
        hasher.update(scope_id.as_bytes());
        let digest = hasher.finalize();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..22])
    }

    fn endpoint_domain(endpoint: &str) -> Result<String, DispatchError> {
        let url = Url::parse(endpoint)
            .map_err(|error| DispatchError::remote(format!("invalid webpush endpoint: {error}")))?;
        let Some(host) = url.host_str() else {
            return Err(DispatchError::remote(
                "invalid webpush endpoint: missing host",
            ));
        };
        Ok(host.to_owned())
    }

    fn allows_endpoint(&self, endpoint_domain: &str) -> bool {
        self.allowed_endpoints.as_ref().is_none_or(|patterns| {
            patterns
                .iter()
                .any(|pattern| pattern.is_match(endpoint_domain))
        })
    }

    fn subscription_from_device(&self, device: &Device) -> Result<SubscriptionInfo, DispatchError> {
        let endpoint = device
            .data_string("endpoint")
            .ok_or_else(|| DispatchError::remote("webpush device data is missing endpoint"))?;
        let auth = device
            .data_string("auth")
            .ok_or_else(|| DispatchError::remote("webpush device data is missing auth"))?;
        Ok(SubscriptionInfo::new(
            endpoint.to_owned(),
            device.pushkey.clone(),
            auth.to_owned(),
        ))
    }

    fn signature_for(
        &self,
        subscription: &SubscriptionInfo,
    ) -> Result<web_push::VapidSignature, DispatchError> {
        let mut builder = self.vapid_builder.clone().add_sub_info(subscription);
        builder.add_claim("sub", format!("mailto:{}", self.vapid_contact_email));
        builder.build().map_err(|error| {
            DispatchError::internal(format!("failed to build VAPID signature: {error}"))
        })
    }

    async fn send_message(
        &self,
        subscription: &SubscriptionInfo,
        notification: &Notification,
        device: &Device,
    ) -> Result<Vec<String>, DispatchError> {
        let payload =
            serde_json::to_vec(&Self::build_payload(notification, device)).map_err(|error| {
                DispatchError::internal(format!("failed to encode webpush payload: {error}"))
            })?;
        let signature = self.signature_for(subscription)?;

        let mut builder = WebPushMessageBuilder::new(subscription);
        builder.set_ttl(self.ttl);
        builder.set_urgency(if notification.prio.as_deref() == Some("low") {
            Urgency::Low
        } else {
            Urgency::Normal
        });
        if let Some(space_id) = notification
            .scope_id()
            .as_deref()
            .filter(|_| device.data_bool("only_last_per_room") == Some(true))
        {
            builder.set_topic(Self::scope_topic(space_id));
        }
        builder.set_payload(ContentEncoding::Aes128Gcm, &payload);
        builder.set_vapid_signature(signature);

        let message = match builder.build() {
            Ok(message) => message,
            Err(WebPushError::InvalidUri)
            | Err(WebPushError::MissingCryptoKeys)
            | Err(WebPushError::InvalidCryptoKeys) => {
                tracing::warn!(pushkey = %device.pushkey, "rejecting invalid webpush crypto material");
                return Ok(vec![device.pushkey.clone()]);
            }
            Err(WebPushError::InvalidTopic | WebPushError::InvalidClaims) => {
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
        let result = self.client.send(message).await;
        WEBPUSH_ACTIVE_REQUESTS.dec();
        WEBPUSH_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());

        match result {
            Ok(()) => Ok(vec![]),
            Err(WebPushError::EndpointNotFound(_) | WebPushError::EndpointNotValid(_)) => {
                Ok(vec![device.pushkey.clone()])
            }
            Err(WebPushError::ServerError { retry_after, info }) => Err(DispatchError::temporary(
                format!("webpush server error: {info}"),
                retry_after,
            )),
            Err(WebPushError::Unauthorized(info)) => Err(DispatchError::remote(format!(
                "webpush unauthorized: {info}"
            ))),
            Err(WebPushError::BadRequest(info)) => Err(DispatchError::remote(format!(
                "webpush bad request: {info}"
            ))),
            Err(WebPushError::Other(info)) => Err(DispatchError::remote(format!(
                "webpush endpoint error: {info}"
            ))),
            Err(WebPushError::Unspecified) => Err(DispatchError::temporary(
                "webpush request failed".to_owned(),
                None,
            )),
            Err(error) => Err(DispatchError::remote(format!(
                "webpush request failed: {error}"
            ))),
        }
    }
}

#[async_trait]
impl Pushkin for WebpushPushkin {
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

        if device.data.is_none() {
            tracing::warn!(pushkey = %device.pushkey, "rejecting webpush device without data object");
            return Ok(vec![device.pushkey.clone()]);
        }

        if device.data_bool("events_only") == Some(true) && notification.event_id.is_none() {
            return Ok(vec![]);
        }

        let subscription = match self.subscription_from_device(device) {
            Ok(subscription) => subscription,
            Err(error) => {
                tracing::warn!(pushkey = %device.pushkey, error = %error, "rejecting invalid webpush subscription");
                return Ok(vec![device.pushkey.clone()]);
            }
        };

        let endpoint_domain = match Self::endpoint_domain(&subscription.endpoint) {
            Ok(endpoint_domain) => endpoint_domain,
            Err(error) => {
                tracing::warn!(pushkey = %device.pushkey, error = %error, "rejecting invalid webpush endpoint");
                return Ok(vec![device.pushkey.clone()]);
            }
        };

        if !self.allows_endpoint(&endpoint_domain) {
            tracing::error!(
                pushkey = %device.pushkey,
                endpoint = %endpoint_domain,
                "webpush endpoint not allowed by configuration"
            );
            return Ok(vec![]);
        }

        self.send_message(&subscription, notification, device).await
    }
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    let count = input.chars().count();
    if count <= max_chars {
        return input.to_owned();
    }
    let keep = max_chars.saturating_sub(3);
    let mut output = input.chars().take(keep).collect::<String>();
    output.push_str("...");
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::models::{Counts, Tweaks};

    fn device() -> Device {
        Device {
            app_id: "com.example.web".to_owned(),
            pushkey: "p256dh-key".to_owned(),
            pushkey_ts: 42,
            data: Some(
                json!({
                    "endpoint": "https://push.example.test/send",
                    "auth": "auth-secret",
                    "default_payload": {
                        "client": "web"
                    }
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            tweaks: Tweaks::default(),
        }
    }

    fn notification(body: &str) -> Notification {
        Notification {
            room_name: Some("Mission Control".to_owned()),
            room_alias: None,
            prio: Some("low".to_owned()),
            membership: None,
            sender_display_name: Some("Major Tom".to_owned()),
            content: Some(
                json!({
                    "body": body,
                    "formatted_body": "<b>ignored</b>",
                    "ciphertext": "x".repeat(MAX_CIPHERTEXT_LENGTH + 10),
                    "msgtype": "m.text"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            event_id: Some("$event".to_owned()),
            room_id: Some("!room:example.com".to_owned()),
            user_is_target: Some(true),
            r#type: Some("m.room.message".to_owned()),
            sender: Some("@major:example.com".to_owned()),
            devices: vec![device()],
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
            },
        }
    }

    #[test]
    fn builds_webpush_payload() {
        let payload = WebpushPushkin::build_payload(
            &notification(&"x".repeat(MAX_BODY_LENGTH + 20)),
            &device(),
        );

        assert_eq!(
            payload.get("client"),
            Some(&Value::String("web".to_owned()))
        );
        assert_eq!(
            payload.get("room_id"),
            Some(&Value::String("!room:example.com".to_owned()))
        );
        assert_eq!(
            payload.get("event_id"),
            Some(&Value::String("$event".to_owned()))
        );
        assert_eq!(payload.get("unread"), Some(&Value::Number(2.into())));
        assert_eq!(payload.get("missed_calls"), Some(&Value::Number(1.into())));
        assert_eq!(payload.get("user_is_target"), Some(&Value::Bool(true)));

        let content = payload.get("content").and_then(Value::as_object).unwrap();
        assert!(content.get("formatted_body").is_none());
        assert!(content.get("ciphertext").is_none());
        assert!(
            content
                .get("body")
                .and_then(Value::as_str)
                .is_some_and(|body| body.ends_with("..."))
        );
    }

    #[test]
    fn topic_is_base64url_and_short_enough() {
        let topic = WebpushPushkin::room_topic("!room:example.com");
        assert!(topic.len() <= 32);
        assert!(
            topic
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        );
    }

    #[test]
    fn invalid_default_payload_is_ignored() {
        let mut device = device();
        device.data = Some(
            json!({
                "endpoint": "https://push.example.test/send",
                "auth": "auth-secret",
                "default_payload": "bad"
            })
            .as_object()
            .unwrap()
            .clone(),
        );

        let payload = WebpushPushkin::build_payload(&notification("hello"), &device);
        assert!(payload.get("client").is_none());
        assert_eq!(
            payload.get("event_id"),
            Some(&Value::String("$event".to_owned()))
        );
    }
}
