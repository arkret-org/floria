use std::fs::File;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use blake2::digest::Digest;
use globset::{Glob, GlobMatcher};
use isahc::HttpClient;
use isahc::config::{Configurable, ResolveMap};
use prometheus::{Histogram, IntGauge, register_histogram, register_int_gauge};
use reqwest::Url;
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use web_push::{
    ContentEncoding, IsahcWebPushClient, PartialVapidSignatureBuilder, SubscriptionInfo, Urgency,
    VapidSignatureBuilder, WebPushClient, WebPushError, WebPushMessageBuilder,
};

use super::{
    AppMatcher, ConcurrencyGate, Pushkin, build_blind_routing_data, inflight_limit,
    max_connections, random_collapse_key, sanitized_provider_payload,
};
use crate::auth::redact_url_credentials;
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{Device, Notification, NotificationContext};

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
#[cfg(test)]
const MAX_BODY_LENGTH: usize = 1000;
#[cfg(test)]
const MAX_CIPHERTEXT_LENGTH: usize = 2000;

pub struct WebpushPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    /// Parameters needed to (re)build the isahc WebPush client. isahc has
    /// no dynamic per-connection resolver hook like reqwest's
    /// `EgressGuardResolver`, so instead of one shared client we rebuild
    /// the client per dispatch with a `ResolveMap` that pins the endpoint
    /// host to the exact IP we just validated against the egress
    /// blocklist — closing the TOCTOU / DNS-rebinding gap (FLO-03-001).
    client_params: WebpushClientParams,
    vapid_builder: PartialVapidSignatureBuilder,
    vapid_contact_email: String,
    vapid_key_id: String,
    vapid_key_fingerprint: String,
    allowed_endpoints: Option<Vec<GlobMatcher>>,
    ttl: u32,
}

/// Everything required to build (or rebuild) the isahc WebPush client,
/// captured once at construction so each dispatch can mint a client whose
/// DNS resolution is pinned to a pre-validated IP.
#[derive(Clone)]
struct WebpushClientParams {
    max_connections: usize,
    proxy: Option<isahc::http::Uri>,
}

impl WebpushClientParams {
    /// Build an isahc WebPush client. When `pinned` is supplied, every
    /// connection for the listed host:port pairs is forced to the given
    /// IP via curl's resolve override (`CURLOPT_RESOLVE`); the original
    /// host is still used for the TLS SNI and HTTP Host header.
    fn build_client(&self, pinned: Option<ResolveMap>) -> Result<IsahcWebPushClient> {
        // Bound connect + overall request time so a stalled WebPush
        // endpoint cannot pin a gate permit / connection forever
        // (FLO-02-001). isahc's read-timeout alone does not cap connect
        // or total duration.
        let mut builder = HttpClient::builder()
            .max_connections(self.max_connections)
            .connect_timeout(super::reqwest_support::CONNECT_TIMEOUT)
            .timeout(super::reqwest_support::REQUEST_TIMEOUT)
            .default_header("user-agent", "floria");
        if let Some(proxy) = &self.proxy {
            builder = builder.proxy(Some(proxy.clone()));
        }
        if let Some(resolve) = pinned {
            builder = builder.dns_resolve(resolve);
        }
        Ok(IsahcWebPushClient::from(
            builder
                .build()
                .context("failed to build webpush HTTP client")?,
        ))
    }
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

        let proxy = config
            .outbound_proxy()
            .map(|proxy| {
                proxy.parse::<isahc::http::Uri>().with_context(|| {
                    format!("invalid proxy URL `{}`", redact_url_credentials(proxy))
                })
            })
            .transpose()?;
        let client_params = WebpushClientParams {
            max_connections,
            proxy,
        };
        // Fail fast at startup if the client config is unbuildable, rather
        // than surfacing it on the first dispatch.
        client_params.build_client(None)?;

        let vapid_builder = VapidSignatureBuilder::from_pem_no_sub(
            File::open(&vapid_private_key)
                .with_context(|| format!("failed to read {}", vapid_private_key.display()))?,
        )
        .context("invalid VAPID private key")?;

        let key_bytes = std::fs::read(&vapid_private_key).with_context(|| {
            format!(
                "failed to read VAPID private key {}",
                vapid_private_key.display()
            )
        })?;
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
            client_params,
            vapid_builder,
            vapid_contact_email,
            vapid_key_id,
            vapid_key_fingerprint,
            allowed_endpoints,
            ttl,
        })
    }

    /// Stable label for the active VAPID key — surfaced via
    /// `bridge/describe` and the `floria_webpush_vapid_active_key`
    /// gauge so operators can track rotation cadence.
    pub fn vapid_key_id(&self) -> &str {
        &self.vapid_key_id
    }

    pub fn vapid_key_fingerprint(&self) -> &str {
        &self.vapid_key_fingerprint
    }

    /// Build the WebPush JSON payload that goes into the encrypted
    /// `aes128gcm` body. T4.3 — only the SDK-allowed blind-wakeup
    /// fields plus the device's static `default_payload` survive on
    /// the wire. `flow_id` / `realm_id` / `event_id` / `message_id`
    /// / sender / names / body / content / membership / user_is_target
    /// are all dropped: the SW pulls them server-side from an e2ee
    /// envelope keyed on `push_target_id`.
    fn build_payload(notification: &Notification, device: &Device) -> Map<String, Value> {
        let mut payload = device.default_payload_lossy();

        payload.extend(build_blind_routing_data(notification));
        // §5.1 — bucket the absolute counts (0 / 1 / 2-5 / 6+) before
        // they reach the WebPush payload so the exact figure can't be
        // used as a per-`push_target_id` activity correlator.
        if let Some(unread) = notification.counts.unread {
            payload.insert(
                "unread_count".to_owned(),
                Value::Number(crate::sanitize::bucket_count(unread).into()),
            );
        }
        if let Some(missed_calls) = notification.counts.missed_calls {
            payload.insert(
                "badge".to_owned(),
                Value::Number(crate::sanitize::bucket_count(missed_calls).into()),
            );
        }

        // Final defence — strip anything forbidden that might have come
        // in via `device.default_payload_lossy()` (operator-supplied).
        match sanitized_provider_payload(payload) {
            Ok(sanitized) => sanitized,
            Err(rejection) => {
                tracing::warn!(
                    rejection = %rejection,
                    "webpush default_payload contained forbidden field, falling back to minimal payload"
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

    /// Validate the endpoint against the egress blocklist and build a
    /// WebPush client whose DNS resolution for this endpoint's host:port
    /// is pinned to the exact IPs that passed validation.
    ///
    /// isahc/web-push offer no per-request resolver hook (unlike reqwest's
    /// `EgressGuardResolver`), so we resolve + filter here and pin the
    /// surviving IPs via `ResolveMap`. The connection therefore dials only
    /// an already-validated address — a DNS rebind between this check and
    /// the actual connect cannot redirect us to `169.254.169.254`, `::1`,
    /// `10.x`, etc. (FLO-03-001). SNI/Host stay the original hostname.
    fn pinned_client_for_endpoint(&self, endpoint: &str) -> Result<IsahcWebPushClient, String> {
        let url = Url::parse(endpoint)
            .map_err(|error| format!("webpush endpoint: invalid URL: {error}"))?;
        crate::egress::validate_url_for_egress(
            &url,
            "webpush endpoint",
            crate::egress::private_networks_allowed(),
        )?;
        let host = url
            .host_str()
            .ok_or_else(|| "webpush endpoint: URL host is required".to_owned())?;
        let port = url.port_or_known_default().unwrap_or(443);
        let ips = crate::egress::resolved_egress_ips(host, port, "webpush endpoint")?;

        let mut resolve = ResolveMap::new();
        for ip in ips {
            resolve = resolve.add(host, port, ip);
        }
        self.client_params
            .build_client(Some(resolve))
            .map_err(|error| format!("webpush endpoint: failed to build pinned client: {error}"))
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
            device.push_key.clone(),
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
        client: &IsahcWebPushClient,
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
        builder.set_urgency(if notification.is_low_priority() {
            Urgency::Low
        } else {
            Urgency::Normal
        });
        // T4.3 — the topic used to be a blake2 hash of the `realm_id` /
        // `flow_id`. blake2 is non-reversible but the *same* scope still
        // produced the *same* topic across pushes, which let an observer
        // correlate every notification in a given conversation. We now
        // either skip the topic entirely (so the push gateway never
        // dedupes by scope) or emit a per-message random base64 token
        // when the device opted into the legacy "collapse to last per
        // flow" behaviour.
        if device.data_bool("only_last_per_flow") == Some(true) {
            builder.set_topic(random_collapse_key());
        }
        builder.set_payload(ContentEncoding::Aes128Gcm, &payload);
        builder.set_vapid_signature(signature);

        let message = match builder.build() {
            Ok(message) => message,
            Err(WebPushError::InvalidUri)
            | Err(WebPushError::MissingCryptoKeys)
            | Err(WebPushError::InvalidCryptoKeys) => {
                tracing::warn!(
                    push_key_hash = %device.redacted_push_key(),
                    "rejecting invalid webpush crypto material"
                );
                return Ok(vec![device.push_key.clone()]);
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
        let result = client.send(message).await;
        WEBPUSH_ACTIVE_REQUESTS.dec();
        WEBPUSH_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());

        classify_webpush_result(result, &device.push_key)
    }
}

#[async_trait]
impl Pushkin for WebpushPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        "webpush"
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
            tracing::warn!(
                push_key_hash = %device.redacted_push_key(),
                "rejecting webpush device without data object"
            );
            return Ok(vec![device.push_key.clone()]);
        }

        if device.data_bool("events_only") == Some(true) && notification.event_id.is_none() {
            return Ok(vec![]);
        }

        let subscription = match self.subscription_from_device(device) {
            Ok(subscription) => subscription,
            Err(error) => {
                tracing::warn!(
                    push_key_hash = %device.redacted_push_key(),
                    error = %error,
                    "rejecting invalid webpush subscription"
                );
                return Ok(vec![device.push_key.clone()]);
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
                return Ok(vec![device.push_key.clone()]);
            }
        };

        if !self.allows_endpoint(&endpoint_domain) {
            tracing::error!(
                push_key_hash = %device.redacted_push_key(),
                endpoint = %endpoint_domain,
                "webpush endpoint not allowed by configuration"
            );
            return Ok(vec![]);
        }

        let pinned_client = match self.pinned_client_for_endpoint(&subscription.endpoint) {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(
                    push_key_hash = %device.redacted_push_key(),
                    endpoint = %endpoint_domain,
                    error = %error,
                    "webpush endpoint rejected by egress policy"
                );
                return Ok(vec![]);
            }
        };

        self.send_message(&pinned_client, &subscription, notification, device)
            .await
    }
}

fn endpoint_allowed(allowed_endpoints: Option<&[GlobMatcher]>, endpoint_domain: &str) -> bool {
    allowed_endpoints.is_some_and(|patterns| {
        patterns
            .iter()
            .any(|pattern| pattern.is_match(endpoint_domain))
    })
}

fn classify_webpush_result(
    result: Result<(), WebPushError>,
    push_key: &str,
) -> Result<Vec<String>, DispatchError> {
    match result {
        Ok(()) => Ok(vec![]),
        Err(WebPushError::EndpointNotFound(_) | WebPushError::EndpointNotValid(_)) => {
            Ok(vec![push_key.to_owned()])
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use std::{fs, thread};

    use serde_json::json;

    use super::*;
    use crate::config::{AppConfig, Config};
    use crate::models::{Counts, Tweaks};

    fn device() -> Device {
        Device {
            app_id: "com.example.web".to_owned(),
            push_key: "p256dh-key".to_owned(),
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
            push_decision: None,
            target_actor_id: None,
        }
    }

    fn network_device(endpoint: &str) -> Device {
        Device {
            app_id: "com.example.web".to_owned(),
            push_key: "BH1HTeKM7-NwaLGHEqxeu2IamQaVVLkcsFHPIHmsCnqxcBHPQBprF41bEMOr3O1hUQ2jU1opNEm1F_lZV_sxMP8".to_owned(),
            data: Some(
                json!({
                    "endpoint": endpoint,
                    "auth": "sBXU5_tIYz-5w7G2B25BEw",
                    "default_payload": {
                        "client": "web"
                    }
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            tweaks: Tweaks::default(),
            push_decision: None,
            target_actor_id: None,
        }
    }

    fn vapid_test_key_path() -> PathBuf {
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(std::env::var_os("USERPROFILE").expect("USERPROFILE")).join(".cargo")
            });
        cargo_home
            .join("registry")
            .join("src")
            .join("index.crates.io-1949cf8c6b5b557f")
            .join("web-push-0.11.0")
            .join("resources")
            .join("vapid_test_key.pem")
    }

    fn pushkin_with_allowed_endpoints(
        allowed_endpoints: Option<Vec<GlobMatcher>>,
    ) -> WebpushPushkin {
        WebpushPushkin {
            matcher: AppMatcher::new("com.example.web".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client_params: WebpushClientParams {
                max_connections: 1,
                proxy: None,
            },
            vapid_builder: VapidSignatureBuilder::from_pem_no_sub(
                File::open(vapid_test_key_path()).unwrap(),
            )
            .unwrap(),
            vapid_contact_email: "push@example.com".to_owned(),
            vapid_key_id: "test".to_owned(),
            vapid_key_fingerprint: "test".to_owned(),
            allowed_endpoints,
            ttl: DEFAULT_WEBPUSH_TTL_SECS,
        }
    }

    fn notification(body: &str) -> Notification {
        Notification {
            flow_title: Some("Mission Control".to_owned()),
            realm_title: None,
            priority: Some("low".to_owned()),
            membership: None,
            sender_actor_display_name: Some("Major Tom".to_owned()),
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
            event_id: Some("ck:event:01JS0EV000000000000000000".to_owned()),
            message_id: Some("ck:message:01JS0MSG0000000000000000".to_owned()),
            flow_id: Some("ck:flow:01JS0FLOW000000000000000".to_owned()),
            realm_id: Some("ck:realm:01JS0SP000000000000000000".to_owned()),
            user_is_target: Some(true),
            push_target_id: Some("ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            recipient_service_did: None,
            delivery_binding_frontier: None,
            wakeup_kind: Some("message".to_owned()),
            push_hint: None,
            devices: vec![device()],
            mention_redirect_target_actor_ids: Vec::new(),
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
                highlight_count: Some(1),
            },
            ..Default::default()
        }
    }

    #[test]
    fn builds_webpush_payload() {
        let payload = WebpushPushkin::build_payload(
            &notification(&"x".repeat(MAX_BODY_LENGTH + 20)),
            &device(),
        );

        // Device-supplied static config still survives.
        assert_eq!(
            payload.get("client"),
            Some(&Value::String("web".to_owned()))
        );
        // T4.3 — allowed blind-wakeup fields survive.
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
        // §5.1 — unread=2 is bucketed to the `2-5` representative value 5;
        // missed_calls=1 stays in the `1` bucket.
        assert_eq!(payload.get("unread_count"), Some(&Value::Number(5.into())));
        assert_eq!(payload.get("badge"), Some(&Value::Number(1.into())));

        // T4.3 — stable correlation identifiers are stripped.
        for forbidden in [
            "flow_id",
            "realm_id",
            // Both the renamed security id (`realm_id`) AND the
            // renamed container id (`space_id`) are off-wire — SDK
            // sanitizer covers both since spec 59ac1d4.
            "space_id",
            // CKP-0007 — Circle routing identifiers MUST NOT surface
            // on the webpush plaintext envelope.
            "circle_id",
            "effective_scope",
            "scope_circle_id",
            "event_id",
            "message_id",
            "sender",
            "sender_actor_display_name",
            "flow_title",
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
    fn random_collapse_key_does_not_leak_scope_id() {
        let a = super::super::random_collapse_key();
        let b = super::super::random_collapse_key();
        // Per-message randomness — two adjacent calls must differ.
        assert_ne!(a, b);
        // base64url alphabet only — no `ck:` or other typed-id substrings.
        assert!(!a.contains(':'));
        assert!(
            a.chars()
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
        // T4.3 — event_id is no longer copied onto the wire. The
        // surviving routing hook is `push_target_id`.
        assert!(payload.get("event_id").is_none());
        assert_eq!(
            payload.get("push_target_id"),
            Some(&Value::String(
                "ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()
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

    #[tokio::test]
    async fn webpush_dispatch_blocks_private_endpoint_even_when_allowlisted() {
        let patterns = vec![Glob::new("*").unwrap().compile_matcher()];
        let pushkin = pushkin_with_allowed_endpoints(Some(patterns));
        let device = network_device("http://127.0.0.1/push");
        let notification = notification("hello");

        let rejected = pushkin
            .dispatch_notification(
                &notification,
                &device,
                &NotificationContext {
                    request_id: "test".to_owned(),
                    start_time: Instant::now(),
                },
            )
            .await
            .unwrap();

        assert!(rejected.is_empty());
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
            .clone(),
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

    #[tokio::test]
    async fn webpush_gone_endpoint_rejects_push_key() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept webpush request");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            let body = r#"{"code":410,"errno":1,"error":"gone","message":"subscription expired"}"#;
            let response = format!(
                "HTTP/1.1 410 Gone\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
            let _ = stream.shutdown(Shutdown::Write);
        });

        let pushkin = pushkin_with_allowed_endpoints(None);
        let device = network_device(&format!("http://{addr}/push"));
        let notification = notification("hello");
        let subscription = pushkin.subscription_from_device(&device).unwrap();

        // The 410-handling path is orthogonal to IP pinning; use an
        // unpinned client so the loopback test server is reachable.
        let client = pushkin.client_params.build_client(None).unwrap();
        let rejected = pushkin
            .send_message(&client, &subscription, &notification, &device)
            .await
            .unwrap();

        assert_eq!(rejected, vec![device.push_key.clone()]);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn webpush_pins_validated_ip_and_rejects_rebind_to_private() {
        // A hostname that the egress validation would pass (public IP)
        // but which, at connect time, an attacker rebinds to a private
        // address. Because we pin the connection to the *validated* IP
        // (and reject endpoints that resolve only to blocked addresses),
        // the isahc path must refuse to build a client / dispatch.
        //
        // Here the endpoint host is itself a private IP literal, which is
        // the strongest form of the rebind target: `pinned_client_for_endpoint`
        // must reject it via the shared egress blocklist rather than
        // dialing it.
        let pushkin =
            pushkin_with_allowed_endpoints(Some(vec![Glob::new("*").unwrap().compile_matcher()]));

        for blocked in [
            "http://169.254.169.254/push",
            "http://10.0.0.5/push",
            "http://[::1]/push",
        ] {
            let error = match pushkin.pinned_client_for_endpoint(blocked) {
                Ok(_) => panic!("expected pinned client build to reject {blocked}"),
                Err(error) => error,
            };
            assert!(
                error.contains("blocked"),
                "unexpected error for {blocked}: {error}"
            );
        }
    }
}
