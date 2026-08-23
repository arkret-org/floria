use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use arkret_models_integration::{PushDeviceRoute, PushNotificationEnvelope};
use async_trait::async_trait;
use prometheus::{
    Histogram, IntGauge, register_histogram, register_int_counter_vec, register_int_gauge,
};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode};
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use tokio::time::sleep;

use super::android::{AndroidNotificationPayload, build_android_notification_payload};
use super::hms_family::{self, HmsAndroidConfig};
use super::reqwest_support::{
    ClientCredentialsGrant, bearer, build_reqwest_client, parse_retry_after,
};
use super::{AppMatcher, ConcurrencyGate, Pushkin, inflight_limit, max_connections};
use crate::config::{AppConfig, Config};
use crate::error::DispatchError;
use crate::models::{DeviceExt, NotificationContext};

static HUAWEI_QUEUE_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_huawei_queue_time",
        "Time taken waiting for a Huawei Push request slot"
    )
    .expect("register floria_huawei_queue_time")
});

static HUAWEI_REQUEST_TIME: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "floria_huawei_request_time",
        "Time taken to send HTTP request to Huawei Push"
    )
    .expect("register floria_huawei_request_time")
});

static HUAWEI_PENDING_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_pending_huawei_requests",
        "Number of Huawei Push requests waiting for a connection"
    )
    .expect("register floria_pending_huawei_requests")
});

static HUAWEI_ACTIVE_REQUESTS: LazyLock<IntGauge> = LazyLock::new(|| {
    register_int_gauge!(
        "floria_active_huawei_requests",
        "Number of Huawei Push requests in flight"
    )
    .expect("register floria_active_huawei_requests")
});

static HUAWEI_STATUS_CODES: LazyLock<prometheus::IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "floria_huawei_status_codes",
        "Number of HTTP response status codes received from Huawei Push",
        &["pushkin", "code"]
    )
    .expect("register floria_huawei_status_codes")
});

const HUAWEI_MAX_TRIES: usize = 3;
const HUAWEI_RETRY_DELAY_BASE_SECS: u64 = 10;
const HUAWEI_TOKEN_URL: &str = "https://oauth-login.cloud.huawei.com/oauth2/v3/token";
const HUAWEI_API_BASE_URL: &str = "https://push-api.cloud.huawei.com/v1";

pub struct HuaweiPushkin {
    matcher: AppMatcher,
    gate: ConcurrencyGate,
    connection_semaphore: Arc<Semaphore>,
    client: Client,
    token_grant: ClientCredentialsGrant,
    endpoint: String,
    config: HmsAndroidConfig,
}

impl HuaweiPushkin {
    pub fn new(name: String, app: &AppConfig, config: &Config) -> Result<Self> {
        app.warn_unknown_fields(
            &name,
            &[
                "app_id",
                "app_secret",
                "token_url",
                "api_base_url",
                "channel_id",
                "ttl_seconds",
                "android_config",
                "android_notification",
                "click_action",
                "send_badge_counts",
                "max_connections",
                "inflight_request_limit",
            ],
        );

        let app_id = app
            .get_string("app_id")?
            .context("Huawei Push config requires app_id")?;
        let app_secret = app
            .get_string("app_secret")?
            .context("Huawei Push config requires app_secret")?;
        let token_url = app
            .get_string("token_url")?
            .unwrap_or_else(|| HUAWEI_TOKEN_URL.to_owned());
        let api_base_url = app
            .get_string("api_base_url")?
            .unwrap_or_else(|| HUAWEI_API_BASE_URL.to_owned())
            .trim_end_matches('/')
            .to_owned();

        let endpoint = format!("{api_base_url}/{app_id}/messages:send");
        crate::egress::validate_http_url_for_egress(&token_url, "Huawei token endpoint")
            .map_err(|error| anyhow::anyhow!(error))?;
        crate::egress::validate_http_url_for_egress(&endpoint, "Huawei push endpoint")
            .map_err(|error| anyhow::anyhow!(error))?;

        Ok(Self {
            matcher: AppMatcher::new(name)?,
            gate: ConcurrencyGate::new(inflight_limit(app)?),
            connection_semaphore: Arc::new(Semaphore::new(max_connections(app)?.max(1))),
            client: build_reqwest_client(config, "floria")?,
            token_grant: ClientCredentialsGrant::new(app_id.clone(), app_secret, token_url),
            endpoint,
            config: HmsAndroidConfig::from_app(app)?,
        })
    }

    fn build_request_body(
        &self,
        device: &PushDeviceRoute,
        payload: AndroidNotificationPayload,
    ) -> Result<Map<String, Value>, DispatchError> {
        hms_family::build_request_body("Huawei Push", &self.config, device, payload)
    }

    async fn send_once(
        &self,
        device: &PushDeviceRoute,
        payload: AndroidNotificationPayload,
    ) -> Result<Vec<String>, DispatchError> {
        let token = self.token_grant.access_token(&self.client).await?;
        let body = self.build_request_body(device, payload)?;

        HUAWEI_PENDING_REQUESTS.inc();
        let queue_started = Instant::now();
        let _connection_permit = self
            .connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                HUAWEI_PENDING_REQUESTS.dec();
                DispatchError::internal("Huawei Push connection semaphore closed")
            })?;
        HUAWEI_PENDING_REQUESTS.dec();
        HUAWEI_QUEUE_TIME.observe(queue_started.elapsed().as_secs_f64());

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, bearer(&token)?);
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/json; charset=utf-8"),
        );

        HUAWEI_ACTIVE_REQUESTS.inc();
        let request_started = Instant::now();
        let response = self
            .client
            .post(&self.endpoint)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                HUAWEI_ACTIVE_REQUESTS.dec();
                HUAWEI_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());
                DispatchError::temporary(format!("Huawei Push request failed: {error}"), None)
            })?;
        HUAWEI_ACTIVE_REQUESTS.dec();
        HUAWEI_REQUEST_TIME.observe(request_started.elapsed().as_secs_f64());

        let status = response.status();
        HUAWEI_STATUS_CODES
            .with_label_values(&[self.name(), &status.as_u16().to_string()])
            .inc();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read Huawei Push response: {error}"))
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
        hms_family::handle_response(
            "Huawei Push",
            HUAWEI_RETRY_DELAY_BASE_SECS,
            status,
            retry_after,
            body,
            device,
        )
    }
}

#[async_trait]
impl Pushkin for HuaweiPushkin {
    fn name(&self) -> &str {
        self.matcher.name()
    }

    fn kind(&self) -> &'static str {
        "huawei"
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
            tracing::warn!("rejecting Huawei Push device due to empty token");
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

        for attempt in 0..HUAWEI_MAX_TRIES {
            match self.send_once(device, payload.clone()).await {
                Ok(result) => return Ok(result),
                Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < HUAWEI_MAX_TRIES => {
                    let retry_after = error.retry_after().unwrap_or_else(|| {
                        Duration::from_secs(HUAWEI_RETRY_DELAY_BASE_SECS * (1_u64 << attempt))
                    });
                    sleep(retry_after).await;
                }
                Err(error) => return Err(error),
            }
        }

        Err(DispatchError::remote("Huawei Push retried too many times"))
    }
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
            app_id: Some("com.example.huawei".to_owned()),
            push_key: Some(arkret_models_integration::PushKey::new("hw-token").unwrap()),
            platform: None,
            target_route_token: None,
            visible_notification_opt_in: false,
        }
    }

    fn notification() -> PushNotificationEnvelope {
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

    fn pushkin() -> HuaweiPushkin {
        HuaweiPushkin {
            matcher: AppMatcher::new("com.example.huawei".to_owned()).unwrap(),
            gate: ConcurrencyGate::new(1),
            connection_semaphore: Arc::new(Semaphore::new(1)),
            client: Client::builder().build().unwrap(),
            token_grant: ClientCredentialsGrant::new(
                "12345".to_owned(),
                "secret".to_owned(),
                HUAWEI_TOKEN_URL.to_owned(),
            ),
            endpoint: format!("{HUAWEI_API_BASE_URL}/12345/messages:send"),
            config: HmsAndroidConfig {
                channel_id: Some("messages".to_owned()),
                ttl_seconds: Some(3600),
                android_config: Map::new(),
                android_notification: Map::new(),
                click_action: Some(
                    json!({
                        "type": 2,
                        "url": "https://example.com"
                    })
                    .as_object()
                    .unwrap()
                    .clone()
                    .into_iter()
                    .collect(),
                ),
                send_badge_counts: true,
            },
        }
    }

    #[test]
    fn builds_request_body() {
        let device = device();
        let payload =
            build_android_notification_payload(&notification(), Map::new(), true, true).unwrap();
        let body = Value::Object(pushkin().build_request_body(&device, payload).unwrap());

        assert_eq!(
            body.pointer("/message/token/0"),
            Some(&Value::String("hw-token".to_owned()))
        );
        assert_eq!(
            body.pointer("/message/notification/title"),
            Some(&Value::String("Mission Control".to_owned()))
        );
        assert_eq!(
            body.pointer("/message/android/notification/channel_id"),
            Some(&Value::String("messages".to_owned()))
        );
        assert_eq!(
            body.pointer("/message/android/notification/click_action/type"),
            Some(&Value::Number(2.into()))
        );
        assert_eq!(
            body.pointer("/message/android/urgency"),
            Some(&Value::String("NORMAL".to_owned()))
        );
        // T4.3 — the freeform data dictionary must NOT carry stable
        // correlation identifiers any more. push_target_id is the
        // only opaque scope hook that survives.
        let data_blob = body
            .pointer("/message/data")
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            !data_blob.contains("\"strand_id\""),
            "huawei data must not carry strand_id: {data_blob}"
        );
        assert!(
            !data_blob.contains("\"event_id\""),
            "huawei data must not carry event_id: {data_blob}"
        );
        assert!(
            !data_blob.contains("\"sender\""),
            "huawei data must not carry sender: {data_blob}"
        );
        assert!(
            data_blob.contains("\"push_target_id\":\"ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8\""),
            "huawei data must carry push_target_id: {data_blob}"
        );
    }

    #[test]
    fn invalid_token_response_rejects_push_key() {
        let result = pushkin()
            .handle_response(
                StatusCode::OK,
                None,
                r#"{"code":"80300007","msg":"invalid token"}"#,
                &device(),
            )
            .unwrap();

        assert_eq!(result, vec!["hw-token".to_owned()]);
    }

    #[test]
    fn success_code_is_treated_as_success() {
        let result = pushkin()
            .handle_response(
                StatusCode::OK,
                None,
                r#"{"code":"80000000","msg":"Success"}"#,
                &device(),
            )
            .unwrap();

        assert!(result.is_empty());
    }
}
