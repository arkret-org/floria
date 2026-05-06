use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Proxy};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::auth::redact_url_credentials;
use crate::config::Config;
use crate::error::DispatchError;

pub(super) fn build_reqwest_client(config: &Config, user_agent: &str) -> Result<Client> {
    let mut builder = Client::builder().user_agent(user_agent);
    if let Some(proxy) = config.outbound_proxy() {
        builder =
            builder.proxy(Proxy::all(proxy).with_context(|| {
                format!("invalid proxy URL `{}`", redact_url_credentials(proxy))
            })?);
    }
    builder.build().context("failed to build HTTP client")
}

pub(super) fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

pub(super) struct ClientCredentialsGrant {
    client_id: String,
    client_secret: String,
    token_url: String,
    cache: Mutex<Option<CachedAccessToken>>,
}

struct CachedAccessToken {
    token: String,
    expires_at: Instant,
}

impl ClientCredentialsGrant {
    pub fn new(client_id: String, client_secret: String, token_url: String) -> Self {
        Self {
            client_id,
            client_secret,
            token_url,
            cache: Mutex::new(None),
        }
    }

    pub async fn access_token(&self, client: &Client) -> Result<String, DispatchError> {
        {
            let cache = self.cache.lock().await;
            if let Some(token) = cache.as_ref()
                && token.expires_at > Instant::now() + Duration::from_secs(30)
            {
                return Ok(token.token.clone());
            }
        }

        let token: AccessTokenResponse = client
            .post(&self.token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|error| {
                DispatchError::temporary(
                    format!(
                        "failed to fetch access token from {}: {error}",
                        redact_url_credentials(&self.token_url)
                    ),
                    None,
                )
            })?
            .error_for_status()
            .map_err(|error| {
                DispatchError::remote(format!(
                    "token endpoint rejected request to {}: {error}",
                    redact_url_credentials(&self.token_url)
                ))
            })?
            .json()
            .await
            .map_err(|error| {
                DispatchError::remote(format!("failed to parse access token response: {error}"))
            })?;

        let mut cache = self.cache.lock().await;
        *cache = Some(CachedAccessToken {
            token: token.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(token.expires_in.max(60)),
        });
        Ok(token.access_token)
    }
}

pub(super) fn header_value(value: &str) -> Result<HeaderValue, DispatchError> {
    reqwest::header::HeaderValue::from_str(value)
        .map_err(|error| DispatchError::internal(format!("invalid header value: {error}")))
}

pub(super) fn bearer(token: &str) -> Result<reqwest::header::HeaderValue, DispatchError> {
    header_value(&format!("Bearer {token}"))
}

pub(super) fn looks_like_invalid_token(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("token")
        && (lower.contains("invalid")
            || lower.contains("expired")
            || lower.contains("not exist")
            || lower.contains("unregistered"))
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    expires_in: u64,
}
