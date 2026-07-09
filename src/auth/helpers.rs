use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use salvo::http::StatusCode;
use salvo::prelude::Request;

use super::AuthFailure;

pub(super) fn reject_query_string_auth(req: &Request) -> Result<(), AuthFailure> {
    let Some(query) = req.uri().query() else {
        return Ok(());
    };

    for pair in query.split('&') {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        if is_forbidden_query_auth_param(name) {
            return Err(AuthFailure {
                status: StatusCode::BAD_REQUEST,
                code: arkret::error::ERROR_CODE_SCHEMA_VIOLATION,
                message: "query string authentication is not allowed".to_owned(),
            });
        }
    }

    Ok(())
}

fn is_forbidden_query_auth_param(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "access_token"
            | "session_token"
            | "api_key"
            | "auth"
            | "authorization"
            | "signature"
            | "token"
            | "bearer_token"
    )
}

pub(super) fn optional_header(req: &Request, name: &str) -> Option<String> {
    req.header::<String>(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

pub(super) fn required_header(
    req: &Request,
    name: &str,
    missing_message: &str,
) -> Result<String, AuthFailure> {
    req.header::<String>(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: arkret::error::ERROR_CODE_CAPABILITY_DENIED,
            message: missing_message.to_owned(),
        })
}

pub(super) fn authority(req: &Request) -> Result<String, AuthFailure> {
    req.header::<String>("host")
        .or_else(|| req.uri().authority().map(|value| value.to_string()))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ERROR_CODE_INVALID_SIGNATURE,
            message: "request authority is missing".to_owned(),
        })
}

pub(super) fn target_uri(req: &Request) -> Result<String, AuthFailure> {
    if req.uri().scheme_str().is_some() && req.uri().authority().is_some() {
        return Ok(req.uri().to_string());
    }

    let scheme = req
        .header::<String>("x-forwarded-proto")
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "http".to_owned());
    let authority = authority(req)?;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());
    Ok(format!("{scheme}://{authority}{path_and_query}"))
}

pub(super) fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "success" | "verified"
    )
}

pub(super) fn unix_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs() as i64
}

pub fn redact_url_credentials(url: &str) -> String {
    match reqwest::Url::parse(url) {
        Ok(mut parsed) => {
            if !parsed.username().is_empty() {
                let _ = parsed.set_username("***");
            }
            if parsed.password().is_some() {
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        }
        Err(_) => url.to_owned(),
    }
}

pub fn signature_public_key_hex(signing_key_seed_hex: &str) -> Result<String> {
    let bytes = hex::decode(signing_key_seed_hex)?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("signing key seed must be 32 bytes"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(hex::encode(signing_key.verifying_key().to_bytes()))
}
