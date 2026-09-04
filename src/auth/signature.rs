use std::sync::Arc;

use arkret_signatures::http_signature::{
    self as sdk_sig, Component, ContentDigest, HttpMessageVerificationError, SignatureError,
    SignaturePolicyError, SignatureVerificationPolicy,
};
use arkret_wire::DidCoreId;
use salvo::http::StatusCode;
use salvo::prelude::Request;
use sha2::{Digest, Sha256};

use super::helpers::{authority, target_uri, unix_now_secs};
use super::{
    AuthFailure, CONTENT_DIGEST_HEADER, DESTINATION_SERVICE_ID_HEADER, SIGNATURE_HEADER,
    SIGNATURE_INPUT_HEADER, SOURCE_SERVICE_ID_HEADER,
};
use crate::config::{NotifyAuthConfig, NotifyServicePrincipalConfig};
use crate::nonce_store::{NonceCheck, NonceStore};

pub const SIGNATURE_MAX_LIFETIME_SECONDS: i64 = 300;
pub const SIGNATURE_CREATED_MAX_SKEW_SECONDS: i64 = 30;

pub(super) fn verify_message_signature(
    req: &Request,
    body: &[u8],
    auth: &NotifyAuthConfig,
    principal: &NotifyServicePrincipalConfig,
    origin_id: &DidCoreId,
    request_id: &str,
) -> Result<(), AuthFailure> {
    let key_id = principal.signature_verification_method.as_deref().ok_or_else(|| {
        tracing::warn!(
            request_id,
            origin_id = %origin_id,
            "rejecting /notify request because principal is missing signature_verification_method"
        );
        AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
            message: "service principal is missing signature key configuration".to_owned(),
        }
    })?;
    let public_key_hex = principal
        .signature_public_key_hex
        .as_deref()
        .ok_or_else(|| {
            tracing::warn!(
                request_id,
                origin_id = %origin_id,
                "rejecting /notify request because principal is missing signature_public_key_hex"
            );
            AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
                message: "service principal is missing signature key configuration".to_owned(),
            }
        })?;

    // ----- header pull + parse via SDK ----------------------------------
    let raw_signature_input = req
        .header::<String>(SIGNATURE_INPUT_HEADER)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
            message: "missing Signature-Input header".to_owned(),
        })?;
    let signature_input =
        sdk_sig::parse_signature_input(&raw_signature_input).map_err(map_signature_input_error)?;

    if req.header::<String>(SIGNATURE_HEADER).is_none() {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
            message: "missing Signature header".to_owned(),
        });
    }

    // ----- policy checks (key_id, alg, required components, skew) ------
    if signature_input.key_id != key_id {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
            message: "Signature key_id does not match configured service principal".to_owned(),
        });
    }
    let required_components = [
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header(CONTENT_DIGEST_HEADER.to_owned()),
        Component::Header(SOURCE_SERVICE_ID_HEADER.to_owned()),
        Component::Header(DESTINATION_SERVICE_ID_HEADER.to_owned()),
    ];
    let now = unix_now_secs();
    let created_skew =
        (auth.signature_max_skew_seconds() as i64).min(SIGNATURE_CREATED_MAX_SKEW_SECONDS);
    let public_key_bytes = hex::decode(public_key_hex).map_err(|_| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
        message: "configured signature public key is not valid hex".to_owned(),
    })?;
    let public_key =
        sdk_sig::public_key_from_bytes(&public_key_bytes).map_err(|_| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
            message: "configured signature public key is invalid".to_owned(),
        })?;
    let target_uri = target_uri(req)?;
    let authority = authority(req)?.to_owned();
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let policy = SignatureVerificationPolicy::new(required_components)
        .require_content_digest(true)
        .max_clock_skew_seconds(created_skew)
        .max_validity_window_seconds(SIGNATURE_MAX_LIFETIME_SECONDS);
    sdk_sig::verify_signed_canonical_json_message(
        req.method().as_str(),
        &target_uri,
        &authority,
        &path,
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        req.header::<String>("content-encoding").is_some(),
        body,
        &public_key,
        &policy,
        now,
    )
    .map(|_| ())
    .map_err(map_http_message_error)
}

/// Re-verify the RFC 9530 `Content-Digest` against the raw body and
/// return the parsed wire value on success. Routed through SDK's
/// [`ContentDigest`] so the parser semantics live in one place.
pub(super) fn verified_content_digest(req: &Request, body: &[u8]) -> Result<String, AuthFailure> {
    let value = req
        .header::<String>(CONTENT_DIGEST_HEADER)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
            message: "missing Content-Digest header".to_owned(),
        })?;
    let parsed = ContentDigest::parse(value.trim()).map_err(|err| match err {
        SignatureError::MalformedContentDigest => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
            message: "Content-Digest must use the sole Arkret v1 sha-256 token".to_owned(),
        },
        _ => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
            message: "Content-Digest header is invalid".to_owned(),
        },
    })?;
    sdk_sig::verify_content_digest(&parsed, body).map_err(|_| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
        message: "Content-Digest does not match request body".to_owned(),
    })?;
    arkret_wire::canonical::validate_canonical_bytes(body).map_err(|error| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
        message: format!("signed request body is not canonical JSON: {error}"),
    })?;
    Ok(parsed.wire_value)
}

/// Map an SDK `Signature-Input` parse failure into floria's
/// [`AuthFailure`] shape. The previous in-tree parser produced
/// per-failure messages like "Signature-Input is missing created" — we
/// preserve those exact wordings where the SDK error pinpoints the
/// same offending parameter so log scrapers and tests don't break.
fn map_signature_input_error(err: SignatureError) -> AuthFailure {
    let message = match err {
        SignatureError::MalformedSignatureInput => "Signature-Input is malformed".to_owned(),
        SignatureError::EmptyCoveredComponents => {
            "Signature-Input must cover at least one component".to_owned()
        }
        SignatureError::MissingSignatureInputParameter("created") => {
            "Signature-Input is missing created".to_owned()
        }
        SignatureError::MissingSignatureInputParameter("expires") => {
            "Signature-Input is missing expires".to_owned()
        }
        SignatureError::MissingSignatureInputParameter("keyid") => {
            "Signature-Input is missing keyid".to_owned()
        }
        SignatureError::MissingSignatureInputParameter(name) => {
            format!("Signature-Input is missing {name}")
        }
        SignatureError::InvalidSignatureInputParameter(name) => {
            format!("Signature-Input parameter `{name}` is invalid")
        }
        _ => "Signature-Input is malformed".to_owned(),
    };
    AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
        message,
    }
}

fn map_http_message_error(err: HttpMessageVerificationError) -> AuthFailure {
    let code = match &err {
        HttpMessageVerificationError::Policy(
            SignaturePolicyError::CreatedInFuture
            | SignaturePolicyError::CreatedTooOld
            | SignaturePolicyError::Expired,
        ) => "auth_expired",
        _ => arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
    };
    let message = match err {
        HttpMessageVerificationError::ContentEncodingNotAllowed => {
            "signed JSON requests must not use Content-Encoding".to_owned()
        }
        HttpMessageVerificationError::NonCanonicalJson(error) => {
            format!("signed request body is not canonical JSON: {error}")
        }
        HttpMessageVerificationError::Signature(SignatureError::ContentDigestMismatch) => {
            "Content-Digest does not match request body".to_owned()
        }
        HttpMessageVerificationError::Signature(SignatureError::MissingCoveredComponent(name)) => {
            format!("required signed header `{name}` is missing")
        }
        HttpMessageVerificationError::Policy(
            SignaturePolicyError::MissingRequiredCoveredComponent,
        ) => "HTTP Message Signature is missing required covered components".to_owned(),
        HttpMessageVerificationError::Policy(SignaturePolicyError::CreatedInFuture) => {
            "HTTP Message Signature created timestamp is in the future".to_owned()
        }
        HttpMessageVerificationError::Policy(SignaturePolicyError::CreatedTooOld) => {
            "HTTP Message Signature created timestamp is too old".to_owned()
        }
        HttpMessageVerificationError::Policy(SignaturePolicyError::Expired) => {
            "HTTP Message Signature has expired".to_owned()
        }
        HttpMessageVerificationError::Policy(SignaturePolicyError::InvalidValidityWindow) => {
            "HTTP Message Signature lifetime exceeds 300 seconds".to_owned()
        }
        _ => "HTTP Message Signature verification failed".to_owned(),
    };
    AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code,
        message,
    }
}

pub(super) fn has_signature_headers(req: &Request) -> bool {
    req.header::<String>(SIGNATURE_INPUT_HEADER).is_some()
        || req.header::<String>(SIGNATURE_HEADER).is_some()
}

/// Bind the verified Signature header bytes (and the request's
/// content-digest) to a single-use nonce. A replay arriving inside
/// the `expires - created` window is rejected even though every
/// other signature check would still pass. Signed deployments must
/// configure a nonce store; otherwise replay protection fails closed.
pub(super) async fn verify_nonce_freshness(
    req: &Request,
    nonce_store: Option<&Arc<NonceStore>>,
    origin_id: &DidCoreId,
    request_id: &str,
) -> Result<(), AuthFailure> {
    let Some(nonce_store) = nonce_store else {
        tracing::warn!(
            request_id,
            origin_id = %origin_id,
            "rejecting /notify request: nonce store is required for signed requests"
        );
        return Err(AuthFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
            message: "replay protection is not configured".to_owned(),
        });
    };
    let signature_header = req
        .header::<String>(SIGNATURE_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let signature_input = req
        .header::<String>(SIGNATURE_INPUT_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let Some(signature_header) = signature_header else {
        return Ok(());
    };
    let Some(signature_input) = signature_input else {
        return Ok(());
    };

    let mut hasher = Sha256::new();
    hasher.update(signature_header.as_bytes());
    hasher.update([0]);
    hasher.update(signature_input.as_bytes());
    let fingerprint = hex::encode(hasher.finalize());

    match nonce_store.observe_async(&fingerprint).await {
        NonceCheck::Fresh => Ok(()),
        NonceCheck::Replayed => {
            tracing::warn!(
                request_id,
                origin_id = %origin_id,
                "rejecting /notify request as a Signature replay within the expiry window"
            );
            Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret_wire::error_codes::ErrorCode::SIGNATURE_INVALID,
                message: "HTTP Message Signature has already been observed (replay)".to_owned(),
            })
        }
        NonceCheck::BackendUnavailable => {
            tracing::warn!(
                request_id,
                origin_id = %origin_id,
                "rejecting /notify request: nonce store backend unavailable (strict policy)"
            );
            Err(AuthFailure {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: arkret_wire::error_codes::ErrorCode::SERVICE_UNAVAILABLE,
                message: "replay protection backend is unavailable".to_owned(),
            })
        }
    }
}
