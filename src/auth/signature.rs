use std::sync::Arc;

use arkret_signatures::http_signature::{
    self as sdk_sig, Component, ContentDigest, SignatureError, SignedRequestParts,
};
use salvo::http::StatusCode;
use salvo::prelude::Request;
use sha2::{Digest, Sha256};

use super::helpers::{authority, target_uri, unix_now_secs};
use super::{
    AuthFailure, CONTENT_DIGEST_HEADER, DESTINATION_SERVICE_ID_HEADER, ORIGIN_SERVICE_ID_HEADER,
    SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER,
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
    origin_did: &str,
    request_id: &str,
) -> Result<(), AuthFailure> {
    let key_id = principal.signature_key_id.as_deref().ok_or_else(|| {
        tracing::warn!(
            request_id,
            origin_service_id = %origin_did,
            "rejecting /notify request because principal is missing signature_key_id"
        );
        AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "service principal is missing signature key configuration".to_owned(),
        }
    })?;
    let public_key_hex = principal
        .signature_public_key_hex
        .as_deref()
        .ok_or_else(|| {
            tracing::warn!(
                request_id,
                origin_service_id = %origin_did,
                "rejecting /notify request because principal is missing signature_public_key_hex"
            );
            AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret::error::ErrorCode::INVALID_SIGNATURE,
                message: "service principal is missing signature key configuration".to_owned(),
            }
        })?;

    // ----- header pull + parse via SDK ----------------------------------
    let raw_signature_input = req
        .header::<String>(SIGNATURE_INPUT_HEADER)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::UNAUTHENTICATED,
            message: "missing Signature-Input header".to_owned(),
        })?;
    let signature_input =
        sdk_sig::parse_signature_input(&raw_signature_input).map_err(map_signature_input_error)?;

    let raw_signature_header =
        req.header::<String>(SIGNATURE_HEADER)
            .ok_or_else(|| AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret::error::ErrorCode::UNAUTHENTICATED,
                message: "missing Signature header".to_owned(),
            })?;
    // We parse the raw signature header solely to fail fast on a missing
    // label / malformed base64 — verify_signature will redo the decoding,
    // but this lets us produce a precise AuthFailure before building the
    // canonical message.
    let signature_bytes =
        sdk_sig::parse_signature_header(&raw_signature_header, &signature_input.label)
            .map_err(map_signature_header_error)?;
    if signature_bytes.len() != 64 {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "Signature header is not a valid Ed25519 signature".to_owned(),
        });
    }
    // The base64 form of the signature value, with the `label=:` wrap
    // stripped, is what verify_signature expects.
    let signature_b64 = sdk_sig::encode_signature_b64(&signature_bytes);

    // ----- policy checks (key_id, alg, required components, skew) ------
    if signature_input.key_id != key_id {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "Signature key_id does not match configured service principal".to_owned(),
        });
    }
    if signature_input.algorithm != "ed25519" {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "unsupported HTTP Message Signature algorithm".to_owned(),
        });
    }

    let required_components = [
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header(CONTENT_DIGEST_HEADER.to_owned()),
        Component::Header(ORIGIN_SERVICE_ID_HEADER.to_owned()),
        Component::Header(DESTINATION_SERVICE_ID_HEADER.to_owned()),
    ];
    if !signature_input.covers_all(&required_components) {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "HTTP Message Signature is missing required covered components".to_owned(),
        });
    }

    let now = unix_now_secs();
    let created_skew =
        (auth.signature_max_skew_seconds() as i64).min(SIGNATURE_CREATED_MAX_SKEW_SECONDS);
    if signature_input.created > now + created_skew {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "auth_expired",
            message: "HTTP Message Signature created timestamp is in the future".to_owned(),
        });
    }
    if signature_input.created < now - created_skew {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "auth_expired",
            message: "HTTP Message Signature created timestamp is too old".to_owned(),
        });
    }
    if signature_input.expires - signature_input.created > SIGNATURE_MAX_LIFETIME_SECONDS {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "auth_expired",
            message: "HTTP Message Signature lifetime exceeds 300 seconds".to_owned(),
        });
    }
    if signature_input.expires < now - auth.signature_max_skew_seconds() as i64 {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "auth_expired",
            message: "HTTP Message Signature has expired".to_owned(),
        });
    }

    // ----- content-digest enforcement (covered → must verify) ----------
    // floria has always insisted that `content-digest` is a covered
    // component (the required_components check above guarantees it), and
    // that the body matches. We re-verify here against the raw body so
    // tampering is caught before the canonical message is even built.
    let verified_digest = verified_content_digest(req, body)?;

    // ----- canonical message + ed25519 verify --------------------------
    let parts = signed_request_parts(req, &verified_digest)?;
    let message =
        sdk_sig::canonical_message(&parts, &signature_input).map_err(map_canonical_error)?;

    let public_key_bytes = hex::decode(public_key_hex).map_err(|_| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: arkret::error::ErrorCode::INVALID_SIGNATURE,
        message: "configured signature public key is not valid hex".to_owned(),
    })?;
    let public_key =
        sdk_sig::public_key_from_bytes(&public_key_bytes).map_err(|_| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "configured signature public key is invalid".to_owned(),
        })?;
    sdk_sig::verify_signature(&message, &signature_b64, &public_key).map_err(|err| match err {
        SignatureError::InvalidSignatureBase64 => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "Signature header is not valid base64".to_owned(),
        },
        SignatureError::InvalidSignatureLength => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "Signature header is not a valid Ed25519 signature".to_owned(),
        },
        _ => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "HTTP Message Signature verification failed".to_owned(),
        },
    })
}

/// Project a salvo `Request` into the SDK's framework-agnostic
/// [`SignedRequestParts`]. The pre-verified `content-digest` wire value
/// is threaded in so `canonical_message` can emit it without re-parsing
/// the header.
fn signed_request_parts(
    req: &Request,
    verified_content_digest: &str,
) -> Result<SignedRequestParts, AuthFailure> {
    let target_uri = target_uri(req)?;
    let authority = authority(req)?.to_owned();
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());
    let method = req.method().as_str().to_owned();

    // Forward every request header so any non-required covered
    // component the signer chose to include is still resolvable.
    let mut headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    // floria derives `@authority` from the Host header / URI fallback,
    // and SDK canonicalization reads it from `parts.authority` directly
    // (not from a `host` entry in `headers`), so no extra wiring needed.
    // Make sure the content-digest emitted in the canonical message is
    // the body-verified one, not whatever the request header happens to
    // contain (they should match by definition, but we belt-and-brace).
    headers.retain(|(name, _)| name != "content-digest");
    headers.push((
        "content-digest".to_owned(),
        verified_content_digest.to_owned(),
    ));

    Ok(SignedRequestParts {
        method,
        target_uri,
        authority,
        path,
        headers,
        body_digest: Some(verified_content_digest.to_owned()),
    })
}

/// Re-verify the RFC 9530 `Content-Digest` against the raw body and
/// return the parsed wire value on success. Routed through SDK's
/// [`ContentDigest`] so the parser semantics live in one place.
pub(super) fn verified_content_digest(req: &Request, body: &[u8]) -> Result<String, AuthFailure> {
    let value = req
        .header::<String>(CONTENT_DIGEST_HEADER)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "missing Content-Digest header".to_owned(),
        })?;
    let parsed = ContentDigest::parse(value.trim()).map_err(|err| match err {
        SignatureError::MalformedContentDigest => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "Content-Digest must use sha-256 or sha-512".to_owned(),
        },
        _ => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "Content-Digest header is invalid".to_owned(),
        },
    })?;
    // floria has historically locked the wire profile to sha-256 — keep
    // that policy here rather than relaxing it just because the SDK
    // parser also accepts sha-512.
    if parsed.algorithm != sdk_sig::ContentDigestAlgorithm::Sha256 {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::INVALID_SIGNATURE,
            message: "Content-Digest must use sha-256".to_owned(),
        });
    }
    sdk_sig::verify_content_digest(&parsed, body).map_err(|_| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: arkret::error::ErrorCode::INVALID_SIGNATURE,
        message: "Content-Digest does not match request body".to_owned(),
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
        code: arkret::error::ErrorCode::INVALID_SIGNATURE,
        message,
    }
}

fn map_signature_header_error(err: SignatureError) -> AuthFailure {
    let message = match err {
        SignatureError::MalformedSignatureHeader(_) => {
            "Signature header does not contain the declared signature label".to_owned()
        }
        SignatureError::InvalidSignatureBase64 => "Signature header is not valid base64".to_owned(),
        _ => "Signature header is malformed".to_owned(),
    };
    AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: arkret::error::ErrorCode::INVALID_SIGNATURE,
        message,
    }
}

fn map_canonical_error(err: SignatureError) -> AuthFailure {
    let message = match err {
        SignatureError::MissingCoveredComponent(name) => {
            format!("required signed header `{name}` is missing")
        }
        _ => "HTTP Message Signature canonicalization failed".to_owned(),
    };
    AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: arkret::error::ErrorCode::INVALID_SIGNATURE,
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
    origin_did: &str,
    request_id: &str,
) -> Result<(), AuthFailure> {
    let Some(nonce_store) = nonce_store else {
        tracing::warn!(
            request_id,
            origin_service_id = %origin_did,
            "rejecting /notify request: nonce store is required for signed requests"
        );
        return Err(AuthFailure {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: arkret::error::ErrorCode::SERVICE_UNAVAILABLE,
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
                origin_service_id = %origin_did,
                "rejecting /notify request as a Signature replay within the expiry window"
            );
            Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret::error::ErrorCode::INVALID_SIGNATURE,
                message: "HTTP Message Signature has already been observed (replay)".to_owned(),
            })
        }
        NonceCheck::BackendUnavailable => {
            tracing::warn!(
                request_id,
                origin_service_id = %origin_did,
                "rejecting /notify request: nonce store backend unavailable (strict policy)"
            );
            Err(AuthFailure {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: arkret::error::ErrorCode::SERVICE_UNAVAILABLE,
                message: "replay protection backend is unavailable".to_owned(),
            })
        }
    }
}
