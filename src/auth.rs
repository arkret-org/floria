use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use salvo::http::StatusCode;
use salvo::prelude::Request;
use sha2::{Digest, Sha256};

use crate::config::{NotifyAuthConfig, NotifyServicePrincipalConfig};

pub const ORIGIN_SERVICE_DID_HEADER: &str = "x-contrix-origin-service-did";
pub const DESTINATION_SERVICE_DID_HEADER: &str = "x-contrix-destination-service-did";
const CONTENT_DIGEST_HEADER: &str = "content-digest";
const SIGNATURE_INPUT_HEADER: &str = "signature-input";
const SIGNATURE_HEADER: &str = "signature";

#[derive(Debug, Clone)]
pub struct AuthenticatedNotifyCaller {
    pub origin_service_did: String,
    pub allow_plaintext_metadata: bool,
}

#[derive(Debug)]
pub struct AuthFailure {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug)]
struct ParsedSignatureInput {
    label: String,
    covered_components: Vec<String>,
    created: i64,
    expires: i64,
    key_id: String,
    algorithm: String,
}

pub fn authenticate_notify_request(
    req: &Request,
    body: &[u8],
    auth: &NotifyAuthConfig,
    request_id: &str,
) -> Result<AuthenticatedNotifyCaller, AuthFailure> {
    reject_query_string_auth(req)?;

    if !auth.enabled() {
        return Ok(AuthenticatedNotifyCaller {
            origin_service_did: "<anonymous>".to_owned(),
            allow_plaintext_metadata: true,
        });
    }

    let origin_did = optional_header(req, ORIGIN_SERVICE_DID_HEADER);

    if let Some(origin_did) = origin_did.as_deref()
        && let Some(principal) = auth.service_principals.get(origin_did)
    {
        verify_principal_service_type(principal, origin_did, request_id)?;
        verify_destination_service_did(req, auth, origin_did, request_id)?;
        if let Some(expected_endpoint) = principal.service_endpoint.as_deref() {
            let target_uri = target_uri(req)?;
            if !target_uri.starts_with(expected_endpoint) {
                tracing::warn!(
                    request_id,
                    origin_service_did = %origin_did,
                    expected_service_endpoint = %expected_endpoint,
                    target_uri = %target_uri,
                    "rejecting /notify request that does not match configured service endpoint"
                );
                return Err(AuthFailure {
                    status: StatusCode::FORBIDDEN,
                    code: "capability_denied",
                    message: "origin service endpoint does not match configured service binding"
                        .to_owned(),
                });
            }
        }

        let mut authenticated = false;
        if has_signature_headers(req) {
            verify_message_signature(req, body, auth, principal, &origin_did, request_id)?;
            authenticated = true;
        } else if auth.require_message_signatures {
            tracing::warn!(
                request_id,
                origin_service_did = %origin_did,
                "rejecting /notify request without required HTTP Message Signature"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
                message: "HTTP Message Signature is required".to_owned(),
            });
        }

        if !authenticated
            && bearer_matches(
                req,
                &principal.bearer_tokens,
                &principal.bearer_token_hashes,
            )
        {
            authenticated = true;
        }
        if !authenticated {
            tracing::warn!(
                request_id,
                origin_service_did = %origin_did,
                "rejecting /notify request without a valid principal credential"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
                message: "missing or invalid service credential".to_owned(),
            });
        }

        verify_mtls_profile(req, auth, principal, &origin_did, request_id)?;

        return Ok(AuthenticatedNotifyCaller {
            origin_service_did: origin_did.to_owned(),
            allow_plaintext_metadata: principal.allow_plaintext_metadata,
        });
    }

    authenticate_bearer_request(req, auth, origin_did.as_deref(), request_id)
}

fn reject_query_string_auth(req: &Request) -> Result<(), AuthFailure> {
    let Some(query) = req.uri().query() else {
        return Ok(());
    };

    for pair in query.split('&') {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        if is_forbidden_query_auth_param(name) {
            return Err(AuthFailure {
                status: StatusCode::BAD_REQUEST,
                code: "schema_violation",
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

fn authenticate_bearer_request(
    req: &Request,
    auth: &NotifyAuthConfig,
    origin_did: Option<&str>,
    request_id: &str,
) -> Result<AuthenticatedNotifyCaller, AuthFailure> {
    if auth.require_message_signatures {
        tracing::warn!(
            request_id,
            "rejecting /notify request because bearer auth cannot satisfy required HTTP Message Signature"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "HTTP Message Signature is required".to_owned(),
        });
    }

    match bearer_state(req, &auth.bearer_tokens, &auth.bearer_token_hashes) {
        BearerState::Valid => {}
        BearerState::Missing => {
            tracing::warn!(
                request_id,
                "rejecting /notify request without a bearer service token"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
                message: "missing bearer service token".to_owned(),
            });
        }
        BearerState::Invalid => {
            tracing::warn!(
                request_id,
                "rejecting /notify request with an invalid bearer service token"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
                message: "invalid bearer service token".to_owned(),
            });
        }
    }

    let origin_did = origin_did.ok_or_else(|| AuthFailure {
        status: StatusCode::FORBIDDEN,
        code: "capability_denied",
        message: "origin service DID is required".to_owned(),
    })?;

    if !auth.trusted_service_dids.is_empty()
        && !auth
            .trusted_service_dids
            .iter()
            .any(|candidate| candidate == origin_did)
    {
        tracing::warn!(
            request_id,
            origin_service_did = %origin_did,
            "rejecting /notify request from non-allowlisted service DID"
        );
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "origin service DID is not allowlisted".to_owned(),
        });
    }

    verify_destination_service_did(req, auth, origin_did, request_id)?;

    Ok(AuthenticatedNotifyCaller {
        origin_service_did: origin_did.to_owned(),
        allow_plaintext_metadata: auth
            .plaintext_metadata_service_dids
            .iter()
            .any(|candidate| candidate == origin_did),
    })
}

fn verify_principal_service_type(
    principal: &NotifyServicePrincipalConfig,
    origin_did: &str,
    request_id: &str,
) -> Result<(), AuthFailure> {
    let Some(service_type) = principal
        .service_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };

    if matches!(
        service_type.to_ascii_lowercase().as_str(),
        "push" | "push_service" | "principal" | "principal_service" | "sync" | "sync_service"
    ) {
        return Ok(());
    }

    tracing::warn!(
        request_id,
        origin_service_did = %origin_did,
        service_type,
        "rejecting /notify request from service type that is not delegated for push notify"
    );
    Err(AuthFailure {
        status: StatusCode::FORBIDDEN,
        code: "capability_denied",
        message: "origin service is not delegated for push notify".to_owned(),
    })
}

fn verify_destination_service_did(
    req: &Request,
    auth: &NotifyAuthConfig,
    origin_did: &str,
    request_id: &str,
) -> Result<(), AuthFailure> {
    let Some(expected) = auth.gateway_service_did.as_deref() else {
        return Ok(());
    };
    let destination_did = required_header(
        req,
        DESTINATION_SERVICE_DID_HEADER,
        "destination service DID is required",
    )?;
    if destination_did != expected {
        tracing::warn!(
            request_id,
            origin_service_did = %origin_did,
            destination_service_did = %destination_did,
            expected_destination_service_did = %expected,
            "rejecting /notify request for a different gateway DID"
        );
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "destination service DID does not match this gateway".to_owned(),
        });
    }
    Ok(())
}

fn verify_mtls_profile(
    req: &Request,
    auth: &NotifyAuthConfig,
    principal: &NotifyServicePrincipalConfig,
    origin_did: &str,
    request_id: &str,
) -> Result<(), AuthFailure> {
    if !principal.require_mtls {
        return Ok(());
    }
    let verified = req
        .header::<String>(auth.mtls_verified_header())
        .is_some_and(|value| is_truthy(&value));
    let fingerprint = req
        .header::<String>(auth.mtls_fingerprint_header())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    if !verified {
        tracing::warn!(
            request_id,
            origin_service_did = %origin_did,
            "rejecting /notify request without verified mTLS client certificate"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "verified mTLS client certificate is required".to_owned(),
        });
    }
    let Some(fingerprint) = fingerprint else {
        tracing::warn!(
            request_id,
            origin_service_did = %origin_did,
            "rejecting /notify request without mTLS certificate fingerprint"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "mTLS certificate fingerprint is required".to_owned(),
        });
    };
    if !principal.mtls_cert_fingerprints.is_empty()
        && !principal
            .mtls_cert_fingerprints
            .iter()
            .any(|candidate| candidate.trim().eq_ignore_ascii_case(&fingerprint))
    {
        tracing::warn!(
            request_id,
            origin_service_did = %origin_did,
            certificate_fingerprint = %fingerprint,
            "rejecting /notify request with unexpected mTLS certificate fingerprint"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "mTLS certificate fingerprint is not allowlisted".to_owned(),
        });
    }
    Ok(())
}

fn verify_message_signature(
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
            origin_service_did = %origin_did,
            "rejecting /notify request because principal is missing signature_key_id"
        );
        AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "service principal is missing signature key configuration".to_owned(),
        }
    })?;
    let public_key = principal
        .signature_public_key_hex
        .as_deref()
        .ok_or_else(|| {
            tracing::warn!(
                request_id,
                origin_service_did = %origin_did,
                "rejecting /notify request because principal is missing signature_public_key_hex"
            );
            AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "invalid_signature",
                message: "service principal is missing signature key configuration".to_owned(),
            }
        })?;

    let signature_input = req
        .header::<String>(SIGNATURE_INPUT_HEADER)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "missing Signature-Input header".to_owned(),
        })
        .and_then(|value| parse_signature_input(&value))?;
    let signature = req
        .header::<String>(SIGNATURE_HEADER)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "missing Signature header".to_owned(),
        })
        .and_then(|value| parse_signature_header(&value, &signature_input.label))?;

    if signature_input.key_id != key_id {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature key_id does not match configured service principal".to_owned(),
        });
    }
    if signature_input.algorithm != "ed25519" {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "unsupported HTTP Message Signature algorithm".to_owned(),
        });
    }

    let required_components = [
        "@method",
        "@target-uri",
        "@authority",
        "content-digest",
        ORIGIN_SERVICE_DID_HEADER,
        DESTINATION_SERVICE_DID_HEADER,
    ]
    .into_iter()
    .collect::<HashSet<_>>();
    let covered = signature_input
        .covered_components
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if !required_components.is_subset(&covered) {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "HTTP Message Signature is missing required covered components".to_owned(),
        });
    }

    let now = unix_now_secs();
    if signature_input.created > now + auth.signature_max_skew_seconds() as i64 {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "auth_expired",
            message: "HTTP Message Signature created timestamp is in the future".to_owned(),
        });
    }
    if signature_input.expires < now - auth.signature_max_skew_seconds() as i64 {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "auth_expired",
            message: "HTTP Message Signature has expired".to_owned(),
        });
    }

    let signing_string = build_signing_string(req, body, &signature_input)?;
    let public_key_bytes = hex::decode(public_key).map_err(|_| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_signature",
        message: "configured signature public key is not valid hex".to_owned(),
    })?;
    let public_key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|_| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_signature",
        message: "configured signature public key must be 32 bytes".to_owned(),
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_signature",
        message: "configured signature public key is invalid".to_owned(),
    })?;
    let signature = Signature::from_slice(&signature).map_err(|_| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_signature",
        message: "Signature header is not a valid Ed25519 signature".to_owned(),
    })?;
    verifying_key
        .verify(signing_string.as_bytes(), &signature)
        .map_err(|_| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "HTTP Message Signature verification failed".to_owned(),
        })
}

fn build_signing_string(
    req: &Request,
    body: &[u8],
    signature_input: &ParsedSignatureInput,
) -> Result<String, AuthFailure> {
    let mut lines = Vec::new();
    for component in &signature_input.covered_components {
        let value = component_value(req, body, component)?;
        lines.push(format!("\"{component}\": {value}"));
    }
    lines.push(format!(
        "\"@signature-params\": ({})\
;created={};expires={};keyid=\"{}\";alg=\"{}\"",
        signature_input
            .covered_components
            .iter()
            .map(|component| format!("\"{component}\""))
            .collect::<Vec<_>>()
            .join(" "),
        signature_input.created,
        signature_input.expires,
        signature_input.key_id,
        signature_input.algorithm
    ));
    Ok(lines.join("\n"))
}

fn component_value(req: &Request, body: &[u8], component: &str) -> Result<String, AuthFailure> {
    match component {
        "@method" => Ok(req.method().as_str().to_ascii_lowercase()),
        "@target-uri" => Ok(target_uri(req)?),
        "@authority" => Ok(authority(req)?.to_owned()),
        CONTENT_DIGEST_HEADER => verified_content_digest(req, body),
        header => req
            .header::<String>(header)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "invalid_signature",
                message: format!("required signed header `{header}` is missing"),
            }),
    }
}

fn verified_content_digest(req: &Request, body: &[u8]) -> Result<String, AuthFailure> {
    let value = req
        .header::<String>(CONTENT_DIGEST_HEADER)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "missing Content-Digest header".to_owned(),
        })?;
    let parsed = value.trim();
    let Some(encoded) = parsed
        .strip_prefix("sha-256=:")
        .and_then(|value| value.strip_suffix(':'))
    else {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Content-Digest must use sha-256".to_owned(),
        });
    };
    let provided = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Content-Digest is not valid base64".to_owned(),
        })?;
    let mut hasher = Sha256::new();
    hasher.update(body);
    let expected = hasher.finalize().to_vec();
    if provided != expected {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Content-Digest does not match request body".to_owned(),
        });
    }
    Ok(parsed.to_owned())
}

fn parse_signature_input(value: &str) -> Result<ParsedSignatureInput, AuthFailure> {
    let trimmed = value.trim();
    let (label, remainder) = trimmed.split_once('=').ok_or_else(|| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_signature",
        message: "Signature-Input is malformed".to_owned(),
    })?;
    let remainder = remainder.trim();
    let end_components = remainder.find(')').ok_or_else(|| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_signature",
        message: "Signature-Input is missing covered components".to_owned(),
    })?;
    let components_str = remainder
        .strip_prefix('(')
        .and_then(|value| value.get(..end_components - 1))
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature-Input covered components are malformed".to_owned(),
        })?;
    let covered_components = components_str
        .split_ascii_whitespace()
        .map(|component| component.trim_matches('"').to_ascii_lowercase())
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    if covered_components.is_empty() {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature-Input must cover at least one component".to_owned(),
        });
    }

    let mut created = None;
    let mut expires = None;
    let mut key_id = None;
    let mut algorithm = None;
    for param in remainder[end_components + 1..]
        .split(';')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let (name, raw_value) = param.split_once('=').ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature-Input parameter is malformed".to_owned(),
        })?;
        match name {
            "created" => {
                created = raw_value.parse::<i64>().ok();
            }
            "expires" => {
                expires = raw_value.parse::<i64>().ok();
            }
            "keyid" => {
                key_id = Some(raw_value.trim_matches('"').to_owned());
            }
            "alg" => {
                algorithm = Some(raw_value.trim_matches('"').to_ascii_lowercase());
            }
            _ => {}
        }
    }

    Ok(ParsedSignatureInput {
        label: label.trim().to_owned(),
        covered_components,
        created: created.ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature-Input is missing created".to_owned(),
        })?,
        expires: expires.ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature-Input is missing expires".to_owned(),
        })?,
        key_id: key_id.ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature-Input is missing keyid".to_owned(),
        })?,
        algorithm: algorithm.unwrap_or_else(|| "ed25519".to_owned()),
    })
}

fn parse_signature_header(value: &str, label: &str) -> Result<Vec<u8>, AuthFailure> {
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let Some((candidate, encoded)) = part.split_once("=:") else {
            continue;
        };
        if candidate.trim() != label {
            continue;
        }
        let encoded = encoded.strip_suffix(':').ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature header is malformed".to_owned(),
        })?;
        return base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "invalid_signature",
                message: "Signature header is not valid base64".to_owned(),
            });
    }

    Err(AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_signature",
        message: "Signature header does not contain the declared signature label".to_owned(),
    })
}

fn has_signature_headers(req: &Request) -> bool {
    req.header::<String>(SIGNATURE_INPUT_HEADER).is_some()
        || req.header::<String>(SIGNATURE_HEADER).is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BearerState {
    Missing,
    Invalid,
    Valid,
}

fn bearer_matches(req: &Request, candidates: &[String], candidate_hashes: &[String]) -> bool {
    matches!(
        bearer_state(req, candidates, candidate_hashes),
        BearerState::Valid
    )
}

fn bearer_state(req: &Request, candidates: &[String], candidate_hashes: &[String]) -> BearerState {
    let Some(raw) = req.header::<String>("authorization") else {
        return BearerState::Missing;
    };
    let Some(token) = parse_bearer_token(&raw) else {
        return BearerState::Invalid;
    };
    if candidates.iter().any(|candidate| candidate == token)
        || candidate_hashes
            .iter()
            .any(|candidate| bearer_token_hash_matches(token, candidate))
    {
        BearerState::Valid
    } else {
        BearerState::Invalid
    }
}

fn optional_header(req: &Request, name: &str) -> Option<String> {
    let Some(token) = req
        .header::<String>(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return None;
    };
    Some(token)
}

fn parse_bearer_token(value: &str) -> Option<&str> {
    let value = value.trim();
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

fn bearer_token_hash_matches(token: &str, candidate: &str) -> bool {
    let candidate = candidate
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| candidate.trim());
    !candidate.is_empty() && bearer_token_sha256_hex(token).eq_ignore_ascii_case(candidate)
}

pub fn bearer_token_sha256_hex(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn required_header(
    req: &Request,
    name: &str,
    missing_message: &str,
) -> Result<String, AuthFailure> {
    req.header::<String>(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: missing_message.to_owned(),
        })
}

fn authority(req: &Request) -> Result<&str, AuthFailure> {
    req.header::<String>("host")
        .or_else(|| req.uri().authority().map(|value| value.to_string()))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(|value| Box::leak(value.into_boxed_str()) as &str)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "request authority is missing".to_owned(),
        })
}

fn target_uri(req: &Request) -> Result<String, AuthFailure> {
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

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "success" | "verified"
    )
}

fn unix_now_secs() -> i64 {
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

#[cfg(test)]
mod tests {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use salvo::test::{ResponseExt, TestClient};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::AppState;
    use crate::pushkin::{Pushkin, PushkinRegistry};
    use crate::service::build_router;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct NoopPushkin;

    #[async_trait::async_trait]
    impl Pushkin for NoopPushkin {
        fn name(&self) -> &str {
            "noop"
        }

        fn kind(&self) -> &'static str {
            "noop"
        }

        fn handles_appid(&self, appid: &str) -> bool {
            appid == "com.example.app"
        }

        async fn dispatch_notification(
            &self,
            _notification: &crate::models::Notification,
            _device: &crate::models::Device,
            _context: &crate::models::NotificationContext,
        ) -> Result<Vec<String>, crate::error::DispatchError> {
            Ok(vec![])
        }
    }

    fn test_service_with_principal(principal: NotifyServicePrincipalConfig) -> salvo::Service {
        let registry = PushkinRegistry::new(HashMap::from([(
            "com.example.app".to_owned(),
            Arc::new(NoopPushkin) as Arc<dyn Pushkin>,
        )]));
        let mut state = AppState::new(Arc::new(registry));
        let mut notify_auth = NotifyAuthConfig::default();
        notify_auth.gateway_service_did = Some("did:web:push.example.com".to_owned());
        notify_auth.require_message_signatures = true;
        notify_auth.service_principals =
            HashMap::from([("did:web:sync.example.com".to_owned(), principal)]);
        state.notify_auth = notify_auth;
        salvo::Service::new(build_router(Arc::new(state)))
    }

    fn sign_request(
        seed_hex: &str,
        method: &str,
        target_uri: &str,
        authority: &str,
        body: &[u8],
    ) -> (String, String, String) {
        let seed = hex::decode(seed_hex).unwrap();
        let seed: [u8; 32] = seed.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);

        let mut hasher = Sha256::new();
        hasher.update(body);
        let digest = format!(
            "sha-256=:{}:",
            base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
        );
        let now = unix_now_secs();
        let signature_input = format!(
            "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"x-contrix-origin-service-did\" \"x-contrix-destination-service-did\");created={};expires={};keyid=\"did:web:sync.example.com#push\";alg=\"ed25519\"",
            now - 1,
            now + 300
        );
        let signing_string = [
            format!("\"@method\": {}", method.to_ascii_lowercase()),
            format!("\"@target-uri\": {target_uri}"),
            format!("\"@authority\": {authority}"),
            format!("\"content-digest\": {digest}"),
            "\"x-contrix-origin-service-did\": did:web:sync.example.com".to_owned(),
            "\"x-contrix-destination-service-did\": did:web:push.example.com".to_owned(),
            format!(
                "\"@signature-params\": (\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"x-contrix-origin-service-did\" \"x-contrix-destination-service-did\");created={};expires={};keyid=\"did:web:sync.example.com#push\";alg=\"ed25519\"",
                now - 1,
                now + 300
            ),
        ]
        .join("\n");
        let signature = signing_key.sign(signing_string.as_bytes());
        let signature = format!(
            "sig1=:{}:",
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
        );
        (digest, signature_input, signature)
    }

    #[tokio::test]
    async fn http_message_signature_authenticates_notify_request() {
        let seed_hex = "0101010101010101010101010101010101010101010101010101010101010101";
        let public_key_hex = signature_public_key_hex(seed_hex).unwrap();
        let mut principal = NotifyServicePrincipalConfig::default();
        principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
        principal.signature_public_key_hex = Some(public_key_hex);
        let service = test_service_with_principal(principal);
        let body = json!({
            "operation_id": "cx.push.notify",
            "origin_service_did": "did:web:sync.example.com",
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "message_id": "cx:message:01JS0MSG0000000000000000",
                "flow_id": "cx:flow:01JS0FLOW000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "type": "cx.message.create",
                "push_hint": "New message",
                "devices": [{
                    "app_id": "com.example.app",
                    "pushkey": "accept",
                    "pushkey_ts": 42
                }]
            }
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let (content_digest, signature_input, signature) = sign_request(
            seed_hex,
            "POST",
            "http://127.0.0.1/api/v1/push/notify",
            "127.0.0.1",
            &body_bytes,
        );

        let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("host", "127.0.0.1", true)
            .add_header("content-digest", content_digest, true)
            .add_header("signature-input", signature_input, true)
            .add_header("signature", signature, true)
            .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
            .add_header(
                DESTINATION_SERVICE_DID_HEADER,
                "did:web:push.example.com",
                true,
            )
            .json(&body)
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mtls_profile_authenticates_notify_request() {
        let seed_hex = "0202020202020202020202020202020202020202020202020202020202020202";
        let public_key_hex = signature_public_key_hex(seed_hex).unwrap();
        let mut principal = NotifyServicePrincipalConfig::default();
        principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
        principal.signature_public_key_hex = Some(public_key_hex);
        principal.require_mtls = true;
        principal.mtls_cert_fingerprints = vec!["aa:bb:cc".to_owned()];
        let service = test_service_with_principal(principal);
        let body = json!({
            "operation_id": "cx.push.notify",
            "origin_service_did": "did:web:sync.example.com",
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "message_id": "cx:message:01JS0MSG0000000000000000",
                "flow_id": "cx:flow:01JS0FLOW000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "type": "cx.message.create",
                "push_hint": "New message",
                "devices": [{
                    "app_id": "com.example.app",
                    "pushkey": "accept",
                    "pushkey_ts": 42
                }]
            }
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let (content_digest, signature_input, signature) = sign_request(
            seed_hex,
            "POST",
            "http://127.0.0.1/api/v1/push/notify",
            "127.0.0.1",
            &body_bytes,
        );

        let response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("host", "127.0.0.1", true)
            .add_header("content-digest", content_digest, true)
            .add_header("signature-input", signature_input, true)
            .add_header("signature", signature, true)
            .add_header("x-client-certificate-verified", "true", true)
            .add_header("x-client-certificate-sha256", "aa:bb:cc", true)
            .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
            .add_header(
                DESTINATION_SERVICE_DID_HEADER,
                "did:web:push.example.com",
                true,
            )
            .json(&body)
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
    }

    #[tokio::test]
    async fn mtls_profile_rejects_missing_verified_client_certificate() {
        let seed_hex = "0303030303030303030303030303030303030303030303030303030303030303";
        let public_key_hex = signature_public_key_hex(seed_hex).unwrap();
        let mut principal = NotifyServicePrincipalConfig::default();
        principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
        principal.signature_public_key_hex = Some(public_key_hex);
        principal.require_mtls = true;
        let service = test_service_with_principal(principal);
        let body = json!({
            "operation_id": "cx.push.notify",
            "origin_service_did": "did:web:sync.example.com",
            "notification": {
                "event_id": "cx:event:01JS0EV000000000000000000",
                "message_id": "cx:message:01JS0MSG0000000000000000",
                "flow_id": "cx:flow:01JS0FLOW000000000000000",
                "space_id": "cx:space:01JS0SP000000000000000000",
                "type": "cx.message.create",
                "push_hint": "New message",
                "devices": [{
                    "app_id": "com.example.app",
                    "pushkey": "accept",
                    "pushkey_ts": 42
                }]
            }
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let (content_digest, signature_input, signature) = sign_request(
            seed_hex,
            "POST",
            "http://127.0.0.1/api/v1/push/notify",
            "127.0.0.1",
            &body_bytes,
        );

        let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("host", "127.0.0.1", true)
            .add_header("content-digest", content_digest, true)
            .add_header("signature-input", signature_input, true)
            .add_header("signature", signature, true)
            .add_header(ORIGIN_SERVICE_DID_HEADER, "did:web:sync.example.com", true)
            .add_header(
                DESTINATION_SERVICE_DID_HEADER,
                "did:web:push.example.com",
                true,
            )
            .json(&body)
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
        let body = response.take_string().await.unwrap();
        assert!(body.contains("verified mTLS client certificate is required"));
    }

    #[test]
    fn redacts_proxy_credentials() {
        assert_eq!(
            redact_url_credentials("http://alice:secret@proxy.example.com:8080"),
            "http://***:***@proxy.example.com:8080/"
        );
    }
}
