use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use contrix::http_signature::{
    self as sdk_sig, Component, ContentDigest, SignatureError, SignedRequestParts,
};
use salvo::http::StatusCode;
use salvo::prelude::Request;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::{NotifyAuthConfig, NotifyServicePrincipalConfig};
use crate::nonce_store::{NonceCheck, NonceStore};

pub const ORIGIN_SERVICE_DID_HEADER: &str = "x-contrix-origin-service-did";
pub const DESTINATION_SERVICE_DID_HEADER: &str = "x-contrix-destination-service-did";
const CONTENT_DIGEST_HEADER: &str = "content-digest";
const SIGNATURE_INPUT_HEADER: &str = "signature-input";
const SIGNATURE_HEADER: &str = "signature";

#[derive(Debug, Clone)]
pub struct AuthenticatedNotifyCaller {
    pub origin_service_did: String,
    /// Whether this caller is gated for the visible-notification
    /// profile (`cx.profile.push_gateway.visible_notification.v1`).
    ///
    /// Set ONLY when the principal has both `allow_plaintext_metadata`
    /// flipped on AND a `service_type` that is on the plaintext-eligible
    /// allow-list (see [`crate::config::is_plaintext_eligible_service_kind`]).
    /// Anonymous callers (auth disabled) keep the legacy behaviour
    /// (set to `true`) to avoid breaking existing development setups,
    /// but the request still has to walk through the visible-profile
    /// gate at the notify ingress before any plaintext metadata can
    /// be propagated to a provider adapter. (`production_mode` rejects
    /// anonymous callers outright, so this dev-only default never relaxes
    /// the privacy baseline in production.)
    pub allow_plaintext_metadata: bool,
}

#[derive(Debug)]
pub struct AuthFailure {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub fn authenticate_notify_request(
    req: &Request,
    body: &[u8],
    auth: &NotifyAuthConfig,
    nonce_store: Option<&NonceStore>,
    request_id: &str,
) -> Result<AuthenticatedNotifyCaller, AuthFailure> {
    reject_query_string_auth(req)?;

    if !auth.enabled() {
        if auth.production_mode {
            tracing::error!(
                request_id,
                "rejecting /notify request: production_mode is enabled but notify_auth is not configured"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
                message: "anonymous /notify is disabled in production mode".to_owned(),
            });
        }
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
            verify_message_signature(req, body, auth, principal, origin_did, request_id)?;
            verify_nonce_freshness(req, nonce_store, origin_did, request_id)?;
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

        if !authenticated {
            if auth.production_mode {
                tracing::warn!(
                    request_id,
                    origin_service_did = %origin_did,
                    "rejecting /notify request: production_mode requires HTTP Message Signature or mTLS, bearer fallback is disabled"
                );
                return Err(AuthFailure {
                    status: StatusCode::UNAUTHORIZED,
                    code: "unauthenticated",
                    message: "production mode requires HTTP Message Signature or mTLS".to_owned(),
                });
            }
            if bearer_matches(
                req,
                &principal.bearer_tokens,
                &principal.bearer_token_hashes,
            ) {
                authenticated = true;
            }
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

        verify_mtls_profile(req, auth, principal, origin_did, request_id)?;

        // RFC 9530 Content-Digest is verified inside verify_message_signature
        // when a signature was supplied. When the caller authenticated via
        // mTLS only (no signature) we still want body integrity in
        // production mode, so verify the digest header against the raw
        // body here as well.
        if auth.production_mode && !has_signature_headers(req) {
            verified_content_digest(req, body)?;
        }

        let allow_plaintext =
            principal.allow_plaintext_metadata && principal_is_plaintext_eligible(principal);
        return Ok(AuthenticatedNotifyCaller {
            origin_service_did: origin_did.to_owned(),
            allow_plaintext_metadata: allow_plaintext,
        });
    }

    if auth.production_mode {
        tracing::warn!(
            request_id,
            origin_service_did = origin_did.as_deref().unwrap_or("<missing>"),
            "rejecting /notify request: production_mode rejects gateway-wide bearer fallback"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "production mode requires a configured service principal".to_owned(),
        });
    }

    authenticate_bearer_request(req, auth, origin_did.as_deref(), request_id)
}

fn principal_is_plaintext_eligible(principal: &NotifyServicePrincipalConfig) -> bool {
    let Some(kind) = principal
        .service_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    crate::config::is_plaintext_eligible_service_kind(kind)
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

    // Multi-tenant isolation: when `bind_bearer_to_origin_did` is set,
    // a gateway-wide bearer token is NOT enough — the caller must
    // declare an origin_service_did and present a bearer credential
    // configured for THAT principal. This blocks a stolen gateway
    // bearer token from being used to impersonate an arbitrary tenant
    // by spoofing the X-Contrix-Origin-Service-DID header.
    if auth.bind_bearer_to_origin_did {
        let Some(origin_did) = origin_did else {
            tracing::warn!(
                request_id,
                "rejecting /notify request: bind_bearer_to_origin_did requires origin_service_did"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
                message: "origin service DID is required for bearer authentication".to_owned(),
            });
        };
        let Some(principal) = auth.service_principals.get(origin_did) else {
            tracing::warn!(
                request_id,
                origin_service_did = %origin_did,
                "rejecting /notify request: bind_bearer_to_origin_did requires a configured service_principal for the origin DID"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
                message: "origin service DID does not have a configured principal".to_owned(),
            });
        };
        match bearer_state(
            req,
            &principal.bearer_tokens,
            &principal.bearer_token_hashes,
        ) {
            BearerState::Valid => {}
            BearerState::Missing => {
                tracing::warn!(
                    request_id,
                    origin_service_did = %origin_did,
                    "rejecting /notify request without a bearer credential bound to the origin DID"
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
                    origin_service_did = %origin_did,
                    "rejecting /notify request: bearer credential is not bound to the declared origin DID"
                );
                return Err(AuthFailure {
                    status: StatusCode::UNAUTHORIZED,
                    code: "unauthenticated",
                    message: "bearer service token is not bound to the declared origin service DID"
                        .to_owned(),
                });
            }
        }
        verify_destination_service_did(req, auth, origin_did, request_id)?;
        let allow_plaintext_metadata = auth
            .plaintext_metadata_service_dids
            .iter()
            .any(|candidate| candidate == origin_did)
            || (principal.allow_plaintext_metadata && principal_is_plaintext_eligible(principal));
        return Ok(AuthenticatedNotifyCaller {
            origin_service_did: origin_did.to_owned(),
            allow_plaintext_metadata,
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

    let allow_plaintext_metadata = auth
        .plaintext_metadata_service_dids
        .iter()
        .any(|candidate| candidate == origin_did);
    Ok(AuthenticatedNotifyCaller {
        origin_service_did: origin_did.to_owned(),
        allow_plaintext_metadata,
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
    if let Some(expected_dn) = principal.mtls_subject_dn.as_deref() {
        let observed_dn = req
            .header::<String>(auth.mtls_subject_dn_header())
            .map(|value| normalize_dn(&value));
        let expected = normalize_dn(expected_dn);
        if observed_dn.as_deref() != Some(expected.as_str()) {
            tracing::warn!(
                request_id,
                origin_service_did = %origin_did,
                observed_subject_dn = %observed_dn.as_deref().unwrap_or("<missing>"),
                expected_subject_dn = %expected,
                "rejecting /notify request with unexpected mTLS Subject DN"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
                message: "mTLS Subject DN does not match service principal binding".to_owned(),
            });
        }
    }
    if !principal.mtls_subject_alt_names.is_empty() {
        let observed_sans = req
            .header::<String>(auth.mtls_subject_alt_names_header())
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_ascii_lowercase())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        for required in &principal.mtls_subject_alt_names {
            let required = required.trim().to_ascii_lowercase();
            if required.is_empty() {
                continue;
            }
            if !observed_sans.contains(&required) {
                tracing::warn!(
                    request_id,
                    origin_service_did = %origin_did,
                    expected_san = %required,
                    "rejecting /notify request whose mTLS certificate is missing a required SAN"
                );
                return Err(AuthFailure {
                    status: StatusCode::UNAUTHORIZED,
                    code: "unauthenticated",
                    message: "mTLS certificate is missing a required Subject Alternative Name"
                        .to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Normalise a Distinguished Name for comparison: collapse runs of
/// whitespace, lowercase, trim. We do not attempt full RFC 4514
/// canonicalisation — operators are expected to copy-paste the DN
/// emitted by the reverse proxy.
fn normalize_dn(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
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
    let public_key_hex = principal
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

    // ----- header pull + parse via SDK ----------------------------------
    let raw_signature_input = req
        .header::<String>(SIGNATURE_INPUT_HEADER)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "missing Signature-Input header".to_owned(),
        })?;
    let signature_input =
        sdk_sig::parse_signature_input(&raw_signature_input).map_err(map_signature_input_error)?;

    let raw_signature_header =
        req.header::<String>(SIGNATURE_HEADER)
            .ok_or_else(|| AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "unauthenticated",
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
            code: "invalid_signature",
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
        Component::Method,
        Component::TargetUri,
        Component::Authority,
        Component::Header(CONTENT_DIGEST_HEADER.to_owned()),
        Component::Header(ORIGIN_SERVICE_DID_HEADER.to_owned()),
        Component::Header(DESTINATION_SERVICE_DID_HEADER.to_owned()),
    ];
    if !signature_input.covers_all(&required_components) {
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
        code: "invalid_signature",
        message: "configured signature public key is not valid hex".to_owned(),
    })?;
    let public_key =
        sdk_sig::public_key_from_bytes(&public_key_bytes).map_err(|_| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "configured signature public key is invalid".to_owned(),
        })?;
    sdk_sig::verify_signature(&message, &signature_b64, &public_key).map_err(|err| match err {
        SignatureError::InvalidSignatureBase64 => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature header is not valid base64".to_owned(),
        },
        SignatureError::InvalidSignatureLength => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Signature header is not a valid Ed25519 signature".to_owned(),
        },
        _ => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
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
fn verified_content_digest(req: &Request, body: &[u8]) -> Result<String, AuthFailure> {
    let value = req
        .header::<String>(CONTENT_DIGEST_HEADER)
        .ok_or_else(|| AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "missing Content-Digest header".to_owned(),
        })?;
    let parsed = ContentDigest::parse(value.trim()).map_err(|err| match err {
        SignatureError::MalformedContentDigest => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Content-Digest must use sha-256 or sha-512".to_owned(),
        },
        _ => AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Content-Digest header is invalid".to_owned(),
        },
    })?;
    // floria has historically locked the wire profile to sha-256 — keep
    // that policy here rather than relaxing it just because the SDK
    // parser also accepts sha-512.
    if parsed.algorithm != sdk_sig::ContentDigestAlgorithm::Sha256 {
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_signature",
            message: "Content-Digest must use sha-256".to_owned(),
        });
    }
    sdk_sig::verify_content_digest(&parsed, body).map_err(|_| AuthFailure {
        status: StatusCode::UNAUTHORIZED,
        code: "invalid_signature",
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
        code: "invalid_signature",
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
        code: "invalid_signature",
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
        code: "invalid_signature",
        message,
    }
}

fn has_signature_headers(req: &Request) -> bool {
    req.header::<String>(SIGNATURE_INPUT_HEADER).is_some()
        || req.header::<String>(SIGNATURE_HEADER).is_some()
}

/// Bind the verified Signature header bytes (and the request's
/// content-digest) to a single-use nonce. A replay arriving inside
/// the `expires - created` window is rejected even though every
/// other signature check would still pass. When no nonce store is
/// configured this is a no-op so signature semantics are unchanged.
fn verify_nonce_freshness(
    req: &Request,
    nonce_store: Option<&NonceStore>,
    origin_did: &str,
    request_id: &str,
) -> Result<(), AuthFailure> {
    let Some(nonce_store) = nonce_store else {
        return Ok(());
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

    match nonce_store.observe(&fingerprint) {
        NonceCheck::Fresh => Ok(()),
        NonceCheck::Replayed => {
            tracing::warn!(
                request_id,
                origin_service_did = %origin_did,
                "rejecting /notify request as a Signature replay within the expiry window"
            );
            Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: "invalid_signature",
                message: "HTTP Message Signature has already been observed (replay)".to_owned(),
            })
        }
        NonceCheck::BackendUnavailable => {
            tracing::warn!(
                request_id,
                origin_service_did = %origin_did,
                "rejecting /notify request: nonce store backend unavailable (strict policy)"
            );
            Err(AuthFailure {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "service_unavailable",
                message: "replay protection backend is unavailable".to_owned(),
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BearerState {
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

pub(crate) fn bearer_state(
    req: &Request,
    candidates: &[String],
    candidate_hashes: &[String],
) -> BearerState {
    let Some(raw) = req.header::<String>("authorization") else {
        return BearerState::Missing;
    };
    let Some(token) = parse_bearer_token(&raw) else {
        return BearerState::Invalid;
    };
    let token_digest = bearer_token_sha256(token);
    if candidates
        .iter()
        .any(|candidate| token_digest.ct_eq(&bearer_token_sha256(candidate)).into())
        || candidate_hashes
            .iter()
            .any(|candidate| bearer_token_hash_matches(&token_digest, candidate))
    {
        BearerState::Valid
    } else {
        BearerState::Invalid
    }
}

fn optional_header(req: &Request, name: &str) -> Option<String> {
    req.header::<String>(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_bearer_token(value: &str) -> Option<&str> {
    let value = value.trim();
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

/// Compares a pre-computed SHA-256 of the presented bearer token against
/// a configured hash candidate in constant time. The candidate is parsed
/// from its `sha256:`-prefixed hex form into raw bytes; a length / decode
/// mismatch is a non-match (no early-return timing signal that depends on
/// the secret).
fn bearer_token_hash_matches(token_digest: &[u8; 32], candidate: &str) -> bool {
    let candidate = candidate
        .trim()
        .strip_prefix("sha256:")
        .unwrap_or_else(|| candidate.trim());
    let Ok(candidate_bytes) = hex::decode(candidate) else {
        return false;
    };
    candidate_bytes.len() == token_digest.len() && token_digest.ct_eq(&candidate_bytes).into()
}

fn bearer_token_sha256(token: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().into()
}

pub fn bearer_token_sha256_hex(token: &str) -> String {
    hex::encode(bearer_token_sha256(token))
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

fn authority(req: &Request) -> Result<String, AuthFailure> {
    req.header::<String>("host")
        .or_else(|| req.uri().authority().map(|value| value.to_string()))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
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
    use std::collections::HashMap;
    use std::sync::Arc;

    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use salvo::test::{ResponseExt, TestClient};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::AppState;
    use crate::pushkin::{Pushkin, PushkinRegistry};
    use crate::service::build_router;

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
                "realm_id": "cx:realm:01JS0SP000000000000000000",
                "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "push_hint": "new_message",
                "devices": [{
                    "app_id": "com.example.app",
                    "push_key": "accept"
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
                "realm_id": "cx:realm:01JS0SP000000000000000000",
                "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "push_hint": "new_message",
                "devices": [{
                    "app_id": "com.example.app",
                    "push_key": "accept"
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
                "realm_id": "cx:realm:01JS0SP000000000000000000",
                "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "push_hint": "new_message",
                "devices": [{
                    "app_id": "com.example.app",
                    "push_key": "accept"
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

    // Pin the verifier's rejection set so a future SDK bump can't
    // silently loosen which inputs floria refuses.

    #[tokio::test]
    async fn rejects_tampered_body() {
        let seed_hex = "0404040404040404040404040404040404040404040404040404040404040404";
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
                "realm_id": "cx:realm:01JS0SP000000000000000000",
                "push_target_id": "cx:pseudonym:push:01HYZ8Z000000000000000",
                "wakeup_kind": "message",
                "push_hint": "new_message",
                "devices": [{"app_id": "com.example.app", "push_key": "accept"}]
            }
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        // Sign one body, send a *different* body — content-digest
        // recomputation must reject this.
        let (content_digest, signature_input, signature) = sign_request(
            seed_hex,
            "POST",
            "http://127.0.0.1/api/v1/push/notify",
            "127.0.0.1",
            &body_bytes,
        );
        let tampered_body = json!({"hello": "world"});

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
            .json(&tampered_body)
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::UNAUTHORIZED);
        let resp_body = response.take_string().await.unwrap();
        assert!(
            resp_body.contains("Content-Digest does not match request body"),
            "expected body-mismatch rejection, got: {resp_body}"
        );
    }

    #[tokio::test]
    async fn rejects_signature_missing_required_components() {
        let seed_hex = "0505050505050505050505050505050505050505050505050505050505050505";
        let public_key_hex = signature_public_key_hex(seed_hex).unwrap();
        let mut principal = NotifyServicePrincipalConfig::default();
        principal.signature_key_id = Some("did:web:sync.example.com#push".to_owned());
        principal.signature_public_key_hex = Some(public_key_hex);
        let service = test_service_with_principal(principal);
        let body = json!({"operation_id": "cx.push.notify"});
        let body_bytes = serde_json::to_vec(&body).unwrap();

        let seed = hex::decode(seed_hex).unwrap();
        let seed: [u8; 32] = seed.try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);

        let mut hasher = Sha256::new();
        hasher.update(&body_bytes);
        let digest = format!(
            "sha-256=:{}:",
            base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
        );
        let now = unix_now_secs();
        // Intentionally omit `@authority` from the covered components —
        // floria's required-component policy must still trip this.
        let signature_input = format!(
            "sig1=(\"@method\" \"@target-uri\" \"content-digest\" \"x-contrix-origin-service-did\" \"x-contrix-destination-service-did\");created={};expires={};keyid=\"did:web:sync.example.com#push\";alg=\"ed25519\"",
            now - 1,
            now + 300
        );
        let signing_string = [
            "\"@method\": post".to_owned(),
            "\"@target-uri\": http://127.0.0.1/api/v1/push/notify".to_owned(),
            format!("\"content-digest\": {digest}"),
            "\"x-contrix-origin-service-did\": did:web:sync.example.com".to_owned(),
            "\"x-contrix-destination-service-did\": did:web:push.example.com".to_owned(),
            format!(
                "\"@signature-params\": (\"@method\" \"@target-uri\" \"content-digest\" \"x-contrix-origin-service-did\" \"x-contrix-destination-service-did\");created={};expires={};keyid=\"did:web:sync.example.com#push\";alg=\"ed25519\"",
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

        let mut response = TestClient::post("http://127.0.0.1/api/v1/push/notify")
            .add_header("host", "127.0.0.1", true)
            .add_header("content-digest", digest, true)
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
        let resp_body = response.take_string().await.unwrap();
        assert!(
            resp_body.contains("missing required covered components"),
            "expected required-components rejection, got: {resp_body}"
        );
    }
}
