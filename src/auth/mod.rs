use std::sync::Arc;

use arkret_wire::DidCoreId;
use salvo::http::StatusCode;
use salvo::prelude::Request;

use crate::config::{NotifyAuthConfig, NotifyServicePrincipalConfig};
use crate::nonce_store::NonceStore;

mod bearer;
mod helpers;
mod mtls;
mod signature;

#[cfg(test)]
mod tests;

use bearer::bearer_matches;
pub use bearer::bearer_token_sha256_hex;
pub(crate) use bearer::{BearerState, bearer_state};
use helpers::{optional_header, reject_query_string_auth};
pub use helpers::{redact_url_credentials, signature_public_key_hex};
use mtls::{verify_destination_id, verify_mtls_profile, verify_principal_service_kind};
use signature::{
    has_signature_headers, verified_content_digest, verify_message_signature,
    verify_nonce_freshness,
};

pub const SOURCE_SERVICE_ID_HEADER: &str = "source-service-id";
pub const DESTINATION_SERVICE_ID_HEADER: &str = "destination-service-id";
const CONTENT_DIGEST_HEADER: &str = "content-digest";
const SIGNATURE_INPUT_HEADER: &str = "signature-input";
const SIGNATURE_HEADER: &str = "signature";

#[derive(Debug, Clone)]
pub struct AuthenticatedNotifyCaller {
    /// Stable identity of the authenticated origin service. This is absent
    /// only for the explicit development-only anonymous path when notify
    /// authentication is disabled.
    pub origin_id: Option<DidCoreId>,
    /// Stable destination service identity parsed from the transport header.
    pub destination_id: Option<DidCoreId>,
    /// Whether this caller is gated for the visible-notification
    /// profile (`ak.profile.push_gateway.visible_notification.v1`).
    ///
    /// Set ONLY when the principal has both `allow_plaintext_metadata`
    /// flipped on AND a `service_kind` that is on the plaintext-eligible
    /// allow-list (see [`crate::config::is_plaintext_eligible_service_kind`]).
    /// Anonymous callers (auth disabled) stay on the blind-wakeup
    /// profile. Development deployments may still exercise blind
    /// routing without credentials, but plaintext visible metadata now
    /// requires an explicitly configured principal.
    pub allow_plaintext_metadata: bool,
}

#[derive(Debug)]
pub struct AuthFailure {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub async fn authenticate_notify_request(
    req: &Request,
    body: &[u8],
    auth: &NotifyAuthConfig,
    nonce_store: Option<&Arc<NonceStore>>,
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
                code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
                message: "anonymous /notify is disabled in production mode".to_owned(),
            });
        }
        return Ok(AuthenticatedNotifyCaller {
            origin_id: None,
            destination_id: None,
            allow_plaintext_metadata: false,
        });
    }

    let origin_id = optional_header(req, SOURCE_SERVICE_ID_HEADER)
        .map(DidCoreId::new)
        .transpose()
        .map_err(|_| AuthFailure {
            status: StatusCode::BAD_REQUEST,
            code: arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
            message: "Source-Service-ID must be a service core id".to_owned(),
        })?;

    if let Some(origin_id) = origin_id.as_ref()
        && let Some(principal) = auth.service_principals.get(origin_id.as_str())
    {
        verify_principal_service_kind(principal, origin_id, request_id)?;
        let destination_id = verify_destination_id(req, auth, origin_id, request_id)?;
        if let Some(expected_endpoint) = principal.service_endpoint.as_deref() {
            let target_uri = helpers::target_uri(req)?;
            if !target_uri.starts_with(expected_endpoint) {
                tracing::warn!(
                    request_id,
                    origin_id = %origin_id,
                    expected_service_endpoint = %expected_endpoint,
                    target_uri = %target_uri,
                    "rejecting /notify request that does not match configured service endpoint"
                );
                return Err(AuthFailure {
                    status: StatusCode::FORBIDDEN,
                    code: arkret_wire::error_codes::ErrorCode::CAPABILITY_DENIED,
                    message: "origin service endpoint does not match configured service binding"
                        .to_owned(),
                });
            }
        }

        let mut authenticated = false;
        if has_signature_headers(req) {
            verify_message_signature(req, body, principal, origin_id, request_id)?;
            verify_nonce_freshness(req, nonce_store, origin_id, request_id).await?;
            authenticated = true;
        } else if auth.require_message_signatures {
            tracing::warn!(
                request_id,
                origin_id = %origin_id,
                "rejecting /notify request without required HTTP Message Signature"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
                message: "HTTP Message Signature is required".to_owned(),
            });
        }

        if !authenticated {
            if auth.production_mode {
                tracing::warn!(
                    request_id,
                    origin_id = %origin_id,
                    "rejecting /notify request: production_mode requires HTTP Message Signature or mTLS, bearer fallback is disabled"
                );
                return Err(AuthFailure {
                    status: StatusCode::UNAUTHORIZED,
                    code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
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
                origin_id = %origin_id,
                "rejecting /notify request without a valid principal credential"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
                message: "missing or invalid service credential".to_owned(),
            });
        }

        verify_mtls_profile(req, auth, principal, origin_id, request_id)?;

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
            origin_id: Some(origin_id.clone()),
            destination_id,
            allow_plaintext_metadata: allow_plaintext,
        });
    }

    if auth.production_mode {
        tracing::warn!(
            request_id,
            origin_id = origin_id
                .as_ref()
                .map(DidCoreId::as_str)
                .unwrap_or("<missing>"),
            "rejecting /notify request: production_mode rejects gateway-wide bearer fallback"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
            message: "production mode requires a configured service principal".to_owned(),
        });
    }

    authenticate_bearer_request(req, auth, origin_id.as_ref(), request_id)
}

fn principal_is_plaintext_eligible(principal: &NotifyServicePrincipalConfig) -> bool {
    let Some(kind) = principal
        .service_kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    crate::config::is_plaintext_eligible_service_kind(kind)
}

fn authenticate_bearer_request(
    req: &Request,
    auth: &NotifyAuthConfig,
    origin_id: Option<&DidCoreId>,
    request_id: &str,
) -> Result<AuthenticatedNotifyCaller, AuthFailure> {
    if auth.require_message_signatures {
        tracing::warn!(
            request_id,
            "rejecting /notify request because bearer auth cannot satisfy required HTTP Message Signature"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
            message: "HTTP Message Signature is required".to_owned(),
        });
    }

    // Multi-tenant isolation: when `bind_bearer_to_origin_id` is set,
    // a gateway-wide bearer token is NOT enough — the caller must
    // declare an origin_id and present a bearer credential
    // configured for THAT principal. This blocks a stolen gateway
    // bearer token from being used to impersonate an arbitrary tenant
    // by spoofing the X-Arkret-Origin-Service-ID header.
    if auth.bind_bearer_to_origin_id {
        let Some(origin_id) = origin_id else {
            tracing::warn!(
                request_id,
                "rejecting /notify request: bind_bearer_to_origin_id requires origin_id"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
                message: "origin service id is required for bearer authentication".to_owned(),
            });
        };
        let Some(principal) = auth.service_principals.get(origin_id.as_str()) else {
            tracing::warn!(
                request_id,
                origin_id = %origin_id,
                "rejecting /notify request: bind_bearer_to_origin_id requires a configured service_principal for the origin id"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
                message: "origin service id does not have a configured principal".to_owned(),
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
                    origin_id = %origin_id,
                    "rejecting /notify request without a bearer credential bound to the origin id"
                );
                return Err(AuthFailure {
                    status: StatusCode::UNAUTHORIZED,
                    code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
                    message: "missing bearer service token".to_owned(),
                });
            }
            BearerState::Invalid => {
                tracing::warn!(
                    request_id,
                    origin_id = %origin_id,
                    "rejecting /notify request: bearer credential is not bound to the declared origin id"
                );
                return Err(AuthFailure {
                    status: StatusCode::UNAUTHORIZED,
                    code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
                    message: "bearer service token is not bound to the declared origin service id"
                        .to_owned(),
                });
            }
        }
        let destination_id = verify_destination_id(req, auth, origin_id, request_id)?;
        let allow_plaintext_metadata = auth
            .plaintext_metadata_service_ids
            .iter()
            .any(|candidate| candidate == origin_id.as_str())
            || (principal.allow_plaintext_metadata && principal_is_plaintext_eligible(principal));
        return Ok(AuthenticatedNotifyCaller {
            origin_id: Some(origin_id.clone()),
            destination_id,
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
                code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
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
                code: arkret_wire::error_codes::ErrorCode::UNAUTHENTICATED,
                message: "invalid bearer service token".to_owned(),
            });
        }
    }

    let origin_id = origin_id.ok_or_else(|| AuthFailure {
        status: StatusCode::FORBIDDEN,
        code: arkret_wire::error_codes::ErrorCode::CAPABILITY_DENIED,
        message: "origin service id is required".to_owned(),
    })?;

    if !auth.trusted_service_ids.is_empty()
        && !auth
            .trusted_service_ids
            .iter()
            .any(|candidate| candidate == origin_id.as_str())
    {
        tracing::warn!(
            request_id,
            origin_id = %origin_id,
            "rejecting /notify request from non-allowlisted service id"
        );
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: arkret_wire::error_codes::ErrorCode::CAPABILITY_DENIED,
            message: "origin service id is not allowlisted".to_owned(),
        });
    }

    let destination_id = verify_destination_id(req, auth, origin_id, request_id)?;

    let allow_plaintext_metadata = auth
        .plaintext_metadata_service_ids
        .iter()
        .any(|candidate| candidate == origin_id.as_str());
    Ok(AuthenticatedNotifyCaller {
        origin_id: Some(origin_id.clone()),
        destination_id,
        allow_plaintext_metadata,
    })
}
