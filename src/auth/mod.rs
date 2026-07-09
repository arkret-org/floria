use std::sync::Arc;

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
use mtls::{verify_destination_service_did, verify_mtls_profile, verify_principal_service_type};
use signature::{
    has_signature_headers, verified_content_digest, verify_message_signature,
    verify_nonce_freshness,
};

pub const ORIGIN_SERVICE_DID_HEADER: &str = "x-arkret-origin-service-did";
pub const DESTINATION_SERVICE_DID_HEADER: &str = "x-arkret-destination-service-did";
const CONTENT_DIGEST_HEADER: &str = "content-digest";
const SIGNATURE_INPUT_HEADER: &str = "signature-input";
const SIGNATURE_HEADER: &str = "signature";

#[derive(Debug, Clone)]
pub struct AuthenticatedNotifyCaller {
    pub origin_service_did: String,
    /// Whether this caller is gated for the visible-notification
    /// profile (`ck.profile.push_gateway.visible_notification.v1`).
    ///
    /// Set ONLY when the principal has both `allow_plaintext_metadata`
    /// flipped on AND a `service_type` that is on the plaintext-eligible
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
                code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
                message: "anonymous /notify is disabled in production mode".to_owned(),
            });
        }
        return Ok(AuthenticatedNotifyCaller {
            origin_service_did: "<anonymous>".to_owned(),
            allow_plaintext_metadata: false,
        });
    }

    let origin_did = optional_header(req, ORIGIN_SERVICE_DID_HEADER);

    if let Some(origin_did) = origin_did.as_deref()
        && let Some(principal) = auth.service_principals.get(origin_did)
    {
        verify_principal_service_type(principal, origin_did, request_id)?;
        verify_destination_service_did(req, auth, origin_did, request_id)?;
        if let Some(expected_endpoint) = principal.service_endpoint.as_deref() {
            let target_uri = helpers::target_uri(req)?;
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
                    code: arkret::error::ERROR_CODE_CAPABILITY_DENIED,
                    message: "origin service endpoint does not match configured service binding"
                        .to_owned(),
                });
            }
        }

        let mut authenticated = false;
        if has_signature_headers(req) {
            verify_message_signature(req, body, auth, principal, origin_did, request_id)?;
            verify_nonce_freshness(req, nonce_store, origin_did, request_id).await?;
            authenticated = true;
        } else if auth.require_message_signatures {
            tracing::warn!(
                request_id,
                origin_service_did = %origin_did,
                "rejecting /notify request without required HTTP Message Signature"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
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
                    code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
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
                code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
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
            code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
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
            code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
            message: "HTTP Message Signature is required".to_owned(),
        });
    }

    // Multi-tenant isolation: when `bind_bearer_to_origin_did` is set,
    // a gateway-wide bearer token is NOT enough — the caller must
    // declare an origin_service_did and present a bearer credential
    // configured for THAT principal. This blocks a stolen gateway
    // bearer token from being used to impersonate an arbitrary tenant
    // by spoofing the X-Arkret-Origin-Service-DID header.
    if auth.bind_bearer_to_origin_did {
        let Some(origin_did) = origin_did else {
            tracing::warn!(
                request_id,
                "rejecting /notify request: bind_bearer_to_origin_did requires origin_service_did"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
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
                code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
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
                    code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
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
                    code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
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
                code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
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
                code: arkret::error::ERROR_CODE_UNAUTHENTICATED,
                message: "invalid bearer service token".to_owned(),
            });
        }
    }

    let origin_did = origin_did.ok_or_else(|| AuthFailure {
        status: StatusCode::FORBIDDEN,
        code: arkret::error::ERROR_CODE_CAPABILITY_DENIED,
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
            code: arkret::error::ERROR_CODE_CAPABILITY_DENIED,
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
