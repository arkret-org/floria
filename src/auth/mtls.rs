use std::collections::HashSet;

use salvo::http::StatusCode;
use salvo::prelude::Request;

use super::AuthFailure;
use super::helpers::{is_truthy, required_header};
use crate::config::{NotifyAuthConfig, NotifyServicePrincipalConfig};

pub(super) fn verify_principal_service_type(
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
        origin_service_id = %origin_did,
        service_type,
        "rejecting /notify request from service type that is not delegated for push notify"
    );
    Err(AuthFailure {
        status: StatusCode::FORBIDDEN,
        code: arkret::error::ErrorCode::CAPABILITY_DENIED,
        message: "origin service is not delegated for push notify".to_owned(),
    })
}

pub(super) fn verify_destination_service_id(
    req: &Request,
    auth: &NotifyAuthConfig,
    origin_did: &str,
    request_id: &str,
) -> Result<(), AuthFailure> {
    let Some(expected) = auth.gateway_service_id.as_deref() else {
        return Ok(());
    };
    let destination_did = required_header(
        req,
        super::DESTINATION_SERVICE_ID_HEADER,
        "destination service DID is required",
    )?;
    if destination_did != expected {
        tracing::warn!(
            request_id,
            origin_service_id = %origin_did,
            destination_service_id = %destination_did,
            expected_destination_service_id = %expected,
            "rejecting /notify request for a different gateway DID"
        );
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: arkret::error::ErrorCode::CAPABILITY_DENIED,
            message: "destination service DID does not match this gateway".to_owned(),
        });
    }
    Ok(())
}

pub(super) fn verify_mtls_profile(
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
            origin_service_id = %origin_did,
            "rejecting /notify request without verified mTLS client certificate"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::UNAUTHENTICATED,
            message: "verified mTLS client certificate is required".to_owned(),
        });
    }
    let Some(fingerprint) = fingerprint else {
        tracing::warn!(
            request_id,
            origin_service_id = %origin_did,
            "rejecting /notify request without mTLS certificate fingerprint"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::UNAUTHENTICATED,
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
            origin_service_id = %origin_did,
            certificate_fingerprint = %fingerprint,
            "rejecting /notify request with unexpected mTLS certificate fingerprint"
        );
        return Err(AuthFailure {
            status: StatusCode::UNAUTHORIZED,
            code: arkret::error::ErrorCode::UNAUTHENTICATED,
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
                origin_service_id = %origin_did,
                observed_subject_dn = %observed_dn.as_deref().unwrap_or("<missing>"),
                expected_subject_dn = %expected,
                "rejecting /notify request with unexpected mTLS Subject DN"
            );
            return Err(AuthFailure {
                status: StatusCode::UNAUTHORIZED,
                code: arkret::error::ErrorCode::UNAUTHENTICATED,
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
                    origin_service_id = %origin_did,
                    expected_san = %required,
                    "rejecting /notify request whose mTLS certificate is missing a required SAN"
                );
                return Err(AuthFailure {
                    status: StatusCode::UNAUTHORIZED,
                    code: arkret::error::ErrorCode::UNAUTHENTICATED,
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
