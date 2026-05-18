use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::Value;

use crate::AppState;
use crate::auth::{DESTINATION_SERVICE_DID_HEADER, ORIGIN_SERVICE_DID_HEADER};
use crate::pushkin::{PROVIDER_CAPABILITIES_VERSION, ProviderCapabilityDescriptor};

use super::metrics::{ErrorBody, ErrorEnvelope};
use super::server_describe::{
    describe_auth_modes, describe_plaintext_visibility, describe_rate_limit_scopes,
};
use super::{MAX_REQUEST_SIZE, NOTIFY_OPERATION_ID};

#[derive(Debug, Serialize)]
struct PushBridgeDescribeResponse {
    contract: &'static str,
    version: &'static str,
    api_base_path: &'static str,
    gateway: PushBridgeGatewayDescriptor,
    notify: PushBridgeNotifyDescriptor,
    privacy: PushBridgePrivacyDescriptor,
    provider_capabilities_version: &'static str,
    provider_capabilities: Vec<ProviderCapabilityDescriptor>,
    failure_codes: Vec<PushBridgeFailureCodeDescriptor>,
    examples: PushBridgeDescribeExamples,
}

#[derive(Debug, Serialize)]
struct PushBridgeGatewayDescriptor {
    service_did: Option<String>,
    supported_profiles: Vec<&'static str>,
    supported_providers: Vec<String>,
    auth_modes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct PushBridgeNotifyDescriptor {
    notify_path: &'static str,
    operation_id: &'static str,
    request_id_header: &'static str,
    idempotency_key_header: &'static str,
    origin_service_did_header: &'static str,
    destination_service_did_header: &'static str,
    max_request_size_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    dedup_backend: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dedup_ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_limit_window_seconds: Option<u64>,
    rate_limit_scopes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct PushBridgePrivacyDescriptor {
    default_mode: &'static str,
    plaintext_visibility_class: &'static str,
    active_reference_fields: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct PushBridgeFailureCodeDescriptor {
    code: &'static str,
    http_status: u16,
    retryable: bool,
    description: &'static str,
}

#[derive(Debug, Serialize)]
struct PushBridgeDescribeExamples {
    notify_headers: Value,
    blind_wakeup_request: Value,
    plaintext_visible_service_request: Value,
}

#[handler]
pub(super) async fn bridge_describe(depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<Arc<AppState>>() else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        res.render(Json(ErrorEnvelope {
            ok: false,
            request_id: None,
            error: ErrorBody {
                code: "internal_error",
                message: "application state missing",
                retry_after_ms: None,
            },
        }));
        return;
    };

    let dedup_backend = state
        .notify_deduplicator
        .as_ref()
        .map(|deduplicator| deduplicator.backend_name());
    let dedup_ttl_seconds = state
        .notify_deduplicator
        .as_ref()
        .map(|deduplicator| deduplicator.ttl().as_secs());
    let rate_limit_window_seconds = state
        .notify_rate_limiter
        .as_ref()
        .map(|limiter| limiter.config().window_seconds.max(1));
    let rate_limit_scopes = state
        .notify_rate_limiter
        .as_ref()
        .map(|limiter| describe_rate_limit_scopes(limiter.config()))
        .unwrap_or_default();

    let body = PushBridgeDescribeResponse {
        contract: "cx.push.bridge.describe",
        version: "2026-05-07",
        api_base_path: "/api/v1/push",
        gateway: PushBridgeGatewayDescriptor {
            service_did: state.notify_auth.gateway_service_did.clone(),
            supported_profiles: vec!["cx.profile.push_gateway.v1"],
            supported_providers: state.registry.provider_names(),
            auth_modes: describe_auth_modes(&state.notify_auth),
        },
        notify: PushBridgeNotifyDescriptor {
            notify_path: "/api/v1/push/notify",
            operation_id: NOTIFY_OPERATION_ID,
            request_id_header: "X-Contrix-Request-Id",
            idempotency_key_header: "Idempotency-Key",
            origin_service_did_header: ORIGIN_SERVICE_DID_HEADER,
            destination_service_did_header: DESTINATION_SERVICE_DID_HEADER,
            max_request_size_bytes: MAX_REQUEST_SIZE,
            dedup_backend,
            dedup_ttl_seconds,
            rate_limit_window_seconds,
            rate_limit_scopes,
        },
        privacy: PushBridgePrivacyDescriptor {
            default_mode: "e2ee_blind_wakeup",
            plaintext_visibility_class: describe_plaintext_visibility(&state.notify_auth),
            active_reference_fields: vec![
                "notification.push_target_id",
                "notification.wakeup_kind",
            ],
        },
        provider_capabilities_version: PROVIDER_CAPABILITIES_VERSION,
        provider_capabilities: state.registry.provider_capabilities(),
        failure_codes: vec![
            PushBridgeFailureCodeDescriptor {
                code: "capability_denied",
                http_status: StatusCode::FORBIDDEN.as_u16(),
                retryable: false,
                description: "The caller is authenticated but not allowed to send this notify shape or destination.",
            },
            PushBridgeFailureCodeDescriptor {
                code: "duplicate_conflict",
                http_status: StatusCode::CONFLICT.as_u16(),
                retryable: false,
                description: "The same idempotency key was replayed with a different canonical request body.",
            },
            PushBridgeFailureCodeDescriptor {
                code: "method_not_allowed",
                http_status: StatusCode::METHOD_NOT_ALLOWED.as_u16(),
                retryable: false,
                description: "The notify surface only accepts POST.",
            },
            PushBridgeFailureCodeDescriptor {
                code: "payload_too_large",
                http_status: StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                retryable: false,
                description: "The notify request body exceeded the configured maximum size.",
            },
            PushBridgeFailureCodeDescriptor {
                code: "rate_limited",
                http_status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                retryable: true,
                description: "A rate-limit scope rejected the request; callers should respect Retry-After.",
            },
            PushBridgeFailureCodeDescriptor {
                code: "schema_violation",
                http_status: StatusCode::BAD_REQUEST.as_u16(),
                retryable: false,
                description: "The request body or headers did not match the active cx.push.notify contract.",
            },
            PushBridgeFailureCodeDescriptor {
                code: "temporarily_unavailable",
                http_status: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                retryable: true,
                description: "All dispatch attempts failed with retryable provider or gateway conditions.",
            },
            PushBridgeFailureCodeDescriptor {
                code: "unsupported_feature",
                http_status: StatusCode::BAD_REQUEST.as_u16(),
                retryable: false,
                description: "The caller requested a non-canonical notify operation or unsupported contract feature.",
            },
        ],
        examples: PushBridgeDescribeExamples {
            notify_headers: serde_json::json!({
                "X-Contrix-Request-Id": "req_01js0000000000000000000000",
                "Idempotency-Key": "notify-01js0000000000000000000000",
                "X-Contrix-Origin-Service-Did": "did:web:soland.example",
                "X-Contrix-Destination-Service-Did": state.notify_auth.gateway_service_did,
            }),
            blind_wakeup_request: serde_json::json!({
                "notification": {
                    "event_id": "cx:event:01964000-0000-7000-8000-000000000000",
                    "flow_id": "cx:flow:01964000-0000-7000-8000-000000000000",
                    "space_id": "cx:space:01964000-0000-7000-8000-000000000000",
                    "push_hint": "new_activity",
                    "counts": {"unread": 3}
                }
            }),
            plaintext_visible_service_request: serde_json::json!({
                "notification": {
                    "event_id": "cx:event:01964000-0000-7000-8000-000000000000",
                    "flow_id": "cx:flow:01964000-0000-7000-8000-000000000000",
                    "space_id": "cx:space:01964000-0000-7000-8000-000000000000",
                    "push_hint": "message_visible_to_service",
                    "preview": "Alice: deploy is complete",
                    "counts": {"unread": 3}
                }
            }),
        },
    };

    res.status_code(StatusCode::OK);
    res.render(Json(body));
}
