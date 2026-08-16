use std::sync::Arc;

use arkret_models_integration::push::{
    PushBridgeDescribeExamples, PushBridgeDescribeGatewayDescriptor,
    PushBridgeDescribeNotifyDescriptor, PushBridgeDescribeOutcome,
    PushBridgeDescribePrivacyDescriptor, PushBridgeFailureCodeDescriptor,
};
use arkret_wire::{ServiceContractId, ServiceOperationId};
use salvo::http::StatusCode;
use salvo::prelude::*;

use super::MAX_REQUEST_SIZE;
use super::server_describe::{
    describe_auth_modes, describe_plaintext_visibility, describe_rate_limit_scopes,
    describe_supported_profiles,
};
use crate::AppState;
use crate::auth::{DESTINATION_SERVICE_ID_HEADER, SOURCE_SERVICE_ID_HEADER};
use crate::pushkin::PROVIDER_CAPABILITIES_VERSION;

fn owned(items: Vec<&'static str>) -> Vec<String> {
    items.into_iter().map(str::to_owned).collect()
}

#[handler]
pub(super) async fn bridge_describe(depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<Arc<AppState>>() else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        res.render(Json(
            arkret_wire::ErrorEnvelope::new(
                arkret_wire::error_codes::ErrorCode::INTERNAL_ERROR,
                "application state missing",
            )
            .with_request_id(arkret_wire::new_prefixed_uuid7("ak:request:")),
        ));
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
    let gateway_service_id = state
        .notify_auth
        .gateway_service_core_id()
        .ok()
        .flatten()
        .map(|id| id.as_str().to_owned());

    let body = PushBridgeDescribeOutcome {
        // Canonical bridge-outcome contract id (SDK
        // `models-integration/src/push.rs`). This is the single id for this
        // route: the integration-describe surface, soland's accepted-contract
        // list and chime's drift cache all reference the same value.
        contract: ServiceContractId::PUSH_BRIDGE_V1.to_owned(),
        // `version` is the bridge-describe CONTRACT version (the shape of
        // this response), distinct from `spec_version` below (the
        // arkret-spec revision the SDK is compiled against) and from the
        // config-file `SCHEMA_VERSION`. Pinned to the SDK provider-matrix
        // version so it moves in lockstep with the capability snapshot
        // rather than drifting as a hand-edited date.
        version: PROVIDER_CAPABILITIES_VERSION.to_owned(),
        api_base_path: "/_floria/push".to_owned(),
        // `spec_version` = the arkret-spec revision the SDK was built
        // against (single source: SDK constant). See `version` above for
        // the contract-vs-spec distinction.
        spec_version: Some(arkret_models_integration::push::EXPECTED_SPEC_VERSION.to_owned()),
        gateway: PushBridgeDescribeGatewayDescriptor {
            service_id: gateway_service_id.clone(),
            supported_profiles: describe_supported_profiles(&state.notify_auth)
                .into_iter()
                .map(str::to_owned)
                .collect(),
            supported_providers: state.registry.provider_names(),
            auth_modes: owned(describe_auth_modes(&state.notify_auth)),
        },
        notify: PushBridgeDescribeNotifyDescriptor {
            notify_path: "/_arkret/edge/push/notify".to_owned(),
            operation_id: ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY.to_owned(),
            request_id_header: "X-Arkret-Request-Id".to_owned(),
            idempotency_key_header: "Idempotency-Key".to_owned(),
            source_service_id_header: SOURCE_SERVICE_ID_HEADER.to_owned(),
            destination_service_id_header: DESTINATION_SERVICE_ID_HEADER.to_owned(),
            max_request_size_bytes: MAX_REQUEST_SIZE,
            dedup_backend: dedup_backend.map(str::to_owned),
            dedup_ttl_seconds,
            rate_limit_window_seconds,
            rate_limit_scopes: owned(rate_limit_scopes),
        },
        privacy: PushBridgeDescribePrivacyDescriptor {
            default_mode: "e2ee_blind_wakeup".to_owned(),
            plaintext_visibility_class: describe_plaintext_visibility(&state.notify_auth)
                .to_owned(),
            active_reference_fields: vec![
                "notification.push_target_id".to_owned(),
                "notification.wakeup_kind".to_owned(),
                "notification.timing_profile_hint".to_owned(),
            ],
        },
        provider_capabilities_version: Some(PROVIDER_CAPABILITIES_VERSION.to_owned()),
        provider_capabilities: state.registry.provider_capabilities(),
        failure_reason_codes: vec![
            PushBridgeFailureCodeDescriptor::new(
                arkret_wire::error_codes::ErrorCode::CAPABILITY_DENIED,
                StatusCode::FORBIDDEN.as_u16(),
                false,
                "The caller is authenticated but not allowed to send this notify shape or destination.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret_wire::error_codes::ErrorCode::DUPLICATE_CONFLICT,
                StatusCode::CONFLICT.as_u16(),
                false,
                "The same idempotency key was replayed with a different canonical request body.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret_wire::error_codes::ErrorCode::METHOD_NOT_ALLOWED,
                StatusCode::METHOD_NOT_ALLOWED.as_u16(),
                false,
                "The notify surface only accepts POST.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret_wire::error_codes::ErrorCode::PAYLOAD_TOO_LARGE,
                StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                false,
                "The notify request body exceeded the configured maximum size.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret_wire::error_codes::ErrorCode::RATE_LIMITED,
                StatusCode::TOO_MANY_REQUESTS.as_u16(),
                true,
                "A rate-limit scope rejected the request; callers should respect Retry-After.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret_wire::error_codes::ErrorCode::SCHEMA_VIOLATION,
                StatusCode::BAD_REQUEST.as_u16(),
                false,
                "The request body or headers did not match the active ak.edge.push.command.notify contract.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret_wire::error_codes::ErrorCode::TEMPORARILY_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                true,
                "All dispatch attempts failed with retryable provider or gateway conditions.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret_wire::error_codes::ErrorCode::UNSUPPORTED_FEATURE,
                StatusCode::BAD_REQUEST.as_u16(),
                false,
                "The caller requested a non-canonical notify operation or unsupported contract feature.",
            ),
            // Recording-artifact routing is an independent media pipeline
            // constraint. Agent lifecycle and participation are upstream
            // admission gates and are not advertised as Floria failures.
            PushBridgeFailureCodeDescriptor::new(
                arkret_wire::error_codes::ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED,
                StatusCode::FORBIDDEN.as_u16(),
                false,
                "A media-service token-exchange or recording artifact reference would route through a destination outside the Arkret blob pipeline (e.g. LiveKit Egress pointed at S3 directly). Floria refuses to relay the corresponding push.",
            ),
        ],
        examples: PushBridgeDescribeExamples {
            notify_headers: serde_json::json!({
                "X-Arkret-Request-Id": "req_01js0000000000000000000000",
                "Idempotency-Key": "notify-01js0000000000000000000000",
                "X-Arkret-Origin-Service-ID": "ak:did_core:web:soland.example",
                "X-Arkret-Destination-Service-ID": gateway_service_id,
            }),
            // Default interop privacy baseline
            // (`ak.profile.push_gateway.blind_wakeup.v1`): identifying
            // fields (`event_id` / `strand_id` / `realm_id` / sender) MUST
            // NOT appear — only the opaque pseudonym, wakeup discriminator
            // and bounded counts. Identifying-field examples live under
            // `plaintext_visible_service_request` (visible_notification
            // profile) below. Spec push-notifications.md §5.1.
            // Blind wakeup MUST NOT carry a plaintext absolute unread count
            // (push-notifications.md §5.1). Use the closed `counts` keys
            // (`badge` hysteresis bucket / `unread_increment` / `missed_call`)
            // defined by push-operations.schema.json#/$defs/counts.
            blind_wakeup_request: serde_json::json!({
                "notification": {
                    "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "push_hint": "new_message",
                    "counts": {"badge": "2-5"}
                }
            }),
            // visible_notification is additionalProperties:false: no free-text
            // `preview` field exists; identifying refs travel in the typed
            // id fields and `counts` follows the same closed schema.
            plaintext_visible_service_request: serde_json::json!({
                "notification": {
                    "event_id": "ak:event:AXYmt-Fuaq8Z8WqGu-VhVW_K-DQCqU0mMHZaXotnF-7g",
                    "strand_id": "ak:strand:AXYmt-Fuaq8Z8WqGu-VhVW_K-DQCqU0mMHZaXotnF-7g",
                    "realm_id": "ak:realm:AW2ArxAsk4QV_AskkaL7o8Oli_HF9cYojMSbnlxYnNs6",
                    "push_target_id": "ak:pseudonym:push:01HYZ8Z000000000000000",
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "push_hint": "new_message",
                    "counts": {"unread_increment": 1},
                    "devices": [{
                        "device_id": "ak:device:01964000-0000-7000-8000-000000000000",
                        "app_id": "com.example.app",
                        "push_key": "<opaque-provider-token>",
                        "visible_notification_opt_in": true
                    }]
                }
            }),
        },
        todos: Vec::new(),
    };

    res.status_code(StatusCode::OK);
    res.render(Json(body));
}
