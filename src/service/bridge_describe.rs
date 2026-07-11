use std::sync::Arc;

use arkret::push_gateway_api::{
    PushBridgeDescribeExamples, PushBridgeDescribeGatewayDescriptor,
    PushBridgeDescribeNotifyDescriptor, PushBridgeDescribeOutcome,
    PushBridgeDescribePrivacyDescriptor, PushBridgeFailureCodeDescriptor,
};
use salvo::http::StatusCode;
use salvo::prelude::*;

use super::metrics::{ErrorBody, ErrorEnvelope};
use super::server_describe::{
    describe_auth_modes, describe_plaintext_visibility, describe_rate_limit_scopes,
    describe_supported_profiles,
};
use super::{MAX_REQUEST_SIZE, NOTIFY_OPERATION_ID};
use crate::AppState;
use crate::auth::{DESTINATION_SERVICE_ID_HEADER, ORIGIN_SERVICE_ID_HEADER};
use crate::pushkin::PROVIDER_CAPABILITIES_VERSION;

fn owned(items: Vec<&'static str>) -> Vec<String> {
    items.into_iter().map(str::to_owned).collect()
}

#[handler]
pub(super) async fn bridge_describe(depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<Arc<AppState>>() else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        res.render(Json(ErrorEnvelope {
            ok: false,
            request_id: None,
            error: ErrorBody {
                code: arkret::error::ERROR_CODE_INTERNAL_ERROR,
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

    let body = PushBridgeDescribeOutcome {
        contract: "ak.push.bridge.describe".to_owned(),
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
        spec_version: Some(arkret::push_gateway_api::EXPECTED_SPEC_VERSION.to_owned()),
        gateway: PushBridgeDescribeGatewayDescriptor {
            service_id: state.notify_auth.gateway_service_id.clone(),
            supported_profiles: describe_supported_profiles(&state.notify_auth)
                .into_iter()
                .map(str::to_owned)
                .collect(),
            supported_providers: state.registry.provider_names(),
            auth_modes: owned(describe_auth_modes(&state.notify_auth)),
        },
        notify: PushBridgeDescribeNotifyDescriptor {
            notify_path: "/_arkret/edge/push/notify".to_owned(),
            operation_id: NOTIFY_OPERATION_ID.to_owned(),
            request_id_header: "X-Arkret-Request-Id".to_owned(),
            idempotency_key_header: "Idempotency-Key".to_owned(),
            origin_service_id_header: ORIGIN_SERVICE_ID_HEADER.to_owned(),
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
        failure_codes: vec![
            PushBridgeFailureCodeDescriptor::new(
                arkret::error::ERROR_CODE_CAPABILITY_DENIED,
                StatusCode::FORBIDDEN.as_u16(),
                false,
                "The caller is authenticated but not allowed to send this notify shape or destination.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret::error::ERROR_CODE_DUPLICATE_CONFLICT,
                StatusCode::CONFLICT.as_u16(),
                false,
                "The same idempotency key was replayed with a different canonical request body.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret::error::ERROR_CODE_METHOD_NOT_ALLOWED,
                StatusCode::METHOD_NOT_ALLOWED.as_u16(),
                false,
                "The notify surface only accepts POST.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret::error::ERROR_CODE_PAYLOAD_TOO_LARGE,
                StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                false,
                "The notify request body exceeded the configured maximum size.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret::error::ERROR_CODE_RATE_LIMITED,
                StatusCode::TOO_MANY_REQUESTS.as_u16(),
                true,
                "A rate-limit scope rejected the request; callers should respect Retry-After.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret::error::ERROR_CODE_SCHEMA_VIOLATION,
                StatusCode::BAD_REQUEST.as_u16(),
                false,
                "The request body or headers did not match the active ak.edge.push.command.notify contract.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret::error::ERROR_CODE_TEMPORARILY_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                true,
                "All dispatch attempts failed with retryable provider or gateway conditions.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret::error::ERROR_CODE_UNSUPPORTED_FEATURE,
                StatusCode::BAD_REQUEST.as_u16(),
                false,
                "The caller requested a non-canonical notify operation or unsupported contract feature.",
            ),
            // CARD-1 (R3 spec-sync 2026-05-27, `_before_todos.md` §0.7,
            // AKP-0008 / AKP-0009 / AKP-0010) — push surface
            // failure codes for Personal Agent lifecycle state and the
            // recording-artifact pipeline. Floria's notify pipeline
            // already silently consumes the durable `ak.agent.*` event
            // kinds and flushes the PSI cache when soland broadcasts
            // `consent_revoke{reason=agent_paused|agent_deactivated}`;
            // these descriptors expose the wire-form error codes so
            // operator dashboards and SDK callers can surface the
            // fail-closed shape in the rare path where floria itself
            // emits the code (e.g. a future push policy gate that
            // rejects fan-out for a deactivated controller, or the
            // recording-artifact destination check on a token-exchange
            // proxy hop). The strings are pinned to the SDK error-code
            // constants so a spec-side rename forces a recompile here.
            PushBridgeFailureCodeDescriptor::new(
                "agent_paused",
                StatusCode::FORBIDDEN.as_u16(),
                false,
                "The notification references a Personal Agent principal whose runtime is paused; floria fails closed so a paused agent does not pump pushes from a stale capability cache.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                "agent_deactivated",
                StatusCode::FORBIDDEN.as_u16(),
                false,
                "The notification references a Personal Agent principal that has been deactivated (terminal state). The push is rejected; controllers must provision a new agent before retrying.",
            ),
            PushBridgeFailureCodeDescriptor::new(
                arkret::error::REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED,
                StatusCode::FORBIDDEN.as_u16(),
                false,
                "A media-service token-exchange or recording artifact reference would route through a destination outside the Arkret blob pipeline (e.g. LiveKit Egress pointed at S3 directly). Floria refuses to relay the corresponding push.",
            ),
        ],
        examples: PushBridgeDescribeExamples {
            notify_headers: serde_json::json!({
                "X-Arkret-Request-Id": "req_01js0000000000000000000000",
                "Idempotency-Key": "notify-01js0000000000000000000000",
                "X-Arkret-Origin-Service-ID": "did:web:soland.example",
                "X-Arkret-Destination-Service-ID": state.notify_auth.gateway_service_id,
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
                    "event_id": "ak:event:01964000-0000-7000-8000-000000000000",
                    "strand_id": "ak:strand:01964000-0000-7000-8000-000000000000",
                    "realm_id": "ak:realm:01964000-0000-7000-8000-000000000000",
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
