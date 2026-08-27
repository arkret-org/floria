use arkret_models_integration::{IntegrationDescribeOutcome, IntegrationSurfaceDescriptor};
use arkret_wire::{ProfileId, ServiceContractId, ServiceOperationId};
use salvo::http::StatusCode;
use salvo::prelude::*;

/// `GET /_floria/integration/describe` emits the shared SDK integration
/// manifest (`arkret_models_integration::IntegrationDescribeOutcome`).
///
/// The shape MUST come from the SDK: chime deserializes this exact route with
/// the SDK type (`floria_integration_describe`), so a product-local mirror
/// silently breaks the client the moment the SDK adds or renames a required
/// field.
#[handler]
pub(super) async fn integration_describe(_depot: &mut Depot, res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Json(IntegrationDescribeOutcome {
        // Canonical manifest contract id per the SDK
        // (`models-integration/src/integration.rs`).
        contract: ServiceContractId::INTEGRATION_MANIFEST_V1.to_owned(),
        version: "2026-05-07".to_owned(),
        service: "floria".to_owned(),
        service_kind: "push_gateway".to_owned(),
        api_base_path: "/_floria".to_owned(),
        describe_path: "/_floria/integration/describe".to_owned(),
        dependencies: Vec::new(),
        surfaces: vec![
            IntegrationSurfaceDescriptor {
                name: "push_notify".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/edge/push/notify".to_owned(),
                contract: ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1.to_owned(),
                stability: "active".to_owned(),
                todo: "dedup, rate limit, HTTP Message Signature and mTLS are enforced only for the modes the deployment configures; the contract itself mandates none of them.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "gateway_describe".to_owned(),
                method: "GET".to_owned(),
                path: "/_arkret/describe".to_owned(),
                contract: ProfileId::PUSH_GATEWAY_V1.to_owned(),
                stability: "active".to_owned(),
                todo: "profiles are self-claimed only (no cotest verifier is wired in, so verified_profiles is always empty) and trust_domain / privacy_derivation still emit deployment placeholders.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "ready".to_owned(),
                method: "GET".to_owned(),
                path: "/ready".to_owned(),
                contract: "plain_text_readiness_probe.v1".to_owned(),
                stability: "active".to_owned(),
                todo: "readiness covers the auth and dedup dependencies only; provider upstream reachability is not probed.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "readyz".to_owned(),
                method: "GET".to_owned(),
                path: "/readyz".to_owned(),
                contract: "json_strict_readiness_probe.v1".to_owned(),
                stability: "active".to_owned(),
                todo: "readyz checks the provider registry and Redis-backed dependencies; per-provider credentials are not validated.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "metrics".to_owned(),
                method: "GET".to_owned(),
                path: "/metrics".to_owned(),
                contract: "prometheus.text.0.0.4".to_owned(),
                stability: "active".to_owned(),
                todo: "the scrape surface is unauthenticated and is served only when the dedicated metrics listener is enabled.".to_owned(),
            },
        ],
        examples: serde_json::json!({
            "canonical_discovery": {
                "describe": {
                    "path": "/_arkret/describe",
                    "operation_bundle": "ak.operation_bundle.push_gateway.describe.v1"
                },
                "notify": {
                    "path": "/_arkret/edge/push/notify",
                    "operation_id": ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1
                }
            }
        }),
        todos: vec![
            "wire a cotest verifier so the push gateway profile moves from self-claimed to verified in /_arkret/describe.".to_owned(),
            "configure the deployment trust_domain and push_target_id salt-epoch inputs so /_arkret/describe stops emitting placeholders.".to_owned(),
        ],
    }));
}
