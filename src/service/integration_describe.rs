use arkret_models_integration::{
    IntegrationDependencyDescriptor, IntegrationDescribeOutcome, IntegrationSurfaceDescriptor,
};
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
        dependencies: vec![
            IntegrationDependencyDescriptor {
                service: "soland".to_owned(),
                purpose: "principal_outbound_push_delivery".to_owned(),
                // Names the contract soland actually publishes at the
                // discovery path below; it is a product-local soland id with
                // no SDK/spec counterpart, so it is quoted verbatim rather
                // than mapped onto an invented `ak.*` id.
                required_contract: "arkret.rest.outbound_push_bridge.v1".to_owned(),
                discovery_path: "/_soland/edge/push/outbound/bridge/describe".to_owned(),
                mode: "remote_principal_contract".to_owned(),
            },
            IntegrationDependencyDescriptor {
                service: "chime".to_owned(),
                purpose: "client_sdk_consumption".to_owned(),
                required_contract: ServiceContractId::PUSH_BRIDGE_V1.to_owned(),
                discovery_path: "/_floria/push/bridge/describe".to_owned(),
                mode: "sdk_contract_discovery".to_owned(),
            },
        ],
        surfaces: vec![
            IntegrationSurfaceDescriptor {
                name: "push_bridge".to_owned(),
                method: "GET".to_owned(),
                path: "/_floria/push/bridge/describe".to_owned(),
                // The contract this surface serves is the contract of the
                // payload it returns. There is exactly one, and it is the id
                // `bridge_describe.rs` actually emits and chime's
                // `BridgeContractCache` compares — so the surface must not
                // carry a second, unregistered `ak.push.bridge.describe` label.
                contract: ServiceContractId::PUSH_BRIDGE_V1.to_owned(),
                stability: "active".to_owned(),
                todo: "the provider capability matrix is self-declared and unattested; consumers must pin provider_capabilities_version to detect a silent matrix change.".to_owned(),
            },
            IntegrationSurfaceDescriptor {
                name: "push_notify".to_owned(),
                method: "POST".to_owned(),
                path: "/_arkret/edge/push/notify".to_owned(),
                contract: ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY.to_owned(),
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
            "compose_strand": {
                "step_1": {
                    "service": "soland",
                    "path": "/_soland/edge/push/outbound/bridge/fetch",
                    "method": "POST"
                },
                "step_2": {
                    "service": "floria",
                    "path": "/_floria/push/bridge/describe",
                    "method": "GET"
                },
                "step_3": {
                    "service": "floria",
                    "path": "/_arkret/edge/push/notify",
                    "method": "POST"
                }
            }
        }),
        todos: vec![
            "wire a cotest verifier so the push gateway profile moves from self-claimed to verified in /_arkret/describe.".to_owned(),
            "configure the deployment trust_domain and push_target_id salt-epoch inputs so /_arkret/describe stops emitting placeholders.".to_owned(),
        ],
    }));
}
