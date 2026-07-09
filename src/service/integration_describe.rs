use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
struct IntegrationDescribeOutcome {
    contract: &'static str,
    version: &'static str,
    service: &'static str,
    service_kind: &'static str,
    api_base_path: &'static str,
    describe_path: &'static str,
    dependencies: Vec<IntegrationDependencyDescriptor>,
    surfaces: Vec<IntegrationSurfaceDescriptor>,
    examples: Value,
}

#[derive(Debug, Serialize)]
struct IntegrationDependencyDescriptor {
    service: &'static str,
    purpose: &'static str,
    required_contract: &'static str,
    discovery_path: &'static str,
    mode: &'static str,
}

#[derive(Debug, Serialize)]
struct IntegrationSurfaceDescriptor {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    contract: &'static str,
    stability: &'static str,
    description: &'static str,
}

#[handler]
pub(super) async fn integration_describe(_depot: &mut Depot, res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Json(IntegrationDescribeOutcome {
        contract: "arkret.rest.integration_manifest.v1",
        version: "2026-05-07",
        service: "floria",
        service_kind: "push_gateway",
        api_base_path: "/_floria",
        describe_path: "/_floria/integration/describe",
        dependencies: vec![
            IntegrationDependencyDescriptor {
                service: "soland",
                purpose: "principal_outbound_push_delivery",
                required_contract: "arkret.rest.outbound_push_bridge.v1",
                discovery_path: "/_soland/edge/push/outbound/bridge/describe",
                mode: "remote_principal_contract",
            },
            IntegrationDependencyDescriptor {
                service: "chime",
                purpose: "client_sdk_consumption",
                required_contract: "ck.push.bridge.describe",
                discovery_path: "/_floria/push/bridge/describe",
                mode: "sdk_contract_discovery",
            },
        ],
        surfaces: vec![
            IntegrationSurfaceDescriptor {
                name: "push_bridge",
                method: "GET",
                path: "/_floria/push/bridge/describe",
                contract: "ck.push.bridge.describe",
                stability: "active",
                description: "GET /_floria/push/bridge/describe exposes the frozen provider capability matrix; consumers should pin provider_capabilities_version.",
            },
            IntegrationSurfaceDescriptor {
                name: "push_notify",
                method: "POST",
                path: "/_arkret/edge/push/notify",
                contract: "ck.edge.push.command.notify",
                stability: "active",
                description: "POST /_arkret/edge/push/notify enforces blind-wakeup, dedup, rate limit, and HTTP Message Signature when configured.",
            },
            IntegrationSurfaceDescriptor {
                name: "gateway_describe",
                method: "GET",
                path: "/_arkret/describe",
                contract: "ck.profile.push_gateway.v1",
                stability: "active",
                description: "GET /_arkret/describe advertises the gateway profile at the root meta position; it is the only protocol-surface describe and is kept in sync with bridge/describe.",
            },
            IntegrationSurfaceDescriptor {
                name: "health",
                method: "GET",
                path: "/health",
                contract: "plain_text_health_probe.v1",
                stability: "active",
                description: "GET /health is the liveness probe surface and intentionally returns an empty plain-text body.",
            },
            IntegrationSurfaceDescriptor {
                name: "ready",
                method: "GET",
                path: "/ready",
                contract: "plain_text_readiness_probe.v1",
                stability: "active",
                description: "GET /ready verifies auth and dedup dependencies before returning plain-text `ok`.",
            },
            IntegrationSurfaceDescriptor {
                name: "readyz",
                method: "GET",
                path: "/readyz",
                contract: "json_strict_readiness_probe.v1",
                stability: "active",
                description: "GET /readyz verifies the provider registry is populated and enabled Redis-backed dependencies answer PING.",
            },
            IntegrationSurfaceDescriptor {
                name: "metrics",
                method: "GET",
                path: "/metrics",
                contract: "prometheus.text.0.0.4",
                stability: "active",
                description: "Prometheus scrape surface is served on the dedicated metrics listener when metrics are enabled.",
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
    }));
}
