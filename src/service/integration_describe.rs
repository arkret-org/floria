use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
struct IntegrationDescribeResponse {
    contract: &'static str,
    version: &'static str,
    service: &'static str,
    service_kind: &'static str,
    api_base_path: &'static str,
    describe_path: &'static str,
    dependencies: Vec<IntegrationDependencyDescriptor>,
    surfaces: Vec<IntegrationSurfaceDescriptor>,
    examples: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    todos: Vec<&'static str>,
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
    todo: &'static str,
}

#[handler]
pub(super) async fn integration_describe(_depot: &mut Depot, res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.render(Json(IntegrationDescribeResponse {
        contract: "contrix.rest.integration_manifest.v1",
        version: "2026-05-05-scaffold",
        service: "floria",
        service_kind: "push_gateway",
        api_base_path: "/api/v1",
        describe_path: "/api/v1/integration/describe",
        dependencies: vec![
            IntegrationDependencyDescriptor {
                service: "soland",
                purpose: "principal_outbound_push_delivery",
                required_contract: "contrix.rest.outbound_push_bridge.v1",
                discovery_path: "/api/v1/push/outbound/bridge/describe",
                mode: "remote_principal_contract",
            },
            IntegrationDependencyDescriptor {
                service: "chime",
                purpose: "client_sdk_consumption",
                required_contract: "cx.push.bridge.describe",
                discovery_path: "/api/v1/push/bridge/describe",
                mode: "sdk_contract_discovery",
            },
        ],
        surfaces: vec![
            IntegrationSurfaceDescriptor {
                name: "push_bridge",
                method: "GET",
                path: "/api/v1/push/bridge/describe",
                contract: "cx.push.bridge.describe",
                stability: "scaffold",
                todo: "TODO: freeze provider auth modes, plaintext boundary classes, and example payloads as final machine-readable contract fields.",
            },
            IntegrationSurfaceDescriptor {
                name: "push_notify",
                method: "POST",
                path: "/api/v1/push/notify",
                contract: "cx.push.notify.v1",
                stability: "scaffold",
                todo: "TODO: back the notify path with durable dedup, retry, and provider error taxonomy.",
            },
            IntegrationSurfaceDescriptor {
                name: "gateway_describe",
                method: "GET",
                path: "/api/v1/push/describe",
                contract: "cx.profile.push_gateway.v1",
                stability: "scaffold",
                todo: "TODO: align profile and bridge describe fields so soland and chime can derive one canonical gateway snapshot.",
            },
            IntegrationSurfaceDescriptor {
                name: "health",
                method: "GET",
                path: "/health",
                contract: "plain_text_health_probe.v1",
                stability: "active",
                todo: "GET /health is the liveness probe surface and intentionally returns an empty plain-text body.",
            },
            IntegrationSurfaceDescriptor {
                name: "ready",
                method: "GET",
                path: "/ready",
                contract: "plain_text_readiness_probe.v1",
                stability: "active",
                todo: "GET /ready verifies auth and dedup dependencies before returning plain-text `ok`.",
            },
            IntegrationSurfaceDescriptor {
                name: "metrics",
                method: "GET",
                path: "/metrics",
                contract: "prometheus.text.0.0.4",
                stability: "active",
                todo: "Prometheus scrape surface is served on the dedicated metrics listener when metrics are enabled.",
            },
        ],
        examples: serde_json::json!({
            "compose_flow": {
                "step_1": {
                    "service": "soland",
                    "path": "/api/v1/push/outbound/bridge/fetch",
                    "method": "POST"
                },
                "step_2": {
                    "service": "floria",
                    "path": "/api/v1/push/bridge/describe",
                    "method": "GET"
                },
                "step_3": {
                    "service": "floria",
                    "path": "/api/v1/push/notify",
                    "method": "POST"
                }
            }
        }),
        todos: vec![
            "TODO: persist contract snapshots and drift state so principal servers can cache gateway compatibility.",
            "TODO: publish provider capability examples that match real gateway auth modes.",
            "TODO: align the integration manifest and push bridge describe contracts with one shared version cadence.",
        ],
    }));
}
