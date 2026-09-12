use std::sync::Arc;

use arkret_wire::{Did, DidCoreId, ProfileId, ServiceOperationId};
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Map, json};

use super::MAX_REQUEST_SIZE;
use super::metrics::render_problem;
use crate::AppState;
use crate::config::NotifyAuthConfig;

/// FLORIA-01 — `GET /_arkret/describe` MUST emit the canonical
/// `ServiceDescribe` (`arkret_models_discovery::ServiceDescribe` = `ServiceDescribe`)
/// defined by `service-describe.schema.json`, not a push-gateway-private
/// shape. The push-private matrix (provider list, auth modes, dedup,
/// rate-limit scopes, operation id) lives under the canonical
/// `limits`/`supported_features`/`auth_metadata` fields and `x_floria_*`
/// extension keys — never as bespoke top-level fields. The product's
/// private describe surface stays on `/_floria/*`.
///
/// DEFERRED (deployment-input gap): the SDK can express the canonical
/// `privacy_derivation.push_target_id` block, but Floria does not yet own
/// configured salt-epoch and rotation metadata. It is intentionally not
/// fabricated here. The non-authoritative derivation profile hint remains
/// mirrored under `limits.x_floria_privacy_derivation` until those inputs
/// are available.
fn floria_service_did(auth: &NotifyAuthConfig) -> arkret_wire::Result<Did> {
    let raw = auth.gateway_service_did.clone().ok_or_else(|| {
        arkret_wire::WireError::Protocol(
            "http.notify_auth.gateway_service_did is required for ServiceDescribe".to_owned(),
        )
    })?;
    Ok(Did::new(raw)?)
}

fn floria_service_identity(
    auth: &NotifyAuthConfig,
) -> arkret_wire::Result<(DidCoreId, arkret_models_identity::ResolutionCommitment)> {
    let did = floria_service_did(auth)?;
    let service_id = arkret_wire::project_did_to_core_id(&did)?;
    let method_history_head = auth
        .gateway_service_method_history_head
        .clone()
        .unwrap_or_else(|| "development-unverified".to_owned());
    let version_id = auth
        .gateway_service_version_id
        .clone()
        .unwrap_or_else(|| "development-unverified".to_owned());
    Ok((
        service_id,
        arkret_models_identity::ResolutionCommitment {
            did,
            method_history_head,
            version_id,
        },
    ))
}

#[handler]
pub(super) async fn describe(depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.get_typed::<Arc<AppState>>() else {
        render_problem(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            arkret_wire::Problem::from_code(
                arkret_wire::error_codes::ErrorCode::INTERNAL_ERROR,
                "application state missing",
            )
            .with_instance(arkret_wire::new_prefixed_uuid7("ak:request:")),
        );
        return;
    };

    let auth = &state.notify_auth;

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

    // T6.1 — floria has no cotest verifier wired in, so the push gateway
    // profile is self-claimed only and `verified_profiles` is always
    // empty. The `development_mode=true => verified_profiles=[]`
    // invariant (validated by `ServiceDescribe::validate`) is trivially
    // upheld.
    let development_mode = !auth.production_mode;
    let verified_profiles: Vec<arkret_models_discovery::VerifiedProfileEntry> = Vec::new();

    let supported_profiles = describe_supported_profiles(auth);
    let auth_modes = describe_auth_modes(auth);
    let plaintext_class = describe_plaintext_visibility(auth);

    // Push-gateway-private matrix folded into the canonical `limits`
    // object as floria extension keys (`x_floria_*`). The schema permits
    // an arbitrary `limits` object; receivers that only understand
    // canonical fields ignore the extensions, while floria-aware clients
    // recover the provider matrix, dedup config and rate-limit scopes.
    let mut limits = Map::new();
    limits.insert("max_request_size_bytes".to_owned(), json!(MAX_REQUEST_SIZE));
    limits.insert(
        "x_floria_operation_id".to_owned(),
        json!(ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY_V1),
    );
    limits.insert(
        "x_floria_supported_providers".to_owned(),
        json!(state.registry.provider_names()),
    );
    limits.insert(
        "x_floria_plaintext_visibility_class".to_owned(),
        json!(plaintext_class),
    );
    limits.insert("x_floria_auth_modes".to_owned(), json!(auth_modes));
    if let Some(backend) = dedup_backend {
        limits.insert("x_floria_dedup_backend".to_owned(), json!(backend));
    }
    if let Some(ttl) = dedup_ttl_seconds {
        limits.insert("x_floria_dedup_ttl_seconds".to_owned(), json!(ttl));
    }
    limits.insert(
        "x_floria_rate_limit_window_seconds".to_owned(),
        json!(rate_limit_window_seconds),
    );
    limits.insert(
        "x_floria_rate_limit_scopes".to_owned(),
        json!(rate_limit_scopes),
    );
    // DEFERRED mirror — see module doc: canonical epoch/rotation deployment
    // inputs are not configured yet, so only the profile hint is surfaced
    // under Floria's extension namespace.
    limits.insert(
        "x_floria_privacy_derivation".to_owned(),
        json!({
            "push_target_id": {
                "derivation_profile": "ak.push_target_id.hmac_sha256.v1",
                "secret_scope": "per_service"
            }
        }),
    );

    // The floria-specific mode list rides in the `x_*`-only `extra` map.
    let mut auth_metadata = arkret_models_discovery::AuthMetadata::minimal();
    auth_metadata
        .extra
        .insert("x_floria_auth_modes".to_owned(), json!(auth_modes))
        .expect("x_floria_auth_modes is a valid extension key");

    let plaintext_visibility = if plaintext_class == "service-gated" {
        arkret_models_discovery::PlaintextVisibility {
            max_visibility: Some(arkret_models_discovery::PlaintextMaxVisibility::DerivedPlaintext),
            notes: Some(
                "service-gated visible-notification plaintext; per-service allowlisted".to_owned(),
            ),
            ..arkret_models_discovery::PlaintextVisibility::default()
        }
    } else {
        arkret_models_discovery::PlaintextVisibility::none()
    };

    let Ok((service_id, service_resolution)) = floria_service_identity(auth) else {
        render_problem(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            arkret_wire::Problem::from_code(
                arkret_wire::ErrorCode::INTERNAL_ERROR,
                "gateway service resolution is not configured",
            )
            .with_instance(arkret_wire::new_prefixed_uuid7("ak:request:")),
        );
        return;
    };
    let body = arkret_models_discovery::ServiceDescribe {
        service_id,
        service_resolution,
        // DEFERRED: floria has no configured deployment trust domain; a
        // stable placeholder is emitted until a `trust_domain` config
        // field is wired in (see module doc / FLORIA-01 deferred items).
        trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:floria")
            .expect("static placeholder trust domain is well-formed"),
        service_kind: arkret_wire::ServiceKind::PushGateway,
        protocol_version: arkret_models_discovery::ServiceProtocolVersion::V1,
        supported_profiles: supported_profiles.iter().map(|p| p.to_string()).collect(),
        profile_bindings: Default::default(),
        supported_operation_bundles: vec![
            "ak.operation_bundle.push_gateway.describe.v1".to_owned(),
            "ak.operation_bundle.push_gateway.http_notify.v1".to_owned(),
        ],
        transport_bindings: vec![arkret_models_discovery::TransportBinding::HttpJson {
            base_url: state.public_base_url.clone(),
            extension_profile_required: (),
        }],
        supported_features: vec!["ak.feature.notifications.v1".to_owned()],
        // A push gateway claims no Calendar profile, so it advertises no
        // executable TZDB release set. `service-describe.schema.json` requires
        // this field only for a service that claims one.
        calendar_tzdb_versions: Vec::new(),
        auth_metadata,
        limits: arkret_models_discovery::ServerLimits {
            mls_governance_proof: None,
            extensions: limits.into_iter().collect(),
        },
        plaintext_visibility,
        privacy_derivation: None,
        receive_policy_constraints: None,
        verified_profiles,
        interop_surfaces: vec![],
        development_mode,
        rate_limit_policy: Some(arkret_models_discovery::RateLimitPolicy::unspecified()),
        rate_limit_policy_id: None,
        egress_network_policy: Some(
            arkret_models_discovery::EgressNetworkPolicy::deny_private_defaults(),
        ),
        resource_kinds: vec![],
        restricted_query_proof: None,
        accept_policy_kind: None,
        accept_policy_ref: None,
        default_ttl_seconds: None,
        max_ttl_seconds: None,
        revalidation_grace_seconds: None,
        accepted_resource_kinds: vec![],
        accepted_did_methods: vec![],
        takedown_contact: None,
        rate_limits: None,
        supported_reducer_profiles: vec![],
        invite_addressing: None,
        private_contact_discovery: None,
        extensions: Default::default(),
    };

    debug_assert!(
        body.validate().is_ok(),
        "floria ServiceDescribe must satisfy schema cross-field invariants"
    );

    res.status_code(StatusCode::OK);
    res.render(Json(body));
}

/// Profiles the gateway actually supports and gates on, in claim order.
/// The base profile and its mandatory blind-wakeup baseline are always
/// present; the visible-notification profile is added only when a
/// plaintext-eligible service surface is configured (matching the
/// internal `allow_plaintext_metadata` gate in `notify.rs`).
pub(super) fn describe_supported_profiles(auth: &NotifyAuthConfig) -> Vec<&'static str> {
    let mut profiles = vec![
        ProfileId::PUSH_GATEWAY_V1,
        ProfileId::PUSH_GATEWAY_BLIND_WAKEUP_V1,
    ];
    if describe_plaintext_visibility(auth) == "service-gated" {
        profiles.push(ProfileId::PUSH_GATEWAY_VISIBLE_NOTIFICATION_V1);
    }
    profiles
}

pub(super) fn describe_plaintext_visibility(auth: &NotifyAuthConfig) -> &'static str {
    if !auth.plaintext_metadata_service_ids.is_empty()
        || auth
            .service_principals
            .values()
            .any(|principal| principal.allow_plaintext_metadata)
    {
        "service-gated"
    } else {
        "blind-wakeup-only"
    }
}

pub(super) fn describe_auth_modes(auth: &NotifyAuthConfig) -> Vec<&'static str> {
    if !auth.enabled() {
        return vec!["anonymous"];
    }

    let mut modes = Vec::new();
    if !auth.production_mode
        && (!auth.bearer_tokens.is_empty()
            || !auth.bearer_token_hashes.is_empty()
            || auth.service_principals.values().any(|principal| {
                !principal.bearer_tokens.is_empty() || !principal.bearer_token_hashes.is_empty()
            }))
    {
        modes.push("bearer");
    }
    if auth.require_message_signatures
        || auth.service_principals.values().any(|principal| {
            principal.signature_verification_method.is_some()
                && principal.signature_public_key_hex.is_some()
        })
    {
        modes.push("http-message-signature");
    }
    if auth
        .service_principals
        .values()
        .any(|principal| principal.require_mtls)
    {
        modes.push("mtls");
    }
    if !auth.trusted_service_ids.is_empty() || auth.gateway_service_did.is_some() {
        modes.push("service-id");
    }
    modes.sort_unstable();
    modes.dedup();
    modes
}

pub(super) fn describe_rate_limit_scopes(
    config: &crate::config::NotifyRateLimitConfig,
) -> Vec<&'static str> {
    let mut scopes = Vec::new();
    if config.per_origin_service.is_some_and(|limit| limit > 0) {
        scopes.push("origin_service");
    }
    if config.per_app_id.is_some_and(|limit| limit > 0) {
        scopes.push("app_id");
    }
    if config.per_provider.is_some_and(|limit| limit > 0) {
        scopes.push("provider");
    }
    if config.per_push_key_hash.is_some_and(|limit| limit > 0) {
        scopes.push("push_key_hash");
    }
    if config.per_endpoint.is_some_and(|limit| limit > 0) {
        scopes.push("endpoint");
    }
    scopes
}
