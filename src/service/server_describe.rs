use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Map, Value, json};

use super::metrics::{ErrorBody, ErrorEnvelope};
use super::{MAX_REQUEST_SIZE, NOTIFY_OPERATION_ID};
use crate::AppState;
use crate::config::NotifyAuthConfig;

/// FLORIA-01 — `GET /_arkret/describe` MUST emit the canonical
/// `ServiceDescribe` (`arkret::ServiceDescribe` = `ServerDescription`)
/// defined by `service-describe.schema.json`, not a push-gateway-private
/// shape. The push-private matrix (provider list, auth modes, dedup,
/// rate-limit scopes, operation id) lives under the canonical
/// `limits`/`supported_features`/`auth_metadata` fields and `x_floria_*`
/// extension keys — never as bespoke top-level fields. The product's
/// private describe surface stays on `/_floria/*`.
///
/// DEFERRED (SDK gap): the schema's `service_type=push_gateway` branch
/// additionally requires a top-level `privacy_derivation.push_target_id`
/// block. The SDK `ServerDescription` struct has no `privacy_derivation`
/// field and exposes no top-level `extra` flatten, so this gateway-only
/// required block cannot be expressed through the strongly-typed SDK
/// surface today. It is intentionally NOT fabricated here; emitting it
/// must wait for an SDK field (tracked as a FLORIA-01 deferred sub-item).
/// Floria's HMAC push-target-id derivation profile metadata is mirrored
/// into `limits.x_floria_privacy_derivation` so consumers that read the
/// floria extension still see it.
fn floria_service_did(auth: &NotifyAuthConfig) -> arkret::Did {
    // production_mode enforces a configured gateway_service_did; in dev
    // postures it may be absent, so fall back to a stable, clearly
    // non-routable placeholder DID rather than failing the describe.
    let raw = auth
        .gateway_service_did
        .clone()
        .unwrap_or_else(|| "did:web:floria.invalid".to_owned());
    arkret::Did::new(raw).unwrap_or_else(|_| {
        arkret::Did::new("did:web:floria.invalid".to_owned())
            .expect("static placeholder DID is well-formed")
    })
}

#[handler]
pub(super) async fn describe(depot: &mut Depot, res: &mut Response) {
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
    // invariant (validated by `ServerDescription::validate`) is trivially
    // upheld.
    let development_mode = false;
    let verified_profiles: Vec<arkret::VerifiedProfileEntry> = Vec::new();

    let supported_profiles = describe_supported_profiles(auth);
    let claimed_profiles = supported_profiles
        .iter()
        .map(|&profile_id| {
            let mut entry = arkret::ClaimedProfileEntry::self_claimed(profile_id);
            if profile_id == PROFILE_PUSH_GATEWAY {
                entry.notes = Some(
                    "push gateway profile self-claimed; cotest verification not yet wired in (§3.0)"
                        .to_owned(),
                );
            }
            entry
        })
        .collect();

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
        json!(NOTIFY_OPERATION_ID),
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
    // DEFERRED mirror — see module doc: canonical top-level
    // `privacy_derivation` cannot be expressed via the SDK struct yet, so
    // the floria derivation profile metadata is surfaced under the floria
    // extension namespace until the SDK gains the strong field.
    limits.insert(
        "x_floria_privacy_derivation".to_owned(),
        json!({
            "push_target_id": {
                "derivation_profile": "ck.push_target_id.hmac_sha256.v1",
                "secret_scope": "per_service"
            }
        }),
    );

    // Auth metadata: canonical `mode` summarises the gateway posture; the
    // floria-specific mode list rides in the `x_*`-only `extra` map.
    let mode = if auth.enabled() {
        "service"
    } else {
        "anonymous"
    };
    let mut auth_metadata = arkret::AuthMetadata::minimal(mode);
    auth_metadata
        .extra
        .insert("x_floria_auth_modes".to_owned(), json!(auth_modes));

    let plaintext_visibility = if plaintext_class == "service-gated" {
        arkret::PlaintextVisibility {
            max_visibility: Some(arkret::PlaintextMaxVisibility::DerivedPlaintext),
            notes: Some(
                "service-gated visible-notification plaintext; per-service allowlisted".to_owned(),
            ),
            ..arkret::PlaintextVisibility::default()
        }
    } else {
        arkret::PlaintextVisibility::none()
    };

    let body = arkret::ServiceDescribe {
        service_did: floria_service_did(auth),
        // DEFERRED: floria has no configured deployment trust domain; a
        // stable placeholder is emitted until a `trust_domain` config
        // field is wired in (see module doc / FLORIA-01 deferred items).
        trust_domain: arkret::TypedTrustDomainId::new("ak:trust_domain:floria")
            .expect("static placeholder trust domain is well-formed"),
        service_type: "push_gateway".to_owned(),
        protocol_version: arkret::PROTOCOL_VERSION.to_owned(),
        supported_profiles: supported_profiles.iter().map(|p| p.to_string()).collect(),
        supported_operations: vec![NOTIFY_OPERATION_ID.to_owned()],
        supported_bindings: vec![arkret::SupportedBinding::new("http")],
        supported_features: vec![
            "push.notify".to_owned(),
            "push.bridge_describe".to_owned(),
            "push.dedup".to_owned(),
            "push.rate_limit".to_owned(),
            "push.provider_matrix".to_owned(),
        ],
        auth_metadata,
        limits: Value::Object(limits),
        plaintext_visibility,
        privacy_derivation: None,
        receive_policy_constraints: None,
        implemented_features: vec![
            "push.notify".to_owned(),
            "push.bridge_describe".to_owned(),
            "push.dedup".to_owned(),
            "push.rate_limit".to_owned(),
            "push.provider_matrix".to_owned(),
        ],
        claimed_profiles,
        verified_profiles,
        experimental_features: vec![
            "push.bridge.failure_codes".to_owned(),
            "push.notify.retry_queue".to_owned(),
        ],
        compat_surfaces: vec![],
        development_mode,
        rate_limit_policy: Some(arkret::RateLimitPolicy::unspecified()),
        rate_limit_policy_id: None,
        egress_network_policy: Some(arkret::EgressNetworkPolicy::deny_private_defaults()),
        resource_types: vec![],
        discovery_profiles: vec![],
        restricted_query_proof: None,
        ingest_modes: vec![],
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
        supported_schema_profiles: vec![],
        frontier: Vec::new(),
        snapshot_frontier: Vec::new(),
        reducer_profile: None,
        last_materialized_at: None,
    };

    debug_assert!(
        body.validate().is_ok(),
        "floria ServiceDescribe must satisfy schema cross-field invariants"
    );

    res.status_code(StatusCode::OK);
    res.render(Json(body));
}

/// Base push-gateway profile id.
pub(super) const PROFILE_PUSH_GATEWAY: &str = "ck.profile.push_gateway.v1";
/// Mandatory default-interop privacy baseline. Spec (push-notifications.md
/// §0, conformance-profiles.json) — any implementation claiming
/// `ck.profile.push_gateway.v1` MUST also claim this profile.
pub(super) const PROFILE_BLIND_WAKEUP: &str = "ck.profile.push_gateway.blind_wakeup.v1";
/// Opt-in visible-payload profile. Only advertised when the gateway is
/// configured with a plaintext-eligible service surface
/// (`describe_plaintext_visibility == "service-gated"`).
pub(super) const PROFILE_VISIBLE_NOTIFICATION: &str =
    "ck.profile.push_gateway.visible_notification.v1";

/// Profiles the gateway actually supports and gates on, in claim order.
/// The base profile and its mandatory blind-wakeup baseline are always
/// present; the visible-notification profile is added only when a
/// plaintext-eligible service surface is configured (matching the
/// internal `allow_plaintext_metadata` gate in `notify.rs`).
pub(super) fn describe_supported_profiles(auth: &NotifyAuthConfig) -> Vec<&'static str> {
    let mut profiles = vec![PROFILE_PUSH_GATEWAY, PROFILE_BLIND_WAKEUP];
    if describe_plaintext_visibility(auth) == "service-gated" {
        profiles.push(PROFILE_VISIBLE_NOTIFICATION);
    }
    profiles
}

pub(super) fn describe_plaintext_visibility(auth: &NotifyAuthConfig) -> &'static str {
    if !auth.plaintext_metadata_service_dids.is_empty()
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
            principal.signature_key_id.is_some() && principal.signature_public_key_hex.is_some()
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
    if !auth.trusted_service_dids.is_empty() || auth.gateway_service_did.is_some() {
        modes.push("service-did");
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
