use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::Serialize;

use super::metrics::{ErrorBody, ErrorEnvelope};
use super::{MAX_REQUEST_SIZE, NOTIFY_OPERATION_ID};
use crate::AppState;
use crate::config::NotifyAuthConfig;

#[derive(Debug, Serialize)]
struct PushGatewayDescribeOutcome {
    service_did: Option<String>,
    operation_id: &'static str,
    supported_profiles: Vec<&'static str>,
    supported_providers: Vec<String>,
    plaintext_visibility_class: &'static str,
    limits: GatewayDescribeLimits,
    auth_modes: Vec<&'static str>,
    // T6.1 — claim-level partition (service-surface.md §3.0 /
    // ck.schema.service_describe.v1). `supported_profiles` above is kept
    // for backward compatibility with existing clients; the fields below
    // partition feature implementation from profile claims and dev
    // posture from cotest-verified claims.
    /// feature_ids the service has implementation code for but does NOT
    /// necessarily claim conformance for.
    implemented_features: Vec<&'static str>,
    /// Self-claimed profiles. `claim_kind` MUST be `self_claimed`.
    claimed_profiles: Vec<ClaimedProfile>,
    /// cotest-verified profiles. MUST be empty when
    /// `development_mode=true` (floria has no dedicated dev toggle, so
    /// this is always `[]` until a cotest verifier writes a real entry).
    verified_profiles: Vec<VerifiedProfile>,
    /// Features exposed but NOT promised stable interop.
    experimental_features: Vec<&'static str>,
    /// Legacy / external-interop surfaces; not part of v1 conformance.
    compat_surfaces: Vec<CompatSurface>,
    /// Mirror of the service's development-mode flag. floria has no
    /// dedicated dev toggle today; if one is added later the
    /// `verified_profiles=[]` invariant MUST be re-enforced.
    development_mode: bool,
}

/// T6.1 — self-claimed profile entry; `claim_kind` is always
/// `self_claimed`.
#[derive(Debug, Serialize)]
struct ClaimedProfile {
    profile_id: &'static str,
    claim_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'static str>,
}

/// T6.1 — cotest-verified profile entry. Required `cotest_run_id`,
/// `artifact_digest`, `artifact_ref`, `cotest_issuer_did`, `signature`,
/// `timestamp`. Dev-mode posture MUST NOT advertise any such entry.
#[derive(Debug, Serialize)]
struct VerifiedProfile {
    profile_id: String,
    claim_kind: &'static str,
    cotest_run_id: String,
    artifact_digest: String,
    artifact_ref: String,
    cotest_issuer_did: String,
    signature: String,
    timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

/// T6.1 — compat / external-interop surface entry. `kind` ∈ schema enum.
#[derive(Debug, Serialize)]
struct CompatSurface {
    name: &'static str,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct GatewayDescribeLimits {
    max_request_size_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    dedup_backend: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dedup_ttl_seconds: Option<u64>,
    rate_limit_window_seconds: Option<u64>,
    rate_limit_scopes: Vec<&'static str>,
}

#[handler]
pub(super) async fn describe(depot: &mut Depot, res: &mut Response) {
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
    // T6.1 — claim-level partition fields. Today floria has no cotest
    // verifier wired in, so `verified_profiles=[]` always; the push
    // gateway profile is self-claimed only. The `development_mode=true
    // => verified_profiles=[]` invariant is trivially upheld and
    // debug_asserted below.
    let development_mode = false;
    let verified_profiles: Vec<VerifiedProfile> = Vec::new();
    debug_assert!(
        !development_mode || verified_profiles.is_empty(),
        "development_mode=true requires verified_profiles=[] (service-surface.md §3.0)"
    );

    let supported_profiles = describe_supported_profiles(&state.notify_auth);
    let claimed_profiles = supported_profiles
        .iter()
        .map(|&profile_id| ClaimedProfile {
            profile_id,
            claim_kind: "self_claimed",
            notes: (profile_id == PROFILE_PUSH_GATEWAY).then_some(
                "push gateway profile self-claimed; cotest verification not yet wired in (§3.0)",
            ),
        })
        .collect();

    let body = PushGatewayDescribeOutcome {
        service_did: state.notify_auth.gateway_service_did.clone(),
        operation_id: NOTIFY_OPERATION_ID,
        supported_profiles,
        supported_providers: state.registry.provider_names(),
        plaintext_visibility_class: describe_plaintext_visibility(&state.notify_auth),
        limits: GatewayDescribeLimits {
            max_request_size_bytes: MAX_REQUEST_SIZE,
            dedup_backend,
            dedup_ttl_seconds,
            rate_limit_window_seconds,
            rate_limit_scopes,
        },
        auth_modes: describe_auth_modes(&state.notify_auth),
        implemented_features: vec![
            "push.notify",
            "push.bridge_describe",
            "push.dedup",
            "push.rate_limit",
            "push.provider_matrix",
        ],
        claimed_profiles,
        verified_profiles,
        experimental_features: vec!["push.bridge.failure_codes", "push.notify.retry_queue"],
        compat_surfaces: vec![],
        development_mode,
    };
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
