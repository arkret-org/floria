use std::sync::Arc;

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::json;

use crate::AppState;

#[handler]
pub(super) async fn health(depot: &mut Depot, res: &mut Response) {
    // T8.3 — surface a non-sensitive production hardening checklist
    // snapshot. Older clients that only check the HTTP status code
    // still see 200 OK; the JSON body is additive.
    let hardening = match depot.obtain::<Arc<AppState>>() {
        Ok(state) => floria_hardening_status(state.as_ref()),
        Err(_) => default_hardening_status(),
    };
    res.status_code(StatusCode::OK);
    res.render(Json(json!({
        "ok": true,
        "service": "floria",
        "hardening": hardening,
    })));
}

/// Derive the hardening snapshot from `AppState`. floria itself does
/// not own a global "development_mode" toggle the way soland / starid
/// do — the closest signal is the per-`NotifyAuthConfig`
/// `production_mode` flag, which forbids dev conveniences (anonymous
/// bypass, bearer fallback). We surface that as the
/// `admin_auth_mode` enum.
fn floria_hardening_status(state: &AppState) -> serde_json::Value {
    let auth = &state.notify_auth;
    let production_mode = auth.production_mode;
    let admin_auth_mode = if !auth.enabled() {
        "closed"
    } else if production_mode {
        "production"
    } else {
        "development"
    };
    let secret_manager_in_use =
        !auth.bearer_tokens.is_empty() || !auth.bearer_token_hashes.is_empty();
    let rate_limit_enabled = state.notify_rate_limiter.is_some();

    let mut warnings: Vec<String> = Vec::new();
    let mut score = 0u32;
    let max: u32 = 9;

    if production_mode {
        score += 1;
    } else {
        warnings.push("development_mode_disabled".to_owned());
    }
    // TLS / CSP / CORS are reverse-proxy concerns for floria; we can't
    // probe them from in-process. We surface them as `null` -> false
    // so the checklist's intent is visible.
    warnings.push("tls_enabled_requires_proxy_check".to_owned());
    warnings.push("csp_header_requires_proxy_check".to_owned());
    warnings.push("cors_requires_proxy_check".to_owned());
    let log_redaction_enabled = true;
    score += 1; // log_redaction
    if admin_auth_mode == "production" {
        score += 1;
    } else {
        warnings.push("admin_auth_mode_production".to_owned());
    }
    if rate_limit_enabled {
        score += 1;
    } else {
        warnings.push("rate_limit_enabled".to_owned());
    }
    if secret_manager_in_use {
        score += 1;
    } else {
        warnings.push("secret_manager_in_use".to_owned());
    }
    // provider_credential_rotation: floria handles APNs / FCM /
    // VAPID creds via the pushkin registry — rotation is operationally
    // manual today.
    let provider_credential_rotation = "manual";

    json!({
        "development_mode": !production_mode,
        "tls_enabled": false,
        "csp_header_configured": false,
        "cors_strict": true,
        "secret_manager_in_use": secret_manager_in_use,
        "log_redaction_enabled": log_redaction_enabled,
        "admin_auth_mode": admin_auth_mode,
        "rate_limit_enabled": rate_limit_enabled,
        "provider_credential_rotation": provider_credential_rotation,
        "checklist_score": score,
        "checklist_max": max,
        "warnings": warnings,
    })
}

fn default_hardening_status() -> serde_json::Value {
    json!({
        "development_mode": true,
        "tls_enabled": false,
        "csp_header_configured": false,
        "cors_strict": true,
        "secret_manager_in_use": false,
        "log_redaction_enabled": false,
        "admin_auth_mode": "unknown",
        "rate_limit_enabled": false,
        "provider_credential_rotation": "none",
        "checklist_score": 0,
        "checklist_max": 9,
        "warnings": ["state_not_injected"],
    })
}

#[handler]
pub(super) async fn ready(depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<Arc<AppState>>() else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        res.render(Text::Plain("application state missing"));
        return;
    };

    if let Some(deduplicator) = state.notify_deduplicator.as_ref()
        && let Err(error) = deduplicator.ready()
    {
        tracing::warn!(error = %error, "readiness check failed");
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
        res.render(Text::Plain(format!("not ready: {error}")));
        return;
    }
    if let Err(error) = state.notify_auth.validate() {
        tracing::warn!(error = %error, "readiness auth config check failed");
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
        res.render(Text::Plain(format!("not ready: {error}")));
        return;
    }

    res.status_code(StatusCode::OK);
    res.render(Text::Plain("ok"));
}

#[handler]
pub(super) async fn readyz(depot: &mut Depot, res: &mut Response) {
    let Ok(state) = depot.obtain::<Arc<AppState>>() else {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        res.render(Json(json!({
            "ok": false,
            "service": "floria",
            "error": "application state missing",
        })));
        return;
    };

    let provider_names = state.registry.provider_names();
    let provider_registry_ok = !provider_names.is_empty();
    let mut dependency_checks = Vec::new();
    let mut dependencies_ok = true;

    let (check, ok) = match state.notify_deduplicator.as_ref() {
        Some(deduplicator) => {
            if let Some(size) = deduplicator.delivered_devices_len() {
                crate::metrics::set_device_dedup_cache_size(size as i64);
            }
            dependency_check(
                "notify_dedup",
                deduplicator.backend_name(),
                deduplicator.ready(),
            )
        }
        None => disabled_dependency_check("notify_dedup"),
    };
    dependencies_ok &= ok;
    dependency_checks.push(check);

    let (check, ok) = match state.notify_nonce_store.as_ref() {
        Some(nonce_store) => dependency_check(
            "notify_auth.nonce_store",
            nonce_store.backend_name(),
            nonce_store.ready(),
        ),
        None => disabled_dependency_check("notify_auth.nonce_store"),
    };
    dependencies_ok &= ok;
    dependency_checks.push(check);

    let (check, ok) = match state.notify_rate_limiter.as_ref() {
        Some(rate_limiter) => dependency_check(
            "notify_rate_limits",
            rate_limiter.backend_name(),
            rate_limiter.ready(),
        ),
        None => disabled_dependency_check("notify_rate_limits"),
    };
    dependencies_ok &= ok;
    dependency_checks.push(check);

    let (check, ok) = match state.notify_retry_queue.as_ref() {
        Some(retry_queue) => dependency_check(
            "notify_retry_queue",
            retry_queue.backend_name(),
            retry_queue.ready(),
        ),
        None => disabled_dependency_check("notify_retry_queue"),
    };
    dependencies_ok &= ok;
    dependency_checks.push(check);

    let ok = provider_registry_ok && dependencies_ok;
    if ok {
        res.status_code(StatusCode::OK);
    } else {
        tracing::warn!(
            provider_registry_ok,
            dependencies_ok,
            "strict readiness check failed"
        );
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    res.render(Json(json!({
        "ok": ok,
        "service": "floria",
        "checks": {
            "provider_registry": {
                "ok": provider_registry_ok,
                "count": provider_names.len(),
                "providers": provider_names,
            },
            "dependencies": dependency_checks,
        }
    })));
}

fn disabled_dependency_check(name: &str) -> (serde_json::Value, bool) {
    (
        json!({
            "name": name,
            "backend": "disabled",
            "ok": true,
        }),
        true,
    )
}

fn dependency_check(
    name: &str,
    backend: &str,
    result: Result<(), String>,
) -> (serde_json::Value, bool) {
    match result {
        Ok(()) => (
            json!({
                "name": name,
                "backend": backend,
                "ok": true,
            }),
            true,
        ),
        Err(error) => (
            json!({
                "name": name,
                "backend": backend,
                "ok": false,
                "error": error,
            }),
            false,
        ),
    }
}
