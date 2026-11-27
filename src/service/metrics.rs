use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use arkret_models_integration::PushNotificationEnvelope;
use salvo::http::StatusCode;
use salvo::http::header::{HeaderName, HeaderValue};
use salvo::prelude::*;
use serde::Serialize;

use crate::metrics as app_metrics;
use crate::models::{DeliveryReceipt, NotificationExt};

/// Maximum number of distinct Realm identifiers included in delivery metrics.
const REALM_LABEL_LIMIT: usize = 5_000;
static REALM_SCOPE_SEEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);
static REALM_SCOPE_DOWNGRADED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn reset_cardinality_guard_for_tests() {
    REALM_SCOPE_DOWNGRADED.store(false, Ordering::Relaxed);
    *REALM_SCOPE_SEEN.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// Generic per-dimension cardinality guard. Returns whether the detailed
/// `id` may still be used as a label. Records `id` against the
/// dimension's guard set; when the unique-count threshold is crossed,
/// flips the sticky downgrade flag AND emits a one-shot warning so
/// operators see it. Subsequent calls observe the flag and return
/// `false` (the caller aggregates / drops the id).
fn record_and_check_guard(
    seen: &Mutex<Option<HashSet<String>>>,
    downgraded: &AtomicBool,
    id: &str,
    dimension: &str,
) -> bool {
    if downgraded.load(Ordering::Relaxed) {
        return false;
    }
    let mut guard = seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let set = guard.get_or_insert_with(HashSet::new);
    if set.len() >= REALM_LABEL_LIMIT && !set.contains(id) {
        // Trip the breaker once — log, set the sticky flag, and clear
        // the set so we do not retain unbounded memory after downgrade.
        downgraded.store(true, Ordering::Relaxed);
        let observed = set.len();
        set.clear();
        tracing::warn!(
            dimension,
            observed_ids = observed,
            threshold = REALM_LABEL_LIMIT,
            "scope-label cardinality guard tripped; auto-aggregating this dimension for the rest of this process lifetime"
        );
        return false;
    }
    set.insert(id.to_owned());
    true
}

fn record_realm_and_check_guard(realm_id: &str) -> bool {
    record_and_check_guard(
        &REALM_SCOPE_SEEN,
        &REALM_SCOPE_DOWNGRADED,
        realm_id,
        "realm",
    )
}

pub(super) fn record_delivery_receipt_outcomes(
    delivery_receipts: &[DeliveryReceipt],
    accepted: usize,
    rejected: usize,
) {
    let retryable = delivery_receipts
        .iter()
        .filter(|receipt| receipt.status.as_deref() == Some("retryable"))
        .count();
    let failed = delivery_receipts
        .iter()
        .filter(|receipt| receipt.status.as_deref() == Some("failed"))
        .count();
    app_metrics::notify_delivery_outcomes(accepted, rejected, retryable, failed);

    let mut per_provider: std::collections::HashMap<(String, &'static str), usize> =
        std::collections::HashMap::new();
    for receipt in delivery_receipts {
        let Some(status) = receipt.status.as_deref() else {
            continue;
        };
        let outcome = canonical_outcome(status);
        let Some(provider) = receipt.provider.as_deref() else {
            continue;
        };
        *per_provider
            .entry((provider.to_owned(), outcome))
            .or_default() += 1;
    }
    for ((provider, outcome), count) in per_provider {
        app_metrics::notify_delivery_outcome_by_provider(&provider, outcome, count);
    }
}

/// Opaque routes are aggregated without emitting a private routing token.
pub(super) fn record_notify_delivery_by_scope(
    notification: &PushNotificationEnvelope,
    delivery_receipts: &[DeliveryReceipt],
) {
    let (scope_kind, scope_id) = if notification.scope_route_token().is_some() {
        ("scope", None)
    } else {
        ("realm", notification.realm_id().filter(|id| record_realm_and_check_guard(id)))
    };

    let mut per_provider: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for receipt in delivery_receipts {
        let Some(provider) = receipt.provider.as_deref() else {
            continue;
        };
        if receipt.status.as_deref() != Some("accepted")
            && receipt.status.as_deref() != Some("accepted_cached")
        {
            continue;
        }
        *per_provider.entry(provider.to_owned()).or_default() += 1;
    }
    for (provider, count) in per_provider {
        app_metrics::notify_delivery_by_scope(&provider, scope_kind, scope_id, count);
    }
}

fn canonical_outcome(status: &str) -> &'static str {
    match status {
        "accepted" => "accepted",
        "accepted_cached" => "accepted_cached",
        "rejected" => "rejected",
        "retryable" => "retryable",
        "failed" => "failed",
        _ => "other",
    }
}

pub(super) fn render_problem(
    res: &mut Response,
    status: StatusCode,
    envelope: arkret_wire::Problem,
) {
    let problem = envelope.with_status(status.as_u16());
    let mut output = salvo::http::Problem::new(status)
        .kind(problem.problem_type)
        .title(problem.title)
        .detail(problem.detail)
        .with_extensions(
            problem
                .extensions
                .into_iter()
                .collect::<serde_json::Map<_, _>>(),
        );
    if let Some(instance) = problem.instance {
        output = output.instance(instance);
    }
    res.render(output);
}

pub(super) fn finish_error(
    res: &mut Response,
    status: StatusCode,
    code: &str,
    body: &str,
    retry_after: Option<Duration>,
    request_id: Option<&str>,
    started: Instant,
) {
    if let Some(retry_after) = retry_after {
        let seconds = retry_after.as_secs().max(1).to_string();
        let _ = res.add_header(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_str(&seconds).unwrap_or_else(|_| HeaderValue::from_static("1")),
            true,
        );
    }
    let request_id = request_id
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| arkret_wire::new_prefixed_uuid7("ak:request:"));
    let body = arkret_wire::Problem::from_code(code, body)
        .with_instance(request_id)
        .with_retry_after_ms(
            retry_after.map(|value| value.as_millis().min(u64::MAX as u128) as u64),
        );
    render_problem(res, status, body);
    app_metrics::pushgateway_response(status);
    app_metrics::observe_notify_handle(status, started.elapsed());
}

pub(super) fn finish_json<T: Serialize + Send>(
    res: &mut Response,
    status: StatusCode,
    body: T,
    started: Instant,
) {
    res.status_code(status);
    res.render(Json(body));
    app_metrics::pushgateway_response(status);
    app_metrics::observe_notify_handle(status, started.elapsed());
}

#[cfg(test)]
mod cardinality_guard_tests {
    use std::sync::Mutex as StdMutex;

    use super::*;

    // The guard uses module-level statics, so concurrent tests would
    // race. A shared mutex serialises this file's test cases. Other
    // test files do not touch the guard.
    static GUARD_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        GUARD_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn guard_allows_detailed_below_threshold() {
        let _g = lock();
        reset_cardinality_guard_for_tests();
        for i in 0..10 {
            assert!(
                record_realm_and_check_guard(&format!("realm-fixture-{i}")),
                "well under threshold must keep returning true"
            );
        }
        assert!(!REALM_SCOPE_DOWNGRADED.load(Ordering::Relaxed));
    }

    #[test]
    fn guard_trips_at_threshold_and_stays_downgraded() {
        let _g = lock();
        reset_cardinality_guard_for_tests();
        // Fill the set up to the threshold.
        for i in 0..REALM_LABEL_LIMIT {
            assert!(record_realm_and_check_guard(&format!(
                "realm-fixture-{i}"
            )));
        }
        assert!(!REALM_SCOPE_DOWNGRADED.load(Ordering::Relaxed));
        // The (threshold+1)th NEW id trips the guard.
        assert!(!record_realm_and_check_guard("realm-fixture-trip"));
        assert!(REALM_SCOPE_DOWNGRADED.load(Ordering::Relaxed));
        // Subsequent calls keep returning false without re-touching the set.
        assert!(!record_realm_and_check_guard("realm-fixture-after"));
    }
}
