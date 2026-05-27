use std::collections::HashSet;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use salvo::http::StatusCode;
use salvo::http::header::{HeaderName, HeaderValue};
use salvo::prelude::*;
use serde::Serialize;

use crate::metrics as app_metrics;
use crate::models::{DeliveryReceipt, Notification, NotifyResponse};

/// Cardinality guard threshold for `metrics_detailed_circle_labels`.
/// Once the count of unique circle_ids observed since startup crosses
/// this number, the guard logs a warning and auto-downgrades to the
/// non-detailed (`realm`-keyed) label scheme so Prometheus does not
/// explode under cardinality. Tuned to 5000 — well above any realistic
/// Circle population for a single tenant but small enough that a
/// runaway opt-in does not blow the metric vector.
pub(super) const DETAILED_CIRCLE_LABEL_THRESHOLD: usize = 5_000;

/// Observed-circle set + a sticky downgrade flag. Both live behind a
/// single Mutex / AtomicBool so the hot path (already inside the
/// delivery-receipt loop) pays the cost only when detailed labels are
/// enabled AND a circle_id is present.
static DETAILED_CIRCLE_SEEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);
static DETAILED_CIRCLE_DOWNGRADED: AtomicBool = AtomicBool::new(false);

/// True iff the cardinality guard has fired. `pub(crate)` so tests
/// and any future `/admin` introspection inside the crate can confirm
/// the downgrade.
#[allow(dead_code)]
pub(crate) fn detailed_circle_labels_downgraded() -> bool {
    DETAILED_CIRCLE_DOWNGRADED.load(Ordering::Relaxed)
}

/// Test-only hook to reset the guard between cases. `pub(crate)` so it
/// is reachable from `#[cfg(test)]` integration helpers but does not
/// leak into the public API.
#[cfg(test)]
pub(crate) fn reset_cardinality_guard_for_tests() {
    DETAILED_CIRCLE_DOWNGRADED.store(false, Ordering::Relaxed);
    let mut guard = DETAILED_CIRCLE_SEEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = None;
}

/// Returns whether detailed labels should be used right now. Records
/// the supplied `circle_id` against the global guard set; when the
/// unique-count threshold is crossed, flips the sticky downgrade flag
/// AND emits a one-shot warning so operators see it in the audit
/// stream. Subsequent calls observe the flag and return `false`.
fn record_circle_and_check_guard(circle_id: &str) -> bool {
    if DETAILED_CIRCLE_DOWNGRADED.load(Ordering::Relaxed) {
        return false;
    }
    let mut guard = DETAILED_CIRCLE_SEEN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let set = guard.get_or_insert_with(HashSet::new);
    if set.len() >= DETAILED_CIRCLE_LABEL_THRESHOLD && !set.contains(circle_id) {
        // Trip the breaker once — log, set the sticky flag, and clear
        // the set so we do not retain unbounded memory after downgrade.
        DETAILED_CIRCLE_DOWNGRADED.store(true, Ordering::Relaxed);
        let observed = set.len();
        set.clear();
        tracing::warn!(
            observed_circle_ids = observed,
            threshold = DETAILED_CIRCLE_LABEL_THRESHOLD,
            "metrics_detailed_circle_labels=true cardinality guard tripped; auto-downgrading to realm-keyed labels for the rest of this process lifetime"
        );
        return false;
    }
    set.insert(circle_id.to_owned());
    true
}

#[derive(Debug, Serialize)]
pub(super) struct ErrorEnvelope<'a> {
    pub(super) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) request_id: Option<&'a str>,
    pub(super) error: ErrorBody<'a>,
}

#[derive(Debug, Serialize)]
pub(super) struct ErrorBody<'a> {
    pub(super) code: &'a str,
    pub(super) message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) retry_after_ms: Option<u64>,
}

pub(super) fn record_notify_delivery_outcomes(response: &NotifyResponse) {
    record_delivery_receipt_outcomes(
        &response.delivery_receipts,
        response.accepted,
        response.rejected.len(),
    );
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

/// CXP-0007 — emit the per-(provider, scope) delivery counter. When
/// `detailed_circle_labels` is `true` and the notification carried a
/// `circle_id`, labels with `scope_kind=circle, scope_id=<cx:circle:…>`.
/// Otherwise labels with `scope_kind=realm, scope_id=<cx:realm:…>` to
/// keep the cardinality bounded.
pub(super) fn record_notify_delivery_by_scope(
    notification: &Notification,
    delivery_receipts: &[DeliveryReceipt],
    detailed_circle_labels: bool,
) {
    // P5 cardinality guard: detailed-circle labels are operator-opt-in,
    // but a runaway tenant could still observe more circles than the
    // metric vector should hold. The guard records each new circle_id;
    // once unique count exceeds DETAILED_CIRCLE_LABEL_THRESHOLD we
    // auto-downgrade to the realm-keyed scheme for the rest of the
    // process lifetime.
    let effective_detailed = match (detailed_circle_labels, notification.circle_id()) {
        (true, Some(circle)) => record_circle_and_check_guard(circle),
        _ => detailed_circle_labels,
    };
    let (scope_kind, scope_id): (&'static str, Option<&str>) =
        match (effective_detailed, notification.circle_id()) {
            (true, Some(circle)) => ("circle", Some(circle)),
            _ => ("realm", notification.realm_id()),
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
    let body = ErrorEnvelope {
        ok: false,
        request_id,
        error: ErrorBody {
            code,
            message: body,
            retry_after_ms: retry_after.map(|value| value.as_millis().min(u64::MAX as u128) as u64),
        },
    };
    res.status_code(status);
    res.render(Json(body));
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
    use super::*;
    use std::sync::Mutex as StdMutex;

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
                record_circle_and_check_guard(&format!("cx:circle:{i}")),
                "well under threshold must keep returning true"
            );
        }
        assert!(!detailed_circle_labels_downgraded());
    }

    #[test]
    fn guard_trips_at_threshold_and_stays_downgraded() {
        let _g = lock();
        reset_cardinality_guard_for_tests();
        // Fill the set up to the threshold.
        for i in 0..DETAILED_CIRCLE_LABEL_THRESHOLD {
            assert!(record_circle_and_check_guard(&format!("cx:circle:{i}")));
        }
        assert!(!detailed_circle_labels_downgraded());
        // The (threshold+1)th NEW id trips the guard.
        assert!(!record_circle_and_check_guard("cx:circle:trip"));
        assert!(detailed_circle_labels_downgraded());
        // Subsequent calls keep returning false without re-touching the set.
        assert!(!record_circle_and_check_guard("cx:circle:after"));
    }
}
