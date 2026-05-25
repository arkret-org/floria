use std::time::{Duration, Instant};

use salvo::http::StatusCode;
use salvo::http::header::{HeaderName, HeaderValue};
use salvo::prelude::*;
use serde::Serialize;

use crate::metrics as app_metrics;
use crate::models::{DeliveryReceipt, Notification, NotifyResponse};

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
    let (scope_kind, scope_id): (&'static str, Option<&str>) =
        match (detailed_circle_labels, notification.circle_id()) {
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
