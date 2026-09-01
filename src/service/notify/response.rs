use std::time::{Duration, Instant};

use arkret_models_integration::{PushNotificationEnvelope, PushNotifyDeviceOutcome};
use salvo::http::StatusCode;
use salvo::prelude::Response;

use super::super::metrics::{record_delivery_receipt_outcomes, record_notify_delivery_by_scope};
use super::helpers::{
    cache_success_response, finish_standard_notify_json, record_rejected_devices_audit_or_finish,
};
use super::push_target_id;
use crate::auth::AuthenticatedNotifyCaller;
use crate::models::{DeliveryReceipt, NotifyDispatchResult, RejectedDevice};
use crate::{AppState, metrics as app_metrics};

pub(super) struct DispatchSummary {
    pub(super) rejected: Vec<RejectedDevice>,
    pub(super) outcomes: Vec<PushNotifyDeviceOutcome>,
    pub(super) delivered_now: usize,
    pub(super) skipped_delivered: usize,
    pub(super) delivery_receipts: Vec<DeliveryReceipt>,
    pub(super) first_remote_error: Option<String>,
    pub(super) first_temporary_error: Option<(String, Option<Duration>)>,
    pub(super) first_internal_error: Option<String>,
}

impl DispatchSummary {
    fn cached_delivery_status(&self) -> StatusCode {
        if self.first_internal_error.is_some() {
            StatusCode::INTERNAL_SERVER_ERROR
        } else if self.first_temporary_error.is_some() {
            StatusCode::SERVICE_UNAVAILABLE
        } else if self.first_remote_error.is_some() {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::OK
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn finish_dispatch(
    state: &std::sync::Arc<AppState>,
    caller: &AuthenticatedNotifyCaller,
    request_id: &str,
    notification: &PushNotificationEnvelope,
    dedup_key: &str,
    request_fingerprint: &str,
    summary: DispatchSummary,
    res: &mut Response,
    started: Instant,
) {
    let cached_delivery_status = summary.cached_delivery_status();
    let DispatchSummary {
        rejected,
        outcomes,
        delivered_now,
        skipped_delivered,
        delivery_receipts,
        first_remote_error,
        first_temporary_error,
        first_internal_error,
    } = summary;
    let fully_settled = first_internal_error.is_none()
        && first_temporary_error.is_none()
        && first_remote_error.is_none();
    let had_errors = !fully_settled;

    if delivered_now > 0 {
        if had_errors {
            app_metrics::notify_partial_success(StatusCode::OK);
        }
        if skipped_delivered > 0 {
            app_metrics::notify_retry_with_skips(StatusCode::OK);
        }
        if let Some(message) = first_internal_error.as_deref() {
            tracing::warn!(
                request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                error = %message,
                "returning success despite partial internal dispatch failures"
            );
        } else if let Some((message, retry_after)) = first_temporary_error.as_ref() {
            tracing::warn!(
                request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                retry_after_secs = retry_after.map(|value| value.as_secs()),
                error = %message,
                "returning success despite partial temporary dispatch failures"
            );
        } else if let Some(message) = first_remote_error.as_deref() {
            tracing::warn!(
                request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                error = %message,
                "returning success despite partial remote dispatch failures"
            );
        } else if skipped_delivered > 0 {
            tracing::info!(
                request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                "returning success with cached delivered devices"
            );
        }
    } else if skipped_delivered > 0 {
        app_metrics::notify_retry_with_skips(cached_delivery_status);
        tracing::info!(
            request_id,
            skipped_delivered,
            rejected = rejected.len(),
            "all currently delivered devices came from dedup cache"
        );
    }

    let response = NotifyDispatchResult::new(
        request_id.to_owned(),
        push_target_id(notification),
        outcomes,
    );
    if !record_rejected_devices_audit_or_finish(
        state,
        request_id,
        caller,
        notification,
        &rejected,
        res,
        started,
    )
    .await
    {
        return;
    }
    cache_success_response(state, dedup_key, request_fingerprint, &response).await;
    record_delivery_receipt_outcomes(&delivery_receipts, response.accepted(), rejected.len());
    record_notify_delivery_by_scope(
        notification,
        &delivery_receipts,
        state.metrics_detailed_circle_labels,
    );
    finish_standard_notify_json(res, StatusCode::OK, &response, started);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> DispatchSummary {
        DispatchSummary {
            rejected: Vec::new(),
            outcomes: Vec::new(),
            delivered_now: 0,
            skipped_delivered: 1,
            delivery_receipts: Vec::new(),
            first_remote_error: None,
            first_temporary_error: None,
            first_internal_error: None,
        }
    }

    #[test]
    fn cached_delivery_status_preserves_failure_priority() {
        let mut summary = summary();
        assert_eq!(summary.cached_delivery_status(), StatusCode::OK);

        summary.first_remote_error = Some("remote".to_owned());
        assert_eq!(summary.cached_delivery_status(), StatusCode::BAD_GATEWAY);

        summary.first_temporary_error = Some(("temporary".to_owned(), None));
        assert_eq!(
            summary.cached_delivery_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        summary.first_internal_error = Some("internal".to_owned());
        assert_eq!(
            summary.cached_delivery_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
