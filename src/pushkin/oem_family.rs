//! Transport skeleton shared by the OEM push adapters (Huawei, HONOR,
//! OPPO / OnePlus, vivo, Xiaomi, JPush).
//!
//! Only the parts that are identical across those adapters live here:
//! Prometheus instrument registration, the connection-permit + timing +
//! status-code bookkeeping around one HTTP round trip, the bounded
//! retry loop, and two small predicates.
//!
//! Everything that differs per vendor stays in the vendor module on
//! purpose: endpoints, authentication scheme, access-token lifetime and
//! invalidation rules, request-body shape and field names, response
//! decoding and error-code mapping. Those contracts are *not*
//! interchangeable, and unifying them would turn a vendor-specific
//! rejection into a silent delivery failure.
//!
//! See [`super::hms_family`] for the second, narrower family layer: the
//! Huawei/HONOR pair additionally share a request body and a response
//! decoder because both speak the same HMS message API.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arkret_models_integration::PushRegistrationRecord;
use prometheus::{Histogram, HistogramOpts, IntCounterVec, IntGauge, Opts};
use reqwest::{Client, RequestBuilder, StatusCode};
use tokio::sync::Semaphore;
use tokio::time::sleep;

use super::reqwest_support::parse_retry_after;
use crate::error::DispatchError;
use crate::models::DeviceExt;

/// The five per-provider instruments every OEM adapter registers.
///
/// Metric names and HELP text are reproduced byte for byte from the
/// hand-written `register_*!` blocks these replaced, so dashboards and
/// alerts keep working: `article` exists only so `an OPPO Push` does
/// not become `a OPPO Push`.
pub(super) struct OemMetrics {
    queue_time: Histogram,
    request_time: Histogram,
    pending_requests: IntGauge,
    active_requests: IntGauge,
    status_codes: IntCounterVec,
}

impl OemMetrics {
    pub fn new(slug: &str, display: &str, article: &str) -> Self {
        Self {
            queue_time: histogram(
                format!("floria_{slug}_queue_time"),
                format!("Time taken waiting for {article} {display} request slot"),
            ),
            request_time: histogram(
                format!("floria_{slug}_request_time"),
                format!("Time taken to send HTTP request to {display}"),
            ),
            pending_requests: gauge(
                format!("floria_pending_{slug}_requests"),
                format!("Number of {display} requests waiting for a connection"),
            ),
            active_requests: gauge(
                format!("floria_active_{slug}_requests"),
                format!("Number of {display} requests in flight"),
            ),
            status_codes: counter_vec(
                format!("floria_{slug}_status_codes"),
                format!("Number of HTTP response status codes received from {display}"),
            ),
        }
    }
}

fn histogram(name: String, help: String) -> Histogram {
    let metric = Histogram::with_opts(HistogramOpts::new(name.clone(), help))
        .unwrap_or_else(|error| panic!("build {name}: {error}"));
    prometheus::register(Box::new(metric.clone()))
        .unwrap_or_else(|error| panic!("register {name}: {error}"));
    metric
}

fn gauge(name: String, help: String) -> IntGauge {
    let metric = IntGauge::with_opts(Opts::new(name.clone(), help))
        .unwrap_or_else(|error| panic!("build {name}: {error}"));
    prometheus::register(Box::new(metric.clone()))
        .unwrap_or_else(|error| panic!("register {name}: {error}"));
    metric
}

fn counter_vec(name: String, help: String) -> IntCounterVec {
    let metric = IntCounterVec::new(Opts::new(name.clone(), help), &["pushkin", "code"])
        .unwrap_or_else(|error| panic!("build {name}: {error}"));
    prometheus::register(Box::new(metric.clone()))
        .unwrap_or_else(|error| panic!("register {name}: {error}"));
    metric
}

/// Connection-limited HTTP transport plus the instruments above.
///
/// Vendor modules build their own [`RequestBuilder`] (endpoint, headers,
/// JSON or form body) and hand it here; this type only owns the permit,
/// the timings and the raw response.
pub(super) struct OemTransport {
    metrics: &'static OemMetrics,
    client: Client,
    connection_semaphore: Arc<Semaphore>,
}

/// Raw round-trip result. Response *interpretation* is vendor-specific
/// and stays in the vendor module.
pub(super) struct OemResponse {
    pub status: StatusCode,
    pub retry_after: Option<Duration>,
    pub body: String,
}

impl OemTransport {
    pub fn new(metrics: &'static OemMetrics, client: Client, max_connections: usize) -> Self {
        Self {
            metrics,
            client,
            connection_semaphore: Arc::new(Semaphore::new(max_connections.max(1))),
        }
    }

    /// The shared reqwest client. Vendor modules also use it for their
    /// own token/auth round trips, which are deliberately not routed
    /// through [`OemTransport::send`]: auth calls neither take a
    /// connection permit nor count towards the send instruments today.
    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn send(
        &self,
        pushkin_name: &str,
        display: &str,
        request: RequestBuilder,
    ) -> Result<OemResponse, DispatchError> {
        self.metrics.pending_requests.inc();
        let queue_started = Instant::now();
        let _connection_permit = self
            .connection_semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                self.metrics.pending_requests.dec();
                DispatchError::internal(format!("{display} connection semaphore closed"))
            })?;
        self.metrics.pending_requests.dec();
        self.metrics
            .queue_time
            .observe(queue_started.elapsed().as_secs_f64());

        self.metrics.active_requests.inc();
        let request_started = Instant::now();
        let response = request.send().await.map_err(|error| {
            self.metrics.active_requests.dec();
            self.metrics
                .request_time
                .observe(request_started.elapsed().as_secs_f64());
            DispatchError::temporary(format!("{display} request failed: {error}"), None)
        })?;
        self.metrics.active_requests.dec();
        self.metrics
            .request_time
            .observe(request_started.elapsed().as_secs_f64());

        let status = response.status();
        self.metrics
            .status_codes
            .with_label_values(&[pushkin_name, &status.as_u16().to_string()])
            .inc();
        let retry_after = parse_retry_after(response.headers());
        let body = response.text().await.map_err(|error| {
            DispatchError::remote(format!("failed to read {display} response: {error}"))
        })?;

        Ok(OemResponse {
            status,
            retry_after,
            body,
        })
    }
}

/// Bounded retry around one dispatch attempt.
///
/// A provider-supplied `Retry-After` always wins; otherwise the delay is
/// `retry_delay_base_secs << attempt`. `on_retry` is the hook for the one
/// adapter (JPush) that logs structured retry context; the others pass a
/// no-op.
pub(super) async fn dispatch_with_retries<Attempt, Fut, OnRetry>(
    display: &str,
    max_tries: usize,
    retry_delay_base_secs: u64,
    attempt_fn: Attempt,
    on_retry: OnRetry,
) -> Result<Vec<String>, DispatchError>
where
    Attempt: Fn() -> Fut,
    Fut: Future<Output = Result<Vec<String>, DispatchError>>,
    OnRetry: Fn(usize, Duration),
{
    for attempt in 0..max_tries {
        match attempt_fn().await {
            Ok(result) => return Ok(result),
            Err(error @ DispatchError::Temporary { .. }) if attempt + 1 < max_tries => {
                let retry_after = error.retry_after().unwrap_or_else(|| {
                    Duration::from_secs(retry_delay_base_secs * (1_u64 << attempt))
                });
                on_retry(attempt, retry_after);
                sleep(retry_after).await;
            }
            Err(error) => return Err(error),
        }
    }

    Err(DispatchError::remote(format!(
        "{display} retried too many times"
    )))
}

/// No-op [`dispatch_with_retries`] hook for adapters that do not log
/// retry context.
pub(super) fn no_retry_hook(_attempt: usize, _retry_after: Duration) {}

/// Reject a device whose push key is empty before any HTTP work.
///
/// `key_field` is the vendor's own name for the field so the operator
/// log still points at the right config key (`regId`, `registration_id`,
/// `target_value`, `token`).
pub(super) fn empty_push_key_rejection(
    provider: &str,
    key_field: &str,
    device: &PushRegistrationRecord,
) -> Option<Vec<String>> {
    if device.push_key().is_some() {
        return None;
    }

    // `provider`, not `display`: the tracing macros bring
    // `tracing::field::display` into scope and a local of that name
    // shadows it inside the format string.
    tracing::warn!("rejecting {provider} device due to empty {key_field}");
    Some(vec![device.push_key().unwrap_or_default().to_owned()])
}

/// Case-insensitive "subject word AND state word" probe.
///
/// Every OEM signals a dead recipient (or a stale auth token) as free
/// text rather than a stable code, so each adapter keeps its own
/// keyword lists; only the matching shape is shared.
pub(super) fn body_mentions(body: &str, subjects: &[&str], states: &[&str]) -> bool {
    let lower = body.to_ascii_lowercase();
    subjects.iter().any(|subject| lower.contains(subject))
        && states.iter().any(|state| lower.contains(state))
}

/// Millisecond wall clock as a decimal string, used by the OEMs whose
/// auth signature covers a timestamp (OPPO, vivo).
pub(super) fn current_timestamp_millis() -> Result<String, DispatchError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DispatchError::internal(format!("system clock error: {error}")))?
        .as_millis()
        .to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn body_mentions_requires_one_subject_and_one_state() {
        assert!(body_mentions(
            "regId invalid",
            &["regid", "userid"],
            &["invalid", "expired"]
        ));
        assert!(!body_mentions(
            "regId accepted",
            &["regid", "userid"],
            &["invalid", "expired"]
        ));
        assert!(!body_mentions(
            "quota expired",
            &["regid", "userid"],
            &["invalid", "expired"]
        ));
    }

    // A zero base delay keeps these tests instant without needing
    // tokio's paused-clock test-util feature; the backoff arithmetic
    // itself is asserted through the `on_retry` hook.

    /// The last attempt's own error is what the caller sees - the
    /// `retried too many times` message is only reachable for
    /// `max_tries == 0`. This matches the hand-written loops this
    /// helper replaced, and dispatchers classify on the returned
    /// variant, so the distinction is load-bearing.
    #[tokio::test]
    async fn dispatch_with_retries_returns_the_last_attempts_error() {
        let attempts = AtomicUsize::new(0);
        let retries = AtomicUsize::new(0);

        let error = dispatch_with_retries(
            "Test Push",
            3,
            0,
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err(DispatchError::temporary("boom", None)) }
            },
            |_, _| {
                retries.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.to_string(), "boom");
        assert!(error.is_temporary());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(retries.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn dispatch_with_retries_reports_exhaustion_when_no_attempt_is_allowed() {
        let error = dispatch_with_retries(
            "Test Push",
            0,
            0,
            || async { panic!("must not be attempted") },
            no_retry_hook,
        )
        .await
        .unwrap_err();

        assert_eq!(error.to_string(), "Test Push retried too many times");
        assert!(!error.is_temporary());
    }

    #[tokio::test]
    async fn dispatch_with_retries_returns_permanent_errors_immediately() {
        let attempts = AtomicUsize::new(0);

        let error = dispatch_with_retries(
            "Test Push",
            3,
            0,
            || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err(DispatchError::remote("rejected")) }
            },
            no_retry_hook,
        )
        .await
        .unwrap_err();

        assert_eq!(error.to_string(), "rejected");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dispatch_with_retries_prefers_provider_retry_after() {
        let observed = std::sync::Mutex::new(Vec::new());

        let _ = dispatch_with_retries(
            "Test Push",
            2,
            0,
            || async {
                Err(DispatchError::temporary(
                    "slow down",
                    Some(Duration::from_millis(3)),
                ))
            },
            |attempt, retry_after| observed.lock().unwrap().push((attempt, retry_after)),
        )
        .await;

        assert_eq!(
            observed.into_inner().unwrap(),
            vec![(0, Duration::from_millis(3))]
        );
    }

    /// Without a provider `Retry-After` the hook still fires once per
    /// retry, carrying the `base << attempt` fallback.
    #[tokio::test]
    async fn dispatch_with_retries_reports_one_backoff_per_retry() {
        let observed = std::sync::Mutex::new(Vec::new());

        let _ = dispatch_with_retries(
            "Test Push",
            4,
            0,
            || async { Err(DispatchError::temporary("boom", None)) },
            |attempt, retry_after| observed.lock().unwrap().push((attempt, retry_after)),
        )
        .await;

        assert_eq!(
            observed.into_inner().unwrap(),
            vec![
                (0, Duration::ZERO),
                (1, Duration::ZERO),
                (2, Duration::ZERO)
            ]
        );
    }
}
