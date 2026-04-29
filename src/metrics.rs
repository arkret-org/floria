use std::sync::LazyLock;
use std::time::Duration;

use prometheus::{
    Encoder, HistogramVec, IntCounter, IntCounterVec, IntGaugeVec, TextEncoder,
    register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge_vec,
};
use salvo::http::StatusCode;
use salvo::http::header::CONTENT_TYPE;
use salvo::prelude::*;

static NOTIFS_RECEIVED_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "soflare_notifications_received",
        "Number of notification pokes received"
    )
    .expect("register soflare_notifications_received")
});

static NOTIFY_REQUEST_CACHE_HITS_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "soflare_notify_request_cache_hits",
        "Number of /notify requests served from the in-memory request dedup cache"
    )
    .expect("register soflare_notify_request_cache_hits")
});

static NOTIFY_DEVICE_SKIP_HITS_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "soflare_notify_device_skip_hits",
        "Number of devices skipped because they were already delivered within the dedup ttl"
    )
    .expect("register soflare_notify_device_skip_hits")
});

static NOTIFY_DEVICE_SKIP_BY_PUSHKIN_COUNTER: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "soflare_notify_device_skip_by_pushkin",
        "Number of devices skipped because they were already delivered within the dedup ttl, grouped by pushkin",
        &["pushkin"]
    )
    .expect("register soflare_notify_device_skip_by_pushkin")
});

static NOTIFY_PARTIAL_SUCCESS_COUNTER: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "soflare_notify_partial_success_total",
        "Number of /notify requests that had at least one successful delivery and at least one non-success outcome",
        &["code"]
    )
    .expect("register soflare_notify_partial_success_total")
});

static NOTIFY_RETRY_WITH_SKIPS_COUNTER: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "soflare_notify_retry_with_skips_total",
        "Number of /notify requests that skipped at least one previously delivered device",
        &["code"]
    )
    .expect("register soflare_notify_retry_with_skips_total")
});

static NOTIFS_RECEIVED_DEVICE_PUSH_COUNTER: LazyLock<IntCounter> = LazyLock::new(|| {
    register_int_counter!(
        "soflare_notifications_devices_received",
        "Number of devices been asked to push"
    )
    .expect("register soflare_notifications_devices_received")
});

static NOTIFS_BY_PUSHKIN: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "soflare_per_pushkin_type",
        "Number of pushes sent via each type of pushkin",
        &["pushkin"]
    )
    .expect("register soflare_per_pushkin_type")
});

static PUSHGATEWAY_HTTP_RESPONSES_COUNTER: LazyLock<IntCounterVec> = LazyLock::new(|| {
    register_int_counter_vec!(
        "soflare_pushgateway_status_codes",
        "HTTP response codes given on the Push Gateway API",
        &["code"]
    )
    .expect("register soflare_pushgateway_status_codes")
});

static NOTIFY_HANDLE_HISTOGRAM: LazyLock<HistogramVec> = LazyLock::new(|| {
    register_histogram_vec!(
        "soflare_notify_time",
        "Time taken to handle /notify push gateway request",
        &["code"]
    )
    .expect("register soflare_notify_time")
});

static REQUESTS_IN_FLIGHT_GAUGE: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    register_int_gauge_vec!(
        "soflare_requests_in_flight",
        "Number of HTTP requests in flight",
        &["resource"]
    )
    .expect("register soflare_requests_in_flight")
});

pub fn init() {
    LazyLock::force(&NOTIFS_RECEIVED_COUNTER);
    LazyLock::force(&NOTIFY_REQUEST_CACHE_HITS_COUNTER);
    LazyLock::force(&NOTIFY_DEVICE_SKIP_HITS_COUNTER);
    LazyLock::force(&NOTIFY_DEVICE_SKIP_BY_PUSHKIN_COUNTER);
    LazyLock::force(&NOTIFY_PARTIAL_SUCCESS_COUNTER);
    LazyLock::force(&NOTIFY_RETRY_WITH_SKIPS_COUNTER);
    LazyLock::force(&NOTIFS_RECEIVED_DEVICE_PUSH_COUNTER);
    LazyLock::force(&NOTIFS_BY_PUSHKIN);
    LazyLock::force(&PUSHGATEWAY_HTTP_RESPONSES_COUNTER);
    LazyLock::force(&NOTIFY_HANDLE_HISTOGRAM);
    LazyLock::force(&REQUESTS_IN_FLIGHT_GAUGE);
}

pub fn notification_received() {
    NOTIFS_RECEIVED_COUNTER.inc();
}

pub fn notify_request_cache_hit() {
    NOTIFY_REQUEST_CACHE_HITS_COUNTER.inc();
}

pub fn notify_device_skip_hit(count: usize) {
    NOTIFY_DEVICE_SKIP_HITS_COUNTER.inc_by(count as u64);
}

pub fn notify_device_skip_by_pushkin(pushkin: &str, count: usize) {
    NOTIFY_DEVICE_SKIP_BY_PUSHKIN_COUNTER
        .with_label_values(&[pushkin])
        .inc_by(count as u64);
}

pub fn notify_partial_success(status: StatusCode) {
    let code = status.as_u16().to_string();
    NOTIFY_PARTIAL_SUCCESS_COUNTER
        .with_label_values(&[code.as_str()])
        .inc();
}

pub fn notify_retry_with_skips(status: StatusCode) {
    let code = status.as_u16().to_string();
    NOTIFY_RETRY_WITH_SKIPS_COUNTER
        .with_label_values(&[code.as_str()])
        .inc();
}

pub fn device_push_received() {
    NOTIFS_RECEIVED_DEVICE_PUSH_COUNTER.inc();
}

pub fn pushkin_selected(pushkin: &str) {
    NOTIFS_BY_PUSHKIN.with_label_values(&[pushkin]).inc();
}

pub fn pushgateway_response(status: StatusCode) {
    let code = status.as_u16().to_string();
    PUSHGATEWAY_HTTP_RESPONSES_COUNTER
        .with_label_values(&[code.as_str()])
        .inc();
}

pub fn observe_notify_handle(status: StatusCode, elapsed: Duration) {
    let code = status.as_u16().to_string();
    NOTIFY_HANDLE_HISTOGRAM
        .with_label_values(&[code.as_str()])
        .observe(elapsed.as_secs_f64());
}

pub fn track_inflight(resource: &'static str) -> InflightGuard {
    REQUESTS_IN_FLIGHT_GAUGE
        .with_label_values(&[resource])
        .inc();
    InflightGuard { resource }
}

pub fn build_router() -> Router {
    Router::with_path("metrics").get(scrape_metrics)
}

pub struct InflightGuard {
    resource: &'static str,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        REQUESTS_IN_FLIGHT_GAUGE
            .with_label_values(&[self.resource])
            .dec();
    }
}

#[handler]
async fn scrape_metrics(res: &mut Response) {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    match encoder.encode(&metric_families, &mut buffer) {
        Ok(()) => {
            res.status_code(StatusCode::OK);
            let _ = res.add_header(CONTENT_TYPE, encoder.format_type(), true);
            res.render(Text::Plain(String::from_utf8_lossy(&buffer).into_owned()));
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to encode prometheus metrics");
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Text::Plain("failed to encode metrics".to_owned()));
        }
    }
}

#[cfg(test)]
mod tests {
    use salvo::test::{ResponseExt, TestClient};

    use super::*;

    #[tokio::test]
    async fn metrics_endpoint_renders_prometheus_output() {
        init();
        notification_received();
        notify_request_cache_hit();
        notify_device_skip_hit(2);
        notify_device_skip_by_pushkin("com.example.app", 1);
        notify_partial_success(StatusCode::OK);
        notify_retry_with_skips(StatusCode::SERVICE_UNAVAILABLE);

        let service = Service::new(build_router());
        let mut response = TestClient::get("http://127.0.0.1/metrics")
            .send(&service)
            .await;

        assert_eq!(response.status_code.unwrap(), StatusCode::OK);
        let body = response.take_string().await.unwrap();
        assert!(body.contains("soflare_notifications_received"));
        assert!(body.contains("soflare_notify_request_cache_hits"));
        assert!(body.contains("soflare_notify_device_skip_hits"));
        assert!(body.contains("soflare_notify_device_skip_by_pushkin"));
        assert!(body.contains("soflare_notify_partial_success_total"));
        assert!(body.contains("soflare_notify_retry_with_skips_total"));
    }
}
