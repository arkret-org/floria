# Internal Endpoints

floria exposes a small set of routes under `/_floria/internal/*` that
are intended for in-cluster service-to-service traffic only. They are
NOT the public `/_cokret/edge/push/notify` surface and they have a
different auth and rate-limit posture.

## Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/_floria/internal/account_deactivate_fanout` | POST | soland-broadcast hook: drains the per-actor deactivation queue and emits provider unregister calls |
| `/_floria/internal/consent_revoke` | POST | Drops every cached PSI verdict for the affected principal so the next push goes through a fresh consent check |

Both handlers live in `src/service/internal.rs` and are wired into
the router in `src/service/mod.rs`. They share the same `AppState`
as `/notify` but never touch the public dedup cache or rate limiter.

## Auth posture

floria enforces `http.internal_auth` bearer/shared-secret
authentication on `/_floria/internal/*` and the operator-only
`/_floria/admin/push/status/*` / `/_floria/admin/push/device/unregister` routes. If
no internal bearer token or token hash is configured, these routes fail
closed with `503 service_unavailable`; missing or invalid credentials
return `401 unauthenticated`.

Prefer `bearer_token_hashes` in production configs and rotate the
shared secret independently from `/_cokret/edge/push/notify` caller
credentials. Network isolation and service-mesh mTLS are still
recommended defense-in-depth controls, but the handlers no longer rely
on ingress topology for their only authorization boundary.

Wire-level schema violations return `400 schema_violation`; missing
application state returns `500 internal_error`; unknown / drained
broadcast channels return `503 service_unavailable`.

## Rate limit posture

The internal endpoints are NOT subject to `notify_rate_limits`. The
expectation is that the upstream broadcast bus (soland) backpressures
on its own queue depth, and floria's role is to drain whatever shows
up. If you need flow control, set it on the upstream bus rather than
on floria.

Internal endpoints DO honor the `notify_retry_queue` configuration:
if a provider call inside `account_deactivate_fanout` produces a
transient error, the failed unregister is enqueued on the same retry
queue and respects `max_attempts` / `default_backoff` like any other
dispatch failure.

## Observability

| Metric | Endpoint |
|--------|----------|
| `floria_audit_divert_total{event_type, outcome}` | both |
| `floria_audit_rejected_devices_total{reason}` | both |
| `floria_notify_dead_letter_total{pushkin, reason}` | both — when fanout retries exhaust |

Trace spans are emitted with `service.name=floria`,
`http.target=/_floria/internal/<route>`, and the broadcast event id
attached as a span attribute when present.
