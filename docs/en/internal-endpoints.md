# Internal Endpoints

floria exposes a small set of routes under `/api/v1/internal/*` that
are intended for in-cluster service-to-service traffic only. They are
NOT the public `/api/v1/push/notify` surface and they have a
different auth and rate-limit posture.

## Routes

| Route | Method | Purpose |
|-------|--------|---------|
| `/api/v1/internal/account_deactivate_fanout` | POST | soland-broadcast hook: drains the per-actor deactivation queue and emits provider unregister calls |
| `/api/v1/internal/consent_revoke` | POST | Drops every cached PSI verdict for the affected principal so the next push goes through a fresh consent check |

Both handlers live in `src/service/internal.rs` and are wired into
the router in `src/service/mod.rs`. They share the same `AppState`
as `/notify` but never touch the public dedup cache or rate limiter.

## Auth posture

floria deliberately does NOT enforce its own bearer / HTTP Message
Signature check on `/api/v1/internal/*`. The expectation is:

1. **Network isolation** — bind the gateway to an internal-only
   listener (e.g. a separate `bind_addresses` entry on a private
   interface), or front it with a service mesh that terminates mTLS.
2. **mTLS at the mesh layer** — if your deployment uses Linkerd /
   Istio / Consul Connect, the mesh's mTLS already covers
   intra-cluster auth; floria treats the request as trusted.
3. **No public exposure** — `/api/v1/internal/*` MUST NOT be exposed
   through the public ingress. Reject these paths at the edge proxy
   (see `examples/reverse-proxy/` for nginx / Caddy snippets).

The handlers themselves validate only request shape. Wire-level
schema violations return `400 schema_violation`; missing application
state returns `500 internal_error`; unknown / drained broadcast
channels return `503 service_unavailable`.

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
| `floria_takedown_notification_failures_total{stage}` | future (TODO(P5-impl)) |

Trace spans are emitted with `service.name=floria`,
`http.target=/api/v1/internal/<route>`, and the broadcast event id
attached as a span attribute when present.
