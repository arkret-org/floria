# Troubleshooting

Common operational failure modes for floria, with diagnostic commands
and a recovery path. Pair this with `docs/en/grafana-dashboard.json`
and the alert rules in `docs/en/prometheus-alerts.yml`.

## Redis disconnect

**Symptom**: `/ready` returns 503; logs show
`failed to connect to Redis backend …`; Prometheus
`floria_redis_disconnect_total` climbs; `/notify` returns 503 when
`notify_dedup.backend=redis` (permissive policy) or 429 (strict).

**Triage**:

1. From a floria pod, `redis-cli -u $REDIS_URL ping` — confirms the
   network path and AUTH.
2. Inspect Redis memory pressure: `INFO memory`. The dedup cache uses
   short TTLs, but a long-tail retry-queue Lua eviction can be
   triggered by `maxmemory-policy=allkeys-lru`. Set the policy to
   `volatile-lru` so only TTL'd keys are evicted.
3. Check the failure policy in config: `notify_dedup.redis_failure_policy`
   and `notify_rate_limits.redis_failure_policy`. `permissive` favors
   availability (request flows through with reduced guarantees);
   `strict` favors correctness (429 until Redis recovers).

**Recovery**:

- Restart Redis primary; floria reconnects on the next request.
- If running with Sentinel, force failover with `redis-cli SENTINEL FAILOVER mymaster`.
- After recovery, watch `floria_notify_dedup_lookup_total{outcome="miss"}` —
  a brief spike of misses is expected as the cache warms up; sustained
  miss-rate above 50% suggests Redis still has connectivity issues.

## Retry queue backlog

**Symptom**: `floria_retry_queue_depth` keeps climbing; alert
`FloriaRetryQueueBackedUp` fires; dead-letter ring fills (visible
through `/admin/retry/dead-letter` or PG overlay).

**Triage**:

1. Identify the offending provider — check
   `floria_notify_retry_enqueued_total{pushkin}` and the new
   `floria_notify_retry_queue_depth{provider}` labels (only emitted
   when `metrics_detailed_circle_labels=true`, otherwise reconstruct
   from counter deltas).
2. Look at `floria_pushkin_dispatch_seconds{outcome="error"}` — slow
   provider responses are usually a provider-side outage or a stale
   credential.
3. Inspect dead-letter entries: each carries `last_error` so a
   misconfigured provider key surfaces quickly.

**Recovery**:

- If a single provider is at fault, you can drain the queue by
  tightening `notify_rate_limits.per_provider` so new traffic backs
  off, then let the retry worker catch up.
- If the queue is stuck behind a permanently-broken provider, use the
  dead-letter snapshot to extract envelopes for manual replay; the
  retry worker eventually dead-letters them after `max_attempts`.
- Increase `batch_size` on the retry worker (it polls every
  `poll_interval_ms`) if the backlog is caused by burstiness rather
  than provider failure.

## Circuit breaker open

**Symptom**: `floria_circuit_breaker_state{pushkin}=2` (open);
delivery receipts show `status="retryable"` with
`code="circuit_open"`; `/notify` returns 200 with all receipts in
retryable state.

**Triage**:

1. The breaker opens after consecutive failures. Look at the recent
   `floria_pushkin_dispatch_seconds{outcome}` history — typical
   triggers are token revocation, an expired certificate, or a
   provider regional outage.
2. Probe the provider directly from a floria pod using the bundled
   `examples/minimal.notify.request.json`; a successful direct push
   indicates the breaker was tripped by an earlier transient blip and
   will close on its own.

**Recovery**:

- The breaker auto-closes after a successful half-open probe
  (configurable via `circuit_breaker.recovery_timeout_seconds`).
- For a hard credential failure, rotate per
  `docs/en/credential-rotation.md` then SIGHUP / rolling-restart;
  rotated credentials reset the breaker state.

## Cardinality guard auto-downgrade

**Symptom**: log line
`metrics_detailed_circle_labels=true cardinality guard tripped`; the
detailed per-Circle metrics stop updating.

**Triage / Recovery**:

This is by design — floria automatically downgrades to realm-keyed
labels once the unique-circle count crosses 5,000 so Prometheus
storage does not explode. Either accept the downgrade (the
realm-keyed series still answers the SLI dashboards) or shard your
deployment so each floria instance only serves a subset of Circles.

A process restart resets the guard.
