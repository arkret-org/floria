# floria — Release-Readiness Tasks

> Parent plan: [`../_todos_all.md`](../_todos_all.md)
> Project role: push gateway implementation (Soflare).
> Phase: **2 (track 2c)**.

## State at start (2026-05-24)

- ~22.6 k LoC; Salvo + reqwest; 11 provider adapters (FCM v1, APNS HTTP/2, WebPush VAPID, Huawei, OPPO, Vivo, Xiaomi, Honor, JPush, Custom, Android base).
- HTTP Message Signature auth (RFC 9421) on ingress + bearer fallback.
- Rate limiting: per-app, per-token, per-IP windowed token bucket; backend in-memory or Redis.
- Dedup: idempotency-key + body hash; in-memory or Redis.
- Metrics: comprehensive Prometheus surface (per-provider, per-app, per-scope).
- Tracing: OpenTelemetry + Sentry + structured JSON logs.
- 16 TODOs identified.
- CI: fmt, clippy, test, docker. **No** SCA / audit / typos / image scan.

## Phase 2 tasks (critical-path)

### Audit pipeline closure (highest priority — currently swallows events)
- [x] §1 `src/service/notify.rs:73` — wire `e2ee_late_recovery` audit divert to a real audit pipeline (currently returns 200 without forwarding).
- [x] §2 `src/service/notify.rs:1091` — same audit-pipeline routing for the other path.
- [x] §3 `src/models.rs:50` — wire audit-pipeline forwarding for `RejectedDevice`.
- [x] §4 Define an `AuditSink` trait + an in-process variant (file-based JSONL) + an HTTP variant (POST to soland audit endpoint).

### Deactivation queue drain (broadcast received but not processed)
- [ ] §5 `src/deactivation.rs:24,208,244` — replace stub queue-drain logic with a real implementation reading from `cx.push.delivery_queue` or analogous postgres table.
- [ ] §6 `src/service/internal.rs:10,119` — replace HTTP-only broadcast assumption with a real in-process broadcast bus once soland signature is pinned (R2/R3 closure).

### Push contact cache (in-memory only — won't survive restart)
- [ ] §7 `src/push_contact_cache.rs:23` — implement a postgres-backed overlay so consent revoke cache survives restart.

### SDK-sync drift markers
- [ ] §8 `src/pushkin/android.rs:318`, `src/pushkin/fcm.rs:761`, `src/pushkin/mod.rs:554,582`, `src/pushkin/webpush.rs:698`, `src/service/notify.rs:431,547` — once SDK §1-§3 (this and `_contrix-rust-sdk_todos.md`) finish exporting `is_forbidden_payload_key` for round-4, replace floria's local sweep with SDK calls.

### Configuration & secrets
- [x] §9 Document the env-var substitution semantics in `docs/en/configuration.md` (KDL `${ENV_VAR}` patterns).
- [x] §10 Add a vault adapter (HashiCorp Vault or AWS Secrets Manager) as an optional feature for `apns.cert_path` / `fcm.bearer_token`. Or document operator workflow.
- [x] §11 Add a SIGHUP handler for hot config reload (or document restart-required in `README.md`).

### Engineering hygiene (master plan §5)
- [x] §12 Add `cargo audit` weekly + on PR (currently absent).
- [x] §13 Add `cargo deny check` to CI.
- [x] §14 Add `typos` workflow.
- [x] §15 Add Trivy scan on docker image; fail build on HIGH+ CVEs.
- [x] §16 Generate SBOM as a local artifact.
- [x] §17 Add local cosign/SLSA provenance command documentation; do not push images or tags.

### Observability polish
- [ ] §18 Add `/readyz` (provider registry + Redis reachable) — currently `/ready` checks registry only.
- [ ] §19 Add metrics for the audit-divert paths added in §1-§3.
- [ ] §20 Document the recommended Grafana dashboard JSON under `docs/en/grafana-dashboard.json`.

### Tests
- [ ] §21 Add a soak/chaos test: 10k notifications/min for 30 min, assert rate-limit cleanup doesn't OOM.
- [ ] §22 Add a load test verifying Redis dedup TTL math.
- [ ] §23 Add an integration test that simulates a deactivation broadcast and asserts §5 actually drains.

### Docs
- [ ] §24 Add a server-side integration guide (`docs/en/server-integration.md`) for soland calling `/api/v1/push/notify`.
- [ ] §25 Add a mobile-dev integration guide (`docs/en/mobile-integration.md`) referencing chime.
- [ ] §26 Publish an OpenAPI spec for `/notify`, `/bridge/describe`, `/integration/describe`.

## Phase 5

- [ ] §27 External security review focusing on auth + replay-protection + multi-tenant isolation.
- [ ] §28 Record local `v1.0.0` milestone.

## Exit gate (phase 2)

All of:
1. §1-§7 closed (audit + deactivation + cache no longer stubbed).
2. CI passes audit + deny + typos.
3. Trivy + cosign + SBOM produce local artifacts.
4. Local internal milestone `v0.9.0` recorded in docs/todos.

## Notes

- The 11 provider adapters share little code today; consider a `PushProvider` trait extraction once §1-§7 stabilize.
- `examples/soflare.domestic-android.production.sample.kdl` is the closest thing to a deployment template — surface it from `README.md` quick-start.
