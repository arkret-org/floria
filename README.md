# floria

Push gateway service in Rust.

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo fmt --all -- --check` and `cargo clippy --no-deps -- -D
warnings` on staged Rust changes. If `.githooks/pre-commit` is missing on
a branch, copy it from
[`arkret-rust-sdk`](https://github.com/arkret-org/arkret-rust-sdk) and
adapt to your local toolchain.

## Realm vs Space

`floria` forwards `ak.device.push_route` and `ak.edge.push.command.notify.v1` events that
target a specific security boundary:

- **Realm:** security boundary membership, capability, E2EE, federation.
- **Space:** navigation container board, list, section, calendar bucket;
  lives inside a Realm.

The inbound push notify model uses `realm_id` for the security boundary and
hard-rejects `space_id`. Provider-facing blind wakeups strip Realm, Space,
Strand, Event, Message and actor identifiers before dispatch.

## Round R4 (protocol review closures)

Spec round 4 (`arkret-spec` range `2a4d39b..a77b995`, 8 commits) adds
three push-pipeline behaviours. See [`CHANGELOG.md`](CHANGELOG.md)
`[Unreleased]` for the canonical wire-breaking list.

- **`mention_redirect_target_route_tokens` plaintext routing**
  message / system-message payloads now carry an explicit
  redirect-target actor list. If the recipient device's actor is not in
  the list, floria runs fail-closed: a blind wakeup goes out, the
  content is not decrypted.
- **`historical_only` is push-quiet** when an upstream service
  attaches `reason_code=historical_only` to a federation idempotency
  replay, floria does not run a fresh push fanout. The event is
  diagnostic only.
- **`e2ee_late_recovery` audit path**
  `ak.audit.policy_access{access_kind=e2ee_late_recovery}` routes
  through the audit pipeline and never produces a push wakeup.

## Round R2/R3 notes

Spec rounds 2+3 (2026-05-20) extended the blind-wakeup sanitizer's
forbidden-field list (`appeal_id`, `attestation_evidence`,
`audit_purpose`, `attestation_chain`, `audit_policy_version_digest`,
`policy_frontier_digest`, `trust_domain`) and added the internal
`POST /_floria/internal/account_deactivate_fanout` (T07) broadcast
endpoint. That endpoint implements the push-gateway half of the
deactivation fanout required by
[`account-lifecycle.md` §7.1](../arkret-spec/spec/v1/zh/identity/account-lifecycle.md);
no Principal Server currently drives it. Contact/DM, Agent participation,
Sidecar, and operation-control admission stay upstream of the push gateway. See
[`CHANGELOG.md`](CHANGELOG.md) `[Unreleased]` and
[`push-notifications.md`](../arkret-spec/spec/v1/zh/discovery/push-notifications.md)
for the normative source. Signal kinds (`ak.presence`, `ak.typing`,
`ak.receipt.read`, `ak.call.signal`) are confirmed to bypass floria
entirely; they ride the encrypted `SignalEnvelope` rail in the Sync
Service (`spec/v1/zh/sync/signal.md`). The former plaintext realtime rail
and transaction-body field are gone, superseded by `SignalEnvelope` /
`signals`.

## Stack

- `salvo` for HTTP API
- `reqwest` for outbound APNS / FCM calls
- `kdl` for KDL config (default)
- `serde-saphyr` for YAML config (also supported)

PostgreSQL is optional and used only for deactivation queue draining.

## Supported features

- `POST /_arkret/edge/push/notify` as the canonical Arkret notify endpoint
- `GET /_arkret/describe` gateway profile discovery at the root meta position
- `GET /health`
- `GET /ready`
- `GET /readyz`
- Prometheus metrics on a dedicated `/metrics` listener
- app id exact match and glob match
- per-pushkin in-flight concurrency limit
- optional in-memory or Redis dedup cache for successful `/notify` requests
- optional in-memory `/notify` rate limits with `429` + `Retry-After`
- `/notify` service auth via HTTP Message Signature, bearer fallback, and optional mTLS profile
- APNS certificate auth and token auth
- FCM HTTP v1
- JPush REST v3 with `third_party_channel` passthrough
- Huawei Push Kit / HarmonyOS server push
- HONOR Push Kit server push
- OPPO / OPlus / OnePlus server push
- vivo Push server push
- Xiaomi Mi Push server push
- WebPush / VAPID
- `FLORIA_CONF` env var
- `HTTPS_PROXY` env var fallback for outbound proxying
- KDL config (default) and YAML config, detected by file extension
- structured logging via `log.setup` (text or JSON formatter, EnvFilter / `RUST_LOG`)
- distributed tracing via `metrics.opentracing` (OTLP / OpenTelemetry, gRPC)
- error reporting via `metrics.sentry` (DSN, environment, release, sample rates)

## Configuration

The config format is detected by file extension:
- `.kdl` [KDL](https://kdl.dev) (default when `FLORIA_CONF` is not set)
- `.yaml` / `.yml` YAML

See [docs/en/configuration.md](./docs/en/configuration.md) for the full configuration reference.
See [docs/en/server-integration.md](./docs/en/server-integration.md) for soland / server-side `/notify` integration.
See [docs/en/mobile-integration.md](./docs/en/mobile-integration.md) for chime / mobile-client integration boundaries.
See [docs/en/credential-rotation.md](./docs/en/credential-rotation.md) for the credential rotation runbook.
See [docs/en/reverse-proxy.md](./docs/en/reverse-proxy.md) for the TLS-termination / mTLS reverse-proxy reference (sample nginx and Caddy configs in `examples/reverse-proxy/`).
See [docs/en/supply-chain.md](./docs/en/supply-chain.md) for local Trivy, Syft SBOM, and Cosign/SLSA provenance commands.
See [docs/en/openapi.json](./docs/en/openapi.json) for the local OpenAPI artifact.

Quick notes:
- `proxy` in the config file takes precedence over `HTTPS_PROXY`
- config file strings are not environment-expanded; `${ENV_VAR}` remains literal unless an external deploy step renders it before startup
- floria does not hot reload config or secrets; use a process restart or rolling restart for every config change
- 1.0 deployments should use an external secret manager, sidecar, or init step to mount/render APNs, FCM, VAPID, custom push, and service-auth secrets before floria starts
- `metrics.prometheus` starts a separate listener, defaulting to `127.0.0.1:8000`
- import `docs/en/grafana-dashboard.json` for the recommended Prometheus dashboard
- `storage.postgres_url` enables durable deactivation queue drain state
- unknown config sections / fields emit startup warnings
- the `memory` dedup backend is single-instance only; use Redis-backed dedup for HA deployments
- `push_hint` is a body-free wakeup hint and must not contain plaintext message content
- the push gateway is a derived wakeup surface, not canonical truth for events or unread state

## Arkret notify semantics

- `/_arkret/edge/push/notify` accepts authenticated service calls and supports the `Idempotency-Key` header
- `ak.edge.push.command.notify.v1` accepts only the SDK `PushNotifyRequestBody`; operation identity and the source/destination service DIDs stay in the URL and signed transport headers, never in the body
- error responses use a JSON envelope with `capability_denied`, `unsupported_feature`, `schema_violation`, `payload_too_large`, `rate_limited`, or `temporarily_unavailable` for gateway contract failures
- E2EE wakeups are validated as blind/minimized payloads: message body, encrypted payload bytes, SDP, ICE, and TURN credentials are rejected
- unauthorized callers cannot attach `sender_actor_display_name`, `strand_name`, `space_name`, `sender`, `target_did`, or nested `did:` literals inside notification/default payload fields
- notify requests use the current `push_target_id`, `wakeup_kind`, and `push_key` field names; unknown notification fields are rejected by the wire model
- notify responses conserve `(push_target_id, device_id)` outcomes and expose neither raw push tokens nor token hashes
- provider delivery receipts and token hashes are gateway-private telemetry and never appear in the synchronous notify response
- bearer fallback is header-only; query string auth material is rejected
- WebPush endpoints must match the configured allowlist and must not include query strings
- lightweight readiness probes hit `GET /ready`; strict readiness probes can use `GET /readyz` to require a populated provider registry and reachable Redis-backed dependencies

Sample files:
- `floria.sample.kdl` KDL config with all providers commented out
- `floria.sample.yaml` YAML config with all providers commented out

## Recommended strategy

- For mainland Android delivery, prefer `JPush` as the broad aggregation layer.
- Keep direct `Huawei Push Kit`, `HONOR Push`, `Xiaomi Mi Push`, `OPPO / OnePlus Push`, and `vivo Push` enabled for apps that already hold first-party credentials or need tighter channel control.
- Use JPush `third_party_channel` to steer Huawei/Xiaomi/OPPO/vivo/HONOR/HMOS routing without adding another backend integration per OEM.
- JPush currently has no explicit `third_party_channel.oneplus` vendor key; OnePlus should use the dedicated `oneplus` provider.

## Run

```powershell
$env:FLORIA_CONF="$PWD\floria.sample.kdl"
cargo run
```

## Docker

Build the image:

```powershell
docker build -t floria .
```

Generate local supply-chain artifacts without publishing an image or Git tag:

```powershell
.\scripts\local-supply-chain.ps1 -Image floria:local-supply-chain -SkipCosign
```

Run it with a mounted config file:

```powershell
docker run --rm -p 5000:5000 -p 8000:8000 -v ${PWD}/floria.sample.kdl:/app/floria.kdl floria
```

## Docker Compose

An example `compose.yml` is provided in the `examples/` directory.

For the smallest config and one canonical notify request shape, see
[examples/README.md](./examples/README.md),
[examples/minimal.kdl](./examples/minimal.kdl), and
[examples/minimal.notify.request.json](./examples/minimal.notify.request.json).

```sh
cp floria.sample.kdl examples/floria.kdl
cd examples
docker compose up -d
```

See [examples/compose.yml](./examples/compose.yml) for full instructions.

## Production Deployment Checklist

Before exposing floria to the public internet, walk every item below.
The same list will be computed at runtime and surfaced on
`/health.hardening` so sodmin's `/hardening` dashboard can flag failing
checks across the whole fleet (see T8.3 for the cross-service shape).

- [ ] `http.notify_auth.production_mode true` (surfaced as `hardening.admin_auth_mode`)
- [ ] TLS terminated at the reverse proxy — floria has no in-process TLS listener
- [ ] CSP header configured at the reverse proxy
- [ ] CORS limited to the allowed origins for principal-server callers
- [ ] Secrets sourced from an external secret manager and mounted/rendered before startup (APNs auth key/cert, FCM service account, VAPID keys, custom push secrets, service-auth keys)
- [ ] Log redaction enabled (default outside dev mode)
- [ ] Admin auth in production mode (no dev bypass)
- [ ] Rate limit enabled
- [ ] Provider credential rotation scheduled for APNs / FCM / VAPID

## License

Licensed under Apache 2.0. See `LICENSE`.
