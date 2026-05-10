# floria

Push gateway service in Rust.

## Stack

- `salvo` for HTTP API
- `reqwest` for outbound APNS / FCM calls
- `kdl` for KDL config (default)
- `serde-saphyr` for YAML config (also supported)

`diesel` / PostgreSQL are intentionally not included because the service does not use a database.

## Supported features

- `POST /api/v1/push/notify` as the canonical Contrix notify endpoint
- `GET /api/v1/push/describe` gateway profile discovery
- `GET /health`
- `GET /ready`
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
- `SOFLARE_CONF` env var
- `HTTPS_PROXY` env var fallback for outbound proxying
- KDL config (default) and YAML config, detected by file extension
- structured logging via `log.setup` (text or JSON formatter, EnvFilter / `RUST_LOG`)
- distributed tracing via `metrics.opentracing` (OTLP / OpenTelemetry, gRPC)
- error reporting via `metrics.sentry` (DSN, environment, release, sample rates)

## Configuration

The config format is detected by file extension:
- `.kdl` — [KDL](https://kdl.dev) (default when `SOFLARE_CONF` is not set)
- `.yaml` / `.yml` — YAML

See [docs/en/configuration.md](./docs/en/configuration.md) for the full configuration reference.
See [docs/en/credential-rotation.md](./docs/en/credential-rotation.md) for the credential rotation runbook.
See [docs/en/reverse-proxy.md](./docs/en/reverse-proxy.md) for the TLS-termination / mTLS reverse-proxy reference (sample nginx and Caddy configs in `examples/reverse-proxy/`).

Quick notes:
- `proxy` in the config file takes precedence over `HTTPS_PROXY`
- `metrics.prometheus` starts a separate listener, defaulting to `127.0.0.1:8000`
- unknown config sections / fields emit startup warnings
- the `memory` dedup backend is single-instance only; use Redis-backed dedup for HA deployments
- `push_hint` is a body-free wakeup hint and must not contain plaintext message content
- the push gateway is a derived wakeup surface, not canonical truth for events or unread state

## Contrix notify semantics

- `/api/v1/push/notify` accepts authenticated service calls and supports `Idempotency-Key` or body `idempotency_key`
- `cx.push.notify` accepts active `flow` / `message` / `event` refs, optional `space_*` projection refs, `origin_service_did`, destination gateway DID, priority/TTL/collapse hints, and target device references
- error responses use a JSON envelope with `capability_denied`, `unsupported_feature`, `schema_violation`, `payload_too_large`, `rate_limited`, or `temporarily_unavailable` for gateway contract failures
- E2EE wakeups are validated as blind/minimized payloads: message body, encrypted payload bytes, SDP, ICE, and TURN credentials are rejected
- unauthorized callers cannot attach `sender_display_name`, `flow_name`, `space_name`, `sender`, `target_did`, or nested `did:` literals inside notification/default payload fields
- legacy `room_*`, `card_*`, `subject*`, Matrix `m.room.*`, and `only_last_per_room` inputs are rejected
- rejected push tokens are returned as hashes, not raw platform tokens
- response delivery receipt refs contain provider/status/token hash metadata only, never plaintext payloads
- bearer fallback is header-only; query string auth material is rejected
- WebPush endpoints must match the configured allowlist and must not include query strings
- readiness probes hit `GET /ready`; Docker health checks use the same endpoint

Sample files:
- `soflare.sample.kdl` — KDL config with all providers commented out
- `soflare.sample.yaml` — YAML config with all providers commented out

## Recommended strategy

- For mainland Android delivery, prefer `JPush` as the broad aggregation layer.
- Keep direct `Huawei Push Kit`, `HONOR Push`, `Xiaomi Mi Push`, `OPPO / OnePlus Push`, and `vivo Push` enabled for apps that already hold first-party credentials or need tighter channel control.
- Use JPush `third_party_channel` to steer Huawei/Xiaomi/OPPO/vivo/HONOR/HMOS routing without adding another backend integration per OEM.
- JPush currently has no explicit `third_party_channel.oneplus` vendor key; OnePlus should use the dedicated `oneplus` provider.

## Run

```powershell
$env:SOFLARE_CONF="E:\Works\contrix-dev\floria\soflare.sample.kdl"
cargo run
```

## Docker

Build the image:

```powershell
docker build -t floria .
```

Run it with a mounted config file:

```powershell
docker run --rm -p 5000:5000 -p 8000:8000 -v ${PWD}/soflare.sample.kdl:/app/floria.kdl floria
```

## Docker Compose

An example `compose.yml` is provided in the `examples/` directory.

For the smallest config and one canonical notify request shape, see
[examples/README.md](./examples/README.md),
[examples/minimal.kdl](./examples/minimal.kdl), and
[examples/minimal.notify.request.json](./examples/minimal.notify.request.json).

```sh
cp soflare.sample.kdl examples/floria.kdl
cd examples
docker compose up -d
```

See [examples/compose.yml](./examples/compose.yml) for full instructions.

## License

Licensed under Apache 2.0. See `LICENSE`.
