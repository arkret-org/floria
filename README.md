# floria

Push gateway service in Rust.

## Stack

- `salvo` for HTTP API
- `reqwest` for outbound APNS / FCM calls
- `kdl` for KDL config (default)
- `serde-saphyr` for YAML config (also supported)

`diesel` / PostgreSQL are intentionally not included because the service does not use a database.

## Supported features

- `POST /contrix/push/v1/notify`
- `GET /health`
- Prometheus metrics on a dedicated `/metrics` listener
- app id exact match and glob match
- per-pushkin in-flight concurrency limit
- optional in-memory dedup cache for successful `/notify` requests
- APNS certificate auth and token auth
- FCM legacy and FCM HTTP v1
- FCM legacy `registration_ids` batching
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

## Configuration

The config format is detected by file extension:
- `.kdl` — [KDL](https://kdl.dev) (default when `SOFLARE_CONF` is not set)
- `.yaml` / `.yml` — YAML

See [`configuration.md`](configuration.md) for the full configuration reference.

Quick notes:
- `proxy` in the config file takes precedence over `HTTPS_PROXY`
- `metrics.prometheus` starts a separate listener, defaulting to `127.0.0.1:8000`
- unknown config sections / fields emit startup warnings
- legacy `db` / `database` config sections are detected and warned about

Sample files:
- `floria.kdl.sample` — KDL config with all providers commented out
- `floria.yaml.sample` — YAML config with all providers commented out
- `floria.domestic-android.production.kdl.sample` — production mainland Android template (KDL)
- `floria.domestic-android.production.yaml.sample` — production mainland Android template (YAML)

## Recommended strategy

- For mainland Android delivery, prefer `JPush` as the broad aggregation layer.
- Keep direct `Huawei Push Kit`, `HONOR Push`, `Xiaomi Mi Push`, `OPPO / OnePlus Push`, and `vivo Push` enabled for apps that already hold first-party credentials or need tighter channel control.
- Use JPush `third_party_channel` to steer Huawei/Xiaomi/OPPO/vivo/HONOR/HMOS routing without adding another backend integration per OEM.
- JPush currently has no explicit `third_party_channel.oneplus` vendor key; OnePlus should use the dedicated `oneplus` provider.

## Current gaps

- `metrics.opentracing` and `metrics.sentry` are not implemented yet
- `log.setup` is not implemented yet

## Run

```powershell
$env:SOFLARE_CONF="E:\Works\palpo-im\floria\floria.kdl.sample"
cargo run
```

## Docker

Build the image:

```powershell
docker build -t floria .
```

Run it with a mounted config file:

```powershell
docker run --rm -p 5000:5000 -p 8000:8000 -v ${PWD}/floria.kdl.sample:/app/floria.kdl floria
```

## Docker Compose

An example `compose.yml` is provided in the `examples/` directory.

```sh
cp floria.kdl.sample examples/floria.kdl
cd examples
docker compose up -d
```

See [`examples/compose.yml`](../../examples/compose.yml) for full instructions.

## License

Licensed under Apache 2.0. See `LICENSE`.
