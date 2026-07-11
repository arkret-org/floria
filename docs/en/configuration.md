# Configuration Reference

floria reads its configuration from a file specified by the `FLORIA_CONF` environment variable.
When unset, it defaults to `floria.kdl` in the working directory.

## Config format

The format is detected by file extension:

| Extension      | Format |
|----------------|--------|
| `.kdl`         | [KDL](https://kdl.dev) (default) |
| `.yaml` `.yml` | YAML   |

Both formats support the same configuration structure.

## KDL conventions

KDL is a node-oriented document language. floria maps KDL to its internal
config using these conventions:

```
// Scalar value
port 5000

// Array — multiple arguments on one node
bind_addresses "127.0.0.1" "0.0.0.0"

// Array — dash-children convention (useful for long lists)
allowed_endpoints {
  - "*.push.services.mozilla.com"
  - "fcm.googleapis.com"
}

// Nested object
click_action {
  type 2
  url "https://example.com/app"
}
```

### KDL environment placeholders

floria does not expand shell-style placeholders inside config files. A KDL value
such as `bearer_tokens "${FLORIA_NOTIFY_TOKEN}"` is passed to validation and
runtime as the literal string `${FLORIA_NOTIFY_TOKEN}`; YAML behaves the same
way. The only environment variables read directly by floria are listed in
[Environment variables](#environment-variables).

If a deployment wants `${ENV_VAR}` substitution, render the config before
starting floria and point `FLORIA_CONF` at the rendered file. Keep the rendered
file owned by the service account, restrict file permissions, and restart the
process after replacing it. Provider credential paths such as APNs `keyfile` /
`certfile`, FCM `service_account_file`, and WebPush `vapid_private_key` are
resolved at startup; relative paths are resolved from the directory containing
`FLORIA_CONF` when that variable is set, otherwise from the current working
directory.

## Top-level sections

```kdl
log { ... }
http { ... }
storage { ... }
metrics { ... }
proxy "http://user:pass@proxy:8080"
apps { ... }
```

### `log`

```kdl
log {
  access {
    x_forwarded_for false
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `access.x_forwarded_for` | bool | `false` | Use the first IP from `X-Forwarded-For` for access logs |

Logging is controlled by the `RUST_LOG` environment variable (e.g. `RUST_LOG=floria=debug,info`).

### `http`

```kdl
http {
  bind_addresses "127.0.0.1"
  port 5000
  notify_dedup_ttl_seconds 0
  notify_dedup {
    backend "memory"
    key_prefix "floria"
    // redis_url "redis://127.0.0.1:6379/0"
  }
  notify_auth {
    bearer_tokens "replace-me"
    // bearer_token_hashes "sha256:<hex-digest>"
    trusted_service_ids "did:web:sync.example.com"
    plaintext_metadata_service_ids "did:web:sync.example.com"
    gateway_service_id "did:web:push.example.com"
    // require_message_signatures true
    // production_mode true
    // service_principals {
    //   "did:web:sync.example.com" {
    //     allow_plaintext_metadata true
    //     // bearer_tokens is non-production only; production_mode rejects it.
    //     bearer_token_hashes "sha256:<hex-digest>"
    //     signature_key_id "did:web:sync.example.com#push"
    //     signature_public_key_hex "replace-with-ed25519-public-key-hex"
    //     service_endpoint "https://push.example.com/_arkret/edge/push/notify"
    //     require_mtls true
    //     mtls_cert_fingerprints "aa:bb:cc"
    //   }
    // }
  }
  internal_auth {
    // bearer_tokens "replace-me-internal"
    bearer_token_hashes "sha256:<hex-digest>"
  }
  notify_rate_limits {
    window_seconds 60
    per_origin_service 600
    per_app_id 5000
    per_provider 5000
    per_push_key_hash 120
    per_endpoint 10000
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_addresses` | string[] | `["127.0.0.1"]` | Addresses to bind the HTTP listener; each entry may be a host/IP or an explicit `host:port` |
| `port` | u16 | `5000` | HTTP listener port |
| `notify_dedup_ttl_seconds` | u64 | `0` | Dedup TTL for successful `/notify` request bodies; `0` disables dedup entirely |
| `notify_dedup.backend` | string | `"memory"` | Dedup backend: `"memory"` or `"redis"` |
| `notify_dedup.redis_url` | string | — | Redis connection URL when `notify_dedup.backend=redis` |
| `notify_dedup.key_prefix` | string | `"floria"` | Prefix used for dedup keys in Redis |
| `notify_auth.bearer_tokens` | string/string[] | — | Allowed bearer service tokens for non-production `/notify`; rejected when `production_mode=true` |
| `notify_auth.bearer_token_hashes` | string/string[] | — | SHA-256 bearer token digests, optionally prefixed with `sha256:` |
| `notify_auth.trusted_service_ids` | string/string[] | — | Allowlisted origin service DIDs for `/notify` |
| `notify_auth.plaintext_metadata_service_ids` | string/string[] | — | Services allowed to send plaintext metadata fields such as `sender_actor_display_name` and `space_name` |
| `notify_auth.gateway_service_id` | string | — | Expected destination gateway DID |
| `notify_auth.require_message_signatures` | bool | `false` | Require HTTP Message Signature verification for configured service principals |
| `notify_auth.production_mode` | bool | `false` | Reject anonymous/bearer-only `/notify`, require configured signed or mTLS service principals, and reject plaintext notify bearer tokens |
| `notify_auth.signature_max_skew_seconds` | u64 | `300` | Allowed clock skew when verifying signature `created` / `expires` |
| `notify_auth.mtls_verified_header` | string | `"x-client-certificate-verified"` | Ingress-provided header used to signal verified mTLS client auth |
| `notify_auth.mtls_fingerprint_header` | string | `"x-client-certificate-sha256"` | Ingress-provided header carrying the client certificate fingerprint |
| `notify_auth.mtls_subject_dn_header` | string | `"x-client-certificate-subject"` | Ingress-provided header carrying the client certificate Subject DN |
| `notify_auth.mtls_subject_alt_names_header` | string | `"x-client-certificate-san"` | Ingress-provided header carrying the comma-joined SAN list |
| `notify_auth.service_principals` | object | — | Per-service auth profile keyed by origin service DID; supports bearer fallback, signature key, endpoint binding, plaintext metadata permission, and optional mTLS |
| `internal_auth.bearer_tokens` | string/string[] | — | Internal/operator bearer tokens for `/_floria/internal/*`, `/_floria/admin/push/status/*`, and `/_floria/admin/push/device/unregister` |
| `internal_auth.bearer_token_hashes` | string/string[] | — | SHA-256 internal bearer token digests, optionally prefixed with `sha256:`; when both internal credential lists are empty, internal/operator routes fail closed |
| `notify_rate_limits.window_seconds` | u64 | `60` | Fixed window size for in-memory `/notify` rate limits |
| `notify_rate_limits.per_origin_service` | u64 | — | Max `/notify` requests per origin service DID per window |
| `notify_rate_limits.per_app_id` | u64 | — | Max `/notify` requests per target app ID per window |
| `notify_rate_limits.per_provider` | u64 | — | Max `/notify` requests per resolved provider per window |
| `notify_rate_limits.per_push_key_hash` | u64 | — | Max `/notify` requests per push token hash per window |
| `notify_rate_limits.per_endpoint` | u64 | — | Max `/notify` requests per HTTP endpoint path per window |
| `notify_rate_limits.per_provider_concurrency` | u64 | `100` | Max concurrent in-flight notify dispatches per resolved provider. `0` disables; defends against a single provider monopolising the fanout worker pool |

`push_hint` is a body-free wakeup hint. floria treats push delivery as a derived wakeup surface, not canonical truth for events or unread state. When plaintext metadata permission is absent, `sender_actor_display_name`, `strand_name`, `space_name`, `sender`, `target_did`, and nested `did:` literals in notification/default payload content are rejected. Notify requests use the current `push_target_id`, `wakeup_kind`, `timing_profile_hint`, and `push_key` field names; unknown notification fields are rejected by the wire model. The `memory` dedup backend is single-instance only; use Redis-backed dedup for multi-instance deployment.

Production `/notify` profile example:

```kdl
http {
  bind_addresses "0.0.0.0"
  port 5000
  notify_dedup_ttl_seconds 60
  notify_dedup {
    backend "redis"
    redis_url "redis://redis.internal:6379/0"
    key_prefix "floria-prod"
  }
  notify_auth {
    gateway_service_id "did:web:push.example.com"
    production_mode true
    require_message_signatures true
    service_principals {
      "did:web:sync.example.com" {
        allow_plaintext_metadata true
        bearer_token_hashes "sha256:<rotated-service-secret-sha256>"
        signature_key_id "did:web:sync.example.com#push"
        signature_public_key_hex "replace-with-ed25519-public-key-hex"
        service_endpoint "https://push.example.com/_arkret/edge/push/notify"
        require_mtls true
        mtls_cert_fingerprints "aa:bb:cc"
      }
    }
  }
  notify_rate_limits {
    window_seconds 60
    per_origin_service 600
    per_app_id 5000
    per_provider 5000
    per_push_key_hash 120
    per_endpoint 10000
  }
}
```

In production, keep `/_arkret/edge/push/notify` behind service-to-service auth, rotate bearer fallback secrets, use HTTP Message Signatures for named service principals, and pair the gateway DID with `/ready` health checks plus Redis-backed dedup for multi-instance deployments.

> **Production-mode requirement (P5)**: do not configure plaintext
> `bearer_tokens` in production. With `production_mode=true`, floria
> rejects gateway-wide `notify_auth.bearer_tokens` and per-principal
> `service_principals.*.bearer_tokens` during config validation.
> Production callers must satisfy HTTP Message Signature or mTLS; bearer
> hashes may be kept only as non-production fallback material. Hashes may
> be specified bare-hex or with a `sha256:` prefix.

For mTLS-fronted deployments, the gateway expects the TLS-terminating reverse proxy to validate the client certificate against a pinned trust root chain and forward the four `X-Client-Certificate-*` headers above. See [docs/en/reverse-proxy.md](./reverse-proxy.md) for the runbook and `examples/reverse-proxy/` for nginx and Caddy reference configurations.

### `storage`

```kdl
storage {
  // Omit postgres_url for in-memory broadcast state.
  // postgres_url "postgres://floria:secret@postgres.internal:5432/floria"
  deactivation_queue_table "floria_push_delivery_queue"
  push_contact_cache_table "floria_push_contact_cache"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `postgres_url` | string | - | Optional PostgreSQL URL. Enables deactivation queue drain and persistent push-contact PSI cache overlay |
| `deactivation_queue_table` | string | `"floria_push_delivery_queue"` | Queue table drained by `account_deactivate_fanout`; accepts `table` or `schema.table` |
| `push_contact_cache_table` | string | `"floria_push_contact_cache"` | Persistent PSI cache table used by `consent_revoke`; accepts `table` or `schema.table` |

The deactivation queue table is expected to contain `actor_id`, `device_id`,
and `push_key_hash` text columns. floria drains it with `DELETE` statements for
the broadcast actor and, when present, the listed device ids / push-key hashes.

The push-contact cache table is expected to contain `principal_id`,
`peer_psi_token`, `verdict`, and `updated_at` columns, with a unique constraint
on `(principal_id, peer_psi_token)`. `verdict` stores `allowed` or `denied`.
When `postgres_url` is unset, the same broadcast bus runs with process-local
state only.

### Secrets and operator workflow

floria 1.0 does not include a built-in HashiCorp Vault, AWS Secrets Manager, or
similar vault adapter. Operators should use their platform's secret manager,
agent, or init process to materialize secret files and config before the
process starts.

Recommended workflow:

1. Store provider private keys, APNs certificate bundles, FCM service account
   JSON, VAPID private keys, custom push bearer tokens, and service-auth signing
   material in the platform secret manager.
2. At deploy time, mount or write those secrets as files readable only by the
   floria service account. Prefer file path fields for provider credentials:
   APNs `keyfile` / `certfile`, FCM `service_account_file`, WebPush
   `vapid_private_key`, and custom push `client_certfile`.
3. For non-production service bearer fallback, prefer
   `bearer_token_hashes` over raw `bearer_tokens` so the gateway config
   does not contain reusable bearer material. Production mode rejects raw
   notify bearer tokens entirely.
4. Render any config that needs environment-specific values before startup; do
   not rely on `${ENV_VAR}` strings being expanded by floria.
5. Roll the deployment and verify `/ready` returns `200` before revoking the old
   provider or caller credential.

This keeps secret retrieval outside the gateway binary while matching the
current configuration surface.

### Audit log rotation

When `audit.backend = "file"`, floria writes one JSONL audit record per
event to `audit.file_path`. floria does not rotate the file itself —
operators are expected to manage rotation through the platform's
standard log rotation tooling.

Recommended approach: use `logrotate` (or the systemd `journal` if you
have switched the audit backend to `systemd-cat`) with a
copy-truncate strategy so floria does not need to reopen the file
descriptor.

An example logrotate config ships in
`examples/logrotate-floria.conf`. The shape is roughly:

```
/var/log/floria/audit.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 floria floria
    copytruncate
    sharedscripts
    postrotate
        # No SIGHUP needed — floria keeps the FD open and the
        # copytruncate strategy preserves writes during rotation.
    endscript
}
```

If you need rotation on a size threshold rather than a daily cadence,
add `size 100M` and drop `daily`. For deployments using systemd, a
matching `systemd.timer` can invoke `logrotate -f` on the same cadence;
the timer file is left to the operator since unit paths vary.

### `metrics`

```kdl
metrics {
  prometheus {
    enabled true
    address "127.0.0.1"
    port 8000
  }
  opentracing {
    enabled true
    endpoint "http://otel-collector:4317"
    service_name "floria"
    sample_rate 0.1
    timeout_seconds 10
  }
  sentry {
    enabled true
    dsn "https://public@o0.ingest.sentry.io/0"
    environment "production"
    release "floria@0.1.0"
    sample_rate 1.0
    traces_sample_rate 0.0
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `prometheus.enabled` | bool | `false` | Start a Prometheus `/metrics` listener |
| `prometheus.address` | string | `"127.0.0.1"` | Prometheus listener bind address |
| `prometheus.port` | u16 | `8000` | Prometheus listener port |
| `opentracing.enabled` | bool | `false` | Enable the OTLP / OpenTelemetry span exporter (gRPC) |
| `opentracing.endpoint` | string | – | OTLP gRPC endpoint (required when enabled) |
| `opentracing.service_name` | string | `"floria"` | `service.name` resource attribute on emitted spans |
| `opentracing.sample_rate` | float | `1.0` | TraceIdRatioBased sampler ratio, 0.0–1.0 |
| `opentracing.timeout_seconds` | u64 | `10` | OTLP exporter request timeout |
| `sentry.enabled` | bool | `false` | Forward `tracing::error!` events and panics to Sentry |
| `sentry.dsn` | string | – | Sentry DSN (required when enabled) |
| `sentry.environment` | string | – | Optional `environment` tag |
| `sentry.release` | string | – | Optional `release` tag |
| `sentry.sample_rate` | float | `1.0` | Fraction of error events to send |
| `sentry.traces_sample_rate` | float | `0.0` | Fraction of transactions/spans to send |

### `log`

```kdl
log {
  setup {
    level "info"        // trace | debug | info | warn | error
    format "json"       // text | json
    // filter "floria=debug,tower_http=info"
  }
  access {
    x_forwarded_for true
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `setup.level` | string | `"info"` | Default tracing level when neither `filter` nor `RUST_LOG` is set |
| `setup.format` | string | `"text"` | `text` (compact) or `json` (structured) formatter |
| `setup.filter` | string | – | Optional explicit `EnvFilter` directive; falls back to `RUST_LOG`, then `level` |
| `access.x_forwarded_for` | bool | `false` | Reserved — proxied access log formatting is not implemented yet |

### `proxy`

```kdl
proxy "http://user:pass@proxy.example.com:8080"
```

Optional outbound HTTP proxy for push requests. If omitted, the `HTTPS_PROXY`
environment variable is used as a fallback.

## `apps` — push providers

Each child node under `apps` is keyed by its arkret `app_id`. The `app_id` can
be an exact string or a glob pattern (e.g. `com.example.*`).

Every provider accepts these common fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | *required* | Provider type (see below) |
| `max_connections` | u64 | `20` | HTTP connection pool size |
| `inflight_request_limit` | u64 | `512` | Max concurrent push requests |
| `send_badge_counts` | bool | `true` | Include unread/missed-call counts |

---

### `apns` — Apple Push Notification Service

```kdl
com.example.ios {
  type "apns"
  keyfile "./AuthKey_ABC123DEFG.p8"
  key_id "ABC123DEFG"
  team_id "DEF456GHIJ"
  topic "com.example.ios"
  platform "production"
  convert_device_token_to_hex false
  inflight_request_limit 512
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `keyfile` | string | — | Path to `.p8` private key (token auth) |
| `key_id` | string | — | Apple key ID (token auth, required with `keyfile`) |
| `team_id` | string | — | Apple team ID (token auth, required with `keyfile`) |
| `certfile` | string | — | Path to certificate PEM (cert auth) |
| `topic` | string | — | APNS topic (bundle ID) |
| `platform` | string | `"production"` | `"production"` / `"prod"` / `"sandbox"` |
| `push_type` | string | — | `"alert"` `"background"` `"voip"` `"complication"` `"fileprovider"` `"mdm"` |
| `convert_device_token_to_hex` | bool | `true` | Convert base64 device tokens to hex |

Provide **either** `keyfile` (token auth) or `certfile` (certificate auth), not both.

---

### `fcm` — Firebase Cloud Messaging

```kdl
com.example.android {
  type "fcm"
  project_id "your-google-project-id"
  service_account_file "./firebase-service-account.json"
  max_connections 20
  inflight_request_limit 512
  fcm_options {
    apns {
      payload {
        aps {
          content-available 1
          mutable-content 1
        }
      }
    }
  }
}
```

FCM is configured in HTTP v1 mode only.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `project_id` | string | — | Google Cloud project ID (v1, required) |
| `service_account_file` | string | — | Path to Firebase service account JSON (v1, required) |
| `fcm_options` | object | — | Arbitrary JSON merged into base message |

---

### `jpush` — JPush

```kdl
com.example.android.cn {
  type "jpush"
  app_key "your-jpush-app-key"
  master_secret "your-jpush-master-secret"
  platforms "android" "hmos"
  time_to_live 86400
  apns_production true
  builder_id 1
  large_icon "https://cdn.example.com/push/icon.png"
  intent "intent:#Intent;component=com.example.android/.MainActivity;end"
  third_party_channel {
    xiaomi { distribution "jpush" }
    huawei { distribution "first_ospush" }
    oppo   { distribution "jpush" }
    vivo   { distribution "jpush" }
    honor  { distribution "secondary_push" }
    hmos   { distribution "jpush" }
  }
  android_notification {
    channel_id "messages"
    badge_add_num 1
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `app_key` | string | *required* | JPush app key |
| `master_secret` | string | *required* | JPush master secret |
| `platforms` | string[] | all | Target platforms (`"android"`, `"hmos"`) |
| `time_to_live` | u64 | — | Message TTL in seconds |
| `apns_production` | bool | — | Use production APNS |
| `builder_id` | u64 | — | Notification builder ID |
| `large_icon` | string | — | Icon URL |
| `intent` | string | — | Android intent URI for deep linking |
| `uri_activity` | string | — | Activity URI |
| `third_party_channel` | object | — | OEM channel routing config |
| `android_notification` | object | — | Android notification fields (`channel_id`, etc.) |
| `hmos_notification` | object | — | HarmonyOS notification fields |

JPush currently has no `third_party_channel.oneplus`; use the dedicated `oneplus` provider.

---

### `huawei` — Huawei Push Kit / HarmonyOS

```kdl
com.example.huawei {
  type "huawei"
  app_id "1234567890123456789"
  app_secret "your-huawei-app-secret"
  channel_id "messages"
  ttl_seconds 3600
  click_action {
    type 2
    url "https://example.com/app"
  }
  android_config {
    collapse_key -1
  }
  android_notification {
    default_sound true
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `app_id` | string | *required* | Huawei app ID |
| `app_secret` | string | *required* | Huawei app secret |
| `token_url` | string | Huawei default | OAuth token URL override |
| `api_base_url` | string | Huawei default | API base URL override |
| `channel_id` | string | — | Notification channel |
| `ttl_seconds` | u64 | — | Message time-to-live |
| `click_action` | object | — | Click action (`type`, `url`) |
| `android_config` | object | — | Android config (`collapse_key`, etc.) |
| `android_notification` | object | — | Notification fields (`default_sound`, etc.) |

---

### `honor` — HONOR Push Kit

Same field set as `huawei`. Defaults point to HONOR cloud endpoints.

```kdl
com.example.honor {
  type "honor"
  app_id "1234567890123456789"
  app_secret "your-honor-app-secret"
  // token_url "https://hnoauth-login.cloud.honor.com/oauth2/v3/token"
  // api_base_url "https://push-api.cloud.honor.com/v1"
  channel_id "messages"
  ttl_seconds 3600
}
```

---

### `xiaomi` — Xiaomi Mi Push

```kdl
com.example.xiaomi {
  type "xiaomi"
  app_secret "your-xiaomi-app-secret"
  restricted_package_name "com.example.android"
  pass_through false
  notify_type 2
  time_to_live 3600
  channel_id "messages"
  notify_effect 2
  intent_uri "intent:#Intent;component=com.example.android/.MainActivity;end"
  extra {
    notification_style_type 1
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `app_secret` | string | *required* | Xiaomi app secret |
| `api_base_url` | string | Xiaomi default | API base URL override |
| `restricted_package_name` | string | *required* | Android package name |
| `pass_through` | bool | `false` | Pass-through mode |
| `notify_type` | u64 | — | Notification type |
| `time_to_live` | u64 | — | TTL in seconds |
| `notify_id` | u64 | — | Notification ID |
| `channel_id` | string | — | Channel ID |
| `notify_effect` | string | — | Notification effect |
| `intent_uri` | string | — | Deep link intent URI |
| `web_uri` | string | — | Web URI fallback |
| `extra` | object | — | Extra parameters |

---

### `oppo` / `oneplus` — OPPO / OPlus / OnePlus Push

OnePlus reuses the OPPO server API.

```kdl
com.example.oppo {
  type "oppo"
  app_key "your-oppo-app-key"
  master_secret "your-oppo-master-secret"
  channel_id "messages"
  click_action_type 1
  action_parameters {
    action_type 1
  }
  notification {
    style 1
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `app_key` | string | *required* | OPlus app key |
| `master_secret` | string | *required* | Master secret (also accepted as `app_secret`) |
| `auth_url` | string | OPPO default | Auth URL override |
| `api_base_url` | string | OPPO default | API base URL override |
| `channel_id` | string | — | Notification channel |
| `click_action_type` | u64 | — | Click action type |
| `action_parameters` | object | — | Action parameters |
| `notification` | object | — | Notification object passthrough |

---

### `vivo` — vivo Push

```kdl
com.example.vivo {
  type "vivo"
  app_id 100000001
  app_key "your-vivo-app-key"
  app_secret "your-vivo-app-secret"
  notify_type 4
  skip_type 4
  skip_content "intent:#Intent;component=com.example.android/.MainActivity;end"
  time_to_live 3600
  classification 1
  category "IM"
  notify_id 1
  foreground_show true
  extra {
    callback.id "push-receipt"
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `app_id` | string/u64 | *required* | vivo app ID (numeric) |
| `app_key` | string | *required* | vivo app key |
| `app_secret` | string | *required* | vivo app secret |
| `auth_url` | string | vivo default | Auth URL override |
| `api_base_url` | string | vivo default | API base URL override |
| `notify_type` | u64 | *required* | Notification type |
| `skip_type` | u64 | *required* | Skip type |
| `skip_content` | string | — | Skip content / intent |
| `time_to_live` | u64 | — | TTL in seconds |
| `classification` | u64 | — | Classification level |
| `category` | string | — | Notification category (e.g. `"IM"`) |
| `push_mode` | u64 | — | Push mode |
| `notify_id` | u64 | — | Notification ID |
| `foreground_show` | bool | — | Show in foreground |
| `timed_display` | object | — | Timed display (`overtimeDisplay`, `showStartTime`, `showEndTime`) |
| `extra` | object | — | Extra fields (`callback.id`, etc.) |

---

### `webpush` — Web Push / VAPID

```kdl
com.example.web {
  type "webpush"
  vapid_private_key "./vapid-private.pem"
  vapid_contact_email "push@example.com"
  ttl 900
  max_connections 20
  allowed_endpoints "*.push.services.mozilla.com" "fcm.googleapis.com"
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `vapid_private_key` | string | *required* | Path to VAPID private key PEM |
| `vapid_contact_email` | string | *required* | Contact email for VAPID |
| `allowed_endpoints` | string[] | — | Glob patterns for allowed subscription endpoints; unset means fail-closed/no WebPush egress |
| `ttl` | u64 | `900` | Message TTL in seconds |

**Device data fields** (in the client's `data` object):

| Field | Type | Description |
|-------|------|-------------|
| `endpoint` | string | WebPush subscription endpoint URL (must not contain a query string and must pass floria's HTTP egress policy) |
| `auth` | string | Authentication secret (base64) |
| `default_payload` | object | Default payload merged into all messages |
| `events_only` | bool | Only send if `event_id` is present |
| `only_last_per_strand` | bool | Topic deduplication per active strand |

## Environment variables

| Variable | Description |
|----------|-------------|
| `FLORIA_CONF` | Config file path (default: `floria.kdl`) |
| `RUST_LOG` | Tracing filter (e.g. `floria=debug,info`) |
| `HTTPS_PROXY` | Outbound proxy fallback (overridden by config `proxy`) |

## Reload semantics

Configuration, provider credentials, auth policy, rate-limit settings, metrics
sinks, and provider registries are loaded once at process startup. floria does
not install a `SIGHUP` handler and does not hot reload config files or mounted
secret files.

To apply any config or secret change, restart each floria process. For HA
deployments, perform a rolling restart, keep old credentials valid through the
overlap window, and wait for `/ready` to return `200` on the restarted instance
before moving to the next one.
