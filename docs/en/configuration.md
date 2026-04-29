# Configuration Reference

soflare reads its configuration from a file specified by the `SOFLARE_CONF` environment variable.
When unset, it defaults to `soflare.kdl` in the working directory.

## Config format

The format is detected by file extension:

| Extension      | Format |
|----------------|--------|
| `.kdl`         | [KDL](https://kdl.dev) (default) |
| `.yaml` `.yml` | YAML   |

Both formats support the same configuration structure.

## KDL conventions

KDL is a node-oriented document language. soflare maps KDL to its internal
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

## Top-level sections

```kdl
log { ... }
http { ... }
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

Logging is controlled by the `RUST_LOG` environment variable (e.g. `RUST_LOG=soflare=debug,info`).

### `http`

```kdl
http {
  bind_addresses "127.0.0.1"
  port 5000
  notify_dedup_ttl_seconds 0
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_addresses` | string[] | `["127.0.0.1"]` | Addresses to bind the HTTP listener; each entry may be a host/IP or an explicit `host:port` |
| `port` | u16 | `5000` | HTTP listener port |
| `notify_dedup_ttl_seconds` | u64 | `0` | In-memory dedup TTL for successful `/notify` request bodies; `0` disables it |

### `metrics`

```kdl
metrics {
  prometheus {
    enabled true
    address "127.0.0.1"
    port 8000
  }
  // parsed but not yet implemented:
  opentracing {
    enabled false
    implementation "jaeger"
    service_name "soflare"
  }
  sentry {
    enabled false
  }
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `prometheus.enabled` | bool | `false` | Start a Prometheus `/metrics` listener |
| `prometheus.address` | string | `"127.0.0.1"` | Prometheus listener bind address |
| `prometheus.port` | u16 | `8000` | Prometheus listener port |

### `proxy`

```kdl
proxy "http://user:pass@proxy.example.com:8080"
```

Optional outbound HTTP proxy for push requests. If omitted, the `HTTPS_PROXY`
environment variable is used as a fallback.

## `apps` — push providers

Each child node under `apps` is keyed by its contrix `app_id`. The `app_id` can
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

### `gcm` / `fcm` — Firebase Cloud Messaging

**Legacy:**

```kdl
com.example.android.legacy {
  type "gcm"
  api_version "legacy"
  api_key "your-fcm-server-key"
  max_connections 20
}
```

**HTTP v1:**

```kdl
com.example.android {
  type "gcm"
  api_version "v1"
  project_id "your-google-project-id"
  service_account_file "./firebase-service-account.json"
  max_connections 20
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

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `api_version` | string | `"legacy"` | `"legacy"` or `"v1"` |
| `api_key` | string | — | FCM server key (legacy, required) |
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
| `allowed_endpoints` | string[] | — | Glob patterns for allowed subscription endpoints |
| `ttl` | u64 | `900` | Message TTL in seconds |

**Device data fields** (in the client's `data` object):

| Field | Type | Description |
|-------|------|-------------|
| `endpoint` | string | WebPush subscription endpoint URL |
| `auth` | string | Authentication secret (base64) |
| `default_payload` | object | Default payload merged into all messages |
| `events_only` | bool | Only send if `event_id` is present |
| `only_last_per_room` | bool | Topic deduplication per room |

## Environment variables

| Variable | Description |
|----------|-------------|
| `SOFLARE_CONF` | Config file path (default: `soflare.kdl`) |
| `RUST_LOG` | Tracing filter (e.g. `soflare=debug,info`) |
| `HTTPS_PROXY` | Outbound proxy fallback (overridden by config `proxy`) |
