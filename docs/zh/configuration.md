# 配置参考

floria 从 `FLORIA_CONF` 环境变量指定的文件中读取配置。
未设置时，默认读取工作目录下的 `floria.kdl`。

## 配置格式

按文件扩展名自动检测：

| 扩展名         | 格式   |
|----------------|--------|
| `.kdl`         | [KDL](https://kdl.dev)（默认） |
| `.yaml` `.yml` | YAML   |

两种格式支持相同的配置结构。

## KDL 约定

KDL 是一种面向节点的文档语言。floria 使用以下约定将 KDL 映射到内部配置：

```
// 标量值
port 5000

// 数组 — 单个节点上的多个参数
bind_addresses "127.0.0.1" "0.0.0.0"

// 数组 — 短横线子节点约定（适用于长列表）
allowed_endpoints {
  - "*.push.services.mozilla.com"
  - "fcm.googleapis.com"
}

// 嵌套对象
click_action {
  type 2
  url "https://example.com/app"
}
```

## 顶层段

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `access.x_forwarded_for` | bool | `false` | 访问日志中使用 `X-Forwarded-For` 的第一个 IP |

日志级别通过 `RUST_LOG` 环境变量控制（如 `RUST_LOG=floria=debug,info`）。

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
    trusted_service_ids "ak:did_core:web:sync.example.com"
    plaintext_metadata_service_ids "ak:did_core:web:sync.example.com"
    gateway_service_did "did:web:push.example.com"
    // require_message_signatures true
    // production_mode true
    // service_principals {
    //   "ak:did_core:web:sync.example.com" {
    //     allow_plaintext_metadata true
    //     // bearer_tokens 仅限非生产；production_mode 会拒绝
    //     bearer_token_hashes "sha256:<hex-digest>"
    //     signature_verification_method "did:web:sync.example.com#push"
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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `bind_addresses` | string[] | `["127.0.0.1"]` | HTTP 监听地址；每项既可以只写 host/IP，也可以直接写 `host:port` |
| `port` | u16 | `5000` | HTTP 监听端口 |
| `public_base_url` | URL | `http://127.0.0.1:5000/` | ServiceDescribe 广告的外部可达 canonical HTTP/JSON base；生产模式必须使用 HTTPS |
| `notify_dedup_ttl_seconds` | u64 | `0` | 成功 `/notify` 请求体的去重 TTL；`0` 表示完全关闭去重 |
| `notify_dedup.backend` | string | `"memory"` | 去重后端：`"memory"` 或 `"redis"` |
| `notify_dedup.redis_url` | string | — | 当 `notify_dedup.backend=redis` 时使用的 Redis 连接 URL |
| `notify_dedup.key_prefix` | string | `"floria"` | Redis 去重键前缀 |
| `notify_auth.bearer_tokens` | string/string[] | — | 非生产 `/notify` 允许的 bearer service token；`production_mode=true` 时会被拒绝 |
| `notify_auth.bearer_token_hashes` | string/string[] | — | bearer token 的 SHA-256 摘要，可带 `sha256:` 前缀 |
| `notify_auth.trusted_service_ids` | string/string[] | — | `/notify` 允许调用的 origin service core ID 列表 |
| `notify_auth.plaintext_metadata_service_ids` | string/string[] | — | 允许发送 `sender_actor_display_name`、`space_name` 等明文元数据的 service core ID 列表 |
| `notify_auth.gateway_service_did` | string | — | gateway 的可解析 DID；传输 header 使用其 core 投影 |
| `notify_auth.require_message_signatures` | bool | `false` | 是否对已配置的 service principal 强制要求 HTTP Message Signature |
| `notify_auth.production_mode` | bool | `false` | 拒绝匿名 / bearer-only `/notify`，要求配置签名或 mTLS service principal，并拒绝明文 notify bearer token |
| `notify_auth.signature_max_skew_seconds` | u64 | `300` | 校验签名 `created` / `expires` 时允许的时钟偏差 |
| `notify_auth.mtls_verified_header` | string | `"x-client-certificate-verified"` | 由入口层注入、表示 mTLS 已校验通过的 header |
| `notify_auth.mtls_fingerprint_header` | string | `"x-client-certificate-sha256"` | 由入口层注入、携带客户端证书指纹的 header |
| `notify_auth.mtls_subject_dn_header` | string | `"x-client-certificate-subject"` | 由入口层注入、携带客户端证书 Subject DN 的 header |
| `notify_auth.mtls_subject_alt_names_header` | string | `"x-client-certificate-san"` | 由入口层注入、携带逗号分隔 SAN 列表的 header |
| `notify_auth.service_principals` | object | — | 以 origin service core ID 为键的逐服务鉴权配置，支持 bearer 回退、签名公钥、endpoint 绑定、plaintext metadata 权限和可选 mTLS |
| `internal_auth.bearer_tokens` | string/string[] | — | `/_floria/internal/*`、`/_floria/admin/push/status/*` 使用的内部/运维 bearer token |
| `internal_auth.bearer_token_hashes` | string/string[] | — | 内部 bearer token 的 SHA-256 摘要，可带 `sha256:` 前缀；两组内部凭据都为空时内部/运维路由 fail-closed |
| `notify_rate_limits.window_seconds` | u64 | `60` | `/notify` 内存限流的固定时间窗口 |
| `notify_rate_limits.per_origin_service` | u64 | — | 每个 origin service ID 在单窗口内允许的 `/notify` 次数 |
| `notify_rate_limits.per_app_id` | u64 | — | 每个 target app ID 在单窗口内允许的 `/notify` 次数 |
| `notify_rate_limits.per_provider` | u64 | — | 每个 resolved provider 在单窗口内允许的 `/notify` 次数 |
| `notify_rate_limits.per_push_key_hash` | u64 | — | 每个 push token hash 在单窗口内允许的 `/notify` 次数 |
| `notify_rate_limits.per_endpoint` | u64 | — | 每个 HTTP endpoint path 在单窗口内允许的 `/notify` 次数 |

`push_hint` 必须是 body-free 的唤醒提示。floria 只负责派生唤醒，不是事件或未读状态的 canonical truth。未获得 plaintext metadata 权限时，`sender_actor_display_name`、`strand_name`、`space_name`、`sender`、`target_did`，以及 notification/default payload 内容里嵌套的 `did:` 字面量都会被拒绝。notify 请求使用当前 `push_target_id`、`wakeup_kind`、`timing_profile_hint` 和 `push_key` 字段；未知 notification 字段会被 wire model 拒绝。`memory` 去重后端只适用于单实例，多实例部署请使用 Redis 去重。

生产环境 `/notify` 配置示例：

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
    gateway_service_did "did:web:push.example.com"
    gateway_service_method_history_head "sha256:<verified-log-head-digest>"
    gateway_service_version_id "1-<verified-version-id>"
    production_mode true
    require_message_signatures true
    service_principals {
      "ak:did_core:web:sync.example.com" {
        allow_plaintext_metadata true
        bearer_token_hashes "sha256:<rotated-service-secret-sha256>"
        signature_verification_method "did:web:sync.example.com#push"
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

生产部署时，应让 `/_arkret/edge/push/notify` 始终处于 service-to-service 鉴权之后，定期轮换 bearer 回退 secret，对命名 service principal 启用 HTTP Message Signature，并结合 `/ready` 健康检查和 Redis 去重支撑多实例部署。

> **生产模式要求（P5）**：生产环境不要配置明文
> `bearer_tokens`。开启 `production_mode=true` 后，floria 会在配置校验阶段拒绝
> gateway-wide `notify_auth.bearer_tokens` 和逐 principal 的
> `service_principals.*.bearer_tokens`。生产调用方必须使用 HTTP Message
> Signature 或 mTLS；`bearer_token_hashes` 仅作为非生产 bearer 回退材料保留。
> hash 可以是纯 hex，也可以带 `sha256:` 前缀。

启用 mTLS 入口时，TLS 终结的反向代理负责用固化的信任根链校验客户端证书，并把上表中的 4 条 `X-Client-Certificate-*` header 转发给 gateway。详见 [docs/zh/reverse-proxy.md](./reverse-proxy.md) 与 `examples/reverse-proxy/` 中的 nginx / Caddy 参考配置。

### Audit 日志轮转

当 `audit.backend = "file"` 时，floria 把每条审计事件作为一行 JSONL 写入
`audit.file_path`。floria 自身不做轮转，请使用平台标准的日志轮转工具
（`logrotate`、systemd `journal` 等）。

推荐 copy-truncate 策略，floria 无需重新打开文件描述符。完整示例见
`examples/logrotate-floria.conf`，大致结构：

```
/var/log/floria/audit.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 floria floria
    copytruncate
}
```

如需按文件大小触发轮转，添加 `size 100M` 并去掉 `daily`。systemd 部署可以用
`systemd.timer` 在同一周期内调用 `logrotate -f`，timer 文件路径因发行版而异，留给运维自行配置。

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `prometheus.enabled` | bool | `false` | 启动 Prometheus `/metrics` 监听器 |
| `prometheus.address` | string | `"127.0.0.1"` | Prometheus 监听绑定地址 |
| `prometheus.port` | u16 | `8000` | Prometheus 监听端口 |
| `opentracing.enabled` | bool | `false` | 启用 OTLP / OpenTelemetry span 导出器（gRPC） |
| `opentracing.endpoint` | string | – | OTLP gRPC 端点（启用时必填） |
| `opentracing.service_name` | string | `"floria"` | span 上的 `service.name` 资源属性 |
| `opentracing.sample_rate` | float | `1.0` | TraceIdRatioBased 采样率，0.0–1.0 |
| `opentracing.timeout_seconds` | u64 | `10` | OTLP exporter 请求超时 |
| `sentry.enabled` | bool | `false` | 通过 tracing 订阅器把 `tracing::error!` 与 panic 上报 Sentry |
| `sentry.dsn` | string | – | Sentry DSN（启用时必填） |
| `sentry.environment` | string | – | 可选 `environment` 标签 |
| `sentry.release` | string | – | 可选 `release` 标签 |
| `sentry.sample_rate` | float | `1.0` | 错误事件采样率 |
| `sentry.traces_sample_rate` | float | `0.0` | 事务/span 采样率 |

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `setup.level` | string | `"info"` | 当 `filter` 与 `RUST_LOG` 都未设置时使用的默认 tracing 级别 |
| `setup.format` | string | `"text"` | `text`（紧凑文本）或 `json`（结构化 JSON）格式器 |
| `setup.filter` | string | – | 可选的 `EnvFilter` 指令；优先于 `RUST_LOG` 与 `level` |
| `access.x_forwarded_for` | bool | `false` | 预留 — 反代访问日志格式化暂未实现 |

### `proxy`

```kdl
proxy "http://user:pass@proxy.example.com:8080"
```

可选的出站 HTTP 代理，用于推送请求。未设置时，使用 `HTTPS_PROXY` 环境变量作为回退。

## `apps` — 推送通道

`apps` 下的每个子节点以 arkret `app_id` 为键。`app_id` 可以是精确字符串或 glob 通配符模式（如 `com.example.*`）。

所有 provider 均接受以下公共字段：

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `type` | string | *必填* | Provider 类型（见下文） |
| `max_connections` | u64 | `20` | HTTP 连接池大小 |
| `inflight_request_limit` | u64 | `512` | 最大并发推送请求数 |
| `send_badge_counts` | bool | `true` | 包含未读 / 未接来电计数 |

---

### `apns` — Apple 推送通知服务

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `keyfile` | string | — | `.p8` 私钥路径（Token 认证） |
| `key_id` | string | — | Apple Key ID（Token 认证，与 `keyfile` 一起使用时必填） |
| `team_id` | string | — | Apple Team ID（Token 认证，与 `keyfile` 一起使用时必填） |
| `certfile` | string | — | 证书 PEM 文件路径（证书认证） |
| `topic` | string | — | APNS topic（Bundle ID） |
| `platform` | string | `"production"` | `"production"` / `"prod"` / `"sandbox"` |
| `push_type` | string | — | `"alert"` `"background"` `"voip"` `"complication"` `"fileprovider"` `"mdm"` |
| `convert_device_token_to_hex` | bool | `true` | 将 base64 设备令牌转换为十六进制 |

请提供 `keyfile`（Token 认证）**或** `certfile`（证书认证），不可同时使用。

---

### `fcm` — Firebase 云消息推送

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

FCM 现仅支持 HTTP v1 模式。

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `project_id` | string | — | Google Cloud 项目 ID（v1 模式必填） |
| `service_account_file` | string | — | Firebase 服务帐号 JSON 文件路径（v1 模式必填） |
| `fcm_options` | object | — | 合并到基础消息中的任意 JSON |

---

### `jpush` — 极光推送

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `app_key` | string | *必填* | 极光推送 App Key |
| `master_secret` | string | *必填* | 极光推送 Master Secret |
| `platforms` | string[] | 全部 | 目标平台（`"android"`、`"hmos"`） |
| `time_to_live` | u64 | — | 消息存活时间（秒） |
| `apns_production` | bool | — | 使用生产环境 APNS |
| `builder_id` | u64 | — | 通知样式编号 |
| `large_icon` | string | — | 图标 URL |
| `intent` | string | — | Android Intent URI，用于深度链接 |
| `uri_activity` | string | — | Activity URI |
| `third_party_channel` | object | — | 厂商通道路由配置 |
| `android_notification` | object | — | Android 通知字段（`channel_id` 等） |
| `hmos_notification` | object | — | HarmonyOS 通知字段 |

极光推送目前没有 `third_party_channel.oneplus`；OnePlus 需使用专用的 `oneplus` provider。

---

### `huawei` — 华为推送 / HarmonyOS

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `app_id` | string | *必填* | 华为 App ID |
| `app_secret` | string | *必填* | 华为 App Secret |
| `token_url` | string | 华为默认 | OAuth Token URL 覆盖 |
| `api_base_url` | string | 华为默认 | API Base URL 覆盖 |
| `channel_id` | string | — | 通知通道 |
| `ttl_seconds` | u64 | — | 消息存活时间 |
| `click_action` | object | — | 点击动作（`type`、`url`） |
| `android_config` | object | — | Android 配置（`collapse_key` 等） |
| `android_notification` | object | — | 通知字段（`default_sound` 等） |

---

### `honor` — 荣耀推送

字段集与 `huawei` 相同，默认端点指向荣耀云服务。

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

### `xiaomi` — 小米推送

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `app_secret` | string | *必填* | 小米 App Secret |
| `api_base_url` | string | 小米默认 | API Base URL 覆盖 |
| `restricted_package_name` | string | *必填* | Android 包名 |
| `pass_through` | bool | `false` | 透传模式 |
| `notify_type` | u64 | — | 通知类型 |
| `time_to_live` | u64 | — | 存活时间（秒） |
| `notify_id` | u64 | — | 通知 ID |
| `channel_id` | string | — | 通道 ID |
| `notify_effect` | string | — | 通知效果 |
| `intent_uri` | string | — | 深度链接 Intent URI |
| `web_uri` | string | — | Web URI 回退 |
| `extra` | object | — | 额外参数 |

---

### `oppo` / `oneplus` — OPPO / OPlus / OnePlus 推送

OnePlus 复用 OPPO 服务端 API。

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `app_key` | string | *必填* | OPlus App Key |
| `master_secret` | string | *必填* | Master Secret（也接受 `app_secret`） |
| `auth_url` | string | OPPO 默认 | Auth URL 覆盖 |
| `api_base_url` | string | OPPO 默认 | API Base URL 覆盖 |
| `channel_id` | string | — | 通知通道 |
| `click_action_type` | u64 | — | 点击动作类型 |
| `action_parameters` | object | — | 动作参数 |
| `notification` | object | — | 通知对象透传 |

---

### `vivo` — vivo 推送

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `app_id` | string/u64 | *必填* | vivo App ID（数字） |
| `app_key` | string | *必填* | vivo App Key |
| `app_secret` | string | *必填* | vivo App Secret |
| `auth_url` | string | vivo 默认 | Auth URL 覆盖 |
| `api_base_url` | string | vivo 默认 | API Base URL 覆盖 |
| `notify_type` | u64 | *必填* | 通知类型 |
| `skip_type` | u64 | *必填* | 跳转类型 |
| `skip_content` | string | — | 跳转内容 / Intent |
| `time_to_live` | u64 | — | 存活时间（秒） |
| `classification` | u64 | — | 消息分类级别 |
| `category` | string | — | 通知分类（如 `"IM"`） |
| `push_mode` | u64 | — | 推送模式 |
| `notify_id` | u64 | — | 通知 ID |
| `foreground_show` | bool | — | 前台展示 |
| `timed_display` | object | — | 定时展示（`overtimeDisplay`、`showStartTime`、`showEndTime`） |
| `extra` | object | — | 额外字段（`callback.id` 等） |

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `vapid_private_key` | string | *必填* | VAPID 私钥 PEM 文件路径 |
| `vapid_contact_email` | string | *必填* | VAPID 联系邮箱 |
| `allowed_endpoints` | string[] | — | 允许的订阅端点 glob 模式；未配置时 fail-closed，不发起 WebPush 出站请求 |
| `ttl` | u64 | `900` | 消息存活时间（秒） |

**设备数据字段**（客户端 `data` 对象中）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `endpoint` | string | WebPush 订阅端点 URL（不得包含 query string，且必须通过 floria HTTP egress 策略） |
| `auth` | string | 认证密钥（base64） |
| `default_payload` | object | 合并到所有消息的默认载荷 |
| `events_only` | bool | 仅在存在 `event_id` 时发送 |
| `only_last_per_strand` | bool | 按 active strand 去重（Topic 去重） |

## 环境变量

| 变量 | 说明 |
|------|------|
| `FLORIA_CONF` | 配置文件路径（默认：`floria.kdl`） |
| `RUST_LOG` | 日志过滤器（如 `floria=debug,info`） |
| `HTTPS_PROXY` | 出站代理回退（被配置文件中的 `proxy` 覆盖） |
