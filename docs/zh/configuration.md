# 配置参考

soflare 从 `SOFLARE_CONF` 环境变量指定的文件中读取配置。
未设置时，默认读取工作目录下的 `soflare.kdl`。

## 配置格式

按文件扩展名自动检测：

| 扩展名         | 格式   |
|----------------|--------|
| `.kdl`         | [KDL](https://kdl.dev)（默认） |
| `.yaml` `.yml` | YAML   |

两种格式支持相同的配置结构。

## KDL 约定

KDL 是一种面向节点的文档语言。soflare 使用以下约定将 KDL 映射到内部配置：

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

日志级别通过 `RUST_LOG` 环境变量控制（如 `RUST_LOG=soflare=debug,info`）。

### `http`

```kdl
http {
  bind_addresses "127.0.0.1"
  port 5000
  notify_dedup_ttl_seconds 0
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `bind_addresses` | string[] | `["127.0.0.1"]` | HTTP 监听地址；每项既可以只写 host/IP，也可以直接写 `host:port` |
| `port` | u16 | `5000` | HTTP 监听端口 |
| `notify_dedup_ttl_seconds` | u64 | `0` | 成功 `/notify` 请求体的内存去重 TTL；`0` 表示关闭 |

### `metrics`

```kdl
metrics {
  prometheus {
    enabled true
    address "127.0.0.1"
    port 8000
  }
  // 已解析但尚未实现：
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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `prometheus.enabled` | bool | `false` | 启动 Prometheus `/metrics` 监听器 |
| `prometheus.address` | string | `"127.0.0.1"` | Prometheus 监听绑定地址 |
| `prometheus.port` | u16 | `8000` | Prometheus 监听端口 |

### `proxy`

```kdl
proxy "http://user:pass@proxy.example.com:8080"
```

可选的出站 HTTP 代理，用于推送请求。未设置时，使用 `HTTPS_PROXY` 环境变量作为回退。

## `apps` — 推送通道

`apps` 下的每个子节点以 contrix `app_id` 为键。`app_id` 可以是精确字符串或 glob 通配符模式（如 `com.example.*`）。

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

### `gcm` / `fcm` — Firebase 云消息推送

**Legacy 模式：**

```kdl
com.example.android.legacy {
  type "gcm"
  api_version "legacy"
  api_key "your-fcm-server-key"
  max_connections 20
}
```

**HTTP v1 模式：**

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

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `api_version` | string | `"legacy"` | `"legacy"` 或 `"v1"` |
| `api_key` | string | — | FCM 服务器密钥（Legacy 模式必填） |
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
| `allowed_endpoints` | string[] | — | 允许的订阅端点 glob 模式 |
| `ttl` | u64 | `900` | 消息存活时间（秒） |

**设备数据字段**（客户端 `data` 对象中）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `endpoint` | string | WebPush 订阅端点 URL |
| `auth` | string | 认证密钥（base64） |
| `default_payload` | object | 合并到所有消息的默认载荷 |
| `events_only` | bool | 仅在存在 `event_id` 时发送 |
| `only_last_per_room` | bool | 按房间去重（Topic 去重） |

## 环境变量

| 变量 | 说明 |
|------|------|
| `SOFLARE_CONF` | 配置文件路径（默认：`soflare.kdl`） |
| `RUST_LOG` | 日志过滤器（如 `soflare=debug,info`） |
| `HTTPS_PROXY` | 出站代理回退（被配置文件中的 `proxy` 覆盖） |
