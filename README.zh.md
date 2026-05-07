# floria

使用 Rust 编写的推送网关服务。

## 技术栈

- `salvo` 提供 HTTP API
- `reqwest` 发送 APNS / FCM 出站请求
- `kdl` 读取 KDL 配置（默认格式）
- `serde-saphyr` 读取 YAML 配置（同样支持）

本服务不使用数据库，因此不包含 `diesel` / PostgreSQL。

## 支持的功能

- `POST /api/v1/push/notify` 作为 Contrix canonical notify endpoint
- `GET /api/v1/push/describe` 网关 profile discovery
- `GET /health`
- `GET /ready`
- 独立 `/metrics` 监听器上的 Prometheus 指标
- app id 精确匹配与 glob 通配符匹配
- 每个 pushkin 的并发请求数限制
- 可选的成功 `/notify` 请求内存或 Redis 去重缓存
- 可选的 `/notify` 内存限流，返回 `429` 与 `Retry-After`
- `/notify` 支持 HTTP Message Signature、Bearer 回退和可选 mTLS 部署鉴权
- APNS 证书认证与 Token 认证
- FCM HTTP v1
- 极光推送 REST v3，支持 `third_party_channel` 透传
- 华为推送 / HarmonyOS 服务端推送
- 荣耀推送服务端推送
- OPPO / OPlus / OnePlus 服务端推送
- vivo 推送服务端推送
- 小米推送服务端推送
- WebPush / VAPID
- `SOFLARE_CONF` 环境变量
- `HTTPS_PROXY` 环境变量用于出站代理回退
- KDL 配置（默认）与 YAML 配置，按文件扩展名自动检测

## 配置

配置格式按文件扩展名自动检测：
- `.kdl` — [KDL](https://kdl.dev)（未设置 `SOFLARE_CONF` 时的默认格式）
- `.yaml` / `.yml` — YAML

完整配置参考请参阅 [docs/zh/configuration.md](./docs/zh/configuration.md)。
凭据轮换流程请参阅 [docs/zh/credential-rotation.md](./docs/zh/credential-rotation.md)。
反向代理 / TLS 终结 / mTLS 部署细节请参阅 [docs/zh/reverse-proxy.md](./docs/zh/reverse-proxy.md)（nginx 与 Caddy 参考样例位于 `examples/reverse-proxy/`）。

要点：
- 配置文件中的 `proxy` 优先于 `HTTPS_PROXY` 环境变量
- `metrics.prometheus` 启动独立的监听器，默认地址为 `127.0.0.1:8000`
- 未知的配置段 / 字段会在启动时输出警告
- `memory` 去重后端只适用于单实例；多实例部署请使用 Redis 去重
- `push_hint` 必须是 body-free 的唤醒提示，不能携带正文
- push gateway 只负责派生唤醒，不是事件或未读状态的 canonical truth

## Contrix notify 语义

- `/api/v1/push/notify` 支持 authenticated service caller，并接受 `Idempotency-Key` header 或 body 内 `idempotency_key`
- `cx.push.notify` 接受 `origin_service_did`、destination gateway DID、priority/TTL/collapse hint 和目标设备引用
- 错误响应使用 JSON envelope，网关 contract 错误码包括 `capability_denied`、`unsupported_feature`、`schema_violation`、`payload_too_large`、`rate_limited` 和 `temporarily_unavailable`
- E2EE 场景下会校验 blind/minimized payload：正文、密文字节、SDP、ICE、TURN credential 都会被拒绝
- 未经 plaintext metadata 授权的调用方不能携带 `sender_display_name`、`flow_name`、`space_name`
- legacy `room_*`、`card_*`、`subject*`、Matrix `m.room.*` 和 `only_last_per_room` 输入会被直接拒绝
- `rejected` 中返回的是 push token hash，不是原始平台 token
- 响应里的 delivery receipt refs 只包含 provider/status/token hash metadata，不包含明文 payload
- bearer fallback 只接受 header；query string 中的认证材料会被拒绝
- WebPush endpoint 必须命中 allowlist，且不得包含 query string
- readiness 探针使用 `GET /ready`，Docker 健康检查同样走这个端点

示例文件：
- `soflare.sample.kdl` — KDL 配置，所有推送通道已注释
- `soflare.sample.yaml` — YAML 配置，所有推送通道已注释

## 推荐策略

- 国内 Android 推送建议优先使用`极光推送`作为聚合通道。
- 对于已持有厂商凭据或需要更精细通道控制的应用，保留直接接入`华为推送`、`荣耀推送`、`小米推送`、`OPPO / OnePlus 推送`和 `vivo 推送`。
- 利用极光推送的 `third_party_channel` 路由华为/小米/OPPO/vivo/荣耀/HMOS，无需为每个 OEM 单独集成后端。
- 极光推送目前没有 `third_party_channel.oneplus` 厂商键；OnePlus 需使用专用的 `oneplus` provider。

## 当前不足

- `metrics.opentracing` 和 `metrics.sentry` 尚未实现
- `log.setup` 尚未实现

## 运行

```powershell
$env:SOFLARE_CONF="E:\Works\contrix-dev\floria\soflare.sample.kdl"
cargo run
```

## Docker

构建镜像：

```powershell
docker build -t floria .
```

使用挂载的配置文件运行：

```powershell
docker run --rm -p 5000:5000 -p 8000:8000 -v ${PWD}/soflare.sample.kdl:/app/floria.kdl floria
```

## Docker Compose

`examples/` 目录下提供了示例 `compose.yml`。

如果要看最小配置和一条 canonical notify 请求示例，见
[examples/README.md](./examples/README.md)、
[examples/minimal.kdl](./examples/minimal.kdl) 和
[examples/minimal.notify.request.json](./examples/minimal.notify.request.json)。

```sh
cp soflare.sample.kdl examples/floria.kdl
cd examples
docker compose up -d
```

详见 [examples/compose.yml](./examples/compose.yml)。

## 许可证

基于 Apache 2.0 许可证。详见 `LICENSE`。
