# floria

使用 Rust 编写的推送网关服务。

## 技术栈

- `salvo` 提供 HTTP API
- `reqwest` 发送 APNS / FCM 出站请求
- `kdl` 读取 KDL 配置（默认格式）
- `serde-saphyr` 读取 YAML 配置（同样支持）

本服务不使用数据库，因此不包含 `diesel` / PostgreSQL。

## 支持的功能

- `POST /contrix/push/v1/notify`
- `GET /health`
- 独立 `/metrics` 监听器上的 Prometheus 指标
- app id 精确匹配与 glob 通配符匹配
- 每个 pushkin 的并发请求数限制
- 可选的成功 `/notify` 请求内存去重缓存
- APNS 证书认证与 Token 认证
- FCM Legacy 与 FCM HTTP v1
- FCM Legacy `registration_ids` 批量发送
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

完整配置参考请参阅 [`configuration.md`](configuration.md)。

要点：
- 配置文件中的 `proxy` 优先于 `HTTPS_PROXY` 环境变量
- `metrics.prometheus` 启动独立的监听器，默认地址为 `127.0.0.1:8000`
- 未知的配置段 / 字段会在启动时输出警告
- 遗留的 `db` / `database` 配置段会被检测并发出警告

示例文件：
- `floria.kdl.sample` — KDL 配置，所有推送通道已注释
- `floria.yaml.sample` — YAML 配置，所有推送通道已注释
- `floria.domestic-android.production.kdl.sample` — 国内 Android 生产环境模板（KDL）
- `floria.domestic-android.production.yaml.sample` — 国内 Android 生产环境模板（YAML）

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
$env:SOFLARE_CONF="E:\Works\palpo-im\floria\floria.kdl.sample"
cargo run
```

## Docker

构建镜像：

```powershell
docker build -t floria .
```

使用挂载的配置文件运行：

```powershell
docker run --rm -p 5000:5000 -p 8000:8000 -v ${PWD}/floria.kdl.sample:/app/floria.kdl floria
```

## Docker Compose

`examples/` 目录下提供了示例 `compose.yml`。

```sh
cp floria.kdl.sample examples/floria.kdl
cd examples
docker compose up -d
```

详见 [`examples/compose.yml`](../../examples/compose.yml)。

## 许可证

基于 Apache 2.0 许可证。详见 `LICENSE`。
