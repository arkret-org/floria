# floria TODO

> 更新时间：2026-05-06
> 当前基线：仓内 legacy/compat 路径已清理到 active-only。

## 已完成收口

- canonical surface 只保留 `/api/v1/push/{notify,describe,bridge/describe}`、`/api/v1/integration/describe`、`/health`、`/ready` 和独立 `/metrics`
- 已删除旧 HTTP alias、DTO/config alias、`sender_service_did` / `push_key` / `plaintext_visible_services` 兼容入口
- FCM 已收敛为 HTTP v1 单一路径；`gcm` / `api_version` / legacy batching 已移除
- examples / sample config / README / configuration 文档已同步到 active-only
- service 已拆模块，privacy fail-closed、legacy-shaped input reject、delivery receipt redaction 已有回归测试

## 本仓剩余任务

### P0 · 近期可独立推进

| # | 任务 | 说明 |
|---|---|---|
| F2 | Pushkin trait 重构 | 抽统一 provider result / retry / backoff / dedup binding，减少各 pushkin 自己拼 dispatch 生命周期 |
| F4 | 配置 schema 产物 | 输出单一 `soflare.config.schema.json`，让 KDL/YAML 共用一套 schema |
| F-2 | config round-trip 测试 | 补 KDL/YAML -> JSON -> config 的 round-trip 覆盖，防止格式漂移 |
| E1 | `bridge/describe` 的 `provider_capabilities` | 暴露每个 provider 对 batch / TTL / collapse / badge/default payload 等能力矩阵 |

### P1 · Privacy / Auth / Reliability

| # | 任务 | 说明 |
|---|---|---|
| A3 | plaintext metadata policy 注入 | 从 spec/artifacts 读 active service kind，并把 plaintext-visible policy 绑定到 caller kind |
| C1 | Redis dedup 多实例语义 | 扩展 cluster / hash strategy，明确多实例一致性边界 |
| C2 | rate-limit 持久化 | 内存限流替换为 Redis 窗口实现 |
| C3 | retry / dead-letter queue | provider 失败后的重试队列、最大尝试次数和失败回报事件 |
| C4 | metrics 扩展 | 增加 per-pushkin/per-app outcome、latency、dedup、rate-limit breakdown |
| C5 | structured tracing | `/notify` 全链路 span，带 caller / app_id / provider / outcome |
| D1 | HTTP Message Signature 完整化 | 强制 `@method` / `@target-uri` / `@authority` / `content-digest` / `created` / `expires` |
| D2 | Content-Digest 强制 | `/notify` 请求体必须通过 RFC 9530 digest 校验 |
| D3 | mTLS trust roots + DID 绑定 | 配置化 client cert trust roots 与 service DID 绑定 |
| D4 | production 禁用 bearer fallback | 非开发模式仅允许 HTTP Signature / mTLS |

### P2 · Provider / Ops / CI

| # | 任务 | 说明 |
|---|---|---|
| B1 | APNs token rotation / cert fallback | 明确 JWT 轮换与失败回退行为 |
| B2 | FCM v1 batching | 若仍需要群播优化，再引入官方 v1 batch 策略 |
| B3 | WebPush VAPID rotation | 管理 public key / lifetime 并对外 describe |
| B4 | JPush channel-aware retry | 把 `third_party_channel` 从透传升级到按 channel 处理重试/限流 |
| B5 | Custom URL pushkin | HMAC / Bearer / mTLS 三套出站鉴权模型 |
| F-1 | Docker 最小镜像 | multi-stage，压缩运行镜像体积 |
| F-3 | provider credential rotation 文档 | 补 OPPO / vivo / 极光 / 华为等轮换手册 |
| Q3 | sample secret scan | 对 `*.sample.{yaml,kdl}` 做真值扫描，防止误提交 |
| Q4 | production feature 安全收口 | dev-only / mock path 在 production 下硬关闭 |
| Q5 | blackbox tests 拆分 | 按 pushkin / 主题拆文件，方便并行扩展 |

## 跨仓任务

| # | 任务 | 说明 |
|---|---|---|
| S1 | 与 soland 联调 `bridge/describe` / drift detection | 需要跨仓稳定 contract version |
| S2 | 与 chime SDK 联调 | 验证 register/unregister/notify shape |
| S3 | 接入 cotest live matrix | 让 floria 成为默认 compose harness 的真实外部依赖 |
| S4 | conformance negative vectors | DID leak / plaintext violation / blind-wakeup-with-body 联调测试 |
