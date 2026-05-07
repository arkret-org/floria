# floria TODO

> 整理日期: 2026-05-07
> 范围: Contrix Push Gateway。当前基线: provider capability matrix 已冻结，production_mode 已落地。

## 当前状态摘要

- canonical surface: `/api/v1/push/{notify,describe,bridge/describe}`、`/api/v1/integration/describe`、`/health`、`/ready`、`/metrics`。
- legacy HTTP/DTO/config alias 已删除；service 模块拆分、privacy fail-closed、legacy-shaped reject、delivery receipt redaction 都有回归测试。
- F2 provider_capabilities matrix 已冻结到 `PROVIDER_CAPABILITIES_VERSION = "2026-05-07"`，新增 `credential_rotation`/`blind_wakeup_required` 字段，移除 scaffold notes。
- F3 `soflare.config.schema.json` 已落地为提交制品；F4 KDL/YAML round-trip + 等价性测试已加入。
- A1+A5+A3 production_mode 已落地：拒绝 anonymous、拒绝 bearer-only fallback、强制 Content-Digest，按 caller `service_type` 绑定 plaintext 政策。
- R4 metrics 扩展 `floria_notify_delivery_outcome_by_provider_total` / `_by_app_total`、`floria_notify_rate_limit_reject_total`、`floria_notify_dedup_lookup_total`、`floria_pushkin_dispatch_seconds`。
- R5 `/notify` 链路打 span（caller / request_id 字段），sub-events 自动继承。
- O3 加入 `tests/sample_config_secret_scan.rs` 防止真凭据进 sample；`tests/sample_config_parse.rs` 防 KDL/YAML grammar drift（已修复 sample.kdl bare-bool bug）。

## 标记说明

- `[ ]` 未完成
- `[~]` 部分完成
- `🅿` parallel-safe
- `🔒` sequential
- `⚠` privacy / auth / delivery contract 高风险

## P0 · Contract / Provider foundation

| # | 状态 | 任务 | 文件/区域 | 阻塞 |
|---|---|---|---|---|
| F1 🔒 | `[ ]` | Pushkin trait 重构（统一 result/retry/backoff/dedup binding） | `src/pushkin/*`、`src/service/*` | 需要先与 R3 retry queue 联调，单独提 PR |

## P1 · Privacy / Auth / Reliability

| # | 状态 | 任务 | 文件/区域 | 说明 |
|---|---|---|---|---|
| A2 ⚠ | `[~]` | HTTP Message Signature 完整化 | `src/auth.rs` | `@method/@target-uri/@authority/content-digest/created/expires` 已强制；下一步 nonce / replay-window store。 |
| A4 ⚠ | `[ ]` | mTLS trust roots + DID 绑定 | auth config | 已有 `mtls_cert_fingerprints` 白名单；TLS-side trust roots 需 reverse-proxy 协同。 |
| R1 🅿 | `[ ]` | Redis dedup 多实例语义 | `src/dedup.rs` | 当前 single-redis 工作；需要 cluster / hash strategy 与一致性边界。 |
| R2 🅿 | `[ ]` | Redis rate-limit 持久化 | `src/rate_limit.rs` | 当前内存窗口；多实例需要 sliding window 的 redis 实现。 |
| R3 🅿 | `[ ]` | retry / dead-letter queue | delivery queue | provider 失败后的重试、最大尝试次数、失败回报事件。 |

## P2 · Provider / Ops / CI

| # | 状态 | 任务 | 说明 |
|---|---|---|---|
| B1 🅿 | `[ ]` | APNs token rotation / cert fallback | JWT 轮换与失败回退实现 |
| B2 🅿 | `[ ]` | FCM v1 batching | 群播优化时引入官方 batch 策略 |
| B3 🅿 | `[ ]` | WebPush VAPID rotation | public key / lifetime 管理并对外 describe |
| B4 🅿 | `[ ]` | JPush channel-aware retry | `third_party_channel` 升级到按 channel 处理重试/限流 |
| B5 🅿 | `[ ]` | Custom URL pushkin | HMAC / Bearer / mTLS 三套出站鉴权 |
| O1 🅿 | `[ ]` | Docker 最小镜像 | multi-stage 减少运行镜像 |
| O2 🅿 | `[ ]` | provider credential rotation 文档 | OPPO / vivo / 极光 / 华为运维手册 |
| O5 🅿 | `[ ]` | blackbox tests 拆分 | 按 pushkin / 主题拆文件 |

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C4 | bridge/describe `provider_capabilities_version=2026-05-07` 已对外冻结；通知 `soland` drift detection、`chime` typed DTO、`yougen` real token、`cotest` privacy matrix 同步刷新。 |
| C8 | 已为 cotest 暴露 plaintext-policy / production_mode 失败向量；live gateway rows 仍待挂入 cotest live matrix。 |
| C9 | health/ready/metrics + production_mode + sample-secret scan 已落地；CI 接入仍需 ops 侧。 |

## 已完成（短 changelog）

- `[x]` active-only surface 和 legacy cleanup。
- `[x]` FCM HTTP v1 单一路径。
- `[x]` service 拆模块和 privacy fail-closed 回归测试。
- `[x]` F2 provider_capabilities matrix 冻结 + 版本化。
- `[x]` F3 `soflare.config.schema.json` 制品 + 一致性快照测试。
- `[x]` F4 KDL/YAML round-trip 等价性测试。
- `[x]` A1 plaintext metadata 绑定 caller `service_type`。
- `[x]` A2 signed required-component 强制（`@method/@target-uri/@authority/content-digest`）。
- `[x]` A3 Content-Digest 在 production_mode 下对所有 /notify body 强制。
- `[x]` A5 production_mode 禁用 anonymous + bearer-only fallback。
- `[x]` R4 per-pushkin / per-app / scope metrics + dispatch latency histogram。
- `[x]` R5 `/notify` span + caller/request_id 结构化字段。
- `[x]` O3 sample-secret scan + sample-config grammar regression tests。
- `[x]` O4 production_mode startup validation（service_principal 必须签名/mTLS、禁用 gateway-wide bearer、plaintext 限制于 sync/principal kind）。
- `[x]` 修复 `*.sample.kdl` 在 KDL 2.0 下 bare-bool 解析失败的隐藏 bug（已加回归测试）。
