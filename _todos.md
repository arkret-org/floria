# floria TODO

> 整理日期: 2026-05-07
> 范围: Contrix Push Gateway。当前基线: provider capability matrix 已冻结，production_mode 已落地，retry/DLQ + replay nonce + Redis 限流 + Custom URL pushkin 已落地。

## 当前状态摘要

- canonical surface: `/api/v1/push/{notify,describe,bridge/describe}`、`/api/v1/integration/describe`、`/health`、`/ready`、`/metrics`。
- legacy HTTP/DTO/config alias 已删除；service 模块拆分、privacy fail-closed、legacy-shaped reject、delivery receipt redaction 都有回归测试。
- F2 provider_capabilities matrix 已冻结到 `PROVIDER_CAPABILITIES_VERSION = "2026-05-07"`，新增 `credential_rotation`/`blind_wakeup_required` 字段，移除 scaffold notes。
- F3 `soflare.config.schema.json` 已落地为提交制品；F4 KDL/YAML round-trip + 等价性测试已加入。
- A1+A5+A3 production_mode 已落地：拒绝 anonymous、拒绝 bearer-only fallback、强制 Content-Digest，按 caller `service_type` 绑定 plaintext 政策。
- R4 metrics 扩展 `floria_notify_delivery_outcome_by_provider_total` / `_by_app_total`、`floria_notify_rate_limit_reject_total`、`floria_notify_dedup_lookup_total`、`floria_pushkin_dispatch_seconds`。
- R5 `/notify` 链路打 span（caller / request_id 字段），sub-events 自动继承。
- O3 加入 `tests/sample_config_secret_scan.rs` 防止真凭据进 sample；`tests/sample_config_parse.rs` 防 KDL/YAML grammar drift（已修复 sample.kdl bare-bool bug）。
- F1 unified `DispatchOutcome` 已加入 trait 默认实现（向后兼容现有 9 个 pushkin）。
- R1 dedup 在 Redis cluster hash tag 化；R2 rate-limit 增加 Redis 后端（Lua atomic）；R3 retry/DLQ + 后台 worker 已落地。
- A2 HTTP Message Signature 增加 nonce/replay-window store（memory + redis）；A4 mTLS Subject DN / SAN binding 已落地。
- B1 APNs JWT 强制旋转 (`token_ttl_seconds`、`InvalidProviderToken` 触发立即 rotation)；B2 FCM HTTP/2 显式 + multicast 工具；B3 WebPush 暴露 `vapid_key_id` + 指纹 metric；B4 JPush channel-aware retry/backoff + per-channel metric；B5 Custom URL pushkin（HMAC / Bearer / mTLS）已落地。
- O1 Dockerfile 多阶段最小化（cargo cache + 非 root user）；O2 `docs/{en,zh}/credential-rotation.md` 全 provider 与 service auth 凭据轮换 runbook 已更新。

## 标记说明

- `[ ]` 未完成
- `[~]` 部分完成
- `🅿` parallel-safe
- `🔒` sequential
- `⚠` privacy / auth / delivery contract 高风险

## P1 · 跨项目 / 运维仍需联动

| # | 状态 | 任务 | 文件/区域 | 说明 |
|---|---|---|---|---|
| A4-tls 🔒 ⚠ | `[~]` | TLS-side trust roots | reverse-proxy 配置 | gateway 已强制 `mtls_subject_dn`/`mtls_subject_alt_names` 与 fingerprint allowlist；TLS 终结端的 trust root 链仍需 reverse-proxy 协同。 |

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C4 | bridge/describe `provider_capabilities_version=2026-05-07` 已对外冻结；通知 `soland` drift detection、`chime` typed DTO、`yougen` real token、`cotest` privacy matrix 同步刷新；新增 `custom` kind 已加入 capability matrix。 |
| C8 | 已为 cotest 暴露 plaintext-policy / production_mode 失败向量；live gateway rows 仍待挂入 cotest live matrix。 |
| C9 | health/ready/metrics + production_mode + sample-secret scan + retry/DLQ + replay nonce + per-channel metrics 已落地；CI 接入仍需 ops 侧。 |

## 已完成（短 changelog）

- `[x]` active-only surface 和 legacy cleanup。
- `[x]` FCM HTTP v1 单一路径。
- `[x]` service 拆模块和 privacy fail-closed 回归测试。
- `[x]` F2 provider_capabilities matrix 冻结 + 版本化。
- `[x]` F3 `soflare.config.schema.json` 制品 + 一致性快照测试。
- `[x]` F4 KDL/YAML round-trip 等价性测试。
- `[x]` A1 plaintext metadata 绑定 caller `service_type`。
- `[x]` A2 signed required-component 强制（`@method/@target-uri/@authority/content-digest`）；nonce / replay-window store（memory + redis）。
- `[x]` A3 Content-Digest 在 production_mode 下对所有 /notify body 强制。
- `[x]` A4 mTLS fingerprint allowlist + Subject DN 严格匹配 + Subject Alternative Names binding（DID 绑定）。
- `[x]` A5 production_mode 禁用 anonymous + bearer-only fallback。
- `[x]` R1 Redis dedup multi-instance：cluster hash tag、fail-open semantics 与文档化的一致性边界。
- `[x]` R2 Redis rate-limit 持久化（Lua atomic check-many；fail-open）。
- `[x]` R3 retry / dead-letter queue（memory + redis backend、exponential backoff、后台 worker、per-pushkin metrics）。
- `[x]` R4 per-pushkin / per-app / scope metrics + dispatch latency histogram + retry/DLQ/replay metrics。
- `[x]` R5 `/notify` span + caller/request_id 结构化字段。
- `[x]` F1 Pushkin trait 增加 unified `DispatchOutcome` 默认实现（向后兼容 9 个现有 pushkin）。
- `[x]` B1 APNs token rotation：`token_ttl_seconds`、`InvalidProviderToken`/`ExpiredProviderToken` 立即 rotation、`floria_apns_jwt_rotations_total`/`floria_apns_token_auth_failures_total` metrics。
- `[x]` B2 FCM v1 batching：HTTP/2 显式 + adaptive_window、`dispatch_batch` 公共 API、`floria_fcm_batch_size`/`_dispatched_total` metrics。
- `[x]` B3 WebPush VAPID rotation：`vapid_key_id` 配置、key fingerprint metric、轮换 runbook。
- `[x]` B4 JPush channel-aware retry：channel_label、严格 channel (huawei/xiaomi) 翻倍 backoff、`floria_jpush_dispatch_by_channel_total` metric。
- `[x]` B5 Custom URL pushkin：`{pushkey}` URL 模板、Bearer/HMAC-SHA256/mTLS 三套出站鉴权。
- `[x]` O1 Dockerfile 多阶段最小化（deps 缓存层 + 非 root user + 移除 libcurl4 等无用依赖）。
- `[x]` O2 `docs/{en,zh}/credential-rotation.md` 全 provider + service auth + nonce store 凭据轮换 runbook。
- `[x]` O3 sample-secret scan + sample-config grammar regression tests。
- `[x]` O4 production_mode startup validation（service_principal 必须签名/mTLS、禁用 gateway-wide bearer、plaintext 限制于 sync/principal kind）。
- `[x]` O5 service blackbox tests 按主题拆分（basics / auth / dedup / rate_limit / legacy / delivery）。
- `[x]` 修复 `*.sample.kdl` 在 KDL 2.0 下 bare-bool 解析失败的隐藏 bug（已加回归测试）。
