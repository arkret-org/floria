# floria TODO

> 整理日期: 2026-05-07
> 范围: Contrix Push Gateway。当前基线: provider capability matrix 已冻结，production_mode 已落地，retry/DLQ + replay nonce + Redis 限流 + Custom URL pushkin 已落地。

## 当前状态摘要

- canonical surface: `/api/v1/push/{notify,describe,bridge/describe}`、`/api/v1/integration/describe`、`/health`、`/ready`、`/metrics`。
- legacy HTTP/DTO/config alias 已删除；service 模块拆分、privacy fail-closed、legacy-shaped reject、delivery receipt redaction 都有回归测试。
- F2 provider_capabilities matrix 已冻结到 `PROVIDER_CAPABILITIES_VERSION = "2026-05-07"`。
- 全功能面（A1-A5、R1-R5、B1-B5、O1-O5、F1/F3/F4）已落地。
- 本仓唯一剩余开放项是 TLS-side trust roots 需 reverse-proxy 协同。

## 标记说明

- `[ ]` 未完成
- `[~]` 部分完成
- `🅿` parallel-safe
- `🔒` sequential
- `⚠` privacy / auth / delivery contract 高风险

## 开放任务

| # | 状态 | 任务 | 文件/区域 | 说明 |
|---|---|---|---|---|
| A4-tls 🔒 ⚠ | `[~]` | TLS-side trust roots | reverse-proxy 配置 | gateway 已强制 `mtls_subject_dn`/`mtls_subject_alt_names` 与 fingerprint allowlist；TLS 终结端的 trust root 链仍需 reverse-proxy 协同。 |

## 跨项目登记

| 根任务 | 本仓责任 |
|---|---|
| C4 | bridge/describe `provider_capabilities_version=2026-05-07` 已对外冻结；通知 `soland` drift detection、`chime` typed DTO、`yougen` real token、`cotest` privacy matrix 同步刷新；新增 `custom` kind 已加入 capability matrix。 |
| C8 | 已为 cotest 暴露 plaintext-policy / production_mode 失败向量；live gateway rows 仍待挂入 cotest live matrix。 |
| C9 | health/ready/metrics + production_mode + sample-secret scan + retry/DLQ + replay nonce + per-channel metrics 已落地；CI 接入仍需 ops 侧。 |

## 已完成（changelog）

- `[x]` active-only surface 和 legacy cleanup。
- `[x]` F1 unified `DispatchOutcome`、F2 provider_capabilities matrix 冻结、F3 config schema、F4 KDL/YAML round-trip。
- `[x]` A1 plaintext metadata 绑定、A2 HTTP Message Signature + nonce/replay、A3 Content-Digest 强制、A4 mTLS fingerprint allowlist + Subject DN/SAN binding、A5 production_mode 禁用 anonymous。
- `[x]` R1 Redis dedup、R2 Redis rate-limit、R3 retry/DLQ + 后台 worker、R4 per-pushkin/per-app metrics、R5 `/notify` span。
- `[x]` B1 APNs JWT rotation、B2 FCM HTTP/2 batching、B3 WebPush VAPID rotation、B4 JPush channel-aware retry、B5 Custom URL pushkin。
- `[x]` O1 Dockerfile 多阶段最小化、O2 credential-rotation runbook、O3 sample-secret scan + grammar regression、O4 production_mode startup validation、O5 service blackbox tests 拆分。
