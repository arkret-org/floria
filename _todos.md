# floria Active TODO

> 更新日期: 2026-04-29
> 范围: Contrix Push Gateway，负责接收授权服务的 `cx.push.notify` 请求并投递到 APNs、FCM、WebPush、JPush 和国内 Android OEM 通道。

## 0. 当前边界

- `floria` 是 Push Gateway，不负责客户端设备注册；设备注册由 Principal Server / Sync Service 提供，客户端 helper 在 `chime`。
- 当前已实现 `/api/v1/push/notify` 与 `/contrix/push/v1/notify`、多 provider、Prometheus metrics、配置文件、内存 dedup。
- 当前主要缺口是 HTTP Message Signature / mTLS、未授权元数据约束、HA dedup、rate limiting 和端到端联调。

## P0: Contrix Notify Wire Contract

目标: `floria` 与 `contrix-spec/discovery/push-notifications.md`、`sync/service-http-binding.md` 对齐。

- [x] 固定 canonical endpoint:
  - [x] `POST /api/v1/push/notify` 为主路径。
  - [x] `/contrix/push/v1/notify` 标记为 compatibility path。
  - [x] `GET/PUT/DELETE` 返回标准 `method_not_allowed`。
- [ ] 请求 schema:
  - [ ] operation id `cx.push.notify`。
  - [ ] notification id / idempotency key。
  - [ ] sender service DID。
  - [x] target devices。
  - [x] app id。
  - [x] push key。
  - [ ] platform。
  - [x] body-free `push_hint`。
  - [x] unread / highlight counts。
  - [ ] wakeup reason。
- [x] 响应 schema:
  - [x] accepted count。
  - [x] rejected tokens。
  - [x] per-provider retry metadata。
  - [x] request id。
  - [x] idempotent duplicate response。
- [ ] 标准错误 envelope:
  - [x] invalid request。
  - [x] unauthenticated。
  - [x] capability denied。
  - [ ] rate limited + `Retry-After`。
  - [x] provider unavailable。
  - [x] payload too large。

并行性: endpoint/error、schema/model、provider mapping 可并行；合并前必须通过同一 HTTP contract test。

## P0: Service Authentication and Authorization

目标: `/notify` 不能作为公网匿名推送接口。

- [ ] 支持 service authentication:
  - [ ] HTTP Message Signature。
  - [x] Bearer service token as deployment fallback。
  - [ ] mTLS as optional deployment profile。
- [ ] HTTP Message Signature 覆盖:
  - [ ] method。
  - [ ] target URI。
  - [ ] authority。
  - [ ] content digest。
  - [ ] origin service DID。
  - [ ] destination gateway DID。
  - [ ] created/expires。
- [ ] service DID 校验:
  - [ ] origin DID document service endpoint。
  - [x] destination DID 等于本 gateway。
  - [x] allowed principal/sync/index services allowlist。
- [ ] capability boundary:
  - [x] 只有授权 Sync / Index / Principal Server 可调用 notify。
  - [ ] 普通客户端 token 不允许调用 notify。
  - [x] rejected auth attempts 写安全审计。

## P0: Privacy and Secret Hygiene

目标: E2EE Space 下只做 blind wakeup，不泄露正文、密文和长期 token。

- [ ] Payload validation:
  - [x] 禁止 message body。
  - [x] 禁止 encrypted payload bytes。
  - [x] 禁止 SDP。
  - [x] 禁止 ICE candidate。
  - [x] 禁止 TURN credential。
  - [ ] 未授权时禁止 sender display name / Space name。
- [ ] push token 脱敏:
  - [x] tracing 字段中不输出完整 `pushkey` / `push_key`。
  - [x] error body 不回显完整 token。
  - [x] rejected list 只在调用方被授权时返回 token 或 token hash。
  - [x] provider error 日志脱敏。
- [ ] URL 安全:
  - [x] WebPush endpoint allowlist。
  - [ ] 禁止 query string 携带 credentials。
  - [ ] 出站 proxy 不记录 Authorization。
- [ ] 文档:
  - [ ] 明确 `push_hint` 是 body-free hint。
  - [ ] 明确 gateway 不存储 canonical truth。

## P0: Provider Delivery Correctness

- [ ] APNs:
  - [ ] token/cert auth 过期处理。
  - [ ] invalid token 映射为 rejected。
  - [ ] collapse id / priority / push type 合规。
- [ ] FCM:
  - [ ] HTTP v1 优先。
  - [ ] legacy batching compatibility。
  - [ ] unregistered token 映射。
  - [ ] quota / unavailable retry。
- [ ] WebPush:
  - [ ] VAPID key validation。
  - [ ] endpoint domain allowlist。
  - [ ] 410 Gone 映射。
- [ ] JPush / domestic OEM:
  - [ ] Huawei / HarmonyOS。
  - [ ] HONOR。
  - [ ] Xiaomi。
  - [ ] OPPO / OnePlus。
  - [ ] vivo。
  - [ ] per-provider invalid-token mapping。
- [x] Retry semantics:
  - [x] provider transient failure returns retryable status。
  - [x] permanent invalid token returns rejected。
  - [x] partial success does not force full retry。

## P1: HA, Dedup and Runtime Operations

- [ ] Dedup backend:
  - [ ] 内存 dedup 仅用于单实例。
  - [ ] Redis / external cache adapter。
  - [x] duplicate same body returns cached result。
  - [x] duplicate different body returns conflict。
- [ ] Rate limiting:
  - [ ] per origin service。
  - [ ] per app id。
  - [ ] per provider。
  - [ ] per push key hash。
- [ ] Observability:
  - [ ] `metrics.opentracing`。
  - [ ] `metrics.sentry`。
  - [ ] structured access log。
  - [ ] provider latency histogram。
  - [ ] rejected reason counters。
- [ ] Configuration:
  - [ ] `log.setup`。
  - [ ] config schema / validation。
  - [ ] secret file permissions check。
  - [ ] config reload policy。
- [ ] Deployment:
  - [ ] Docker health/readiness。
  - [ ] production sample for service DID and auth。
  - [ ] domestic Android production checklist。

## P1: Cross-Project Integration

- [ ] With `soland`:
  - [ ] register-device stores gateway URL compatible with floria。
  - [ ] invalid token rejected by floria causes soland cleanup。
  - [ ] push rules produce blind wakeup payload。
- [ ] With `chime`:
  - [ ] request builder payload matches gateway expectations。
  - [ ] token rotation / unregister roundtrip。
- [ ] With `cotest`:
  - [ ] mock provider mode。
  - [ ] E2E notify flow。
  - [ ] privacy regression vectors。
- [ ] With `chask`:
  - [ ] push settings UI can choose floria / Bugle endpoint。
  - [ ] E2EE notification does not show body preview。

## Definition of Done

- [ ] `/api/v1/push/notify` requires authenticated service caller in production。
- [x] No logs, metrics labels or error responses expose full push token。
- [x] E2EE payload validation rejects body/ciphertext/signaling leakage。
- [x] Provider failure mapping has unit tests and HTTP contract tests。
- [ ] Real `soland -> floria -> provider mock` flow passes in `cotest`。
