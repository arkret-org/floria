# 凭据轮换 Runbook

本文覆盖 floria 部署中的 provider 凭据与 service auth 凭据轮换。

## 通用步骤

1. 先在 provider 控制台或上游服务中添加新凭据。
2. 更新 floria 配置中的 credential path、token hash、key id 或 secret。
3. 保持旧凭据有效，直到所有 floria 实例重启完成且 `/ready` 返回 `200`。
4. 发送 provider mock 或低风险测试推送，并确认网关内部 telemetry 只包含 provider/status/token-hash metadata；同步 notify 响应中不得出现这些字段。
5. 在 provider 控制台或上游服务中吊销旧凭据。
6. 观察 `/metrics`、日志和 provider dashboard，确认没有 retry 或 invalid-token 异常尖峰。

## APNs

- **Token (`.p8`) 认证（推荐）**：
  1. 在 Apple Developer Portal 同 Team ID 下生成新的 `.p8`，记录新 `key_id`。
  2. 在配置中替换 `keyfile` 与 `key_id`；除非 app bundle 变化，否则保持 `topic` 不变。
  3. 可选调整 `token_ttl_seconds`（默认 3000s，最大 3600s — Apple 拒绝超过 60 分钟的 token）。降低 TTL 会强制更频繁地轮换 token，减少 token 泄漏的爆炸半径。
  4. 滚动部署。当 APNs 返回 `InvalidProviderToken` / `ExpiredProviderToken` 时，gateway 会增加 `floria_apns_jwt_rotations_total{reason="forced_rotation"}`，并通过 `floria_apns_token_auth_failures_total{reason}` 暴露原因。
  5. 在 `floria_apns_status_codes` 中确认 403 已不再出现后再吊销旧 key。
- **证书 (`.p12`) 认证**：
  - 在旧证书过期前部署新的 PEM bundle；`floria_client_cert_expiry{pushkin}` 暴露磁盘上证书的过期时间（unix epoch 秒）。
  - Apple 的根 CA 链与你的 client cert 独立轮换 — 把信任链固化进镜像，或定期更新 `ca-certificates`。
- 重启前确认 sandbox/production 选择正确，因为 APNs token 与环境绑定。

## FCM (HTTP v1)

- 轮换 Firebase service account JSON，并保持 `project_id` 稳定。
- gateway 在内存中缓存 OAuth access token；重启即可让新凭据立刻生效。
- 轮换后确认 quota/unavailable 仍被分类为 retryable，unregistered token 仍映射为 rejected token hash。

## WebPush (VAPID)

- 生成新的 EC P-256 keypair，把公钥用新的 `vapid_key_id` 下发给订阅方 — 轮换只对 *新* 订阅生效，老订阅方需要重新订阅。
- 部署新的私钥为 `vapid_private_key`。gateway 暴露 `floria_webpush_vapid_active_key{pushkin, key_fingerprint, key_id}`，其值是 gateway 加载该密钥时的 unix 时间戳 — 如果 90 天没有轮换则告警。
- VAPID 私钥服务端不会自动失效，但建议每季度轮换一次以限制密钥泄漏风险。

## 国内 Android OEM Provider

- **Huawei / HONOR** — 轮换 `app_secret`，保持 `app_id` 稳定。OEM 控制台不支持重叠窗口，部署期间会出现短暂的 401。如果通过 JPush 转发 Huawei，请对 `floria_jpush_dispatch_by_channel_total{channel_label}` 做告警。
- **Xiaomi** — 轮换 `app_secret`，确认 `restricted_package_name` 与 app manifest 保持一致。Xiaomi 接受约 30 分钟的重叠窗口，可据此安排部署。
- **OPPO / OPlus / OnePlus** — 轮换 `master_secret`，保持 `app_key` 稳定。OPPO 要求新 key 在生成 24 小时内启用，配置不要在文件里搁置太久。
- **vivo** — 轮换 `app_secret`，保持 `app_id` 与 `app_key` 稳定。切换期间观察 `floria_pushkin_dispatch_seconds{pushkin="vivo"}` 是否有时延回退。
- **JPush** — 轮换 `master_secret`，保持 `app_key` 稳定。JPush 控制台一旦签发新 secret 即立刻吊销旧 secret，因此用单次滚动部署完成切换。如果配置了 `third_party_channel`，gateway 会用 channel label 标记重试 metrics，便于确认轮换已传导到各 OEM。

## Custom URL pushkin

- **Bearer**：先在接收端轮换 `bearer_token`，再部署 floria。floria 重启之前，旧 token 必须保持有效。
- **HMAC**：`hmac_key_id` 与 `hmac_secret` 一起切换。接收端应在重叠窗口期间同时接受新旧 key id，避免任一侧拒绝请求。
- **mTLS**：先把新的客户端证书 (`client_certfile`) 与其指纹同步到接收端；再滚动 floria；最后移除旧指纹。

## Service Auth（caller → gateway）

- bearer fallback 优先使用 `bearer_token_hashes`，避免在配置中保存 raw `bearer_tokens`。
- HTTP Message Signature：为新的 Ed25519 公钥发布新的 `signature_key_id`，部署配置后再让调用方切换到对应私钥签名。gateway 通过 `notify_auth.nonce_store` 记录已用过的签名指纹；切换 key id 会自然地重置 Redis 中的 nonce 命名空间。
- mTLS：先把新证书指纹加入 `mtls_cert_fingerprints`，重启并验证 `/ready`，待调用方迁移后再移除旧指纹。当配置了 `mtls_subject_dn` 或 `mtls_subject_alt_names` 时，请把它们与指纹一起更新 — gateway 要求两者同时匹配。
- 重放窗口：`replay_window_seconds` 应 ≥ `signature_max_skew_seconds`，以便时钟偏差范围内的重放请求依然能被识别。使用较长签名有效期（5 分钟以上）的 operator 应启用 redis-backed nonce store，确保单实例重启不会丢失重放保护状态。
