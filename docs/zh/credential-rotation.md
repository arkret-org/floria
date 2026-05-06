# 凭据轮换 Runbook

本文覆盖 floria 部署中的 provider 凭据与 service auth 凭据轮换。

## 通用步骤

1. 先在 provider 控制台或上游服务中添加新凭据。
2. 更新 floria 配置中的 credential path、token hash、key id 或 secret。
3. 保持旧凭据有效，直到所有 floria 实例重启完成且 `/ready` 返回 `200`。
4. 发送 provider mock 或低风险测试推送，并确认 delivery receipt 只包含 provider/status/token-hash metadata。
5. 在 provider 控制台或上游服务中吊销旧凭据。
6. 观察 `/metrics`、日志和 provider dashboard，确认没有 retry 或 invalid-token 异常尖峰。

## APNs

- Token auth：`.p8` key、`key_id`、`team_id` 需要成组轮换。除非 app bundle 变化，否则保持 `topic` 不变。
- Certificate auth：在旧证书过期前部署新的 PEM bundle。`/ready` 确认配置可用，证书过期预警会在启动时输出。
- 重启前确认 sandbox/production 选择正确，因为 APNs token 与环境绑定。

## FCM

- HTTP v1：轮换 Firebase service account JSON，并保持 `project_id` 稳定。
- Legacy：优先迁移到 HTTP v1。如果仍启用 legacy，在短暂重叠窗口内轮换 `api_key`。
- 轮换后确认 quota/unavailable 仍被分类为 retryable，unregistered token 仍映射为 rejected token hash。

## 国内 Android OEM Provider

- Huawei/HONOR：轮换 `app_secret`，保持 `app_id` 稳定。
- Xiaomi：轮换 `app_secret`，确认 `restricted_package_name`。
- OPPO/OPlus/OnePlus：轮换 `master_secret`，保持 `app_key` 稳定。
- vivo：轮换 `app_secret`，保持 `app_id` 与 `app_key` 稳定。
- JPush：轮换 `master_secret`，保持 `app_key` 稳定。

## Service Auth

- bearer fallback 优先使用 `bearer_token_hashes`，避免在配置中保存 raw `bearer_tokens`。
- HTTP Message Signature：为新的 Ed25519 公钥发布新的 `signature_key_id`，部署配置后再让调用方切换到对应私钥签名。
- mTLS：先把新证书指纹加入 `mtls_cert_fingerprints`，重启并验证 `/ready`，待调用方迁移后再移除旧指纹。
