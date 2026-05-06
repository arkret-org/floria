# Credential Rotation Runbook

This runbook covers provider and service-auth credential rotation for a running floria deployment.

## General Steps

1. Add the new credential to the provider console or upstream service first.
2. Update floria config with the new credential path, token hash, key id, or secret value.
3. Keep the old credential valid until all floria instances have restarted and `/ready` returns `200`.
4. Send a provider mock or low-risk test push and verify the delivery receipt contains only provider/status/token-hash metadata.
5. Revoke the old credential in the provider console or upstream service.
6. Watch `/metrics`, logs, and provider dashboards for retry or invalid-token spikes.

## APNs

- Token auth: rotate the `.p8` key, `key_id`, or `team_id` together. Keep `topic` unchanged unless the app bundle changes.
- Certificate auth: deploy the new PEM bundle before the old certificate expires. `/ready` confirms config sanity, while certificate expiry warnings are emitted at startup.
- Validate sandbox/production selection before restart because APNs tokens are environment-specific.

## FCM

- HTTP v1: rotate the Firebase service account JSON and keep `project_id` stable.
- Legacy: prefer migrating to HTTP v1. If legacy remains enabled, rotate `api_key` during a short overlap window.
- After rotation, verify quota/unavailable responses still classify as retryable and unregistered tokens still map to rejected token hashes.

## Domestic Android OEM Providers

- Huawei/HONOR: rotate `app_secret`; keep `app_id` stable.
- Xiaomi: rotate `app_secret`; verify `restricted_package_name`.
- OPPO/OPlus/OnePlus: rotate `master_secret`; keep `app_key` stable.
- vivo: rotate `app_secret`; keep `app_id` and `app_key` stable.
- JPush: rotate `master_secret`; keep `app_key` stable.

## Service Auth

- Prefer `bearer_token_hashes` over raw `bearer_tokens` for fallback credentials.
- For HTTP Message Signature, publish the new Ed25519 public key under a new `signature_key_id`, deploy config, then switch callers to sign with the matching private key.
- For mTLS, add the new certificate fingerprint to `mtls_cert_fingerprints`, restart, verify `/ready`, then remove the old fingerprint after callers have migrated.
