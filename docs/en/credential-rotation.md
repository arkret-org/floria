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

- **Token (`.p8`) auth (recommended)**:
  1. Mint a new `.p8` in the Apple Developer Portal under the same Team ID; record the new `key_id`.
  2. Stage the new `keyfile` and `key_id` in config; keep `topic` unchanged unless the app bundle changes.
  3. Optionally tune `token_ttl_seconds` (default 3000s, max 3600s — Apple rejects tokens older than 60 minutes). Lower values force more frequent rotations and reduce blast radius if a token leaks.
  4. Roll the deployment; the gateway emits `floria_apns_jwt_rotations_total{reason="forced_rotation"}` whenever APNs returns `InvalidProviderToken`/`ExpiredProviderToken` and `floria_apns_token_auth_failures_total{reason}` for visibility.
  5. Revoke the old key in the Apple Developer Portal once `floria_apns_status_codes` no longer reports 403s.
- **Certificate (`.p12`) auth**:
  - Deploy the new PEM bundle before the old certificate expires; `floria_client_cert_expiry{pushkin}` exposes the on-disk expiry in unix epoch seconds.
  - Apple rotates root CA chains independently of your client cert — pin the trust chain in your image or pull `ca-certificates` updates regularly.
- Validate sandbox/production selection before restart because APNs tokens are environment-specific.

## FCM (HTTP v1)

- Rotate the Firebase service account JSON and keep `project_id` stable.
- The gateway caches OAuth access tokens in-memory; a restart guarantees the new credentials are in effect immediately.
- After rotation, verify quota/unavailable responses still classify as retryable and unregistered tokens still map to rejected token hashes.

## WebPush (VAPID)

- Mint a new EC P-256 keypair and serve the public key to subscribers under a new `vapid_key_id` — rotation only takes effect for *new* subscriptions until clients re-subscribe.
- Deploy the new private key as `vapid_private_key`. The gateway exposes `floria_webpush_vapid_active_key{pushkin, key_fingerprint, key_id}` whose value is the unix timestamp when the gateway loaded the key — alert if no rotation has happened in 90 days.
- VAPID keys do not expire on the server side, but rotating quarterly is recommended to limit exposure if a private key leaks.

## Domestic Android OEM Providers

- **Huawei / HONOR** — rotate `app_secret`; keep `app_id` stable. The OEM console does not support overlap windows, so push traffic will see brief 401s during deploy. Set `floria_jpush_dispatch_by_channel_total{channel_label}` alerts if you delegate Huawei via JPush.
- **Xiaomi** — rotate `app_secret`; verify `restricted_package_name` matches the app's manifest. Xiaomi accepts a short overlap window (~30 minutes); time the deploy accordingly.
- **OPPO / OPlus / OnePlus** — rotate `master_secret`; keep `app_key` stable. OPPO requires that the new key be used within 24 hours of mint; do not stage configs longer than that.
- **vivo** — rotate `app_secret`; keep `app_id` and `app_key` stable. Watch `floria_pushkin_dispatch_seconds{pushkin="vivo"}` for latency regressions during cutover.
- **JPush** — rotate `master_secret`; keep `app_key` stable. The JPush console invalidates the old secret immediately on issue of the new one, so deploy in a single rolling restart. With `third_party_channel` configured, the gateway tags retry metrics with the channel label so you can confirm the rotation reached each downstream OEM.

## Custom URL pushkin

- **Bearer**: rotate `bearer_token` server-side first, then deploy floria. Until floria restarts, the old token must remain valid.
- **HMAC**: bump `hmac_key_id` and `hmac_secret` together. Receivers should accept *both* the old and new key id during the overlap window so neither side blocks.
- **mTLS**: stage the new client certificate (`client_certfile`) and add its fingerprint on the receiver side first; then roll floria; then remove the old fingerprint.

## Service Auth (caller → gateway)

- Prefer `bearer_token_hashes` over raw `bearer_tokens` for fallback credentials.
- For HTTP Message Signature, publish the new Ed25519 public key under a new `signature_key_id`, deploy config, then switch callers to sign with the matching private key. The gateway tracks signed-request replays in `notify_auth.nonce_store`; bumping the key id resets the in-Redis nonce namespace automatically.
- For mTLS, add the new certificate fingerprint to `mtls_cert_fingerprints`, restart, verify `/ready`, then remove the old fingerprint after callers have migrated. When `mtls_subject_dn` or `mtls_subject_alt_names` are set, update those bindings together with the fingerprint — the gateway requires both to match.
- For replay-window tuning: `replay_window_seconds` should be ≥ `signature_max_skew_seconds` so a clock-skewed retry inside the signature's expiry window still rejects on replay. Operators using long-lived signatures (5 min+) should run the redis-backed nonce store to ensure replay rejections survive a single-instance restart.
