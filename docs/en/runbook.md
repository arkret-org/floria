# floria Operational Runbook

This runbook covers the operational tasks specific to running a production
floria push gateway. Provider-credential rotation specifics live in
[`credential-rotation.md`](./credential-rotation.md); this file focuses on
the higher-level operational decisions that ops engineers face on-call.

## APNS provider cert rotation

The APNS surface supports two auth modes: JWT (`.p8`) and certificate
(`.p12`). The JWT mode is the recommended posture; the cert mode remains
available for deployments that require APNS certificate authentication.

### Pre-rotation checklist

1. Verify alert `floria_client_cert_expiry{pushkin="apns"}` — confirm the
   current cert is still inside its validity window. Rotation MUST land
   before expiry; rotation under expiry leaves a delivery gap.
2. Confirm a non-production stage exists for this APNS topic. Cert
   rotations have non-trivial blast radius — never rotate the production
   cert as your first move.
3. Capture the current `floria_apns_status_codes{}` baseline. Post-rotation
   you'll compare against this.

### Rotation steps

1. Mint the new cert in the Apple Developer Portal, exported as `.p12` or
   converted to PEM with `openssl pkcs12 -in newcert.p12 -out newcert.pem -nodes`.
2. Stage the new PEM bundle on disk; do **not** swap the active config
   yet. Old cert remains in `cert_file`; new cert lands under a staging
   path.
3. Roll one canary instance with the new cert. Observe
   `floria_apns_status_codes` for 5 minutes; 403s here mean the new cert
   isn't accepted (wrong topic, wrong environment, wrong team).
4. If canary is clean, roll the rest of the fleet.
5. Old cert remains valid in the Apple console until the next ceremony;
   leave it provisioned for at least 24h to allow rollback.
6. After 24h, revoke the old cert in the Apple console and remove the old
   PEM from disk.

### Rollback

If rotation produces a 403 spike on any instance:

1. Re-stage the old PEM; flip the canary back; re-roll.
2. The old cert is still valid until you've revoked it in the Apple
   console, so rollback is reversible inside that window.

## FCM service account rotation

FCM's HTTP v1 API uses Google service-account credentials (a JSON keyfile
with an OAuth 2.0 service account). Rotation is conceptually simpler than
APNS but has a few sharp edges.

### Pre-rotation checklist

1. Confirm the service account has `firebaseMessaging.messages.send` in
   IAM and **only** that. Rotation is a good moment to audit privilege
   creep.
2. Capture the current `floria_fcm_dispatch_total{outcome="ok" | "retryable" | "rejected"}` baseline.
3. Verify no client-side `Unregistered` token spike is in flight; rotating
   during a spike makes the post-rotation signal hard to read.

### Rotation steps

1. In the Google Cloud console, generate a new key on the service account.
   This adds a new active key — both old and new are valid until you
   delete the old.
2. Stage the new JSON keyfile on disk under a versioned path
   (`fcm/sa-key-YYYY-MM.json`).
3. Update floria config to point at the new keyfile. The gateway's in-memory
   OAuth access-token cache is invalidated on config reload (or restart);
   confirm via logs that the next `getAccessToken` call uses the new
   credentials.
4. Roll the deployment. Observe `floria_fcm_dispatch_total` for 5 minutes;
   compare to baseline. Watch specifically for an `outcome="rejected"`
   spike — usually a sign that the new key lacks the right IAM role.
5. After 24h, delete the old key from the Google Cloud console.

### Rollback

If the new key produces a rejected-outcome spike:

1. Re-point config at the old keyfile; restart.
2. The old key remains valid until explicitly deleted, so rollback is
   reversible inside the same console session.

## Blind-wakeup vs visible notification profile selection

floria can issue two profiles of notifications to a device:

- **Blind wakeup** — silent / data-only notification; the device wakes
  the app, the app pulls the actual payload from the protocol layer
  (soland / inkson), no user-visible notification is rendered by the OS.
- **Visible notification** — OS-rendered banner / sound / badge; the
  payload itself carries the displayable content.

Profile selection is **per-delivery**, driven by the realm's policy and
the destination device's capabilities. The decision tree:

```text
                   notification arrives at floria
                              │
                              ▼
            ┌─────────────────────────────────────┐
            │ Realm has ck.profile.delivery.visible_required.v1? │
            └─────────────────────────────────────┘
                       │             │
                       │ Yes         │ No
                       ▼             ▼
                  visible       ┌────────────────────────────┐
                                │ Destination device         │
                                │ profile includes           │
                                │ ck.profile.delivery.blind_wakeup.v1? │
                                └────────────────────────────┘
                                          │           │
                                          │ Yes       │ No
                                          ▼           ▼
                              ┌──────────────────┐  visible
                              │ Payload size     │
                              │ <= blind_wakeup_max_bytes (default 1024)? │
                              └──────────────────┘
                                  │           │
                                  │ Yes       │ No
                                  ▼           ▼
                               blind       visible
```

Rules:

1. **Visible-required overrides everything.** If the realm has declared
   `ck.profile.delivery.visible_required.v1`, all notifications are
   visible regardless of device capability. This is the regulated /
   high-assurance posture.
2. **Blind wakeup needs both ends.** Both the realm AND the device must
   carry the blind-wakeup profile. A realm-only declaration produces a
   visible notification.
3. **Payload-size gate.** Blind wakeup payloads MUST fit within
   `blind_wakeup_max_bytes` (default 1024). Larger payloads fall back to
   visible. The gate is in place because the OS will silently drop
   oversized silent pushes on iOS, producing invisible delivery loss.
4. **Battery-saver fallback.** iOS / Android in low-power states throttle
   silent pushes harder than visible. If a device has reported
   `low_power_mode = true` in its last presence beacon, the gateway
   forces visible. Metric:
   `floria_delivery_profile_total{profile="visible", reason="low_power_fallback"}`.

Privacy boundary: visible notifications are provider- and OS-visible by
design. Only callers with `allow_plaintext_metadata=true` and a reviewed
eligible `service_type` may supply displayable title/body metadata. Any
change to `is_plaintext_eligible_service_kind` or any newly accepted
visible plaintext field needs a fresh privacy review before rollout.

Operational signals:

- `floria_delivery_profile_total{profile, reason}` — counter of every
  notification by chosen profile and the deciding reason.
- `floria_blind_wakeup_payload_overrun_total` — counter of dispatches
  that fell back to visible because of the payload-size gate. A spike
  usually means a client is packing too much into the wakeup envelope;
  file a bug against the client.
- `floria_visible_delivery_latency_seconds{provider}` — latency of
  visible deliveries by provider. Compare against
  `floria_blind_wakeup_dispatch_seconds{provider}` for the same provider;
  if visible >> blind, your provider is throttling silent pushes harder
  than you assumed.

## Media token issuer role in v1 (proxy posture)

floria's role in the `ck.self.call.media.exchange.issue_token` strand is **not an
issuer** in v1. The current floria HTTP router and describe endpoints do
not expose a public `/rtc/token` minting surface. If a deployment adds a
separate proxy in front of soland, the canonical issuer is still soland
and floria must relay responses byte-for-byte without caching,
re-signing, or mutating tokens. See
[`docs/zh/media-token-issuer-cn.md`](../zh/media-token-issuer-cn.md) for
the Chinese summary of this decision and the rationale.

There is no local media-token signing module in floria. If you see floria
attempting to mint a token locally, or `/_cokret/describe` advertising an
RTC/media token self-issue feature, that is a bug.
