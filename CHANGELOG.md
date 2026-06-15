# Changelog

All notable changes to floria (Cokret push gateway) will be documented in this
file. The format is loosely based on [Keep a Changelog]; floria follows the
parent Cokret spec's round-numbering for grouping wire-breaking changes.

## R3.4 — Spec sync 2026-05-31 (cokret-spec @ c2848a4)

- Synced protocol-facing names and fixtures to `c2848a4`: event envelope schema naming, `_ids` grant constraints, accountability principal vocabulary, `ck:rtc_participant:` media participants, agent session start fields, and key-backup signature algorithm naming where applicable.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## R3.3 — Spec sync 2026-05-28 (cokret-spec @ cced4b8)

- R3.3 spec sync — pin to cokret-spec @ cced4b8 (CKP-0011 shareable object addressing / `ck.find.directory.query.resolve_target`: N/A for this service; object-address resolution belongs to the Directory Service).

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.
## R3.2 — Spec sync 2026-05-28 (cokret-spec @ b56cab1)

- Audited for mention-reference wire fields: none present (push gateway routes by DID actor lists; `deny_unknown_fields` rejects stray removed fields). No wire change required for the §3.8 mention shape v2.
- Synced to cokret-spec @ b56cab1; media token signing remains `TODO(R3.2.1)`.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.
## R3 — Spec sync 2026-05-27 (cokret-spec @ b47ff6ec)

- MEDIA-1: documented floria's `ck.self.call.media.exchange.issue_token` role — proxy-to-soland for the v1 cycle; self-issue (option b) deferred to R3.1. Role decision lives in `src/media.rs` module docs.
- MEDIA-2: Cokret-native binding token scaffolding (`CokretNativeBackendToken`, `CokretNativeTokenPayload`, `CokretNativeMediaCaps`) per `bindings/cokret-native.md` §2; signing path fails closed until R3.1.
- MEDIA-3: LiveKit binding token scaffolding (`LiveKitBackendToken`, `LiveKitClaims`, `LiveKitVideoGrant`) — `video.recorder=false` by construction, no `metadata` / `canUpdateOwnMetadata`; HS256 JWT signing path stubbed for R3.1.
- MEDIA-4 / MEDIA-5: TTL ceiling (`TOKEN_TTL_MAX_SECS` = 600s, default 300s), issuer-anchor / focus-strict-match guards, and canonical `participant_binding` bytes helper (`participant_binding_canonical_bytes`); Ed25519 signing fails closed pending R3.1.
- CARD-1: `bridge_describe` failure-codes now advertise `agent_paused`, `agent_deactivated`, `recording_artifact_pipeline_bypassed` sourced from `cokret::error::ERROR_CODE_*` so spec renames force a recompile.

> No version tag, no crates.io / Docker Hub / npm publish — git commit only.

## [Unreleased]

### CKP-0007 Circle rollout (circle-rollout branch, spec `2b0d70d`)

Push-gateway alignment with the CKP-0007 Circle primitive landing in
cokret-rust-sdk P1.

#### Added

- `Notification.circle_id` (typed `ck:circle:…`) and
  `Notification.effective_scope` (reducer-stamped envelope binding
  mirrored from the SDK's `EffectiveScope`). Routing / dedup /
  metrics key off `circle_id > strand_id > realm_id` precedence.
- Per-(provider, scope) delivery counter
  `floria_notify_delivery_total{provider, scope_kind, scope_id}` gated
  by the new `http.metrics_detailed_circle_labels` boolean
  (default `false` — labels key off `realm_id` to bound cardinality).
- New `http.circle_rate_limits.{per_circle_qps,
  per_circle_concurrency}` config fields (both default null).
- New `circuit_breaker` module: in-process per-(provider, realm,
  circle) breaker so a single misbehaving Circle does NOT bleed into a
  realm- or provider-wide outage. Threshold + open-window are
  config-driven; auto-resets on cool-down.
- `effective_scope_mismatch` schema rejection — the wire routing
  fields (`realm_id`, `circle_id`) must agree with the envelope's
  `effective_scope` binding when present.
- Three new privacy-invariant tests asserting that Circle routing
  identifiers (`circle_id`, `effective_scope`, `scope_circle_id`)
  NEVER reach a provider's plaintext payload (top-level, recursive,
  builder paths). proptest harness extended with the same forbidden
  keys.

#### Changed

- `rust-version` lowered from `1.94` to `1.92` (edition 2024 is
  stable since 1.85, let-chains since 1.88 — keeping edition 2024
  with a more conservative MSRV floor).
- `.github/workflows/ci.yml`: formatting job now invokes plain
  `cargo fmt --all -- --check` (was `cargo +nightly fmt`, which
  conflicted with the `dtolnay/rust-toolchain@stable` action and
  broke CI on stable). New `msrv` job verifies the workspace builds
  on the declared MSRV.
- Dockerfile: pinned `rust:1.94-bookworm` → `rust:1.92-bookworm` to
  match the new MSRV floor.
- Round-23 local forbidden-key list: drops `realm_id` (SDK now covers
  it) and adds CKP-0007's `circle_id`, `effective_scope`, and
  `scope_circle_id`.

#### Fixed

- Resolved both `TODO(realm-rework)` markers at
  `src/service/notify.rs:432, 548` and the matching markers in
  `src/pushkin/{android,fcm,webpush,mod}.rs`.

#### Notes

- Version number stays `0.1.0` per the milestone hard rule (no
  release this round).

### Round R4 — protocol review closures (2026-05-20, cokret-spec `2a4d39b..a77b995`)

Push-gateway alignment with the round-4 protocol-review commits. See
[`../_todos.md`](../_todos.md) for the workstream context.

- **BREAKING** `message` / `system_message` payloads now route on
  `mention_redirect_target_actor_ids[]`: if the receiving device's actor
  is not in the array, floria runs fail-closed — push is delivered as a
  blind wakeup, content is never decrypted.
- **Added** `reason_code=historical_only` recognition on federation
  idempotency replays: floria treats them as diagnostic only and does NOT
  trigger a new push fanout.
- **Added** `ck.audit.policy_access{access_kind=e2ee_late_recovery}` routes
  through the audit pipeline rather than the push pipeline; late-recovery
  events never produce a wake-up.
- **Added** DID method-name regex sweep tightened to
  `^did:[a-z0-9]+:[^\s]+$` across floria's DID parsers and fixtures.

### Round R2/R3 (2026-05-20, spec 8b7978d) — wire-breaking

This release closes 17 P0/P1 tasks from spec rounds 2+3. Several of the changes
are intentionally **wire-breaking**: aggressive mode is on, there is no
backward-compatibility shim. Operators upgrading from a pre-round-2 floria
MUST upgrade soland and the principal-server fanout to a matching version.

#### Added

- **`/api/v1/internal/account_deactivate_fanout`** (T07) — POST endpoint that
  consumes soland's `account_deactivate_fanout` broadcast. Performs per-actor
  and per-device unbind, tracks the outcome in a small idempotent ledger
  (`deactivation::DeactivationLedger`), and returns an honest
  `outcome=completed|partially_completed|no_op` ack so soland's fanout state
  machine can advance. Sealed push channels (provider rejected the token) are
  counted as drained and **do not** block soland's fanout — per the round-2
  spec contract.
- **`/api/v1/internal/consent_revoke`** (T17) — POST endpoint that consumes
  soland's `consent_revoke{scope=any}` broadcast. Invalidates every cached
  push-contact PSI verdict for the affected principal in the new
  `push_contact_cache::PushContactCache` (in-memory + optional disk-overlay
  tombstone). Scoped (per-realm) revocations are rejected with
  `unsupported_feature` because floria does not learn realm content.
- New `AppState` fields `deactivation_ledger` and `push_contact_cache` so a
  deployment can opt in to the broadcast surfaces. When unset, the internal
  endpoints answer `503 service_unavailable` so misconfigurations surface in
  operator dashboards rather than silently swallowing soland broadcasts.

#### Changed

- **Blind sanitizer forbidden-field list** (T07/T10/T06) extended with the
  round R2/R3 names: `appeal_id`, `attestation_evidence`, `audit_purpose`,
  `attestation_chain`, `audit_policy_version_digest`, `policy_frontier_digest`,
  `trust_domain`, `reset_event_id`. These are all stable correlation
  identifiers introduced by the moderation-appeal,
  attestation-evidence-for-audit-agents, cross-signing-reset, and
  policy-frontier-hash wire additions; any of them on the blind-wakeup wire
  would let an observer link a push to a specific governance event. The local
  strip list runs ahead of the SDK's `is_forbidden_payload_key` until the SDK
  catches up (tracked under `TODO(round23-T07)`).

#### Internal

- Documented that **ephemeral kinds bypass floria** (T04 cross-check) — the
  four broadcast ephemeral signals (`ck.presence`, `ck.typing`,
  `ck.receipt.read`, `ck.call.signal`) travel on dedicated
  `ephemeral_envelope` / device-message channels in the Sync Service, are
  dropped at TTL, and MUST NOT enter floria's durable Event path. The
  `wakeup_kind` validator (closed enum + snake_case custom tokens, rejects
  `ck:` / `did:`) and the ID-prefix gate on
  `event_id` / `message_id` / `strand_id` / `realm_id` together act as
  defence-in-depth — no `ck:presence:` typed-id exists, so the prefix check
  rejects any future caller that tries to smuggle an ephemeral as a durable
  Event. See the comment in `src/service/mod.rs`.
- New test module `service::tests::internal` exercising both broadcast
  endpoints (idempotency, sealed-channel handling, wire-shape rejection,
  503 path when unwired).
- Property test `tests/property_provider_payload.rs` extended with the new
  round R2/R3 forbidden field names so the proptest harness covers them too.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
