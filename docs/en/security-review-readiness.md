# Security Review Readiness

Local record for the v1.0.0 security review gate. This file is not an external
audit report; it records what must be ready before scheduling review.

## Scope

Review focus:

1. `/_cokret/edge/push/notify` authentication, including HTTP Message Signatures,
   bearer fallback, mTLS header binding, and production-mode constraints.
2. Replay protection: nonce store, idempotency keys, Redis failure behavior,
   and dedup collision handling.
3. Multi-tenant isolation: provider app matching, plaintext metadata gates,
   blind payload sanitizer, and token redaction.
4. Internal broadcast paths for deactivation fanout and consent revocation.
5. Supply-chain controls: audit, deny, typos, Trivy, SBOM, and local provenance.

Out of scope for this local readiness record:

1. Publishing images, crates, GitHub releases, or tags.
2. Registry-attached signatures or public SLSA attestations.
3. Mobile app code review; mobile integration is covered separately through
   chime-facing contracts.

## Local Evidence

Run these before handing the repository to reviewers:

```powershell
cargo fmt --check
cargo check
cargo test --lib
cargo test --test provider_payload_strictness
cargo test --test sample_config_parse
cargo test --test property_provider_payload
.\scripts\local-supply-chain.ps1 -Image floria:local-security-review -SkipCosign
```

Optional environment-backed tests:

```powershell
$env:FLORIA_REDIS_URL="redis://127.0.0.1:6379/0"
$env:FLORIA_REDIS_DEDUP_LOAD_RUN="1"
cargo test redis_dedup_ttl_load --lib -- --ignored

$env:FLORIA_SOAK_RUN="1"
cargo test soak_chaos_rate_limit_cleanup --lib -- --ignored
```

## Reviewer Packet

Include these files in the packet:

| File | Purpose |
|------|---------|
| `README.md` | Feature summary and operational notes |
| `docs/en/configuration.md` | Config, secrets, and restart-required semantics |
| `docs/en/server-integration.md` | Server-side notify contract |
| `docs/en/mobile-integration.md` | chime/mobile ownership contract |
| `docs/en/openapi.json` | Machine-readable public API artifact |
| `docs/en/grafana-dashboard.json` | Recommended dashboard |
| `docs/en/supply-chain.md` | Local SBOM/provenance/image-scan commands |
| `docs/en/sdk-sync.md` | SDK forbidden-key upgrade gate |

## Current Readiness Status

As of the local v1.0.0 milestone record, floria has local evidence for auth,
replay protection, sanitizer coverage, readiness probes, audit divert metrics,
and supply-chain artifact generation. External review is still a separate
approval step and should be recorded outside this repository when complete.

## Threat Model Scope

The review focuses on the following adversaries and capabilities:

1. **Untrusted /notify caller** — can craft arbitrary JSON / headers; goal is
   to bypass auth, replay a notification, smuggle plaintext metadata, or
   inject forbidden Round R2/R3/CKP-0007 keys into the provider wire.
2. **Compromised provider credential** — has access to a single APNs key,
   FCM service account, or VAPID private key; goal is to widen the blast
   radius through floria's caches or rate-limit state.
3. **Compromised Redis instance** — can read/modify the dedup, nonce,
   rate-limit, and retry-queue keyspaces; goal is to forge idempotency
   responses, replay nonces, or surface dead-letter content.
4. **In-cluster eavesdropper** — can observe `/_floria/internal/*`
   traffic; goal is to read PII from broadcast events or learn
   account-deactivation timing.

Out of scope for the threat model:

1. Compromise of the host kernel / container runtime — defense delegated
   to the platform's image baseline and SBOM gate.
2. Side-channel attacks against AEAD primitives (ChaCha20-Poly1305 for
   the retry-queue envelopes); the upstream crate is audited and
   floria does not implement its own AEAD.
3. Mobile-app compromise — covered by chime's threat model.

## R3.2 Spec-Sync Closures

These items are intentionally closed as floria-local N/A rather than
implemented:

1. **ROST-FLO-1..3 mention reference v2** — floria is a push gateway,
   not the Message AST authoring or rendering layer. The public
   `ck.edge.push.command.notify` payload must not carry mention-preview fields such
   as `subject_id` or `display_name_at_time`; the typed wire model uses
   `serde(deny_unknown_fields)` and the round4 test
   `mention_reference_v2_fields_are_not_push_payload_fields` proves the
   gateway rejects them with `schema_violation`. The only mention field
   floria accepts is the push-routing allow-list
   `mention_redirect_target_route_tokens`, which carries opaque route
   tokens only.
2. **MEDIA-FLO-1..3 self-issue** — floria v1 does not self-sign media
   tokens. The media token code path was removed from floria;
   `/_cokret/describe` does not advertise an RTC/media token
   self-issue feature, and the production router does not expose a
   public `/rtc/token` minting route. The canonical issuer remains
   soland unless a future release wires a real media-service keystore.

## Known Limitations

Documented for transparency; reviewers may treat these as accepted risks
or open follow-up tickets:

1. **Per-provider concurrency is process-local** — the limiter caps
   in-flight dispatches per pod but does not coordinate across
   replicas. Operators sizing a clustered floria deployment must
   set per-pod budgets accordingly.
2. **Cardinality guard is process-local and sticky** — when
   `metrics_detailed_circle_labels=true` and unique circle_ids exceed
   5,000, floria auto-downgrades to realm-keyed labels for the rest
   of the process lifetime. The downgrade is per-replica and is
   logged once at the warn level.
3. **Retry-queue per-Circle metric is realm-keyed** — the
   `floria_notify_retry_queue_depth` labelled gauge always uses
   `scope_kind=realm` because retry envelopes do not currently carry
   circle_id. Operators reconstruct per-Circle retry health from the
   counter deltas (`floria_notify_retry_enqueued_total`,
   `floria_notify_retry_replayed_total`).
4. **Plaintext bearer tokens are development-only** — the
   `notify_auth.bearer_tokens` field is still supported for
   non-production compatibility, but `production_mode=true` rejects
   both gateway-wide and per-principal plaintext bearer tokens at
   config validation. Production callers must use HTTP Message
   Signatures or mTLS; bearer hashes are retained only as non-production
   fallback material. See `docs/en/configuration.md`.
5. **Takedown notification path is not implemented** — there is no
   takedown-notification handler yet (TODO(P5-impl)). No placeholder
   metric is exported for it; the counter and stub were removed so the
   `/metrics` surface only reflects implemented paths.
6. **Internal endpoints share the public listener** — see
   `docs/en/internal-endpoints.md`. They now require
   `http.internal_auth` and fail closed when it is unset; private
   binds / service-mesh mTLS remain recommended defense-in-depth.
7. **Visible notification payloads are intentionally plaintext** — the
   visible-notification profile can place title/body metadata in
   provider-visible payload fields. floria gates this through
   `allow_plaintext_metadata` plus the reviewed
   `is_plaintext_eligible_service_kind` allow-list; widening that
   allow-list or adding a new visible field requires a fresh privacy
   review.
