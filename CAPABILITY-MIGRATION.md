# Authority-Commit Capability Migration

floria is the `push_gateway` role: it accepts `ak.edge.push.command.notify.v1`
from an authenticated Station, resolves the durable device registration, and
dispatches a blind or visible wakeup to APNs / FCM / WebPush / the domestic
Android OEM providers. It is not an Account Authority and not a Station.

floria authors no Realm Event and holds no `RealmCommit`. Its only contact with
the authority-commit protocol is at two seams: the durable registration row that
a Station writes, and the account-deactivation fanout broadcast a Station sends.
This file records, per product entry point, where the capability lives now and
which test covers it. Empty implementations are named as empty.

## Protocol invariants every row is measured against

Only the invariants that can be violated from inside this repository are listed.

- [x] floria never produces a Realm Event. Nothing it builds carries a
  predecessor, ordering, basis, frontier, Seal or Cell field, and it never
  constructs an `EventCommitSubmission`.
- [x] Registration is a Station-owned operation
  (`discovery/push-notifications.md` §3.3). floria's gateway service identity,
  its `service_signature` and its `push_gateway` profile grant no account
  self-service registration right. `RegistrationDirectory::resolve` opens a
  **read-only** transaction and never creates or repairs a registration.
- [x] A registration is identified by the exact
  `(registration_id, push_target_id, device_id)` triple plus the authenticated
  Station identity. The request's own `device_id`, `push_target_id` and
  `Destination-Service-ID` are never treated as proof of registration.
- [x] `notification.devices[]` carries only `device_id`. A notify request may
  not supply, override or recover provider token, app id, registration identity
  or opt-in state.
- [x] Registration update, unregistration, device revocation, expiry and
  provider invalidation must take effect on floria's next takeover, and a stale
  registration must not be revived by a worker, a cache or a delayed request
  (§3.3). floria re-resolves the durable row immediately before provider I/O,
  including after a timing-bucket delay.
- [x] Under the `blind_wakeup` profile no plaintext content, sender identity,
  routing token, audit tail or absolute activity count reaches a provider.
- [x] No Seal / Cell / frontier / control-proposal vocabulary survives in the
  code, the wire shapes or the guard lists.

## Product capabilities preserved

Route entry points are as declared in `src/service/mod.rs:build_router`.

| Capability / entry point | Implementation (`file:symbol`) | Tests |
|---|---|---|
| `POST /_arkret/edge/push/notify` — the gateway's one product operation: contract validation, dedup, rate limit, fanout, per-device outcome conservation | `src/service/mod.rs:notify_route`, `src/service/notify/mod.rs:notify` | `src/service/tests/basics.rs:notify_endpoint_accepts_active_payload_shape`, `:notify_response_conserves_every_requested_device_id`, `:notify_response_uses_standard_outcome_without_plaintext_tokens`, `:notify_response_carries_no_provider_identifiers`, `:notify_method_not_allowed_returns_problem_details`, `:oversized_requests_are_rejected`, `:operation_selector_is_required_and_route_bound_before_handlers` |
| Notify contract validation: transport fields rejected in body, idempotency key and operation id rejected in body, removed timing hint rejected, unknown route-token member rejected | `src/service/notify/validation.rs:validate_notification_contract`, `:validate_plaintext_identity_metadata` | `basics.rs:notify_envelope_rejects_transport_fields_in_body`, `:notify_rejects_idempotency_key_in_body`, `:notify_rejects_operation_id_in_body`, `:notify_ingress_rejects_removed_timing_hint`, `:notification_rejects_an_unknown_route_token_member`, `:notification_uses_priority_wire_field`, `:notify_request_accepts_cx_push_notify_contract_metadata` |
| Blind-wakeup profile enforcement: no plaintext content, no sender display name, count bucketing, badge booleanisation | `src/service/notify/validation.rs`, `src/sanitize.rs:bucket_count`, `:is_forbidden_egress_key` | `src/service/tests/sanitizer.rs:notify_blind_profile_accepts_pure_blind_payload`, `:notify_blind_profile_rejects_plaintext_content_body`, `:notify_blind_profile_rejects_plaintext_sender_actor_display_name`; `src/sanitize.rs:bucket_count_matches_spec_granularity`; `src/pushkin/mod.rs:badge_count_is_booleanized_for_blind_wakeup`, `:zero_badge_counts_are_dropped`, `:counts_reject_absolute_integer_indicators`, `:counts_accept_boolean_and_bucket_indicators` |
| Visible profile gating: plaintext metadata only for an allow-listed, signed, eligible service kind, and only with device opt-in | `src/service/notify/validation.rs:validate_visible_notification_device_opt_in`, `src/auth/helpers.rs` | `sanitizer.rs:notify_visible_profile_accepts_plaintext_metadata`, `:notify_visible_profile_requires_device_visible_opt_in`, `:notify_visible_profile_rejects_product_private_content_body`; `src/auth/tests.rs:principal_plaintext_policy_requires_eligible_service_kind`, `:production_mode_rejects_plaintext_for_non_eligible_kind` |
| Provider egress sanitiser: forbidden blind-payload names, strip-only routing/audit names, nested and case-insensitive, DID-literal rejection | `src/sanitize.rs:is_forbidden_egress_key`, `:strip_egress_only_keys` (list owned by the SDK's `arkret_push_policy::blind_payload_sanitizer::PROVIDER_EGRESS_STRIP_KEYS`) | `src/sanitize.rs:egress_strips_sdk_and_strip_only_keys`, `:strip_egress_only_keys_removes_nested_and_case_insensitive_names`; `tests/provider_payload_strictness.rs` (16): `sanitizer_strips_route_token_identifiers`, `sanitizer_strips_nested_route_token_metadata`, `sanitizer_strips_private_notification_preferences`, `sanitizer_strips_apns_correlation_identifiers`, `sanitizer_strips_webpush_correlation_identifiers`, `sanitizer_strips_fcm_data_only_forbidden_fields`, `sanitizer_rejects_did_literal`, `sanitizer_rejects_subject_proof_signature`, `sanitizer_rejects_binding_proof_signature`, …; `tests/property_provider_payload.rs` (4) |
| Durable registration resolution against the Station's authoritative store, read-only, ambiguity-refusing, expiry- and target-aware | `src/registrations.rs:RegistrationDirectory::resolve` | `src/registrations.rs:postgres_registration_identity_rotation_and_removal` (requires `FLORIA_REGISTRATION_TEST_DATABASE_URL`); `src/service/tests/delivery.rs:unknown_device_registration_is_rejected_without_dispatch`, `:invalid_registration_is_rejected`, `:malformed_device_identity_is_rejected_before_registration_lookup`, `:registered_blank_provider_app_is_rejected_without_dispatch`, `:dispatch_targets_include_only_the_current_device`, `:accepted_devices_are_not_rejected` |
| Registration re-check after the timing-bucket delay, so a token rotation or opt-out between admission and provider I/O is not raced | `src/service/notify/dispatch.rs:dispatch_notification_devices` | `delivery.rs:dispatch_targets_include_only_the_current_device`, `:notify_cannot_supply_or_override_registration_routing_fields`, `:anonymous_notify_cannot_reach_registration_or_metadata_policy` |
| Authentication: HTTP Message Signature, mTLS, hashed bearer, origin allowlist, production fail-closed policy | `src/auth/mod.rs:authenticate_notify_request`, `src/auth/signature.rs`, `src/auth/mtls.rs`, `src/auth/bearer.rs` | `src/auth/tests.rs` (6) and `src/service/tests/auth.rs` (19): `http_message_signature_authenticates_notify_request`, `mtls_profile_authenticates_notify_request`, `mtls_profile_rejects_missing_verified_client_certificate`, `rejects_tampered_body`, `rejects_signature_missing_required_components`, `notify_rejects_non_allowlisted_origin_id`, `notify_rejects_did_in_source_service_id_header`, `notify_rejects_did_in_destination_service_id_header`, `notify_rejects_mismatched_destination_id`, `notify_rejects_query_string_auth_material`, `production_mode_rejects_anonymous_requests`, `production_mode_rejects_gateway_wide_bearer_tokens`, `production_mode_requires_signed_or_mtls_principal`, … |
| Replay defence: signature nonce store (in-memory + Redis backends) | `src/nonce_store.rs` | `rejects_replayed_fingerprint`, `allows_distinct_fingerprints`, `zero_ttl_disables_observation`, `redis_backend_requires_valid_url` |
| Idempotency and dedup: header and body key resolution, canonical-body fingerprinting, reordering tolerance, duplicate-conflict detection, delivered-device memory | `src/dedup.rs`, `src/service/notify/helpers.rs:normalized_notify_dedup_key`, `:resolve_idempotency_key` | `src/dedup.rs` (6) + `src/service/tests/dedup.rs` (5): `returns_inserted_response_before_expiry`, `expires_entries_after_ttl`, `remembers_delivered_devices_until_expiry`, `detects_duplicate_conflict_for_different_request_body`, `notify_dedup_cache_serves_repeated_success_without_redispatch`, `notify_dedup_cache_matches_reordered_equivalent_payloads`, `notify_duplicate_idempotency_key_with_different_body_returns_conflict`, `notify_supports_header_idempotency_key_replay`, `exact_replay_returns_the_original_per_device_outcomes` |
| Rate limiting per endpoint / app id / provider / push-key hash, with conserved `Retry-After` and rollback on partial failure | `src/rate_limit.rs`, `src/service/notify/helpers.rs:notify_rate_limit_checks` | `src/rate_limit.rs` (4) + `src/service/tests/rate_limit.rs` (6): `notify_rate_limit_can_apply_per_endpoint`, `:per_app_id`, `:per_provider`, `:per_push_key_hash`, `notify_rate_limit_returns_conserved_outcome_with_retry_after`, `dedup_replay_bypasses_rate_limit`, `rolls_back_earlier_increments_when_a_later_check_fails`, `rejects_when_limit_is_exceeded` |
| Durable retry queue with AEAD-encrypted envelopes, due-time dequeue, backoff cap, dead-lettering | `src/retry_queue.rs:RetryQueueCipher`, `:RedisQueue` | `dequeue_returns_only_due_entries`, `next_retry_at_caps_at_max_backoff`, `dead_letters_after_max_attempts`, `redis_backend_requires_valid_url`; `src/service/tests/delivery.rs:temporary_errors_without_durable_retry_return_per_device_backoff` |
| Per-provider circuit breaker with detail downgrade | `src/circuit_breaker.rs` | `opens_at_threshold`, `closes_under_threshold`, `auto_resets_after_open_for_window`, `success_resets_consecutive_counter`, `per_provider_open_for_override`, `guard_trips_at_threshold_and_stays_downgraded`, `guard_allows_detailed_below_threshold` |
| 11 provider adapters: APNs, FCM, WebPush, JPush, HMS family (Huawei/HONOR/HarmonyOS), Xiaomi, OPPO, vivo, generic Android, custom, shared OEM skeleton | `src/pushkin/{apns,fcm,webpush,jpush,hms_family,xiaomi,oppo,vivo,android,custom,oem_family}.rs` | per-adapter unit tests (55 across `src/pushkin/*`), e.g. `builds_request_body_with_extras_and_third_party_channel`, `vivo_sign_matches_official_example`, `auth_response_uses_canonical_oppo_shape`, `only_honor_accepts_a_numeric_app_id`, `hmos_validation_warns_only_distribution`, `oneplus_vendor_name_is_distinct`, `builds_webpush_payload`, `builds_v1_data_payload`, `apns_server_errors_are_temporary`, `fcm_quota_errors_are_temporary`, `invalid_apns_token_is_rejected`, `url_template_substitutes_push_key`, `per_pushkin_concurrency_limit_does_not_leak_provider_state` |
| WebPush SSRF egress guard and endpoint allowlist | `src/egress.rs`, `src/pushkin/webpush.rs` | `webpush_egress_validation_rejects_private_targets`, `webpush_dispatch_blocks_private_endpoint_even_when_allowlisted`, `webpush_dispatch_fails_when_the_endpoint_allowlist_is_unconfigured`, `webpush_endpoint_allowlist_matches_domain`, `webpush_endpoint_rejects_query_string`, `production_rejects_http_and_non_public_targets`, `invalid_vapid_private_key_is_rejected_at_startup` |
| Push-key never leaks into a rejection, a cache, a log or an error body | `src/pushkin/*`, `src/service/notify/helpers.rs:rejected_device` | `rejected_device_redacts_push_key`, `invalid_registration_response_rejects_push_key`, `invalid_target_response_rejects_push_key`, `invalid_token_response_rejects_push_key`, `webpush_gone_response_rejects_push_key`, `v1_not_found_rejects_push_key`, `redacts_proxy_credentials` |
| `GET /_arkret/describe` — role-scoped gateway Describe | `src/service/server_describe.rs:describe` | `basics.rs:describe_endpoint_advertises_gateway_profile`, `:describe_separates_claim_levels`, `:describe_does_not_advertise_media_token_self_issue`, `:describe_fails_closed_when_gateway_service_did_is_missing`, `:describe_fails_closed_when_gateway_service_did_is_invalid`, `:describe_omits_bearer_mode_when_production_disables_bearer_fallback`, `:gateway_describe_lives_at_root_meta_position` |
| `GET /_floria/integration/describe` — operator surface inventory | `src/service/integration_describe.rs:integration_describe` | `basics.rs:integration_describe_lists_operational_surfaces` |
| `POST /_floria/internal/account_deactivate_fanout` — Station-driven principal teardown, idempotent, queue-draining, outcome-reporting | `src/service/internal.rs:account_deactivate_fanout`, `src/deactivation.rs:DeactivationLedger` | `src/service/tests/internal.rs`: `account_deactivate_fanout_completes_for_drained_devices`, `:is_idempotent_across_retries`, `:rejects_missing_actor_id`, `:reports_drained_queue_count`, `:returns_503_when_ledger_unwired`; `src/deactivation.rs`: `ledger_counts_devices_and_marks_complete`, `ledger_is_idempotent_on_retry`, `ledger_reports_no_op_when_actor_already_unbound_and_no_devices`, `ledger_reports_partial_when_queue_drain_fails`, `ledger_reports_drained_message_count_from_queue_drain`, `ledger_lru_bounds_seen_and_binding_state`; `src/broadcast.rs:bus_processes_deactivation_fanout` |
| Agent-actor event routing: private Agent kinds are consumed without fanout, non-Agent kinds fall through to push | `src/service/notify/mod.rs` (via `classify_agent_event_kind`) | `src/service/tests/agent_routing.rs` (6): `agent_actor_private_kinds_are_dropped_without_fanout`, `agent_pause_event_is_silently_consumed_without_fanout`, `agent_resume_event_is_silently_consumed_without_fanout`, `agent_deactivate_event_is_silently_consumed_without_fanout`, `non_agent_event_kind_falls_through_to_push_fanout`, `non_string_event_kind_is_rejected_as_schema_violation` |
| Operator surfaces: `GET /_floria/admin/push/status/{key}`, `GET /_floria/admin/push/dead-letters` (newest-first, egress-key-stripped, internal-auth-gated) | `src/service/internal.rs:push_status`, `:push_dead_letters`, `:require_internal_auth` | `internal.rs` tests: `status_requires_internal_bearer`, `dead_letters_requires_internal_bearer`, `dead_letters_empty_ring_returns_empty_snapshot`, `dead_letters_full_ring_returns_newest_first_and_strips_egress_keys`, `dead_letters_rejects_invalid_limit`, `dead_letters_returns_503_when_retry_queue_disabled`, `internal_routes_accept_hashed_bearer_token`, `internal_routes_reject_missing_and_invalid_bearer`, `internal_routes_fail_closed_when_auth_unconfigured` |
| `/health`, `/ready`, `/readyz`, and the separate metrics listener | `src/service/health.rs`, `src/service/metrics.rs` | `ready_endpoint_returns_ok`, `readyz_endpoint_returns_ok_for_configured_registry`, `readyz_endpoint_fails_when_registry_is_empty`, `healthz_exposes_hardening_status`, `metrics_endpoint_renders_prometheus_output`, `formats_prometheus_ipv6_listen_address`, `supports_bracketed_ipv6_without_explicit_port`, `keeps_explicit_http_ports` |
| Configuration: KDL and YAML parity, JSON schema generation, validation fail-closed rules | `src/config/*`, `examples/emit_schema.rs` | `src/config/tests.rs` (26): `parses_kdl_config`, `yaml_and_kdl_produce_equivalent_configs`, `kdl_to_json_round_trip_preserves_nested_structure`, `validate_rejects_unsafe_storage_table_names`, `validate_requires_service_principals_for_required_signatures`, `validate_rejects_malformed_bearer_token_hash`, …; `tests/config_schema.rs:committed_config_schema_matches_generator`, `:schema_version_is_single_sourced`; `tests/sample_config_parse.rs`; `tests/format_parity.rs:sample_kdl_and_yaml_parse_to_equivalent_config` |
| Audit sink (file / http / redis backends) and observability wiring | `src/audit.rs`, `src/observability.rs` | `jsonl_sink_appends_events`, `build_env_filter_uses_explicit_filter_first`, `opentelemetry_*` (3), `sentry_*` (3), `validate_observability_*` (3) |
| Postgres pool TLS selection and lifecycle | `src/postgres_support.rs` | `postgres_url_sslmode_disable_uses_plain_pool_manager`, `postgres_url_sslmode_require_uses_tls_pool_manager`, `deadletter_pg_overlay_accepts_schema_qualified_table`, `deadletter_pg_overlay_rejects_unsafe_table_identifier` |
| Station↔gateway fanout contract DTOs | `crates/floria-contracts/src/lib.rs:AccountDeactivateFanoutBroadcast`, `:DeactivateFanoutDevice`, `:DeactivateFanoutOutcome` | `crates/floria-contracts/src/lib.rs` (5): `broadcast_wire_shape_round_trips`, `broadcast_defaults_devices_and_reason`, `broadcast_rejects_unknown_fields`, `ack_round_trips_and_tolerates_unknown_fields`, `outcome_tokens_are_pinned` |

### Capabilities that are honestly incomplete

These are named here rather than counted as preserved. None of them is a
regression introduced by this migration; all are pre-existing and
self-declared.

| Surface | What is actually there | Where it says so |
|---|---|---|
| `/_arkret/describe` `verified_profiles` | **Always empty.** The push-gateway profile is self-claimed; no cotest verifier is wired in, so nothing can move a profile from claimed to verified. | `src/service/integration_describe.rs:41` (`todo:` on the `gateway_describe` surface) and the module-level `todos` list |
| `/_arkret/describe` `trust_domain` and `privacy_derivation` | **Static placeholders** until a deployment supplies the real values. The code constructs a fixed well-formed trust domain with `expect("static placeholder trust domain is well-formed")`. | `src/service/server_describe.rs:189-192`; `integration_describe.rs` `todos[1]` |
| `access.x_forwarded_for` | Accepted in config and validated, but proxied access-log formatting is not implemented. | `docs/en/configuration.md:371`, `floria.sample.kdl:12`, `floria.sample.yaml:10` |
| Takedown notification path | Not implemented. Deliberately no placeholder handler and no placeholder metric, so `/metrics` reflects only implemented paths. | `docs/en/security-review-readiness.md:145-149` |
| Redis-backed dedup / rate-limit / nonce / retry-queue backends | The **implementations exist and are wired**, but the automated suite only covers their construction-time URL validation (`redis_backend_requires_valid_url`, four copies). The actual Redis round-trip runs only under `redis_dedup_ttl_load`, which is `#[ignore]`d and needs `FLORIA_REDIS_DEDUP_LOAD_RUN=1` plus `FLORIA_REDIS_URL`. The in-memory backends are what the green suite exercises. | `src/dedup.rs:829`, `src/rate_limit.rs:434` |
| Durable registration lookup | Only one test (`postgres_registration_identity_rotation_and_removal`) touches real Postgres, and it is skipped by panic unless `FLORIA_REGISTRATION_TEST_DATABASE_URL` is set. Everything else uses `registrations::test_support`. | `src/registrations.rs:89` |

## Removed as complete old-protocol units

Verified against `git show` for this repository's clean-break batch
(`9889d83` .. `62601a7`, 2026-09-16), with the surrounding
`3f19609` .. `8c213de` work as context.

- **`policy_frontier_digest`**, from the sanitizer probe fixture and its
  forbidden-name assertion list (`src/pushkin/mod.rs:sanitize_tests`). The name
  designated the digest of a *policy frontier*. A frontier is not an object in
  the authority-commit protocol, and the shared guard list that floria defers
  to — `arkret_push_policy::blind_payload_sanitizer::PROVIDER_EGRESS_STRIP_KEYS`
  — no longer contains it. Keeping the assertion would have pinned floria's test
  to a name the shared guard no longer owns, which is exactly how a guard rots
  into a tautology.
- **`delivery_binding_frontier_token`**, from the nested-stripping fixture in
  `src/sanitize.rs` (replaced by `realm_route_token`, a name the SDK list still
  owns) and from the assertion in `src/sanitize.rs:egress_strips_sdk_and_strip_only_keys`.
  Same reason, and the same removal that took chime's `DeliveryBindingStale` /
  `DeliveryBindingHandedOver` error kinds: a "delivery binding frontier" was the
  federation-side frontier token, and there is no such token to leak.
- **`ServerLimits.mls_governance_proof`** and **`supported_reducer_profiles`**
  from the gateway Describe body (`src/service/server_describe.rs`). Neither is
  a push-gateway fact; both belonged to the removed governance-profile and
  reducer-profile surfaces. A `push_gateway` Describe advertising an MLS
  governance-proof limit was advertising a capability the role does not have.
- **`RetryQueueCipher::seal`**, renamed to `::encrypt`. This is a vocabulary
  removal, not a behaviour change: the AEAD operation is still
  `ChaCha20-Poly1305` sealing. `Seal` is a deleted protocol object, and a method
  named `seal` on a type that stores protocol payloads is the exact collision the
  clean break is meant to eliminate. `serialize_envelope` follows.
- **"cell" as the unit of push state**, from `crates/floria-contracts/src/lib.rs`
  (`AccountDeactivateFanoutBroadcast.devices`, `DeactivateFanoutDevice.push_key_hash`,
  `DeactivateFanoutOutcome::PartiallyCompleted`) and `src/deactivation.rs`. The
  fanout has always operated on `(actor, device)` binding rows and per-device
  queue partitions; calling them cells borrowed the name of a deleted CRDT
  object. See "Residue found and fixed" below for the one leftover this batch
  missed.

Nothing was deleted from the product surface in this round: no route, no
provider adapter, no config key. Every removal above is either a protocol-only
field or a protocol-only name.

## Migrated mixed areas, with the evidence

- **`src/registrations.rs` — the `device_authorization` write.** Three fixture
  `INSERT`s (the regression's `save` closure and `test_support::device`, plus the
  `tests/provider_payload_strictness.rs` fixture) now supply a
  `device_authorization` JSONB column alongside `payload`. This is not
  cosmetic. `device_authorization` is the server-derived
  `DeviceRevocationGateSelector`: `{principal_id, station_id, device_id,
  authorization_ref}`, where `authorization_ref` is a closed
  `CommittedEventRef` (`event_id`, `commit_id`, `stream_ref`,
  `stream_position`) naming the `RealmCommit` that authorised the device. It is
  the carrier that makes `push-notifications.md` §3.3/§3.4's requirement
  reachable — "注册更新、注销、设备撤销、过期与 provider 失效回收 MUST 对
  Gateway 的后续接管生效" — because without it a revocation decision has no
  committed reference to point at. In the Soland-initialised schema the column
  is `jsonb NOT NULL` (verified directly against the test database), so any
  fixture that omits it fails at insert time; the fixtures had to grow the
  column the moment the Station started writing it.
  **What floria itself does with it, stated plainly:** nothing yet.
  `RegistrationDirectory::resolve` selects `payload::text` only and never reads
  the `device_authorization` column, so revocation reaches floria through the
  Station removing or superseding the row — not through a filter floria applies.
  That is consistent with §3.3's shared-storage path (floria is inside the
  Station's trust boundary and reads its authoritative state), but it means the
  column is currently a Station-side obligation that floria stores past rather
  than enforces.
- **`src/sanitize.rs`**: the whole egress-hygiene capability stayed. Only the
  two frontier-derived names left the fixtures. The authority for *what* is
  stripped was already the SDK's `PROVIDER_EGRESS_STRIP_KEYS`; this round only
  removed floria's local restatements of entries the SDK had dropped.
- **`src/service/notify/`**: the dispatch pipeline kept its four stages
  (`validation` → `helpers` → `dispatch` → `response`). The change in this round
  was the registration-resolution seam: delivery now resolves exclusively from
  the authenticated durable registration and re-resolves after the timing-bucket
  delay, instead of trusting anything in the request body.
- **`src/deactivation.rs` and `crates/floria-contracts`**: the fanout state
  machine, the LRU-bounded idempotency ledger, the queue drain and the
  three-valued outcome all stayed. Only the vocabulary moved from "cell" to
  "device binding" / "queue partition".
- **`src/service/server_describe.rs`**: the Describe body kept every
  push-gateway fact — profile claim, claim levels, auth metadata, plaintext
  visibility, rate limits, extensions. Only the two non-gateway limit members
  were dropped.

### Residue found and fixed in this pass

The 2026-09-16 batch renamed the "cell" vocabulary in prose but left one local
binding behind: `observed_at_least_one_cell` in
`src/deactivation.rs:DeactivationLedger::record`. It is a function-local `bool`
with no protocol meaning and no serialised form, but it was the last occurrence
of the word in floria's code. Renamed to `observed_at_least_one_device` as part
of writing this file, so the residue scan below is genuinely zero rather than
zero-with-a-footnote. Behaviour is unchanged and the six `deactivation` tests
still pass.

## Verification gates

Every result below was produced on this machine during this task. Commands were
run from `D:\Works\arkret-org\floria`.

| Command | Result |
|---|---|
| `FLORIA_REGISTRATION_TEST_DATABASE_URL=postgres://postgres:root@127.0.0.1:5432/floria_reg_test cargo test --workspace --all-features --no-fail-fast` | **273 passed, 0 failed, 2 ignored** — run twice, before and after the `observed_at_least_one_device` rename, with identical counts. The two ignored are the explicitly opt-in local scaffolds: `dedup::tests::redis_dedup_ttl_load` and `rate_limit::tests::soak_chaos_rate_limit_cleanup`. Breakdown: 243 `floria` lib unit tests, 16 `tests/provider_payload_strictness.rs`, 5 `floria-contracts` unit tests, 4 `tests/property_provider_payload.rs`, 2 `tests/config_schema.rs`, 2 `tests/sample_config_parse.rs`, 1 `tests/format_parity.rs`. |
| the same command without the env var | `registrations::tests::postgres_registration_identity_rotation_and_removal` panics on `expect("set FLORIA_REGISTRATION_TEST_DATABASE_URL …")`. The variable is mandatory for a complete run; there is no silent skip. |
| module reachability self-check | 2 crates (`floria`, `floria-contracts`), 9 crate roots; **78 `.rs` files on disk under `src/`, `tests/`, `examples/`, `crates/*/src/`; 78 reachable by walking `mod` from those roots; 0 orphans.** The walk resolves `#[path]` attributes and nested inline `mod` blocks, and treats every integration-test file as its own crate root — without that, `tests/common/mod.rs` is falsely reported as an orphan. No file in this repository is excluded from compilation. |
| residue scan (`git grep -i` for `Seal`, `Cell`, `CBS`, `ControlProposal`, `frontier`, `lattice`, `RHRK`, `history_secret`, `policy_root`, `state_root`, `actor_seq`, `encryption_floor`, `governance_profile`, `security_frontier`, `ordinary_authoring`, `Retired`, `Legacy`, `Deprecated`) | **Zero hits in code after the `observed_at_least_one_cell` rename above.** Remaining matches anywhere in the repository: three `#[allow(deprecated)]` shims in `src/retry_queue.rs` (lines 65, 73, 99) around a third-party AEAD API, and two historical `CHANGELOG.md` entries (lines 133, 173) describing "sealed push channels", i.e. a provider having rejected a token. Neither is protocol vocabulary. |
| `cargo fmt` | Not run. `--all` reaches into the sibling `arkret-rust-sdk` path-dependency checkout, which other agents are editing concurrently. |

## External blockers

No product capability in floria is blocked.

Two environmental constraints, recorded because they affect reproducibility:

1. **The sibling `arkret-rust-sdk` checkout is under concurrent edit.** floria
   depends on `arkret-egress-reqwest`, `arkret-models-discovery`,
   `arkret-models-identity`, `arkret-models-integration`, `arkret-push-policy`,
   `arkret-rate-limit`, `arkret-retry`, `arkret-server`, `arkret-signatures`
   and `arkret-wire` by path, so an error in any of them stops floria's build
   outright. Two such windows were observed during this task:
   - `crates/models-identity/src/signer_key_operations.rs` — three errors
     (`validate_for_selector` missing on `ResolvedSignerKey`;
     `SignerKeyQueryResult::selector` used as a field at lines 278 and 308).
   - `crates/signatures/src/detached_object.rs:134` —
     `verify_ed25519_raw_transcript_signature` not found at the crate root.

   A third SDK breakage observed later —
   `crates/http-client/src/endpoints/events.rs:275`, `limit` is `u16` and a
   `u32` was passed — does **not** reach floria: `arkret-http-client` is not in
   floria's dependency graph (`arkret-server` does not pull it), which is why
   the re-verification run after the `observed_at_least_one_device` rename
   still went green while other repositories in this workspace were blocked on
   it. Both 273/0 results above were taken in windows where floria's own SDK
   subset compiled. **Nothing in the SDK was changed to obtain them.**
2. **Postgres is required.** The registration regression needs a live database
   initialised with Soland's schema. On this machine
   `postgres://postgres:root@127.0.0.1:5432/floria_reg_test` already carried the
   schema, including `public.push_devices.device_authorization jsonb NOT NULL`.
   A checkout without that database cannot run a complete suite.
