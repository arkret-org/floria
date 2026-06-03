# SDK Sync Gate

floria still carries a local provider-payload sweep for Round R2/R3
forbidden fields. The SDK exposes
`cokret::blind_payload_sanitizer::is_forbidden_payload_key`, but the
exported list is not yet sufficient for the newer realm, appeal,
attestation, policy-frontier, cross-signing-reset, and Circle
field names.

## Local Sweep

The local sweep is implemented in `src/pushkin/mod.rs` as
`ROUND23_LOCAL_FORBIDDEN` and runs recursively through
`sanitized_provider_payload`. Provider-specific tests in the Android,
FCM, and WebPush adapters also assert that renamed Realm/Space/Circle
identifiers stay off the provider wire.

### Full forbidden-key list

| Field | Round | Rationale |
|-------|-------|-----------|
| `realm_id` | R2 | Stable security-boundary identifier after the Realm/Space rework — leaking it on a provider wire would let an observer pivot pushes back to a tenant scope |
| `appeal_id` | R2 | Links a push to a moderation appeal thread; visible in provider logs would expose that the user is under review |
| `attestation_evidence` | R3 | Reveals audit-agent or device posture (TPM PCR digests, key attestation chain) |
| `audit_purpose` | R3 | Reveals audit routing intent (which downstream audit channel the push will divert to) |
| `attestation_chain` | R3 | Reveals attestation chain material; same leak class as `attestation_evidence` |
| `audit_policy_version_digest` | R3 | Stable audit policy correlator — long-lived, cross-request linkability |
| `policy_frontier_digest` | R3 | Stable policy frontier correlator — same linkability class as the audit policy version |
| `trust_domain` | R3 | Deployment-scope leakage — exposes whether the principal is on a federation edge |
| `reset_event_id` | R3 | Links a push to a cross-signing reset event, exposing key-rotation timing |
| `circle_id` | CXP-0007 | Encryption sub-boundary id — would tell an observer which Circle inside a Realm a push is destined for |
| `effective_scope` | CXP-0007 | Reveals the realm/circle binding the principal server stamped on the request |
| `scope_circle_id` | CXP-0007 | Same class as `circle_id`; an alias used by some draft schemas |

The match is case-insensitive and applies recursively through nested
provider-defined wrappers (e.g. `aps.alert`, `android.notification`,
`data.payload`).

## Mention Reference v2 N/A

ROST-FLO-1..3 mention reference v2 fields are intentionally not part of
floria's push wire model. `subject_id`, `display_name_at_time`, and
related Message AST preview fields belong to chime / principal-service
message rendering, not to `ck.push.notify`. floria keeps the typed
payload closed with `serde(deny_unknown_fields)`; the round4 service
test `mention_reference_v2_fields_are_not_push_payload_fields` rejects
those fields with `schema_violation`.

## Upgrade Gate

Do not remove the local sweep until all of these are true:

1. The SDK helper rejects every name above case-insensitively.
2. The SDK helper is documented as the canonical blind-wakeup
   forbidden-key source for Round R2/R3 and CXP-0007 and later.
3. floria tests pass after deleting `ROUND23_LOCAL_FORBIDDEN` and
   changing `sanitized_provider_payload` to rely on the SDK helper
   only.
4. The adapter tests continue to assert `realm_id` and legacy
   `space_id` are absent from provider payloads.

## Spec round upgrade checklist

Use this when bumping floria to a newer cokret-spec round (R4 →
R5, CXP-0007 → CXP-0008, etc.):

- [ ] Diff the new round's `forbidden_payload_keys` table against
      `ROUND23_LOCAL_FORBIDDEN`. Add any newly forbidden names to
      the local list with a rationale row in this doc.
- [ ] Add a property test in `tests/property_provider_payload.rs`
      that fuzzes the new field name into request bodies and asserts
      the provider wire does not contain it (case-insensitive).
- [ ] Re-snapshot the chime drift-gate fixture (per P6 of the
      coordinated todo) — round upgrades usually move at least one
      timestamp.
- [ ] Update `docs/en/server-integration.md` if the new round
      changes the request wire shape that callers see.
- [ ] Run the local supply-chain script with the new round:
      `.\scripts\local-supply-chain.ps1 -Image floria:local-round-bump`.
- [ ] Confirm `cargo test sanitized_provider_payload --lib` and
      `cargo test provider_payload_strictness --test provider_payload_strictness`
      both still pass.

Suggested local check before removal of the local sweep:

```powershell
cargo test sanitized_provider_payload --lib
cargo test provider_payload_strictness --test provider_payload_strictness
```

Keep this file updated with the SDK commit or release that satisfies
the gate.
