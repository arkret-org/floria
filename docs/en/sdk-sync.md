# SDK Sync Gate

floria still carries a local provider-payload sweep for forbidden egress
fields that are stricter than the SDK's generic blind-payload helper. The
SDK exposes `arkret::blind_payload_sanitizer::is_forbidden_payload_key`,
but the exported list is not yet sufficient for the gateway-internal
routing fragment, appeal, attestation, policy-frontier, or the
actor-private DND / snooze preference field names.

## Local Sweep

The local sweep is implemented in `src/sanitize.rs` as
`is_forbidden_egress_key` and runs recursively through
`pushkin::sanitized_provider_payload`. Provider-specific tests in the
Android, FCM, and WebPush adapters also assert that renamed
Realm/Space/Circle identifiers stay off the provider wire.

### Governance / correlation identifiers

`src/sanitize.rs`'s `STRIP_ONLY_KEYS` is the authoritative list; the
table below records the rationale for the R2/R3 governance and
correlation names only. Names the SDK helper already rejects (for
example `realm_id`, `space_id`, `encrypted_content`,
`sender_actor_display_name`) are deliberately not duplicated locally.

| Field | Round | Rationale |
|-------|-------|-----------|
| `appeal_id` | R2 | Links a push to a moderation appeal thread; visible in provider logs would expose that the user is under review |
| `attestation_evidence` | R3 | Reveals audit-agent or device posture (TPM PCR digests, key attestation chain) |
| `audit_purpose` | R3 | Reveals audit routing intent (which downstream audit channel the push will divert to) |
| `attestation_chain` | R3 | Reveals attestation chain material; same leak class as `attestation_evidence` |
| `audit_policy_version_digest` | R3 | Stable audit policy correlator — long-lived, cross-request linkability |
| `policy_frontier_digest` | R3 | Stable policy frontier correlator — same linkability class as the audit policy version |
| `trust_domain` | R3 | Deployment-scope leakage — exposes whether the principal is on a federation edge |

The match is case-insensitive and applies recursively through nested
provider-defined wrappers (e.g. `aps.alert`, `android.notification`,
`data.payload`).

### Circle identifiers are structurally impossible, not stripped

`circle_id`, `effective_scope` and `scope_circle_id` are **not** on the
sweep list and must not be added back. The v1 push wire model has no
Circle identifier and no scope field at all: `push-notifications.md` §5.1
keeps raw Realm ids, Circle ids and `effective_scope` off
`/_arkret/edge/push/notify`, and `PushNotificationEnvelope` is
`serde(deny_unknown_fields)`, so such a name cannot even deserialize into
floria's typed model. The security scope of an Event lives in its
producer-signed `scope_ref` and never reaches a gateway. The negative
assertions in the Android / FCM / WebPush adapters stay as regression
guards on the allow-list builder.

## Mention Reference Fields N/A

ROST-FLO-1..3 mention reference fields are intentionally not part of
floria's push wire model. `subject_id`, `display_name_at_time`, and
related Message AST preview fields belong to chime / principal-service
message rendering, not to `ak.edge.push.command.notify`. floria keeps the typed
payload closed with `serde(deny_unknown_fields)`, so those fields are
rejected with `schema_violation`.

## Upgrade Gate

Do not remove the local sweep until all of these are true:

1. The SDK helper rejects every `STRIP_ONLY_KEYS` name
   case-insensitively.
2. The SDK helper is documented as the canonical blind-wakeup
   forbidden-key source for Round R2/R3 and AKP-0007 and later.
3. floria tests pass after deleting the local `is_forbidden_egress_key` extension list and
   changing `sanitized_provider_payload` to rely on the SDK helper
   only.
4. The adapter tests continue to assert `realm_id` and `space_id` are
   absent from provider payloads.

## Spec round upgrade checklist

Use this when bumping floria to a newer arkret-spec round (R4 →
R5, AKP-0007 → AKP-0008, etc.):

- [ ] Diff the new round's `forbidden_payload_keys` table against
      `is_forbidden_egress_key`. Add any newly forbidden names to
      the local list with a rationale row in this doc.
- [ ] Add a property test in `tests/property_provider_payload.rs`
      that fuzzes the new field name into request bodies and asserts
      the provider wire does not contain it (case-insensitive).
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
