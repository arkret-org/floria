# SDK Sync Gate

The SDK owns the canonical blind-payload and provider-egress forbidden-key
sets. floria applies that shared policy recursively immediately before an
external provider sees a payload.

## Provider Egress Sweep

The local sweep is implemented in `src/sanitize.rs` as
`is_forbidden_egress_key` and runs recursively through
`pushkin::sanitized_provider_payload`. Provider-specific tests in the
Android, FCM, and WebPush adapters also assert that renamed
Realm/Space/Circle identifiers stay off the provider wire.

### Governance / correlation identifiers

`arkret_push_policy::blind_payload_sanitizer` is authoritative. It exports
the ingress-forbidden names and the additional provider-egress strip set;
floria deliberately carries no local mirror. The table below records the
rationale for governance and correlation names in the shared strip set.

| Field | Rationale |
|-------|-----------|
| `attestation_evidence` | Reveals audit-agent or device posture (TPM PCR digests, key attestation chain) |
| `audit_purpose` | Reveals audit routing intent (which downstream audit channel the push will divert to) |
| `attestation_chain` | Reveals attestation chain material; same leak class as `attestation_evidence` |
| `audit_policy_version_digest` | Stable audit policy correlator — long-lived, cross-request linkability |
| `policy_frontier_digest` | Retired legacy field retained only in the denylist; its stable value has the same linkability risk as an audit policy version |
| `trust_domain` | Deployment-scope leakage — exposes whether the principal is on a federation edge |

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
message rendering, not to `ak.edge.push.command.notify.v1`. floria keeps the typed
payload closed with `serde(deny_unknown_fields)`, so those fields are
rejected with `schema_violation`.

## Spec Update Checklist

Use this when `push-notifications.md` changes its provider-visible payload
rules:

- [ ] Update the SDK's exported forbidden-key sets; do not add a floria-local
      mirror.
- [ ] Add a property test in `tests/property_provider_payload.rs`
      that fuzzes the new field name into request bodies and asserts
      the provider wire does not contain it (case-insensitive).
- [ ] Update `docs/en/server-integration.md` if the new round
      changes the request wire shape that callers see.
- [ ] Run the local supply-chain script:
      `.\scripts\local-supply-chain.ps1 -Image floria:local-spec-update`.
- [ ] Confirm `cargo test sanitized_provider_payload --lib` and
      `cargo test provider_payload_strictness --test provider_payload_strictness`
      both still pass.

Suggested local check:

```powershell
cargo test sanitized_provider_payload --lib
cargo test provider_payload_strictness --test provider_payload_strictness
```

Keep this file aligned with the shared SDK policy surface.
