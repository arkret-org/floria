# SDK Sync Gate

floria still carries a local provider-payload sweep for Round R2/R3 forbidden
fields. The SDK exposes `contrix::blind_payload_sanitizer::is_forbidden_payload_key`,
but the exported list is not yet sufficient for the newer realm, appeal,
attestation, policy-frontier, and cross-signing-reset field names.

## Local Sweep

The local sweep is implemented in `src/pushkin/mod.rs` as
`ROUND23_LOCAL_FORBIDDEN` and runs recursively through
`sanitized_provider_payload`. Provider-specific tests in the Android, FCM, and
WebPush adapters also assert that renamed Realm/Space identifiers stay off the
provider wire.

The locally stripped names are:

| Field | Reason |
|-------|--------|
| `realm_id` | Stable security-boundary identifier after the Realm/Space rework |
| `appeal_id` | Links a push to a moderation appeal thread |
| `attestation_evidence` | Reveals audit-agent or device posture |
| `audit_purpose` | Reveals audit routing intent |
| `attestation_chain` | Reveals attestation chain material |
| `audit_policy_version_digest` | Stable audit policy correlator |
| `policy_frontier_digest` | Stable policy frontier correlator |
| `trust_domain` | Deployment scope leakage |
| `reset_event_id` | Links a push to a cross-signing reset event |

## Upgrade Gate

Do not remove the local sweep until all of these are true:

1. The SDK helper rejects every name above case-insensitively.
2. The SDK helper is documented as the canonical blind-wakeup forbidden-key
   source for Round R2/R3 and later.
3. floria tests pass after deleting `ROUND23_LOCAL_FORBIDDEN` and changing
   `sanitized_provider_payload` to rely on the SDK helper only.
4. The adapter tests continue to assert `realm_id` and legacy `space_id` are
   absent from provider payloads.

Suggested local check before removal:

```powershell
cargo test sanitized_provider_payload --lib
cargo test provider_payload_strictness --test provider_payload_strictness
```

Keep this file updated with the SDK commit or release that satisfies the gate.
