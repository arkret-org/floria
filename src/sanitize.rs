//! Shared helpers for floria's blind-wakeup provider egress payload
//! hygiene.
//!
//!   * [`STRIP_ONLY_KEYS`] — names accepted at ingress but never sent to an external provider. Some
//!     are consumed by floria for routing/audit, others are protocol payload names that remain
//!     outside the blind provider surface.
//!   * Egress also strips everything the SDK's own `is_forbidden_payload_key` covers.
//!
//! These names are floria-local defence-in-depth for identifiers the
//! SDK's `is_forbidden_payload_key` does not yet cover (rounds R2/R3,
//! AKP-0007, the 9dabf26 carrier split). Names the SDK already rejects
//! (e.g. `encrypted_content`, `sender_actor_display_name`, `realm_id`,
//! `space_id`) are intentionally NOT duplicated here.
// TODO(circle-rollout-P2C.5): once the SDK ships `is_forbidden_payload_key`
// coverage for these names, drop the local egress list and route provider
// stripping straight at the SDK predicate.

use arkret_push_policy::blind_payload_sanitizer as sdk;

/// Names accepted inbound but silently stripped before a provider sees
/// them. Matched case-insensitively.
///
///   * SPEC-CR-016 gateway-internal routing fragment (`route_tokens` and its leaves) — consumed by
///     floria for routing/dedup, opaque by construction, never forwarded.
///   * R2/R3 governance / correlation identifiers (moderation appeal, audit attestation posture,
///     cross-signing reset, policy-frontier hash) — meaningful to the audit pipeline, a stable
///     correlator on the provider wire.
pub const STRIP_ONLY_KEYS: &[&str] = &[
    // --- SPEC-CR-016 gateway-internal routing fragment ---
    // The whole `route_tokens` wrapper plus its leaf routing fields are
    // consumed inbound for gateway-side routing / dedup but MUST be stripped
    // before any provider sees them. `build_blind_provider_data` is
    // allow-list based so they never reach a provider by construction; these
    // entries are the defense-in-depth egress backstop.
    "route_tokens",
    "realm_route_token",
    "scope_route_token",
    "mention_redirect_target_route_tokens",
    "delivery_binding_frontier_token",
    "target_route_token",
    "timing_profile_hint",
    // --- Protocol payload names kept off the provider surface ---
    "expected_previous_generation",
    "attestation_evidence",
    "attestation_chain",
    "size",
    "strand_body",
    "message_body",
    "body_only",
    "encrypted_payload",
    "encrypted_metadata",
    "metadata",
    "fields",
    "track",
    "track_name",
    // --- Actor-private notification preference state ---
    "push_rules",
    "dnd",
    "dnd_schedule",
    "dnd_enabled",
    "dnd_exceptions",
    "snooze",
    "snoozed",
    "snooze_expires_at",
    "snooze_until",
    // --- R2/R3 governance / correlation identifiers ---
    "appeal_id",
    "audit_purpose",
    "audit_policy_version_digest",
    "policy_frontier_digest",
    "trust_domain",
    "reset_event_id",
];

/// Returns `true` if `key` must be stripped before a provider sees it:
/// the strip-only routing/audit tail OR the SDK's own forbidden-payload
/// list.
pub fn is_forbidden_egress_key(key: &str) -> bool {
    sdk::is_forbidden_payload_key(key)
        || STRIP_ONLY_KEYS
            .iter()
            .any(|name| name.eq_ignore_ascii_case(key))
}

/// Representative value for the closed `6-20` count bucket.
pub const BUCKET_SIX_TO_TWENTY: u64 = 20;
/// Representative value for the open `21+` count bucket.
pub const BUCKET_TWENTY_ONE_PLUS: u64 = 21;

/// Bucket an absolute count for the `blind_wakeup` profile per
/// push-notifications.md §5.1.
///
/// The absolute unread / missed-call count is an activity side channel:
/// shipping `unread = 37` lets the provider build a cumulative
/// per-`push_target_id` activity profile. §5.1 requires that, if an
/// absolute count is carried at all under `blind_wakeup`, it MUST use
/// the closed default grid (`1` / `2-5` / `6-20` / `21+`).
///
/// This maps a raw count to the *representative* value of its bucket so
/// ordering is preserved while the exact figure is destroyed:
///
/// | input  | bucket | emitted |
/// |--------|--------|---------|
/// | `0`    | none   | `0`     |
/// | `1`    | `1`    | `1`     |
/// | `2..=5`| `2-5`  | `5`     |
/// | `6..=20`| `6-20`| `20`    |
/// | `21..` | `21+`  | `21`    |
///
/// The result is always `<= MAX_COUNT_VALUE`, so it doubles as the
/// upper-bound clamp the egress paths previously did by hand.
pub fn bucket_count(raw: u64) -> u64 {
    match raw {
        0 => 0,
        1 => 1,
        2..=5 => 5,
        6..=20 => BUCKET_SIX_TO_TWENTY,
        _ => BUCKET_TWENTY_ONE_PLUS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_count_matches_spec_granularity() {
        assert_eq!(bucket_count(0), 0);
        assert_eq!(bucket_count(1), 1);
        assert_eq!(bucket_count(2), 5);
        assert_eq!(bucket_count(5), 5);
        assert_eq!(bucket_count(6), 20);
        assert_eq!(bucket_count(20), 20);
        assert_eq!(bucket_count(21), 21);
        // The headline leak case: 37 must NOT reach the wire verbatim.
        assert_eq!(bucket_count(37), 21);
        assert_eq!(bucket_count(9_999), 21);
        assert!(bucket_count(u64::MAX) <= sdk::MAX_COUNT_VALUE);
    }

    #[test]
    fn egress_strips_sdk_and_strip_only_keys() {
        // Strip-only routing/audit tail is egress-stripped.
        assert!(is_forbidden_egress_key("route_tokens"));
        assert!(is_forbidden_egress_key("scope_route_token"));
        assert!(is_forbidden_egress_key("timing_profile_hint"));
        assert!(is_forbidden_egress_key("policy_frontier_digest"));
        // SDK-covered names are egress-stripped.
        assert!(is_forbidden_egress_key("encrypted_content"));
        assert!(is_forbidden_egress_key("target_ref"));
        // Actor-private notification preference state is egress-stripped.
        assert!(is_forbidden_egress_key("dnd_schedule"));
        assert!(is_forbidden_egress_key("snooze_expires_at"));
        // Allowed blind field stays allowed at both layers.
        assert!(!is_forbidden_egress_key("push_target_id"));
    }
}
