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
//! CKP-0007, the 9dabf26 carrier split). Names the SDK already rejects
//! (e.g. `encrypted_content`, `sender_actor_display_name`, `realm_id`,
//! `space_id`) are intentionally NOT duplicated here.
// TODO(circle-rollout-P2C.5): once the SDK ships `is_forbidden_payload_key`
// coverage for these names, drop the local egress list and route provider
// stripping straight at the SDK predicate.

use cokret::blind_payload_sanitizer as sdk;

/// Names accepted inbound but silently stripped before a provider sees
/// them. Matched case-insensitively.
///
///   * CKP-0007 Circle primitive (`circle_id` / `effective_scope` / `scope_circle_id`) — drives
///     gateway-internal routing & dedup normalization; leaking it would disclose the encryption
///     sub-boundary / realm binding.
///   * R2/R3 governance / correlation identifiers (moderation appeal, audit attestation posture,
///     cross-signing reset, policy-frontier hash) — meaningful to the audit pipeline, a stable
///     correlator on the provider wire.
pub const STRIP_ONLY_KEYS: &[&str] = &[
    // --- SPEC-CR-016 gateway-internal routing fragment ---
    // The whole `routing_metadata` wrapper plus its leaf routing fields are
    // consumed inbound for gateway-side routing / dedup but MUST be stripped
    // before any provider sees them. `build_blind_provider_data` is
    // allow-list based so they never reach a provider by construction; these
    // entries are the defense-in-depth egress backstop.
    "routing_metadata",
    "mention_redirect_target_actor_ids",
    "delivery_binding_frontier",
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
    // --- CKP-0007 Circle primitive (routing-only) ---
    "circle_id",
    "effective_scope",
    "scope_circle_id",
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

/// Visible-text leaf keys that a blind-profile caller must not embed in
/// the `content` object. These are *plaintext rendering* fields (alert
/// title/body/etc.).
pub const BLIND_FORBIDDEN_CONTENT_TEXT_KEYS: &[&str] =
    &["title", "body", "subtitle", "alert", "preview", "summary"];

/// Maximum representative value emitted by [`bucket_count`]. The open
/// `6+` bucket collapses to this floor so the absolute count never
/// reaches the wire.
pub const BUCKET_SIX_PLUS: u64 = 6;

/// Bucket an absolute count for the `blind_wakeup` profile per
/// push-notifications.md §5.1.
///
/// The absolute unread / missed-call count is an activity side channel:
/// shipping `unread = 37` lets the provider build a cumulative
/// per-`push_target_id` activity profile. §5.1 requires that, if an
/// absolute count is carried at all under `blind_wakeup`, it MUST be
/// bucketed to the policy-declared granularity (`1` / `2-5` / `6+`).
///
/// This maps a raw count to the *representative* value of its bucket so
/// ordering is preserved while the exact figure is destroyed:
///
/// | input  | bucket | emitted |
/// |--------|--------|---------|
/// | `0`    | none   | `0`     |
/// | `1`    | `1`    | `1`     |
/// | `2..=5`| `2-5`  | `5`     |
/// | `6..`  | `6+`   | `6`     |
///
/// The result is always `<= MAX_COUNT_VALUE`, so it doubles as the
/// upper-bound clamp the egress paths previously did by hand.
pub fn bucket_count(raw: u64) -> u64 {
    match raw {
        0 => 0,
        1 => 1,
        2..=5 => 5,
        _ => BUCKET_SIX_PLUS,
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
        assert_eq!(bucket_count(6), 6);
        // The headline leak case: 37 must NOT reach the wire verbatim.
        assert_eq!(bucket_count(37), 6);
        assert_eq!(bucket_count(9_999), 6);
        assert!(bucket_count(u64::MAX) <= sdk::MAX_COUNT_VALUE);
    }

    #[test]
    fn egress_strips_sdk_and_strip_only_keys() {
        // Strip-only routing/audit tail is egress-stripped.
        assert!(is_forbidden_egress_key("circle_id"));
        assert!(is_forbidden_egress_key("policy_frontier_digest"));
        // SDK-covered names are egress-stripped.
        assert!(is_forbidden_egress_key("encrypted_content"));
        // Allowed blind field stays allowed at both layers.
        assert!(!is_forbidden_egress_key("push_target_id"));
    }
}
