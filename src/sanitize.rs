//! Single authoritative source for floria's blind-wakeup payload
//! hygiene primitives shared between the `/notify` **ingress** (hard
//! reject) and the provider **egress** (silent strip) paths.
//!
//! Before this module existed the "forbidden blind-wire key" set was
//! maintained in three drifting places (the notify ingress leaf-key
//! list, the `content.*` plaintext list, and the pushkin egress strip
//! list). The lists overlapped but disagreed, so a field could pass
//! ingress yet only be caught by the egress strip (or vice versa),
//! making the two defence layers asymmetric.
//!
//! The two layers are *not* the same set — and that asymmetry is
//! intentional, not drift:
//!
//!   * [`FORBIDDEN_INBOUND_KEYS`] — names that must NEVER appear on the inbound request at all
//!     (protocol content / metadata / track selectors / authenticator material). The ingress walker
//!     **hard rejects** these.
//!   * [`STRIP_ONLY_KEYS`] — names that floria legitimately *consumes* inbound for internal routing
//!     (`circle_id` / `effective_scope` / `scope_circle_id`) or audit (`appeal_id`, governance
//!     digests) but that MUST NOT reach a provider. These are accepted at ingress and **silently
//!     stripped** at egress.
//!   * Egress strips the union of both ([`is_forbidden_egress_key`]), plus everything the SDK's own
//!     `is_forbidden_payload_key` covers.
//!
//! So both layers now derive from one shared core; the difference is the
//! *action* (reject vs. strip) and the strip-only routing tail, never a
//! divergently-maintained list.
//!
//! These names are floria-local defence-in-depth for identifiers the
//! SDK's `is_forbidden_payload_key` does not yet cover (rounds R2/R3,
//! CKP-0007, the 9dabf26 carrier split). Names the SDK already rejects
//! (e.g. `encrypted_content`, `sender_actor_display_name`, `realm_id`,
//! `space_id`) are intentionally NOT duplicated here.
// TODO(circle-rollout-P2C.5): once the SDK ships `is_forbidden_payload_key`
// coverage for these names, drop the local lists and route both layers
// straight at the SDK predicate.

use cokret::blind_payload_sanitizer as sdk;

/// Names that must NEVER appear anywhere on the inbound `/notify`
/// request. The ingress walker hard-rejects these; egress strips them
/// too (they are part of [`is_forbidden_egress_key`]). Matched
/// case-insensitively.
///
/// Grouped by the spec revision that introduced each name:
///   * Round-4 authenticator / CAS material that must not ride the push wire
///     (`expected_previous_generation`, `attestation_*`).
///   * Phase P2 (spec 37ce729) legacy field-name aliases that were renamed in the candidate
///     breaking pass; the old forms fail closed so a caller pinned to an old SDK can't smuggle
///     mismatched semantics through (`size` / `strand_body` / `message_body` / `body_only`).
///   * Spec 9dabf26 message/strand carrier split — protocol content / metadata / track selectors
///     (`encrypted_*` / `metadata` / `fields` / `track*`).
pub const FORBIDDEN_INBOUND_KEYS: &[&str] = &[
    // --- Round-4 authenticator / CAS material ---
    "expected_previous_generation",
    "attestation_evidence",
    "attestation_chain",
    // --- Phase P2 (spec 37ce729) legacy field-name aliases ---
    "size",
    "strand_body",
    "message_body",
    "body_only",
    // --- Spec 9dabf26 carrier split (content / metadata / track) ---
    // `encrypted_content` is also on the SDK `is_forbidden_payload_key`
    // list, but the ingress walker does not call the SDK predicate (it
    // would reject legitimate envelope fields like `content`), so we keep
    // an explicit hard-reject entry here to preserve ingress behaviour.
    "encrypted_payload",
    "encrypted_content",
    "encrypted_metadata",
    "metadata",
    "fields",
    "track",
    "track_name",
];

/// Names floria legitimately consumes inbound (internal routing / audit)
/// but that MUST NOT reach a provider. Accepted at ingress, silently
/// stripped at egress. Matched case-insensitively.
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

/// Returns `true` if `key` must be hard-rejected on the inbound request
/// ([`FORBIDDEN_INBOUND_KEYS`]), matched case-insensitively.
pub fn is_forbidden_inbound_key(key: &str) -> bool {
    FORBIDDEN_INBOUND_KEYS
        .iter()
        .any(|name| name.eq_ignore_ascii_case(key))
}

/// Returns `true` if `key` must be stripped before a provider sees it:
/// the inbound-forbidden set, the strip-only routing/audit tail, OR the
/// SDK's own forbidden-payload list. Use this for egress strip so it can
/// never under-cover what ingress rejects.
pub fn is_forbidden_egress_key(key: &str) -> bool {
    sdk::is_forbidden_payload_key(key)
        || is_forbidden_inbound_key(key)
        || STRIP_ONLY_KEYS
            .iter()
            .any(|name| name.eq_ignore_ascii_case(key))
}

/// Visible-text leaf keys that a blind-profile caller must not embed in
/// the `content` object. These are *plaintext rendering* fields (alert
/// title/body/etc.), a distinct concern from the correlation-id set
/// above; the overlapping correlation keys (`metadata`, `fields`,
/// `track`, ...) are covered by [`is_forbidden_inbound_key`] and are not
/// duplicated here.
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
    fn inbound_reject_is_case_insensitive() {
        assert!(is_forbidden_inbound_key("metadata"));
        assert!(is_forbidden_inbound_key("Metadata"));
        assert!(is_forbidden_inbound_key("attestation_evidence"));
        assert!(is_forbidden_inbound_key("size"));
        // Routing-only keys are accepted inbound (stripped at egress).
        assert!(!is_forbidden_inbound_key("circle_id"));
        assert!(!is_forbidden_inbound_key("effective_scope"));
        assert!(!is_forbidden_inbound_key("push_target_id"));
    }

    #[test]
    fn egress_strips_superset_of_inbound() {
        // Everything inbound-forbidden is also egress-stripped.
        for key in FORBIDDEN_INBOUND_KEYS {
            assert!(is_forbidden_egress_key(key), "egress must strip {key}");
        }
        // Strip-only routing/audit tail is egress-stripped...
        assert!(is_forbidden_egress_key("circle_id"));
        assert!(is_forbidden_egress_key("policy_frontier_digest"));
        // ...but those routing keys are NOT rejected at ingress.
        assert!(!is_forbidden_inbound_key("circle_id"));
        // SDK-covered name (not duplicated locally) is egress-stripped.
        assert!(is_forbidden_egress_key("encrypted_content"));
        // Allowed blind field stays allowed at both layers.
        assert!(!is_forbidden_egress_key("push_target_id"));
        assert!(!is_forbidden_inbound_key("push_target_id"));
    }
}
