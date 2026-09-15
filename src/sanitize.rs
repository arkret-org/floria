//! Shared helpers for floria's blind-wakeup provider egress payload
//! hygiene.
//!
//! The shared SDK owns both blind-payload forbidden names and fields accepted
//! at gateway ingress but stripped before an external provider sees them.

use arkret_push_policy::blind_payload_sanitizer as sdk;

/// Returns `true` if `key` must be stripped before a provider sees it:
/// the shared routing/audit strip set or the forbidden blind-payload set.
pub fn is_forbidden_egress_key(key: &str) -> bool {
    sdk::is_forbidden_provider_egress_key(key)
}

/// Recursively remove every **strip-only** routing/audit name
/// (case-insensitive) from a JSON value, descending into nested objects and
/// arrays.
///
/// Used by egress-adjacent surfaces that serialize internal structures for an
/// operator reader — e.g. the dead-letter snapshot route — as a
/// defense-in-depth backstop: even if the serialized shape later grows a
/// routing/audit field, it never leaves the process.
///
/// This is deliberately [`sdk::PROVIDER_EGRESS_STRIP_KEYS`] and **not**
/// [`is_forbidden_egress_key`]. The forbidden blind-payload set is the
/// contract against an external push provider and includes gateway
/// correlation identifiers such as `request_id`; an authenticated operator
/// diagnostic is not that reader, and stripping its correlation id would
/// leave the snapshot unusable without protecting anything.
pub fn strip_egress_only_keys(value: &mut serde_json::Value) {
    fn is_strip_only(key: &str) -> bool {
        sdk::PROVIDER_EGRESS_STRIP_KEYS
            .iter()
            .any(|name| name.eq_ignore_ascii_case(key))
    }
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|key, _| !is_strip_only(key));
            for child in map.values_mut() {
                strip_egress_only_keys(child);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                strip_egress_only_keys(child);
            }
        }
        _ => {}
    }
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
        // Strip-only routing/audit tail, including retired legacy names, is
        // egress-stripped.
        assert!(is_forbidden_egress_key("route_tokens"));
        assert!(is_forbidden_egress_key("scope_route_token"));
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

    #[test]
    fn strip_egress_only_keys_removes_nested_and_case_insensitive_names() {
        let mut value = serde_json::json!({
            "request_id": "req-1",
            "route_tokens": {"realm_route_token": "ak:secret"},
            "Scope_Route_Token": "ak:secret-2",
            "nested": {
                "kept": "yes",
                "list": [
                    {"delivery_binding_frontier_token": "ak:secret-4", "ok": 1}
                ]
            }
        });
        strip_egress_only_keys(&mut value);
        let rendered = serde_json::to_string(&value).unwrap();
        for name in sdk::PROVIDER_EGRESS_STRIP_KEYS {
            assert!(
                !rendered.to_ascii_lowercase().contains(*name),
                "stripped key `{name}` leaked into `{rendered}`"
            );
        }
        assert!(!rendered.contains("ak:secret"));
        assert_eq!(value["request_id"], serde_json::json!("req-1"));
        assert_eq!(value["nested"]["kept"], serde_json::json!("yes"));
        assert_eq!(value["nested"]["list"][0]["ok"], serde_json::json!(1));
    }
}
