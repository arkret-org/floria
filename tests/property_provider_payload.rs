//! T8.2 — property tests for `floria::pushkin::sanitized_provider_payload`.
//!
//! The provider payload sanitizer is floria's last line of defence
//! before a notification leaves the gateway for an external push
//! provider (APNS, FCM, WebPush, Chinese OEM, custom). This file
//! exercises three invariants:
//!
//!  1. **Any forbidden top-level or nested key is stripped** — the sanitized output never contains
//!     a name on the SDK forbidden list at any nesting depth.
//!  2. **`did:` / `ck:` literals are rejected** — strings that smell like correlation identifiers
//!     cause a `ProviderPayloadRejection` rather than silently surviving.
//!  3. **Allowed static config keys (`client`, `wakeup_kind`, etc.) round-trip unchanged** —
//!     sanitization is removal-only.
//!
//! Each block is capped at 64 cases to keep CI fast.

use floria::pushkin::sanitized_provider_payload;
use proptest::prelude::*;
use serde_json::{Map, Value, json};

const PROPTEST_CASES: u32 = 64;

/// SDK forbidden keys mirrored locally so we can drive proptest inputs.
const FORBIDDEN_NAMES: &[&str] = &[
    "event_id",
    "message_id",
    "strand_id",
    "space_id",
    "realm_id",
    "thread_id",
    "correlation_id",
    "sender",
    "sender_did",
    "sender_actor_display_name",
    "from",
    "to",
    "target_did",
    "device_id",
    "device_did",
    "body",
    "content",
    "title",
    "subtitle",
    "preview",
    "summary",
    "alert",
    "filename",
    "file_name",
    "attachment_name",
    "attachment_filename",
    "mime_type",
    "media_url",
    "space_name",
    "strand_name",
    "room_name",
    "provider_payload",
    "provider_data",
    "ciphertext",
    "encrypted_payload",
    "encrypted_content",
    "encrypted_metadata",
    "metadata",
    "fields",
    "track",
    "track_name",
    "sdp",
    "offer",
    "candidate",
    "ice_candidate",
    "facet",
    "view_renderer",
    // Actor-private notification preference state.
    "push_rules",
    "dnd",
    "dnd_schedule",
    "dnd_enabled",
    "dnd_exceptions",
    "snooze",
    "snoozed",
    "snooze_expires_at",
    "snooze_until",
    "target_ref",
    "target_key",
    // Round R2/R3 (2026-05-20) additions — stripped locally by floria
    // ahead of the SDK forbidden-list update (T07/T10/T06).
    "appeal_id",
    "attestation_evidence",
    "audit_purpose",
    "attestation_chain",
    "audit_policy_version_digest",
    "policy_frontier_digest",
    "trust_domain",
    "reset_event_id",
    "route_tokens",
    "realm_route_token",
    "scope_route_token",
    "mention_redirect_target_route_tokens",
    "delivery_binding_frontier_token",
    "target_route_token",
    "encrypted_content",
    "encrypted_metadata",
    "metadata",
    "fields",
    "track",
    "track_name",
];

fn arb_forbidden_key() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(FORBIDDEN_NAMES.to_vec())
}

fn arb_leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        // Non-sensitive ASCII text only (so we don't trigger the
        // `did:` / `ck:` sensitive-literal path in this property).
        "[a-zA-Z0-9_ .-]{0,16}".prop_map(Value::String),
        any::<i32>().prop_map(|n| json!(n)),
    ]
}

/// Recursively scan a value for any forbidden key by name.
fn contains_forbidden_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(k, v)| {
            FORBIDDEN_NAMES.iter().any(|f| f.eq_ignore_ascii_case(k)) || contains_forbidden_key(v)
        }),
        Value::Array(arr) => arr.iter().any(contains_forbidden_key),
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// Property 1 — injecting any forbidden key at the top level
    /// results in it being stripped from the sanitizer output. We
    /// allow either of:
    ///   * Sanitizer returns Ok and the output has no forbidden key.
    ///   * Sanitizer rejects (e.g. the value embedded a `did:` literal).
    #[test]
    fn forbidden_top_level_keys_are_stripped(
        forbidden in arb_forbidden_key(),
        leaf in arb_leaf(),
    ) {
        let mut payload = Map::new();
        payload.insert("client".into(), json!("android"));
        payload.insert("wakeup_kind".into(), json!("message"));
        payload.insert(forbidden.to_string(), leaf);
        let outcome = sanitized_provider_payload(payload);
        if let Ok(out) = outcome {
            // forbidden name must not survive
            prop_assert!(
                !contains_forbidden_key(&Value::Object(out.clone())),
                "forbidden key `{forbidden}` survived: {out:?}"
            );
            // Allowed keys preserved.
            prop_assert_eq!(out.get("client"), Some(&json!("android")));
        }
    }

    /// Property 2 — injecting a forbidden key inside a nested object
    /// also gets stripped (or rejected) — recursive sweep.
    #[test]
    fn forbidden_nested_keys_are_stripped(
        forbidden in arb_forbidden_key(),
        leaf in arb_leaf(),
    ) {
        let mut payload = Map::new();
        payload.insert("client".into(), json!("ios"));
        payload.insert("wakeup_kind".into(), json!("message"));
        payload.insert(
            "nested".into(),
            json!({ "deep": { forbidden: leaf, "ok_key": "value" } }),
        );
        let outcome = sanitized_provider_payload(payload);
        if let Ok(out) = outcome {
            prop_assert!(
                !contains_forbidden_key(&Value::Object(out.clone())),
                "forbidden key `{forbidden}` survived nested sweep: {out:?}"
            );
        }
    }

    /// Property 3 — payloads carrying a `did:` literal in any field
    /// value MUST be rejected by the SDK sanitizer at the final
    /// envelope check. (Top-level `client` / `wakeup_kind` are stripped
    /// of forbidden NAMES but not VALUES until the envelope step.)
    #[test]
    fn did_or_cx_literal_in_extra_field_is_rejected(
        suffix in "[a-z0-9]{1,12}",
        prefix in prop_oneof![Just("did:web:"), Just("ck:event:"), Just("ck:strand:")],
    ) {
        // Use a key that is NOT in the forbidden list, so the only
        // rejection path is the sensitive-literal check.
        let mut payload = Map::new();
        payload.insert("client".into(), json!("android"));
        payload.insert("wakeup_kind".into(), json!("message"));
        payload.insert("custom_tracer".into(), json!(format!("{prefix}{suffix}")));
        prop_assert!(
            sanitized_provider_payload(payload).is_err(),
            "did:/ck: literal smuggled in custom_tracer slipped through"
        );
    }

    /// Property 4 — allowed config keys (`client`, `wakeup_kind`,
    /// `push_target_id` shape) round-trip unchanged when there are no
    /// forbidden siblings.
    #[test]
    fn allowed_keys_round_trip(
        client in prop_oneof![Just("ios"), Just("android"), Just("web")],
    ) {
        let mut payload = Map::new();
        payload.insert("client".into(), json!(client));
        payload.insert("wakeup_kind".into(), json!("message"));
        let out = sanitized_provider_payload(payload).expect("clean payload accepted");
        prop_assert_eq!(out.get("client"), Some(&json!(client)));
        prop_assert_eq!(out.get("wakeup_kind"), Some(&json!("message")));
    }
}
