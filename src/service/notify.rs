use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use salvo::http::ParseError;
use salvo::http::StatusCode;
use salvo::http::header::{HeaderName, HeaderValue};
use salvo::prelude::*;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::AppState;
use crate::audit::AuditEvent;
use crate::auth::{
    AuthFailure, AuthenticatedNotifyCaller, DESTINATION_SERVICE_DID_HEADER,
    ORIGIN_SERVICE_DID_HEADER, authenticate_notify_request,
};
use crate::config::NotifyAuthConfig;
use crate::dedup::request_hash;
use crate::metrics as app_metrics;
use crate::models::{
    DeliveryReceipt, Notification, NotificationContext, NotifyResponse, ProviderRetry,
    RejectedDevice, redact_push_token,
};
use crate::rate_limit::NotifyRateLimitCheck;

use super::metrics::{
    finish_error, finish_json, record_delivery_receipt_outcomes, record_notify_delivery_outcomes,
};
use super::{
    ACTIVE_EVENT_ID_PREFIX, ACTIVE_FLOW_ID_PREFIX, ACTIVE_MESSAGE_ID_PREFIX,
    ACTIVE_REALM_ID_PREFIX, MAX_REQUEST_SIZE, NOTIFY_OPERATION_ID,
};

// Round 4 (spec a77b995) — additional forbidden-key list maintained
// locally as a defense-in-depth layer on top of the SDK's
// `is_forbidden_payload_key`. These cover proof / CAS / attestation
// material that would leak if it ever made it onto a push wire — the
// SDK's blind sanitizer covers most of the round-3 surface, but the
// round-4 protocol-review closures add new authenticator fields
// (`binding_proof.signature`, `subject_proof.signature`,
// `expected_previous_generation`, `attestation_evidence`) that are
// rejected here regardless of profile.
//
// Matched case-insensitively against the leaf key name of any nested
// payload field. Path-shaped matches (`binding_proof.signature`) also
// match when the parent key + leaf key form that path, so callers
// can't smuggle a `signature` under an unrelated parent and have it
// pass.
const ROUND4_FORBIDDEN_LEAF_KEYS: &[&str] =
    &["expected_previous_generation", "attestation_evidence"];

/// Parent key + leaf key pairs that are forbidden. The SDK already
/// rejects any standalone `signature` field reaching the wire, but
/// round-4 specifically calls out the `binding_proof.signature` and
/// `subject_proof.signature` combinations so we add an explicit
/// path-shaped check for them — both for clearer error messages and so
/// a future sanitizer relaxation cannot accidentally re-open the
/// proof-signature leak.
const ROUND4_FORBIDDEN_PARENT_LEAF: &[(&str, &str)] = &[
    ("binding_proof", "signature"),
    ("subject_proof", "signature"),
];

/// Round 4 — `reason_code=historical_only` short-circuits soland's
/// diagnostic replay. floria MUST NOT fan the request out a second
/// time; it answers 200 with an empty rejected list and no provider
/// retries. The wire constant comes from the SDK.
const HISTORICAL_ONLY_REASON: &str = contrix::ERROR_CODE_HISTORICAL_ONLY;

/// Round 4 — `cx.audit.policy_access.access_kind` value that diverts
/// to the audit pipeline. floria MUST NOT push-fan-out when the
/// inbound request carries this access_kind; it forwards to the audit
/// sink and only then acks with 200. The wire literal mirrors the SDK
/// enum serde repr (`snake_case`).
const E2EE_LATE_RECOVERY_ACCESS_KIND: &str = "e2ee_late_recovery";

/// Round 4 — wire reason floria attaches to a RejectedDevice when the
/// device's `target_actor_id` is not present in the
/// `mention_redirect_target_actor_ids` allow-list. Used by both the
/// device-loop reject path and the per-device dedup test that the
/// gate is fail-closed (no provider dispatch, no decryption attempt).
pub(super) const MENTION_REDIRECT_NOT_TARGETED_REASON: &str = "mention_redirect_not_targeted";

#[handler]
pub(super) async fn notify_method_not_allowed(res: &mut Response) {
    let _ = res.add_header(
        HeaderName::from_static("allow"),
        HeaderValue::from_static("POST"),
        true,
    );
    finish_error(
        res,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "method not allowed",
        None,
        None,
        Instant::now(),
    );
}

fn parse_optional_idempotency_key(
    value: Option<&str>,
    source: &str,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{source} must not be empty"));
    }
    Ok(Some(value.to_owned()))
}

fn resolve_idempotency_key(req: &Request, raw: &Value) -> Result<Option<String>, String> {
    let header = parse_optional_idempotency_key(
        req.header::<String>("idempotency-key").as_deref(),
        "Idempotency-Key header",
    )?;
    let body = match raw.get("idempotency_key") {
        None => Ok(None),
        Some(Value::String(value)) => {
            parse_optional_idempotency_key(Some(value), "idempotency_key")
        }
        Some(_) => Err("idempotency_key must be a string".to_owned()),
    }?;

    if let (Some(header), Some(body)) = (header.as_deref(), body.as_deref())
        && header != body
    {
        return Err("Idempotency-Key header does not match body idempotency_key".to_owned());
    }

    Ok(header.or(body))
}

fn validate_notify_operation_id(raw: &Value) -> Result<(), String> {
    let Some(value) = raw.get("operation_id") else {
        return Ok(());
    };
    let Value::String(value) = value else {
        return Err("operation_id must be a string".to_owned());
    };
    if value.trim() == NOTIFY_OPERATION_ID {
        return Ok(());
    }
    Err(format!("operation_id must be {NOTIFY_OPERATION_ID}"))
}

fn validate_origin_service_did(
    raw: &Value,
    caller: &AuthenticatedNotifyCaller,
    auth_enabled: bool,
) -> Result<(), AuthFailure> {
    if !auth_enabled {
        return Ok(());
    }
    let Some(origin_service_did) = optional_string_field(raw, "origin_service_did")? else {
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "origin_service_did is required".to_owned(),
        });
    };
    if origin_service_did != caller.origin_service_did {
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "origin service DID does not match the authenticated caller".to_owned(),
        });
    }
    Ok(())
}

fn validate_destination_service_did(
    raw: &Value,
    req: &Request,
    auth: &NotifyAuthConfig,
    auth_enabled: bool,
) -> Result<(), AuthFailure> {
    if !auth_enabled {
        return Ok(());
    }

    let body_destination = optional_string_field(raw, "destination_service_did")?;
    let header_destination = req
        .header::<String>(DESTINATION_SERVICE_DID_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    if let (Some(body_destination), Some(header_destination)) =
        (body_destination, header_destination.as_deref())
        && body_destination != header_destination
    {
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "destination_service_did does not match the authenticated destination"
                .to_owned(),
        });
    }

    if let Some(expected) = auth.gateway_service_did.as_deref()
        && let Some(destination) = body_destination.or(header_destination.as_deref())
        && destination != expected
    {
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "destination service DID does not match this gateway".to_owned(),
        });
    }

    Ok(())
}

fn optional_string_field<'a>(raw: &'a Value, field: &str) -> Result<Option<&'a str>, AuthFailure> {
    match raw.get(field) {
        Some(Value::String(value)) => Ok(Some(value.trim())),
        Some(_) => Err(AuthFailure {
            status: StatusCode::BAD_REQUEST,
            code: "schema_violation",
            message: format!("{field} must be a string"),
        }),
        None => Ok(None),
    }
}

fn validate_notify_contract_shape(raw: &Value) -> Result<(), String> {
    // Round 4 (spec a77b995) — defense-in-depth: walk the ENTIRE inbound
    // request (envelope + notification + device data) and reject any
    // round-4 forbidden plaintext field (binding_proof.signature /
    // subject_proof.signature / expected_previous_generation /
    // attestation_evidence). The SDK blind-payload sanitizer already
    // rejects most of these by leaf-key name, but the round-4 protocol
    // review closures add new authenticator-shaped material so we run a
    // local walker that knows about parent.leaf-shaped forbidden paths
    // too. This walker fires BEFORE any other contract check so a
    // smuggled CAS-precondition can never even reach the auth /
    // sanitization layer.
    reject_round4_forbidden_fields("", raw)?;

    let Some(notification) = raw.get("notification") else {
        return Ok(());
    };
    let Some(notification) = notification.as_object() else {
        return Ok(());
    };

    validate_active_notification_refs(notification)?;
    validate_push_target_id(notification.get("push_target_id"))?;
    validate_wakeup_kind(notification.get("wakeup_kind"))?;
    validate_device_contract_shape(notification.get("devices"))?;
    validate_mention_redirect_routing(notification)?;

    Ok(())
}

/// Round 4 — wire-format check that the
/// `mention_redirect_target_actor_ids` allow-list (if present) is an
/// array of non-empty DID strings. The actual per-device routing gate
/// is enforced inside the dispatch loop in `notify()` so we have
/// access to the parsed `Notification` + `Device` typed views.
fn validate_mention_redirect_routing(notification: &Map<String, Value>) -> Result<(), String> {
    let Some(value) = notification.get("mention_redirect_target_actor_ids") else {
        return Ok(());
    };
    let Some(items) = value.as_array() else {
        return Err(
            "notification.mention_redirect_target_actor_ids must be an array of DID strings"
                .to_owned(),
        );
    };
    for (index, item) in items.iter().enumerate() {
        let Value::String(actor_id) = item else {
            return Err(format!(
                "notification.mention_redirect_target_actor_ids[{index}] must be a string"
            ));
        };
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            return Err(format!(
                "notification.mention_redirect_target_actor_ids[{index}] must not be empty"
            ));
        }
        // Round 4 DID regex sweep — entries are actor identifiers, so
        // we require the round-4-tightened DID shape `did:[a-z0-9]+:…`
        // here. The SDK enforces the full regex at the sender, this is
        // a defense-in-depth check on the floria entry.
        if !is_round4_did_shape(actor_id) {
            return Err(format!(
                "notification.mention_redirect_target_actor_ids[{index}] must be a DID matching \
                 round-4 regex `^did:[a-z0-9]+:[^\\s]+$`"
            ));
        }
    }
    Ok(())
}

/// Round 4 — match the tightened DID method-name regex
/// `^did:[a-z0-9]+:[^\s]+$`. Method-name segment is lowercase ASCII
/// alphanumeric ONLY (no `.`/`-`/`_`/`:`); the method-specific suffix
/// has to be non-empty and contain no whitespace.
pub(super) fn is_round4_did_shape(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("did:") else {
        return false;
    };
    let Some(colon) = rest.find(':') else {
        return false;
    };
    let (method, suffix) = rest.split_at(colon);
    let suffix = &suffix[1..]; // drop the colon itself
    if method.is_empty() || suffix.is_empty() {
        return false;
    }
    if !method
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
    {
        return false;
    }
    !suffix.chars().any(|ch| ch.is_whitespace())
}

/// Recursive walker that rejects any round-4-forbidden plaintext
/// field anywhere in the JSON tree. `path` is the dotted JSON path to
/// the current value used for error messages.
fn reject_round4_forbidden_fields(path: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let leaf = key.to_ascii_lowercase();
                let next_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if ROUND4_FORBIDDEN_LEAF_KEYS
                    .iter()
                    .any(|forbidden| forbidden.eq_ignore_ascii_case(&leaf))
                {
                    return Err(format!(
                        "field `{next_path}` is forbidden on the push wire model \
                         (round-4 protocol-review closure)"
                    ));
                }
                if let Some(parent_key) = path.rsplit('.').next() {
                    let parent_lower = parent_key.to_ascii_lowercase();
                    if ROUND4_FORBIDDEN_PARENT_LEAF
                        .iter()
                        .any(|(parent, leaf_name)| {
                            parent.eq_ignore_ascii_case(&parent_lower)
                                && leaf_name.eq_ignore_ascii_case(&leaf)
                        })
                    {
                        return Err(format!(
                            "field `{next_path}` is forbidden on the push wire model \
                             (round-4 proof signature must not appear in plaintext)"
                        ));
                    }
                }
                reject_round4_forbidden_fields(&next_path, nested)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                reject_round4_forbidden_fields(&format!("{path}[{index}]"), nested)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_device_contract_shape(devices: Option<&Value>) -> Result<(), String> {
    let Some(devices) = devices else {
        return Ok(());
    };
    let Some(devices) = devices.as_array() else {
        return Ok(());
    };

    for (index, device) in devices.iter().enumerate() {
        let path = format!("notification.devices[{index}]");
        let Some(device) = device.as_object() else {
            continue;
        };

        if let Some(data) = device.get("data") {
            let Some(data) = data.as_object() else {
                continue;
            };
            if let Some(default_payload) = data.get("default_payload") {
                if !default_payload.is_object() {
                    return Err(format!("{path}.data.default_payload must be an object"));
                }
                validate_blind_content(&format!("{path}.data.default_payload"), default_payload)?;
            }
        }
    }

    Ok(())
}

fn validate_active_notification_refs(notification: &Map<String, Value>) -> Result<(), String> {
    validate_active_ref(
        notification.get("event_id"),
        "notification.event_id",
        ACTIVE_EVENT_ID_PREFIX,
    )?;
    validate_active_ref(
        notification.get("message_id"),
        "notification.message_id",
        ACTIVE_MESSAGE_ID_PREFIX,
    )?;
    validate_active_ref(
        notification.get("flow_id"),
        "notification.flow_id",
        ACTIVE_FLOW_ID_PREFIX,
    )?;
    // Realm/Space reversal — Realm/Space/Flow id. The security boundary
    // is now Realm (`cx:realm:`); the new container-level `space_id` is
    // forbidden on the wire and rejected by the sanitizer below.
    validate_active_ref(
        notification.get("realm_id"),
        "notification.realm_id",
        ACTIVE_REALM_ID_PREFIX,
    )?;
    // TODO(realm-rework): the SDK's `is_forbidden_payload_key` still
    // lists the legacy `space_id`. Once it adds `realm_id`, the local
    // defense-in-depth check in `validate_notification_contract` for
    // `realm_id` / `space_id` can fall through to the SDK helper.
    if notification.get("space_id").is_some() {
        return Err(
            "notification.space_id is forbidden on the push wire model (Realm/Space rework)"
                .to_owned(),
        );
    }

    Ok(())
}

fn validate_push_target_id(value: Option<&Value>) -> Result<(), String> {
    const PREFIX: &str = "cx:pseudonym:push:";
    let Some(value) = value else {
        return Err("notification.push_target_id is required".to_owned());
    };
    let Value::String(value) = value else {
        return Err("notification.push_target_id must be a string".to_owned());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("notification.push_target_id must not be empty".to_owned());
    }
    let Some(token) = value.strip_prefix(PREFIX) else {
        return Err(format!(
            "notification.push_target_id must use `{PREFIX}*` typed IDs"
        ));
    };
    if !(22..=128).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("notification.push_target_id must be an opaque base64url token".to_owned());
    }
    Ok(())
}

fn validate_wakeup_kind(value: Option<&Value>) -> Result<(), String> {
    let Some(value) = value else {
        return Err("notification.wakeup_kind is required".to_owned());
    };
    let Value::String(value) = value else {
        return Err("notification.wakeup_kind must be a string".to_owned());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err("notification.wakeup_kind must not be empty".to_owned());
    }
    if value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("notification.wakeup_kind must be an opaque snake_case token".to_owned());
    }
    Ok(())
}

fn validate_active_ref(
    value: Option<&Value>,
    path: &str,
    required_prefix: &str,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    let Value::String(value) = value else {
        return Err(format!("{path} must be a string"));
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{path} must not be empty"));
    }
    if !value.starts_with(required_prefix) {
        return Err(format!(
            "{path} must use active `{required_prefix}*` typed IDs"
        ));
    }
    Ok(())
}

// T4.3 — visible profile / blind profile gate.
//
// floria exposes two push-gateway capability profiles:
//
//   * `cx.profile.push_gateway.blind_wakeup.v1`  (default) — opaque
//     `push_target_id` + `wakeup_kind`, no plaintext metadata. Maps to
//     `caller.allow_plaintext_metadata = false`.
//   * `cx.profile.push_gateway.visible_notification.v1` — the caller
//     has been explicitly gated as a plaintext-eligible service kind
//     (sync / principal) AND the per-principal
//     `allow_plaintext_metadata` flag is set. Maps to
//     `caller.allow_plaintext_metadata = true`.
//
// A caller on the blind profile that submits plaintext metadata is
// rejected with `plaintext_in_blind_profile`. A caller on the visible
// profile can still be rejected if the wire payload contains keys that
// would let an observer correlate pushes across users (forbidden
// payload keys, sensitive `did:` / `cx:` literals).
pub(super) const BLIND_PROFILE_PLAINTEXT_REASON: &str = "plaintext_in_blind_profile";

fn validate_notification_contract(
    notification: &Notification,
    caller: &AuthenticatedNotifyCaller,
) -> Result<(), String> {
    if !caller.allow_plaintext_metadata
        && (notification.sender_display_name.is_some()
            || notification.flow_name.is_some()
            || notification.realm_name.is_some())
    {
        // Realm/Space reversal — `space_name` is gone from the wire
        // model; the security-boundary name is now `realm_name`.
        // TODO(realm-rework): once the broader access-policy schema
        // splits Realm policy from Space (container) policy, gate
        // `realm_name` here against the Realm-policy decision and the
        // new container-`space_name` (if it ever lands on the wire)
        // against a separate Space policy. The blind-profile blanket
        // ban below is still safe in the meantime.
        return Err(format!(
            "{BLIND_PROFILE_PLAINTEXT_REASON}: caller is not authorized to send \
             sender_display_name or flow/realm name metadata under the default \
             `cx.profile.push_gateway.blind_wakeup.v1` profile"
        ));
    }

    if let Some(push_hint) = notification.push_hint.as_deref() {
        validate_push_hint(push_hint)?;
    }

    let Some(content) = notification.content.as_ref() else {
        return Ok(());
    };

    // Blind profile callers must not embed plaintext title/body in
    // `content` either. The SDK sanitizer would reject these as
    // forbidden keys via the `validate_blind_content` path below, but
    // we surface a more specific reason code first so operators can
    // tell the two failure classes apart.
    if !caller.allow_plaintext_metadata {
        for forbidden in ["title", "body", "subtitle", "alert", "preview", "summary"] {
            if content.contains_key(forbidden) {
                return Err(format!(
                    "{BLIND_PROFILE_PLAINTEXT_REASON}: caller is not authorized to send \
                     plaintext `content.{forbidden}` under the default \
                     `cx.profile.push_gateway.blind_wakeup.v1` profile"
                ));
            }
        }
    }

    validate_blind_content("content", &Value::Object(content.clone()))?;

    Ok(())
}

fn validate_plaintext_identity_metadata(
    notification: &Map<String, Value>,
    caller: &AuthenticatedNotifyCaller,
) -> Result<(), String> {
    if caller.allow_plaintext_metadata {
        return Ok(());
    }

    for (key, value) in notification {
        let path = format!("notification.{key}");
        if key.eq_ignore_ascii_case("devices") {
            validate_device_identity_metadata(value)?;
            continue;
        }
        // Round 4 (spec a77b995) — `mention_redirect_target_actor_ids`
        // is a plaintext routing field that legitimately carries DID
        // entries (receivers verify their inclusion WITHOUT decrypting
        // the body). The wire-shape validator already enforced that
        // every entry matches the round-4 DID regex, so the values are
        // bounded to opaque actor identifiers, not arbitrary plaintext
        // identity metadata. Skip the visible-identity scan for this
        // field — the SDK sanitizer's `did:` literal block would
        // otherwise reject the very routing list we're trying to honor.
        if key.eq_ignore_ascii_case("mention_redirect_target_actor_ids") {
            continue;
        }
        if is_identity_metadata_key(key) && has_visible_identity_value(value) {
            return Err(format!(
                "{BLIND_PROFILE_PLAINTEXT_REASON}: caller is not authorized to send \
                 plaintext identity metadata in `{path}` under the default \
                 `cx.profile.push_gateway.blind_wakeup.v1` profile"
            ));
        }
        validate_plaintext_identity_tree(&path, value)?;
    }

    Ok(())
}

fn validate_device_identity_metadata(devices: &Value) -> Result<(), String> {
    let Some(devices) = devices.as_array() else {
        return Ok(());
    };

    for (index, device) in devices.iter().enumerate() {
        let Some(device) = device.as_object() else {
            continue;
        };
        let Some(data) = device.get("data").and_then(Value::as_object) else {
            continue;
        };
        let Some(default_payload) = data.get("default_payload") else {
            continue;
        };
        validate_plaintext_identity_tree(
            &format!("notification.devices[{index}].data.default_payload"),
            default_payload,
        )?;
    }

    Ok(())
}

fn validate_plaintext_identity_tree(path: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let next_path = format!("{path}.{key}");
                if is_identity_metadata_key(key) && has_visible_identity_value(value) {
                    return Err(format!(
                        "{BLIND_PROFILE_PLAINTEXT_REASON}: caller is not authorized to send \
                         plaintext identity metadata in `{next_path}` under the default \
                         `cx.profile.push_gateway.blind_wakeup.v1` profile"
                    ));
                }
                validate_plaintext_identity_tree(&next_path, value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_plaintext_identity_tree(&format!("{path}[{index}]"), value)?;
            }
            Ok(())
        }
        Value::String(value) => validate_plaintext_identity_string(path, value),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn is_identity_metadata_key(key: &str) -> bool {
    matches!(
        key.trim().to_ascii_lowercase().as_str(),
        "sender" | "target_did"
    )
}

fn has_visible_identity_value(value: &Value) -> bool {
    match value {
        Value::String(value) => !value.trim().is_empty(),
        Value::Array(values) => values.iter().any(has_visible_identity_value),
        Value::Object(map) => map.values().any(has_visible_identity_value),
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn validate_plaintext_identity_string(path: &str, value: &str) -> Result<(), String> {
    // Round 4 (spec a77b995) — DID regex sweep: the SDK has tightened
    // its validator to `^did:[a-z0-9]+:[^\s]+$`, but floria treats DID
    // literals as an opaque correlation leak regardless of method-name
    // shape. The substring check here therefore stays — it rejects any
    // `did:` prefix, including round-4 strict forms AND any pre-round-4
    // dotted-method form a misconfigured client might still emit. The
    // canonical regex validator lives in the SDK; floria's job at this
    // boundary is just to keep DID-shaped strings out of plaintext push
    // payloads.
    if value.to_ascii_lowercase().contains("did:") {
        Err(format!(
            "caller is not authorized to send DID literal in `{path}`"
        ))
    } else {
        Ok(())
    }
}

// T1.1 — thin wrapper over the SDK's shared `is_valid_push_hint` so the
// allowed `push_hint` vocabulary cannot drift between chime / floria.
fn validate_push_hint(push_hint: &str) -> Result<(), String> {
    if contrix::blind_payload_sanitizer::is_valid_push_hint(push_hint) {
        return Ok(());
    }
    Err("Contrix blind wakeup push_hint must be one of new_message, incoming_call, mention_self, or l10n_key:<token>".to_owned())
}

// T1.1 — thin wrapper over the SDK's `sanitize_blind_payload` recursive
// scan. We still keep the `validate_blind_string` call setup detection
// (TURN/ICE/SDP literal pattern) because that's a floria-specific
// content rule, not part of the cross-impl key allow/block list.
fn validate_blind_content(path: &str, value: &Value) -> Result<(), String> {
    // Run the SDK sanitizer over the subtree by wrapping it in a synthetic
    // notification envelope so the wrapper-scan path (forbidden keys +
    // sensitive did:/cx: literals) walks the whole tree without needing
    // top-level `push_target_id` / `wakeup_kind` to be present.
    let envelope = serde_json::json!({
        "notification": {
            "push_target_id": "cx:pseudonym:push:0000000000000000000000",
            "wakeup_kind": "message",
        },
        path: value,
    });
    if let Err(err) = contrix::blind_payload_sanitizer::sanitize_blind_payload(&envelope) {
        return Err(format!(
            "Contrix blind wakeup payloads must not include sensitive field `{}` ({})",
            err.field_path,
            err.reason_code.as_str(),
        ));
    }
    // Recurse only to apply the floria-specific call-setup string check.
    walk_blind_strings(path, value)
}

fn walk_blind_strings(path: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                walk_blind_strings(&format!("{path}.{key}"), value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                walk_blind_strings(&format!("{path}[{index}]"), value)?;
            }
            Ok(())
        }
        Value::String(value) => validate_blind_string(path, value),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn validate_blind_string(path: &str, value: &str) -> Result<(), String> {
    let normalized = value.to_ascii_lowercase();
    if normalized.contains("candidate:")
        || normalized.contains("ice-ufrag")
        || normalized.contains("ice-pwd")
        || normalized.contains("turn:")
        || normalized.contains("turns:")
        || normalized.contains("v=0\r")
        || normalized.contains("v=0\n")
    {
        Err(format!(
            "Contrix blind wakeup payloads must not include call setup material in `{path}`"
        ))
    } else {
        Ok(())
    }
}

// T1.1 — the legacy `is_sensitive_payload_key` floria-local allow-list
// has moved into `contrix::blind_payload_sanitizer::is_forbidden_payload_key`
// so the chime/floria rule cannot drift. Callers now go through the SDK
// helper via `validate_blind_content`.

fn dedup_provider_retries(provider_retries: &mut Vec<ProviderRetry>) {
    provider_retries.sort_by(|left, right| {
        left.provider
            .cmp(&right.provider)
            .then(left.retry_after_ms.cmp(&right.retry_after_ms))
    });
    provider_retries.dedup();
}

fn notify_rate_limit_checks(
    req: &Request,
    state: &AppState,
    notification: &Notification,
) -> Vec<NotifyRateLimitCheck> {
    let Some(rate_limiter) = state.notify_rate_limiter.as_ref() else {
        return vec![];
    };
    let config = rate_limiter.config();
    let mut checks = Vec::new();

    if let Some(limit) = config.per_origin_service.filter(|limit| *limit > 0) {
        let subject = req
            .header::<String>(ORIGIN_SERVICE_DID_HEADER)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "<missing>".to_owned());
        checks.push(NotifyRateLimitCheck {
            scope: "origin_service",
            subject,
            limit,
            units: 1,
        });
    }

    if let Some(limit) = config.per_app_id.filter(|limit| *limit > 0) {
        let app_ids = notification
            .devices
            .iter()
            .map(|device| device.app_id.trim())
            .filter(|app_id| !app_id.is_empty())
            .collect::<HashSet<_>>();
        checks.extend(app_ids.into_iter().map(|app_id| NotifyRateLimitCheck {
            scope: "app_id",
            subject: app_id.to_owned(),
            limit,
            units: 1,
        }));
    }

    if let Some(limit) = config.per_push_key_hash.filter(|limit| *limit > 0) {
        let push_key_hashes = notification
            .devices
            .iter()
            .map(|device| device.redacted_push_key())
            .collect::<HashSet<_>>();
        checks.extend(
            push_key_hashes
                .into_iter()
                .map(|push_key_hash| NotifyRateLimitCheck {
                    scope: "push_key_hash",
                    subject: push_key_hash,
                    limit,
                    units: 1,
                }),
        );
    }

    if let Some(limit) = config.per_endpoint.filter(|limit| *limit > 0) {
        checks.push(NotifyRateLimitCheck {
            scope: "endpoint",
            subject: req.uri().path().to_owned(),
            limit,
            units: 1,
        });
    }

    if let Some(limit) = config.per_provider.filter(|limit| *limit > 0) {
        let providers = notification
            .devices
            .iter()
            .flat_map(|device| {
                state
                    .registry
                    .find_pushkins(&device.app_id)
                    .into_iter()
                    .map(|pushkin| pushkin.name().to_owned())
            })
            .collect::<HashSet<_>>();
        checks.extend(providers.into_iter().map(|provider| NotifyRateLimitCheck {
            scope: "provider",
            subject: provider,
            limit,
            units: 1,
        }));
    }

    checks
}

fn optional_json_string(raw: &Value, pointer: &str) -> Option<String> {
    raw.pointer(pointer)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_owned_string(value: Option<&String>) -> Option<String> {
    value
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn request_destination_service_did(req: &Request, raw: &Value) -> Option<String> {
    optional_json_string(raw, "/destination_service_did").or_else(|| {
        req.header::<String>(DESTINATION_SERVICE_DID_HEADER)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

async fn record_required_audit_event(
    state: &Arc<AppState>,
    event: &AuditEvent,
) -> Result<(), String> {
    let sink = state
        .audit_sink
        .as_ref()
        .ok_or_else(|| "audit sink is not configured".to_owned())?;
    sink.record(event).await.map_err(|error| error.to_string())
}

async fn record_rejected_devices_audit(
    state: &Arc<AppState>,
    request_id: &str,
    caller: &AuthenticatedNotifyCaller,
    notification: &Notification,
    rejected: &[RejectedDevice],
) -> Result<(), String> {
    if rejected.is_empty() {
        return Ok(());
    }
    let Some(sink) = state.audit_sink.as_ref() else {
        return Ok(());
    };
    let event = AuditEvent::RejectedDevices {
        request_id: request_id.to_owned(),
        origin_service_did: caller.origin_service_did.clone(),
        notification_event_id: optional_owned_string(notification.event_id.as_ref()),
        notification_flow_id: notification.flow_id().map(ToOwned::to_owned),
        notification_realm_id: notification.realm_id().map(ToOwned::to_owned),
        devices: rejected.to_vec(),
    };
    sink.record(&event).await.map_err(|error| error.to_string())
}

async fn record_rejected_devices_audit_or_finish(
    state: &Arc<AppState>,
    request_id: &str,
    caller: &AuthenticatedNotifyCaller,
    notification: &Notification,
    rejected: &[RejectedDevice],
    res: &mut Response,
    started: Instant,
) -> bool {
    if let Err(message) =
        record_rejected_devices_audit(state, request_id, caller, notification, rejected).await
    {
        tracing::error!(
            request_id = %request_id,
            error = %message,
            rejected = rejected.len(),
            "failed to write rejected-device audit event"
        );
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            &message,
            None,
            Some(request_id),
            started,
        );
        return false;
    }
    true
}

#[handler]
pub(super) async fn notify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let started = Instant::now();
    let _inflight = app_metrics::track_inflight("V1NotifyHandler");

    let span = tracing::info_span!(
        "notify",
        request_id = tracing::field::Empty,
        caller = tracing::field::Empty,
        provider = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let _entered = span.enter();

    let state = match depot.obtain::<Arc<AppState>>() {
        Ok(state) => state.clone(),
        Err(_) => {
            finish_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "application state missing",
                None,
                None,
                started,
            );
            return;
        }
    };
    let request_id = Uuid::new_v4().to_string();
    span.record("request_id", tracing::field::display(&request_id));

    let body = match req.payload_with_max_size(MAX_REQUEST_SIZE).await {
        Ok(bytes) => bytes.to_vec(),
        Err(ParseError::PayloadTooLarge) => {
            finish_error(
                res,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "request body exceeds 512 KiB",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        Err(error) => {
            tracing::warn!(error = %error, "failed to read request body");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "failed to read request body",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    let caller = match authenticate_notify_request(
        req,
        body.as_ref(),
        &state.notify_auth,
        state.notify_nonce_store.as_deref(),
        &request_id,
    ) {
        Ok(caller) => {
            span.record(
                "caller",
                tracing::field::display(&caller.origin_service_did),
            );
            caller
        }
        Err(error) => {
            finish_error(
                res,
                error.status,
                error.code,
                &error.message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    let raw_request_hash = request_hash(body.as_ref());

    let raw = match serde_json::from_slice::<Value>(&body) {
        Ok(raw) => raw,
        Err(error) => {
            tracing::warn!(error = %error, "expected JSON request body");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "expected JSON request body",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };
    if let Err(message) = validate_notify_operation_id(&raw) {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "unsupported_feature",
            &message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }
    if let Err(error) = validate_origin_service_did(&raw, &caller, state.notify_auth.enabled()) {
        finish_error(
            res,
            error.status,
            error.code,
            &error.message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }
    if let Err(error) =
        validate_destination_service_did(&raw, req, &state.notify_auth, state.notify_auth.enabled())
    {
        finish_error(
            res,
            error.status,
            error.code,
            &error.message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }
    if let Err(message) = validate_notify_contract_shape(&raw) {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            &message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }
    // Round 4 (spec a77b995) — short-circuit the push pipeline when
    // soland tells us this is a diagnostic replay
    // (`reason_code=historical_only`). We answer 200 with an empty
    // fanout body so soland's idempotency cache stays consistent but
    // no provider call is issued and no per-device dedup state is
    // touched. Any other `reason_code` value is rejected — floria
    // only honors the well-known no-op shape on the request side.
    match raw.get("reason_code") {
        None => {}
        Some(Value::String(value)) if value == HISTORICAL_ONLY_REASON => {
            tracing::info!(
                request_id = %request_id,
                "answering 200 no-fanout ack for reason_code=historical_only"
            );
            let response = NotifyResponse {
                request_id: request_id.clone(),
                accepted: 0,
                rejected: Vec::new(),
                provider_retries: Vec::new(),
                delivery_receipts: Vec::new(),
            };
            finish_json(res, StatusCode::OK, response, started);
            return;
        }
        Some(_) => {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "reason_code is only valid as `historical_only` on /push/notify",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    }
    // Round 4 — route `cx.audit.policy_access{access_kind=
    // e2ee_late_recovery}` to the audit pipeline, NOT to push. floria
    // writes the audit event first, then acks 200 so the caller's
    // pipeline advances. It does not do push fanout for this shape.
    if let Some(audit_envelope) = raw.get("audit_envelope") {
        match audit_envelope {
            Value::Object(map) => {
                let access_kind = map
                    .get("access_kind")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .unwrap_or_default();
                if access_kind.is_empty() {
                    finish_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "audit_envelope.access_kind must be a non-empty string",
                        None,
                        Some(&request_id),
                        started,
                    );
                    return;
                }
                if access_kind == E2EE_LATE_RECOVERY_ACCESS_KIND
                    && map
                        .get("late_recovery_original_event_id")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .is_none()
                {
                    finish_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "schema_violation",
                        "audit_envelope.access_kind=e2ee_late_recovery requires \
                         late_recovery_original_event_id",
                        None,
                        Some(&request_id),
                        started,
                    );
                    return;
                }
                let late_recovery_original_event_id = map
                    .get("late_recovery_original_event_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned);
                let audit_event = AuditEvent::PolicyAccess {
                    request_id: request_id.clone(),
                    origin_service_did: caller.origin_service_did.clone(),
                    destination_service_did: request_destination_service_did(req, &raw),
                    access_kind: access_kind.to_owned(),
                    late_recovery_original_event_id,
                    notification_event_id: optional_json_string(&raw, "/notification/event_id"),
                    notification_flow_id: optional_json_string(&raw, "/notification/flow_id"),
                    notification_realm_id: optional_json_string(&raw, "/notification/realm_id"),
                };
                if let Err(message) = record_required_audit_event(&state, &audit_event).await {
                    tracing::error!(
                        request_id = %request_id,
                        error = %message,
                        "failed to write policy_access audit event"
                    );
                    finish_error(
                        res,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        &message,
                        None,
                        Some(&request_id),
                        started,
                    );
                    return;
                }
                tracing::info!(
                    request_id = %request_id,
                    access_kind = %access_kind,
                    "answering 200 audit-pipeline ack after audit sink write; SKIPPING push fanout"
                );
                let response = NotifyResponse {
                    request_id: request_id.clone(),
                    accepted: 0,
                    rejected: Vec::new(),
                    provider_retries: Vec::new(),
                    delivery_receipts: Vec::new(),
                };
                finish_json(res, StatusCode::OK, response, started);
                return;
            }
            _ => {
                finish_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    "audit_envelope must be a JSON object",
                    None,
                    Some(&request_id),
                    started,
                );
                return;
            }
        }
    }
    let idempotency_key = match resolve_idempotency_key(req, &raw) {
        Ok(idempotency_key) => idempotency_key,
        Err(message) => {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };

    let Some(notification_value) = raw.get("notification").cloned() else {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "missing notification field",
            None,
            Some(&request_id),
            started,
        );
        return;
    };

    if !notification_value.is_object() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "notification must be an object",
            None,
            Some(&request_id),
            started,
        );
        return;
    }

    let notification_object = notification_value.as_object().cloned();

    let notification: Notification = match serde_json::from_value(notification_value) {
        Ok(notification) => notification,
        Err(error) => {
            tracing::warn!(error = %error, "invalid notification payload");
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                "invalid notification payload",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    };

    // T1.1 — for blind-only callers, additionally run the SDK
    // sanitizer over each device's `data.default_payload` subtree so
    // that any forbidden field or did:/cx: literal that survived the
    // wire-model allow-list gets stopped before fan-out.
    if !caller.allow_plaintext_metadata
        && let Some(devices) = notification_object
            .as_ref()
            .and_then(|obj| obj.get("devices"))
            .and_then(Value::as_array)
    {
        for (index, device) in devices.iter().enumerate() {
            let Some(default_payload) = device
                .get("data")
                .and_then(Value::as_object)
                .and_then(|data| data.get("default_payload"))
            else {
                continue;
            };
            let envelope = serde_json::json!({
                "notification": {
                    "push_target_id": "cx:pseudonym:push:0000000000000000000000",
                    "wakeup_kind": "message",
                },
                "default_payload": default_payload,
            });
            if let Err(err) = contrix::blind_payload_sanitizer::sanitize_blind_payload(&envelope) {
                finish_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "schema_violation",
                    &format!(
                        "blind wakeup sanitizer rejected `notification.devices[{index}].data.default_payload.{}`: {}",
                        err.field_path, err.reason_code,
                    ),
                    None,
                    Some(&request_id),
                    started,
                );
                return;
            }
        }
    }

    match validate_notification_contract(&notification, &caller) {
        Ok(()) => {}
        // T4.3 — blind profile + plaintext metadata is a precondition
        // violation, not an authorization failure: the caller could
        // still have the right credentials, the request just can't
        // be carried by the blind profile they're scoped to.
        Err(message) if message.starts_with(BLIND_PROFILE_PLAINTEXT_REASON) => {
            finish_error(
                res,
                StatusCode::PRECONDITION_FAILED,
                "failed_precondition",
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        Err(message) if message.starts_with("caller is not authorized") => {
            finish_error(
                res,
                StatusCode::FORBIDDEN,
                "capability_denied",
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        Err(message) => {
            finish_error(
                res,
                StatusCode::BAD_REQUEST,
                "schema_violation",
                &message,
                None,
                Some(&request_id),
                started,
            );
            return;
        }
    }

    if let Some(notification) = notification_object.as_ref()
        && let Err(message) = validate_plaintext_identity_metadata(notification, &caller)
    {
        // T4.3 — same reasoning: surface `failed_precondition` when
        // the failure is "wrong profile", and `capability_denied`
        // when the caller lacks the credential entirely.
        let (status, code) = if message.starts_with(BLIND_PROFILE_PLAINTEXT_REASON) {
            (StatusCode::PRECONDITION_FAILED, "failed_precondition")
        } else {
            (StatusCode::FORBIDDEN, "capability_denied")
        };
        finish_error(
            res,
            status,
            code,
            &message,
            None,
            Some(&request_id),
            started,
        );
        return;
    }

    let request_fingerprint =
        normalized_notify_dedup_key(&notification).unwrap_or(raw_request_hash);
    let dedup_key = idempotency_key
        .as_deref()
        .map(idempotency_cache_key)
        .unwrap_or_else(|| request_fingerprint.clone());
    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        if deduplicator.conflicts(&dedup_key, &request_fingerprint) {
            app_metrics::notify_dedup_lookup("conflict");
            finish_error(
                res,
                StatusCode::CONFLICT,
                "duplicate_conflict",
                "same idempotency key maps to different canonical request body",
                None,
                Some(&request_id),
                started,
            );
            return;
        }
        if let Some(cached) = deduplicator.lookup(&dedup_key, &request_fingerprint) {
            app_metrics::notify_dedup_lookup("hit");
            app_metrics::notify_request_cache_hit();
            tracing::info!(
                request_id = %request_id,
                ttl_secs = deduplicator.ttl().as_secs(),
                idempotency_key = idempotency_key
                    .as_deref()
                    .unwrap_or("<canonical-request-hash>"),
                "serving /notify response from dedup cache"
            );
            finish_json(
                res,
                StatusCode::OK,
                cached.response.with_request_id(request_id),
                started,
            );
            return;
        }
        app_metrics::notify_dedup_lookup("miss");
    }
    app_metrics::notification_received();

    if notification.devices.is_empty() {
        finish_error(
            res,
            StatusCode::BAD_REQUEST,
            "schema_violation",
            "no devices in notification",
            None,
            Some(&request_id),
            started,
        );
        return;
    }

    if let Some(rate_limiter) = state.notify_rate_limiter.as_ref() {
        let checks = notify_rate_limit_checks(req, &state, &notification);
        if let Err(rejection) = rate_limiter.check_many(&checks) {
            app_metrics::notify_rate_limit_reject(rejection.scope);
            tracing::warn!(
                request_id = %request_id,
                scope = rejection.scope,
                subject = %rejection.subject,
                limit = rejection.limit,
                retry_after_secs = rejection.retry_after.as_secs(),
                "rejecting /notify request due to rate limit"
            );
            finish_error(
                res,
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                &format!("notify rate limit exceeded for {}", rejection.scope),
                Some(rejection.retry_after),
                Some(&request_id),
                started,
            );
            return;
        }
    }

    let context = NotificationContext {
        request_id: request_id.clone(),
        start_time: Instant::now(),
    };

    let mut rejected = Vec::new();
    let mut delivered_now = 0usize;
    let mut skipped_delivered = 0usize;
    let mut provider_retries = Vec::new();
    let mut delivery_receipts = Vec::new();
    let mut seen_devices = HashSet::new();
    let mut first_remote_error: Option<String> = None;
    let mut first_temporary_error: Option<(String, Option<Duration>)> = None;
    let mut first_internal_error: Option<String> = None;
    for device in &notification.devices {
        let app_id = device.app_id.trim();
        let push_key = device.push_key.trim();
        if app_id.is_empty() || push_key.is_empty() {
            tracing::warn!(
                request_id = %context.request_id,
                app_id = %device.app_id,
                push_key_hash = %device.redacted_push_key(),
                "rejecting device with empty app_id or push_key"
            );
            rejected.push(rejected_device(device, Some(&device.push_key)));
            delivery_receipts.push(delivery_receipt(
                None,
                &device.push_key,
                "rejected",
                None,
                &context.request_id,
            ));
            continue;
        }

        if !seen_devices.insert((app_id.to_owned(), push_key.to_owned())) {
            tracing::info!(
                request_id = %context.request_id,
                app_id,
                push_key_hash = %device.redacted_push_key(),
                "skipping duplicate device entry"
            );
            continue;
        }

        // Round 4 (spec a77b995) — `mention_redirect_target_actor_ids`
        // plaintext routing gate. When soland set a non-empty allow-list
        // the device's `target_actor_id` MUST appear in it, otherwise
        // the device is fail-closed: no provider dispatch, no body
        // decryption is attempted, and the rejection is recorded with
        // the wire-safe `mention_redirect_not_targeted` reason so the
        // operator can tell why the device was skipped. Devices with
        // no `target_actor_id` cannot prove their inclusion in the
        // allow-list — same outcome (fail-closed).
        if !notification.mention_redirect_target_actor_ids.is_empty() {
            let allowed = device
                .target_actor_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some_and(|actor_id| {
                    notification
                        .mention_redirect_target_actor_ids
                        .iter()
                        .any(|allowed| allowed.trim() == actor_id)
                });
            if !allowed {
                tracing::info!(
                    request_id = %context.request_id,
                    app_id,
                    push_key_hash = %device.redacted_push_key(),
                    "fail-closed: device.target_actor_id not in mention_redirect_target_actor_ids"
                );
                rejected.push(
                    rejected_device(device, Some(&device.push_key))
                        .with_reason(Some(MENTION_REDIRECT_NOT_TARGETED_REASON)),
                );
                delivery_receipts.push(delivery_receipt(
                    None,
                    &device.push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
                continue;
            }
        }

        // T4.4 — Caller (Sync Service / soland) may have already
        // evaluated the v1 core push rule and decided `dont_notify`.
        // Honor that decision verbatim: record the rejection with the
        // caller-supplied wire-safe reason code and skip dispatch.
        // floria itself does not re-evaluate watch levels — that's the
        // Sync Service's job.
        if let Some(hint) = device.push_decision.as_ref()
            && !hint.deliver
        {
            tracing::debug!(
                request_id = %context.request_id,
                app_id,
                push_key_hash = %device.redacted_push_key(),
                reason_code = hint.reason_code.as_deref().unwrap_or(""),
                "skipping device per caller-supplied push_decision"
            );
            rejected.push(
                rejected_device(device, Some(&device.push_key))
                    .with_reason(hint.reason_code.as_deref()),
            );
            delivery_receipts.push(delivery_receipt(
                None,
                &device.push_key,
                "rejected",
                None,
                &context.request_id,
            ));
            continue;
        }

        app_metrics::device_push_received();
        let pushkins = state.registry.find_pushkins(&device.app_id);
        match pushkins.as_slice() {
            [] => {
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, push_key_hash = %device.redacted_push_key(), "unknown app id");
                rejected.push(rejected_device(device, Some(&device.push_key)));
                delivery_receipts.push(delivery_receipt(
                    None,
                    &device.push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
                continue;
            }
            [pushkin] => {
                if state
                    .notify_deduplicator
                    .as_ref()
                    .is_some_and(|deduplicator| {
                        deduplicator.contains_delivered_device(&dedup_key, app_id, push_key)
                    })
                {
                    skipped_delivered += 1;
                    app_metrics::notify_device_skip_hit(1);
                    app_metrics::notify_device_skip_by_pushkin(pushkin.name(), 1);
                    delivery_receipts.push(delivery_receipt(
                        Some(pushkin.name()),
                        push_key,
                        "accepted_cached",
                        None,
                        &context.request_id,
                    ));
                    tracing::info!(
                        request_id = %context.request_id,
                        app_id,
                        push_key_hash = %device.redacted_push_key(),
                        pushkin = %pushkin.name(),
                        "skipping device already delivered within dedup ttl"
                    );
                    continue;
                }

                app_metrics::pushkin_selected(pushkin.name());
                let dispatch_targets = pushkin.dispatch_targets(&notification, device);
                let dispatch_started = Instant::now();
                let dispatch_result = pushkin
                    .dispatch_notification(&notification, device, &context)
                    .await;
                let dispatch_outcome = match &dispatch_result {
                    Ok(rejected) if rejected.is_empty() => "accepted",
                    Ok(_) => "partial",
                    Err(error) if error.is_temporary() => "retryable",
                    Err(error) if error.is_remote() => "remote_error",
                    Err(_) => "internal_error",
                };
                app_metrics::observe_pushkin_dispatch(
                    pushkin.name(),
                    dispatch_outcome,
                    dispatch_started.elapsed(),
                );
                app_metrics::notify_delivery_outcome_by_app(app_id, dispatch_outcome, 1);
                match dispatch_result {
                    Ok(mut pushkin_rejected) => {
                        let rejected_set = pushkin_rejected
                            .iter()
                            .cloned()
                            .collect::<HashSet<String>>();
                        let delivered_targets = dispatch_targets
                            .iter()
                            .filter(|target| !rejected_set.contains(&target.push_key))
                            .collect::<Vec<_>>();
                        if !delivered_targets.is_empty() {
                            delivered_now += delivered_targets.len();
                            for target in &delivered_targets {
                                delivery_receipts.push(delivery_receipt(
                                    Some(pushkin.name()),
                                    &target.push_key,
                                    "accepted",
                                    None,
                                    &context.request_id,
                                ));
                            }
                            mark_delivered_devices(
                                &state,
                                &dedup_key,
                                delivered_targets.iter().copied(),
                            );
                        }
                        rejected.extend(pushkin_rejected.drain(..).map(|push_key| {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &push_key,
                                "rejected",
                                None,
                                &context.request_id,
                            ));
                            rejected_device(device, Some(&push_key))
                        }));
                    }
                    Err(error) if error.is_temporary() => {
                        let retry_after = error.retry_after();
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "temporary dispatch failure"
                        );
                        provider_retries.push(ProviderRetry::new(pushkin.name(), retry_after));
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.push_key,
                                "retryable",
                                retry_after,
                                &context.request_id,
                            ));
                            enqueue_retry(
                                &state,
                                &context.request_id,
                                pushkin.name(),
                                &target.app_id,
                                &target.push_key,
                                retry_after,
                                &error,
                            );
                        }
                        first_temporary_error
                            .get_or_insert_with(|| (error.to_string(), retry_after));
                    }
                    Err(error) if error.is_remote() => {
                        tracing::warn!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "remote dispatch failure"
                        );
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.push_key,
                                "failed",
                                None,
                                &context.request_id,
                            ));
                        }
                        first_remote_error.get_or_insert_with(|| error.to_string());
                    }
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            request_id = %context.request_id,
                            app_id = %device.app_id,
                            push_key_hash = %device.redacted_push_key(),
                            "internal dispatch failure"
                        );
                        for target in &dispatch_targets {
                            delivery_receipts.push(delivery_receipt(
                                Some(pushkin.name()),
                                &target.push_key,
                                "failed",
                                None,
                                &context.request_id,
                            ));
                        }
                        first_internal_error.get_or_insert_with(|| error.to_string());
                    }
                }
            }
            _ => {
                tracing::warn!(request_id = %context.request_id, app_id = %device.app_id, push_key_hash = %device.redacted_push_key(), "ambiguous app id");
                rejected.push(rejected_device(device, Some(&device.push_key)));
                delivery_receipts.push(delivery_receipt(
                    None,
                    &device.push_key,
                    "rejected",
                    None,
                    &context.request_id,
                ));
            }
        }
    }

    dedup_provider_retries(&mut provider_retries);

    let fully_settled = first_internal_error.is_none()
        && first_temporary_error.is_none()
        && first_remote_error.is_none();
    let had_errors = !fully_settled;

    if delivered_now > 0 {
        if had_errors {
            app_metrics::notify_partial_success(StatusCode::OK);
        }
        if skipped_delivered > 0 {
            app_metrics::notify_retry_with_skips(StatusCode::OK);
        }
        if let Some(message) = first_internal_error.as_deref() {
            tracing::warn!(
                request_id = %context.request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                error = %message,
                "returning success despite partial internal dispatch failures"
            );
        } else if let Some((message, retry_after)) = first_temporary_error.as_ref() {
            tracing::warn!(
                request_id = %context.request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                retry_after_secs = retry_after.map(|value| value.as_secs()),
                error = %message,
                "returning success despite partial temporary dispatch failures"
            );
        } else if let Some(message) = first_remote_error.as_deref() {
            tracing::warn!(
                request_id = %context.request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                error = %message,
                "returning success despite partial remote dispatch failures"
            );
        } else if skipped_delivered > 0 {
            tracing::info!(
                request_id = %context.request_id,
                delivered = delivered_now,
                skipped_delivered,
                rejected = rejected.len(),
                "returning success with cached delivered devices"
            );
        }
        let response = NotifyResponse {
            request_id: context.request_id.clone(),
            accepted: delivered_now + skipped_delivered,
            rejected,
            provider_retries,
            delivery_receipts,
        };
        if !record_rejected_devices_audit_or_finish(
            &state,
            &context.request_id,
            &caller,
            &notification,
            &response.rejected,
            res,
            started,
        )
        .await
        {
            return;
        }
        if fully_settled {
            cache_success_response(&state, &dedup_key, &request_fingerprint, &response);
        }
        record_notify_delivery_outcomes(&response);
        finish_json(res, StatusCode::OK, response, started);
        return;
    }

    if skipped_delivered > 0 {
        let status = if first_internal_error.is_some() {
            StatusCode::INTERNAL_SERVER_ERROR
        } else if first_temporary_error.is_some() {
            StatusCode::SERVICE_UNAVAILABLE
        } else if first_remote_error.is_some() {
            StatusCode::BAD_GATEWAY
        } else {
            StatusCode::OK
        };
        app_metrics::notify_retry_with_skips(status);
        tracing::info!(
            request_id = %context.request_id,
            skipped_delivered,
            rejected = rejected.len(),
            "all currently delivered devices came from dedup cache"
        );
    }

    if let Some(message) = first_internal_error {
        if !record_rejected_devices_audit_or_finish(
            &state,
            &context.request_id,
            &caller,
            &notification,
            &rejected,
            res,
            started,
        )
        .await
        {
            return;
        }
        record_delivery_receipt_outcomes(
            &delivery_receipts,
            delivered_now + skipped_delivered,
            rejected.len(),
        );
        finish_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            &message,
            None,
            Some(&context.request_id),
            started,
        );
        return;
    }

    if let Some((message, retry_after)) = first_temporary_error {
        if !record_rejected_devices_audit_or_finish(
            &state,
            &context.request_id,
            &caller,
            &notification,
            &rejected,
            res,
            started,
        )
        .await
        {
            return;
        }
        record_delivery_receipt_outcomes(
            &delivery_receipts,
            delivered_now + skipped_delivered,
            rejected.len(),
        );
        finish_error(
            res,
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            &message,
            retry_after,
            Some(&context.request_id),
            started,
        );
        return;
    }

    if let Some(message) = first_remote_error {
        if !record_rejected_devices_audit_or_finish(
            &state,
            &context.request_id,
            &caller,
            &notification,
            &rejected,
            res,
            started,
        )
        .await
        {
            return;
        }
        record_delivery_receipt_outcomes(
            &delivery_receipts,
            delivered_now + skipped_delivered,
            rejected.len(),
        );
        finish_error(
            res,
            StatusCode::BAD_GATEWAY,
            "temporarily_unavailable",
            &message,
            None,
            Some(&context.request_id),
            started,
        );
        return;
    }

    let response = NotifyResponse {
        request_id: context.request_id.clone(),
        accepted: delivered_now + skipped_delivered,
        rejected,
        provider_retries,
        delivery_receipts,
    };
    if !record_rejected_devices_audit_or_finish(
        &state,
        &context.request_id,
        &caller,
        &notification,
        &response.rejected,
        res,
        started,
    )
    .await
    {
        return;
    }
    if fully_settled {
        cache_success_response(&state, &dedup_key, &request_fingerprint, &response);
    }
    record_notify_delivery_outcomes(&response);
    finish_json(res, StatusCode::OK, response, started);
}

fn cache_success_response(
    state: &Arc<AppState>,
    key: &str,
    request_fingerprint: &str,
    response: &NotifyResponse,
) {
    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        deduplicator.insert_success(key, request_fingerprint, response.clone());
    }
}

fn mark_delivered_devices<'a>(
    state: &Arc<AppState>,
    notification_key: &str,
    targets: impl Iterator<Item = &'a crate::pushkin::DispatchTarget>,
) {
    if let Some(deduplicator) = state.notify_deduplicator.as_ref() {
        for target in targets {
            deduplicator.mark_delivered_device(notification_key, &target.app_id, &target.push_key);
        }
    }
}

fn rejected_device(device: &crate::models::Device, push_key: Option<&str>) -> RejectedDevice {
    RejectedDevice::new(Some(&device.app_id), push_key.unwrap_or(&device.push_key))
}

fn delivery_receipt(
    provider: Option<&str>,
    push_key: &str,
    status: &str,
    retry_after: Option<Duration>,
    request_id: &str,
) -> DeliveryReceipt {
    DeliveryReceipt {
        provider: provider.map(ToOwned::to_owned),
        provider_message_id: None,
        push_key_hash: Some(redact_push_token(push_key)),
        status: Some(status.to_owned()),
        retry_after_ms: retry_after.map(|value| value.as_millis().min(u64::MAX as u128) as u64),
        timestamp: Some(unix_timestamp_string()),
        request_id: Some(request_id.to_owned()),
    }
}

fn unix_timestamp_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

fn idempotency_cache_key(idempotency_key: &str) -> String {
    request_hash(format!("idempotency-key\0{idempotency_key}").as_bytes())
}

fn normalized_notify_dedup_key(notification: &Notification) -> Option<String> {
    let mut normalized = Map::new();

    if let Some(value) = notification.flow_name() {
        normalized.insert("flow_name".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.realm_name() {
        normalized.insert("realm_name".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.prio.as_ref() {
        normalized.insert("prio".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.membership.as_ref() {
        normalized.insert("membership".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.sender_display_name.as_ref() {
        normalized.insert(
            "sender_display_name".to_owned(),
            Value::String(value.clone()),
        );
    }
    if let Some(value) = notification.content.as_ref() {
        normalized.insert(
            "content".to_owned(),
            canonical_json_value(&Value::Object(value.clone())),
        );
    }
    if let Some(value) = notification.event_id.as_ref() {
        normalized.insert("event_id".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.message_id() {
        normalized.insert("message_id".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.flow_id() {
        normalized.insert("flow_id".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.realm_id() {
        normalized.insert("realm_id".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.user_is_target {
        normalized.insert("user_is_target".to_owned(), Value::Bool(value));
    }
    if let Some(value) = notification.push_target_id.as_ref() {
        normalized.insert("push_target_id".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.wakeup_kind() {
        normalized.insert("wakeup_kind".to_owned(), Value::String(value.to_owned()));
    }
    if let Some(value) = notification.sender.as_ref() {
        normalized.insert("sender".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = notification.push_hint.as_ref() {
        normalized.insert("push_hint".to_owned(), Value::String(value.clone()));
    }
    // Round 4 (spec a77b995) — `mention_redirect_target_actor_ids` is
    // routing-affecting (two requests with different allow-lists must
    // not collide in the dedup cache). Sort canonically so the
    // fingerprint is order-independent.
    if !notification.mention_redirect_target_actor_ids.is_empty() {
        let mut sorted = notification.mention_redirect_target_actor_ids.clone();
        sorted.sort();
        sorted.dedup();
        normalized.insert(
            "mention_redirect_target_actor_ids".to_owned(),
            Value::Array(sorted.into_iter().map(Value::String).collect()),
        );
    }
    normalized.insert(
        "counts".to_owned(),
        canonical_json_value(&serde_json::to_value(&notification.counts).ok()?),
    );

    let mut devices = notification
        .devices
        .iter()
        .map(|device| {
            let mut normalized = Map::new();
            normalized.insert("app_id".to_owned(), Value::String(device.app_id.clone()));
            normalized.insert(
                "push_key".to_owned(),
                Value::String(device.push_key.clone()),
            );
            // Round 4 — `target_actor_id` participates in the routing
            // decision, so it must be part of the canonical fingerprint.
            if let Some(actor_id) = device.target_actor_id.as_ref() {
                normalized.insert(
                    "target_actor_id".to_owned(),
                    Value::String(actor_id.clone()),
                );
            }
            if let Some(data) = device.data.as_ref() {
                normalized.insert(
                    "data".to_owned(),
                    canonical_json_value(&Value::Object(data.clone())),
                );
            }
            let tweaks = serde_json::to_value(&device.tweaks).ok()?;
            normalized.insert("tweaks".to_owned(), canonical_json_value(&tweaks));
            Some(Value::Object(normalized))
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    devices.sort_by_key(canonical_sort_key);
    devices.dedup();
    normalized.insert("devices".to_owned(), Value::Array(devices));

    serde_json::to_vec(&Value::Object(normalized))
        .ok()
        .map(|bytes| request_hash(&bytes))
}

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_json_value).collect()),
        Value::Object(object) => {
            let mut keys = object.keys().cloned().collect::<Vec<_>>();
            keys.sort_unstable();

            let mut normalized = Map::new();
            for key in keys {
                if let Some(value) = object.get(&key) {
                    normalized.insert(key, canonical_json_value(value));
                }
            }
            Value::Object(normalized)
        }
        _ => value.clone(),
    }
}

fn canonical_sort_key(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

fn enqueue_retry(
    state: &Arc<AppState>,
    request_id: &str,
    pushkin: &str,
    app_id: &str,
    push_key: &str,
    retry_after: Option<Duration>,
    error: &crate::error::DispatchError,
) {
    let Some(queue) = state.notify_retry_queue.as_ref() else {
        return;
    };
    let backoff = retry_after.unwrap_or(queue.config().default_backoff);
    let envelope = crate::retry_queue::RetryEnvelope::new(
        request_id,
        pushkin,
        app_id,
        push_key,
        backoff,
        error.to_string(),
    );
    queue.enqueue(envelope);
    app_metrics::notify_retry_enqueued(pushkin);
}
