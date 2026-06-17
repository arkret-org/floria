use salvo::http::StatusCode;
use salvo::prelude::*;
use serde_json::{Map, Value};

use super::super::{
    ACTIVE_CIRCLE_ID_PREFIX, ACTIVE_EVENT_ID_PREFIX, ACTIVE_MESSAGE_ID_PREFIX,
    ACTIVE_REALM_ID_PREFIX, ACTIVE_STRAND_ID_PREFIX,
};
use crate::auth::{AuthFailure, AuthenticatedNotifyCaller, DESTINATION_SERVICE_DID_HEADER};
use crate::config::NotifyAuthConfig;
use crate::models::Notification;

/// Parent key + leaf key pairs that are forbidden. The SDK already
/// rejects any standalone `signature` field reaching the wire, but
/// round-4 specifically calls out the `binding_proof.signature` and
/// `subject_proof.signature` combinations so we add an explicit
/// path-shaped check for them — both for clearer error messages and so
/// a future sanitizer relaxation cannot accidentally re-open the
/// proof-signature leak.
const FORBIDDEN_PLAINTEXT_PARENT_LEAF: &[(&str, &str)] = &[
    ("binding_proof", "signature"),
    ("subject_proof", "signature"),
];

/// Phase P2 (CKP-0008 / CKP-0009) — durable Personal Agent lifecycle
/// event kinds. When the inbound `/notify` request carries a top-level
/// `event_kind` matching one of these, floria silently consumes the
/// request: it answers 200 with an empty fanout body so the caller's
/// pipeline advances, but it does not dispatch any provider push. The
/// event is treated as an internal cache-invalidation signal only —
/// the `consent_revoke` fanout (with `reason=agent_paused` /
/// `agent_deactivated`) is the authoritative way to invalidate the
/// per-principal capability cache. Pushing these lifecycle kinds to
/// user devices would leak agent state into the operator surface.
const AGENT_LIFECYCLE_SILENT_KINDS: &[&str] = &[
    "ck.self.agent.pause",
    "ck.self.agent.resume",
    "ck.self.agent.deactivate",
];

/// Phase P2 — actor-private Personal Agent event kinds. These never
/// reach user-device push: they're controller-private state transitions
/// between the controller and its native agent runtime. Floria drops
/// them with a 200 + zero-fanout ack — there is no partial routing
/// implementation behind this; drop is the complete behaviour.
const AGENT_ACTOR_PRIVATE_KINDS: &[&str] = &[
    "ck.agent.draft.propose",
    "ck.agent.action_request",
    "ck.agent.action_approve",
    "ck.agent.action_reject",
];

/// Phase P2 — classification of an inbound `event_kind` field. `None`
/// means the request carries no event_kind, OR a kind that floria
/// does not route specially (the historical default — fall through to
/// the normal push fanout path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AgentEventRouting {
    /// Durable agent lifecycle (`ck.agent.{pause,resume,deactivate}`):
    /// silently consumed — 200 OK, no provider dispatch.
    DurableLifecycle,
    /// Actor-private agent kind
    /// (`ck.agent.{draft.propose,action_request,action_approve,
    /// action_reject}`): dropped — 200 OK, no provider dispatch.
    ActorPrivateDrop,
}

/// Classify a top-level `event_kind` string against the Phase P2
/// agent-routing table. Unknown kinds (including non-`ck.agent.*`
/// strings and `ck.agent.*` kinds we don't yet recognize) return
/// `None` and continue down the normal push pipeline.
pub(super) fn classify_agent_event_kind(event_kind: &str) -> Option<AgentEventRouting> {
    if AGENT_LIFECYCLE_SILENT_KINDS.contains(&event_kind) {
        return Some(AgentEventRouting::DurableLifecycle);
    }
    if AGENT_ACTOR_PRIVATE_KINDS.contains(&event_kind) {
        return Some(AgentEventRouting::ActorPrivateDrop);
    }
    None
}

/// Phase P2 — the seven SDK typed-id prefixes
/// (`agent_session`, `agent_key`, `agent_draft`,
/// `accountability_grant`, `sidecar_circle`, `backup_series`,
/// `recovery_session`). `agent_principal_id` is a DID-as-id, not a
/// `ck:*` typed id. Floria does not route on these today — none
/// of them appear in the push-wire reference fields — but we keep the
/// list here so the prefix validator is aware of them when a future
/// notify field starts to carry one. Any caller that smuggles one of
/// these into an `event_id` / `message_id` / `strand_id` / `realm_id` /
/// `circle_id` slot still fails closed against the existing
/// `validate_active_ref` gates because those slots are pinned to
/// their own typed-id prefix (`ck:event:`, etc.).
const PHASE_P2_AGENT_TYPED_ID_PREFIXES: &[&str] = &[
    "ck:agent_session:",
    "ck:agent_key:",
    "ck:agent_draft:",
    "ck:accountability_grant:",
    "ck:sidecar_circle:",
    "ck:backup_series:",
    "ck:recovery_session:",
];

/// Phase P2 — returns `true` if `value` starts with one of the seven
/// new SDK typed-id prefixes. Used by the typed-id prefix recognizer
/// so any future routing code can ask "is this one of the new agent /
/// sidecar / backup / recovery typed IDs?" without having to thread
/// the SDK identifier crate into the wire-validation layer.
pub(in crate::service) fn is_phase_p2_agent_typed_id(value: &str) -> bool {
    PHASE_P2_AGENT_TYPED_ID_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

/// SPEC-CR-016: the originating service DID rides the `Source-Service-DID`
/// transport header (`ORIGIN_SERVICE_DID_HEADER`), which the auth layer
/// already resolved into `caller.origin_service_did`. We keep a
/// defense-in-depth check that the header is present and consistent with
/// the authenticated caller rather than reading a (now removed) body field.
pub(super) fn validate_origin_service_did(
    req: &Request,
    caller: &AuthenticatedNotifyCaller,
    auth_enabled: bool,
) -> Result<(), AuthFailure> {
    if !auth_enabled {
        return Ok(());
    }
    let Some(origin_service_did) = req
        .header::<String>(crate::auth::ORIGIN_SERVICE_DID_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
    else {
        return Err(AuthFailure {
            status: StatusCode::FORBIDDEN,
            code: "capability_denied",
            message: "Source-Service-DID header is required".to_owned(),
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

/// SPEC-CR-016: the destination service DID rides the
/// `Destination-Service-DID` transport header only (the body field is
/// removed). The recipient-service-did scope binding reuses the same
/// header value — `push_target_id` is a per-`(recipient_service_did, ...)`
/// pairwise pseudonym, so the gateway MUST enforce that the declared
/// destination equals its own `gateway_service_did` (spec
/// push-notifications.md §3.1, commit 0a5ab85) rather than treat it as
/// decorative.
pub(super) fn validate_destination_service_did(
    req: &Request,
    auth: &NotifyAuthConfig,
    auth_enabled: bool,
) -> Result<(), AuthFailure> {
    if !auth_enabled {
        return Ok(());
    }

    let header_destination = req
        .header::<String>(DESTINATION_SERVICE_DID_HEADER)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());

    if let Some(expected) = auth.gateway_service_did.as_deref()
        && let Some(destination) = header_destination.as_deref()
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

pub(super) fn validate_notify_contract_shape(raw: &Value) -> Result<(), String> {
    // Walk the inbound request for path-shaped proof-signature pairs
    // before other contract checks so they fail with a stable schema
    // violation.
    reject_forbidden_plaintext_fields("", raw)?;

    let Some(notification) = raw.get("notification") else {
        return Ok(());
    };
    let Some(notification) = notification.as_object() else {
        return Ok(());
    };

    // SPEC-CR-016: gateway-internal routing ids (realm_id / circle_id /
    // mention_redirect_target_actor_ids) now live under
    // `notification.routing_metadata`. The walker reads them from there.
    let routing_metadata = notification
        .get("routing_metadata")
        .and_then(Value::as_object);

    validate_active_notification_refs(notification, routing_metadata)?;
    validate_push_target_id(notification.get("push_target_id"))?;
    validate_wakeup_kind(notification.get("wakeup_kind"))?;
    validate_device_contract_shape(notification.get("devices"))?;
    if let Some(routing_metadata) = routing_metadata {
        validate_mention_redirect_routing(routing_metadata)?;
    }

    Ok(())
}

/// Round 4 — wire-format check that the
/// `mention_redirect_target_actor_ids` allow-list (if present) is an
/// array of non-empty DID strings. The actual per-device routing gate
/// is enforced inside the dispatch loop in `notify()` so we have
/// access to the parsed `Notification` + `Device` typed views.
///
/// SPEC-CR-016: the allow-list lives under
/// `notification.routing_metadata`, so this receives that sub-object.
fn validate_mention_redirect_routing(routing_metadata: &Map<String, Value>) -> Result<(), String> {
    let Some(value) = routing_metadata.get("mention_redirect_target_actor_ids") else {
        return Ok(());
    };
    let Some(items) = value.as_array() else {
        return Err(
            "notification.routing_metadata.mention_redirect_target_actor_ids must be an array of DID strings"
                .to_owned(),
        );
    };
    for (index, item) in items.iter().enumerate() {
        let Value::String(actor_id) = item else {
            return Err(format!(
                "notification.routing_metadata.mention_redirect_target_actor_ids[{index}] must be a string"
            ));
        };
        let actor_id = actor_id.trim();
        if actor_id.is_empty() {
            return Err(format!(
                "notification.routing_metadata.mention_redirect_target_actor_ids[{index}] must not be empty"
            ));
        }
        // Round 4 DID regex sweep — entries are actor identifiers, so
        // we require the round-4-tightened DID shape `did:[a-z0-9]+:…`
        // here. The SDK enforces the full regex at the sender, this is
        // a defense-in-depth check on the floria entry.
        if !is_did_shape(actor_id) {
            return Err(format!(
                "notification.routing_metadata.mention_redirect_target_actor_ids[{index}] must be a DID matching \
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
pub(in crate::service) fn is_did_shape(value: &str) -> bool {
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
fn reject_forbidden_plaintext_fields(path: &str, value: &Value) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                let leaf = key.to_ascii_lowercase();
                let next_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if let Some(parent_key) = path.rsplit('.').next() {
                    let parent_lower = parent_key.to_ascii_lowercase();
                    if FORBIDDEN_PLAINTEXT_PARENT_LEAF
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
                reject_forbidden_plaintext_fields(&next_path, nested)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for (index, nested) in values.iter().enumerate() {
                reject_forbidden_plaintext_fields(&format!("{path}[{index}]"), nested)?;
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

fn validate_active_notification_refs(
    notification: &Map<String, Value>,
    routing_metadata: Option<&Map<String, Value>>,
) -> Result<(), String> {
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
        notification.get("strand_id"),
        "notification.strand_id",
        ACTIVE_STRAND_ID_PREFIX,
    )?;
    // SPEC-CR-016: realm_id / circle_id are gateway-internal routing ids
    // and live under `notification.routing_metadata`.
    // The notification routing boundary is the Realm (`ck:realm:`);
    // container-level `space_id` is not part of the push wire model.
    validate_active_ref(
        routing_metadata.and_then(|routing| routing.get("realm_id")),
        "notification.routing_metadata.realm_id",
        ACTIVE_REALM_ID_PREFIX,
    )?;
    // CKP-0007 — `circle_id` is the encryption-sub-boundary id when the
    // notification is scoped into a Circle. Validated for prefix shape
    // here; consistency with `effective_scope` is enforced separately
    // in `validate_effective_scope_consistency`.
    validate_active_ref(
        routing_metadata.and_then(|routing| routing.get("circle_id")),
        "notification.routing_metadata.circle_id",
        ACTIVE_CIRCLE_ID_PREFIX,
    )?;
    // `space_id` is forbidden at the inbound contract layer because push
    // routing is Realm/Circle-scoped, not container-scoped.
    if notification.get("space_id").is_some()
        || routing_metadata.is_some_and(|routing| routing.get("space_id").is_some())
    {
        return Err("notification.space_id is forbidden on the push wire model".to_owned());
    }

    Ok(())
}

/// CKP-0007 — assert that `notification.effective_scope` (the
/// reducer-stamped envelope binding) is consistent with the routing
/// fields the caller supplied (`realm_id` / `circle_id`). Mismatch
/// means either the principal server stamped a different scope onto
/// the originating Event than the push caller is now claiming, OR
/// the caller forgot to update `circle_id` after a Circle scope
/// switch; both are operator bugs and we fail closed with
/// `effective_scope_mismatch`.
pub(super) fn validate_effective_scope_consistency(
    notification: &Notification,
) -> Result<(), String> {
    let Some(scope) = notification.effective_scope() else {
        return Ok(());
    };
    let scope_realm = scope.realm_id().as_str();
    if let Some(realm_id) = notification.realm_id()
        && realm_id != scope_realm
    {
        return Err(format!(
            "effective_scope_mismatch: notification.realm_id `{realm_id}` does not match \
             effective_scope.realm_id `{scope_realm}`"
        ));
    }
    match (
        scope.circle_id().map(|c| c.as_str()),
        notification.circle_id(),
    ) {
        (Some(scope_circle), Some(wire_circle)) if scope_circle != wire_circle => Err(format!(
            "effective_scope_mismatch: notification.circle_id `{wire_circle}` does not match \
             effective_scope.circle_id `{scope_circle}`"
        )),
        (Some(scope_circle), None) => Err(format!(
            "effective_scope_mismatch: effective_scope is Circle (`{scope_circle}`) but \
             notification.circle_id is absent"
        )),
        (None, Some(wire_circle)) => Err(format!(
            "effective_scope_mismatch: effective_scope is Realm but notification.circle_id \
             `{wire_circle}` is set"
        )),
        _ => Ok(()),
    }
}

fn validate_push_target_id(value: Option<&Value>) -> Result<(), String> {
    const PREFIX: &str = "ck:pseudonym:push:";
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

pub(super) fn validate_wakeup_kind(value: Option<&Value>) -> Result<(), String> {
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
    if !cokret::blind_payload_sanitizer::is_valid_wakeup_kind(value) {
        return Err(format!(
            "notification.wakeup_kind must be one of {}",
            cokret::blind_payload_sanitizer::ALLOWED_WAKEUP_KINDS.join(", ")
        ));
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
        // Phase P2 — if the value carries one of the seven
        // agent / sidecar / backup / recovery typed-id prefixes, fail
        // closed with a clearer error so the caller can see they're
        // routing the wrong typed id into a push-wire slot. Floria's
        // notify model has dedicated slots only for event / message /
        // strand / realm / circle ids — the Phase-P2 typed ids never
        // belong here.
        if is_phase_p2_agent_typed_id(value) {
            return Err(format!(
                "{path} must use active `{required_prefix}*` typed IDs; got a Phase-P2 \
                 agent / sidecar / backup / recovery typed id which has no push-wire slot"
            ));
        }
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
//   * `ck.profile.push_gateway.blind_wakeup.v1`  (default) — opaque `push_target_id` +
//     `wakeup_kind`, no plaintext metadata. Maps to `caller.allow_plaintext_metadata = false`.
//   * `ck.profile.push_gateway.visible_notification.v1` — the caller has been explicitly gated as a
//     plaintext-eligible service kind (sync / principal) AND the per-principal
//     `allow_plaintext_metadata` flag is set. Maps to `caller.allow_plaintext_metadata = true`.
//
// A caller on the blind profile that submits plaintext metadata is
// rejected with `plaintext_in_blind_profile`. A caller on the visible
// profile can still be rejected if the wire payload contains keys that
// would let an observer correlate pushes across users (forbidden
// payload keys, sensitive `did:` / `ck:` literals).
pub(in crate::service) const BLIND_PROFILE_PLAINTEXT_REASON: &str = "plaintext_in_blind_profile";

pub(super) fn validate_notification_contract(
    notification: &Notification,
    caller: &AuthenticatedNotifyCaller,
) -> Result<(), String> {
    if !caller.allow_plaintext_metadata
        && (notification.sender_actor_display_name.is_some()
            || notification.strand_title.is_some()
            || notification.realm_title.is_some())
    {
        // Blind wakeups cannot carry human-readable Realm or Strand names.
        // Container Space names are not part of this push wire model.
        return Err(format!(
            "{BLIND_PROFILE_PLAINTEXT_REASON}: caller is not authorized to send \
             sender_actor_display_name or strand/realm name metadata under the default \
             `ck.profile.push_gateway.blind_wakeup.v1` profile"
        ));
    }

    // CKP-0007 — `effective_scope` must agree with the routing fields
    // when set. This catches operator misconfigurations (caller
    // updated `realm_id` but forgot `circle_id`, or stamped a Circle
    // scope on the envelope but kept `circle_id` blank in the push
    // wire model).
    validate_effective_scope_consistency(notification)?;

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
        // Visible rendering keys (title/body/...) are rejected here so
        // operators get the plaintext-profile reason before the generic
        // blind-content validation runs.
        let forbidden_content = content.keys().find(|key| {
            crate::sanitize::BLIND_FORBIDDEN_CONTENT_TEXT_KEYS
                .iter()
                .any(|name| name.eq_ignore_ascii_case(key))
        });
        if let Some(forbidden) = forbidden_content {
            return Err(format!(
                "{BLIND_PROFILE_PLAINTEXT_REASON}: caller is not authorized to send \
                 plaintext `content.{forbidden}` under the default \
                 `ck.profile.push_gateway.blind_wakeup.v1` profile"
            ));
        }
    }

    validate_blind_content("content", &Value::Object(content.clone()))?;

    Ok(())
}

pub(super) fn validate_plaintext_identity_metadata(
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
        // SPEC-CR-016 — `routing_metadata` is the gateway-internal routing
        // fragment (realm_id / circle_id / effective_scope /
        // mention_redirect_target_actor_ids / delivery_binding_frontier).
        // It legitimately carries typed routing ids and DID entries (the
        // mention-redirect allow-list, which receivers verify WITHOUT
        // decrypting the body), and is stripped before any provider call.
        // The visible-identity scan (and the SDK `did:` literal block)
        // would otherwise reject the very routing fields we're honoring,
        // so the whole sub-object is skipped here. Its shape / DID-regex
        // is already enforced by `validate_active_notification_refs` and
        // `validate_mention_redirect_routing`.
        if key.eq_ignore_ascii_case("routing_metadata") {
            continue;
        }
        if is_identity_metadata_key(key) && has_visible_identity_value(value) {
            return Err(format!(
                "{BLIND_PROFILE_PLAINTEXT_REASON}: caller is not authorized to send \
                 plaintext identity metadata in `{path}` under the default \
                 `ck.profile.push_gateway.blind_wakeup.v1` profile"
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
                         `ck.profile.push_gateway.blind_wakeup.v1` profile"
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
// The blind-wakeup profile only permits coarse hints; actual reaction
// emoji or other message content must never appear in `push_hint`.
fn validate_push_hint(push_hint: &str) -> Result<(), String> {
    if cokret::blind_payload_sanitizer::is_valid_push_hint(push_hint) {
        return Ok(());
    }
    Err("Cokret blind wakeup push_hint must be one of new_message, incoming_call, mention_self, or l10n_key:<token>".to_owned())
}

// T1.1 — thin wrapper over the SDK's `sanitize_blind_payload` recursive
// scan. We still keep the `validate_blind_string` call setup detection
// (TURN/ICE/SDP literal pattern) because that's a floria-specific
// content rule, not part of the cross-impl key allow/block list.
fn validate_blind_content(path: &str, value: &Value) -> Result<(), String> {
    // Run the SDK sanitizer over the subtree by wrapping it in a synthetic
    // notification envelope so the wrapper-scan path (forbidden keys +
    // sensitive did:/ck: literals) walks the whole tree without needing
    // top-level `push_target_id` / `wakeup_kind` to be present.
    let envelope = serde_json::json!({
        "notification": {
            "push_target_id": "ck:pseudonym:push:0000000000000000000000",
            "wakeup_kind": "message",
        },
        path: value,
    });
    if let Err(err) = cokret::blind_payload_sanitizer::sanitize_blind_payload(&envelope) {
        return Err(format!(
            "Cokret blind wakeup payloads must not include sensitive field `{}` ({})",
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
            "Cokret blind wakeup payloads must not include call setup material in `{path}`"
        ))
    } else {
        Ok(())
    }
}

// T1.1 — the floria-local `is_sensitive_payload_key` allow-list moved into
// `cokret::blind_payload_sanitizer::is_forbidden_payload_key`
// so the chime/floria rule cannot drift. Callers now go through the SDK
// helper via `validate_blind_content`.
