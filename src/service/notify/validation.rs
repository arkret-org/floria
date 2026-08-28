use arkret_models_integration::PushNotificationEnvelope;

use crate::auth::AuthenticatedNotifyCaller;
use crate::models::DeviceExt;

// T4.3 — visible profile / blind profile gate.
//
// floria exposes two push-gateway capability profiles:
//
//   * `ak.profile.push_gateway.blind_wakeup.v1`  (default) — opaque `push_target_id` +
//     `wakeup_kind`, no plaintext metadata. Maps to `caller.allow_plaintext_metadata = false`.
//   * `ak.profile.push_gateway.visible_notification.v1` — the caller has been explicitly gated as a
//     plaintext-eligible service kind (sync / principal) AND the per-principal
//     `allow_plaintext_metadata` flag is set. Maps to `caller.allow_plaintext_metadata = true`.
//
// A caller on the blind profile that submits plaintext metadata is
// rejected with `plaintext_in_blind_profile`. A caller on the visible
// profile can still be rejected if the wire payload contains keys that
// would let an observer correlate pushes across users (forbidden
// payload keys, sensitive `did:` / `ak:` literals).
pub(in crate::service) const BLIND_PROFILE_PLAINTEXT_REASON: &str = "plaintext_in_blind_profile";
pub(in crate::service) const VISIBLE_DEVICE_OPT_IN_REASON: &str =
    "visible_notification_device_opt_in_required";

pub(super) fn validate_notification_contract(
    notification: &PushNotificationEnvelope,
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
             `ak.profile.push_gateway.blind_wakeup.v1` profile"
        ));
    }

    // Visible metadata is per-device opt-in even for a caller that is
    // allowed the visible-notification profile.
    validate_visible_notification_device_opt_in(notification, caller)?;

    if let Some(push_hint) = notification.push_hint.as_deref() {
        validate_push_hint(push_hint)?;
    }

    Ok(())
}

fn validate_visible_notification_device_opt_in(
    notification: &PushNotificationEnvelope,
    caller: &AuthenticatedNotifyCaller,
) -> Result<(), String> {
    if !caller.allow_plaintext_metadata || !notification_has_visible_metadata(notification) {
        return Ok(());
    }

    if let Some(device) = notification
        .devices
        .iter()
        .find(|device| !device.visible_notification_opt_in())
    {
        return Err(format!(
            "{VISIBLE_DEVICE_OPT_IN_REASON}: device {} has not explicitly opted in to \
             `ak.profile.push_gateway.visible_notification.v1`",
            device.device_id.as_str()
        ));
    }

    Ok(())
}

fn notification_has_visible_metadata(notification: &PushNotificationEnvelope) -> bool {
    notification.event_id.is_some()
        || notification.realm_id.is_some()
        || notification.sender_actor_id.is_some()
        || notification.strand_id.is_some()
        || notification.message_id.is_some()
        || notification.sender_actor_display_name.is_some()
        || notification.strand_title.is_some()
        || notification.realm_title.is_some()
        || notification.user_is_target.is_some()
        || notification.priority.is_some()
        || notification.membership.is_some()
}

pub(super) fn validate_plaintext_identity_metadata(
    notification: &PushNotificationEnvelope,
    caller: &AuthenticatedNotifyCaller,
) -> Result<(), String> {
    if caller.allow_plaintext_metadata {
        return Ok(());
    }

    validate_optional_plaintext_identity_string(
        "notification.push_target_id",
        notification
            .push_target_id
            .as_ref()
            .map(arkret_wire::PushTargetId::as_str),
    )?;
    validate_optional_plaintext_identity_string(
        "notification.wakeup_kind",
        notification.wakeup_kind.as_deref(),
    )?;
    validate_optional_plaintext_identity_string(
        "notification.push_hint",
        notification.push_hint.as_deref(),
    )?;
    validate_optional_plaintext_identity_string(
        "notification.push_hint_l10n_key",
        notification.push_hint_l10n_key.as_deref(),
    )?;
    if let Some(event_id) = notification.event_id.as_ref() {
        validate_plaintext_identity_string("notification.event_id", event_id.as_str())?;
    }
    if let Some(realm_id) = notification.realm_id.as_ref() {
        validate_plaintext_identity_string("notification.realm_id", realm_id.as_str())?;
    }
    if let Some(sender_actor_id) = notification.sender_actor_id.as_ref() {
        validate_plaintext_identity_string(
            "notification.sender_actor_id",
            sender_actor_id.as_str(),
        )?;
    }
    validate_optional_plaintext_identity_string(
        "notification.sender_actor_display_name",
        notification.sender_actor_display_name.as_deref(),
    )?;
    if let Some(strand_id) = notification.strand_id.as_ref() {
        validate_plaintext_identity_string("notification.strand_id", strand_id.as_str())?;
    }
    if let Some(message_id) = notification.message_id.as_ref() {
        validate_plaintext_identity_string("notification.message_id", message_id.as_str())?;
    }
    validate_optional_plaintext_identity_string(
        "notification.strand_title",
        notification.strand_title.as_deref(),
    )?;
    validate_optional_plaintext_identity_string(
        "notification.realm_title",
        notification.realm_title.as_deref(),
    )?;
    validate_optional_plaintext_identity_string(
        "notification.priority",
        notification.priority.as_deref(),
    )?;
    validate_optional_plaintext_identity_string(
        "notification.membership",
        notification.membership.as_deref(),
    )?;

    Ok(())
}

fn validate_optional_plaintext_identity_string(
    path: &str,
    value: Option<&str>,
) -> Result<(), String> {
    if let Some(value) = value {
        validate_plaintext_identity_string(path, value)?;
    }
    Ok(())
}

fn validate_plaintext_identity_string(path: &str, value: &str) -> Result<(), String> {
    // The SDK's canonical DID validator is `^did:[a-z0-9]+:[^\s]+$`, but
    // floria treats DID literals as an opaque correlation leak regardless of
    // method-name shape. The substring check here therefore rejects any
    // `did:` prefix, well-formed or not. The canonical regex validator lives
    // in the SDK; floria's job at this boundary is just to keep DID-shaped
    // strings out of plaintext push payloads.
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
    if arkret_push_policy::blind_payload_sanitizer::is_valid_push_hint(push_hint) {
        return Ok(());
    }
    Err("Arkret blind wakeup push_hint must be one of new_message, incoming_call, mention_self, or l10n_key:<token>".to_owned())
}
