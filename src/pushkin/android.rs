use serde_json::{Map, Value};

use crate::models::Notification;

use super::{sanitized_provider_payload, truncate_str};

const TITLE_MAX_BYTES: usize = 128;
const BODY_MAX_BYTES: usize = 512;
const CONTENT_BODY_MAX_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AndroidNotificationPayload {
    pub title: String,
    pub body: String,
    pub data: Map<String, Value>,
    pub priority: AndroidPriority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AndroidPriority {
    Normal,
    High,
}

pub(super) fn build_android_notification_payload(
    notification: &Notification,
    mut default_payload: Map<String, Value>,
    send_badge_counts: bool,
) -> Option<AndroidNotificationPayload> {
    merge_notification_data(&mut default_payload, notification, send_badge_counts);

    // T4.3 — last-line-of-defence sanitization. Even if a caller went
    // around the notify ingress (e.g. retry queue re-dispatch with
    // stale payload) we MUST NOT ship a forbidden field on the wire.
    let default_payload = match sanitized_provider_payload(default_payload) {
        Ok(payload) => payload,
        Err(rejection) => {
            tracing::warn!(
                rejection = %rejection,
                "dropping android push payload due to provider sanitizer rejection"
            );
            return None;
        }
    };

    let (title, body) = derive_alert(notification)?;
    Some(AndroidNotificationPayload {
        title,
        body,
        data: default_payload,
        priority: if notification.prio.as_deref() == Some("low") {
            AndroidPriority::Normal
        } else {
            AndroidPriority::High
        },
    })
}

fn merge_notification_data(
    payload: &mut Map<String, Value>,
    notification: &Notification,
    send_badge_counts: bool,
) {
    // T4.3 — only emit fields that the SDK blind-wakeup contract allows.
    // `event_id` / `message_id` / `flow_id` / `realm_id` / sender / names
    // are stable correlation identifiers; the client now derives them
    // from the e2ee wakeup payload it pulls server-side, never from the
    // provider wire format. `push_hint` survives only when it matches
    // the SDK's closed enum (validated via `sanitized_provider_payload`).
    use contrix::blind_payload_sanitizer as sdk;

    if let Some(push_target_id) = notification.push_target_id.as_deref()
        && sdk::is_valid_push_target_id(push_target_id)
    {
        let (value, _) = truncate_str(push_target_id, CONTENT_BODY_MAX_BYTES);
        payload.insert("push_target_id".to_owned(), Value::String(value));
    }
    if let Some(wakeup_kind) = notification.wakeup_kind()
        && sdk::is_valid_wakeup_kind(wakeup_kind)
    {
        let (value, _) = truncate_str(wakeup_kind, CONTENT_BODY_MAX_BYTES);
        payload.insert("wakeup_kind".to_owned(), Value::String(value));
    }
    if let Some(push_hint) = notification.push_hint.as_deref()
        && sdk::is_valid_push_hint(push_hint)
    {
        let (value, _) = truncate_str(push_hint, CONTENT_BODY_MAX_BYTES);
        payload.insert("push_hint".to_owned(), Value::String(value));
    }

    payload.insert(
        "prio".to_owned(),
        Value::String(
            if notification.prio.as_deref() == Some("low") {
                "normal"
            } else {
                "high"
            }
            .to_owned(),
        ),
    );

    if send_badge_counts {
        // Clamp counts to SDK MAX_COUNT_VALUE so a 4-byte stable
        // counter can't be smuggled through as a correlation tag.
        if let Some(unread) = notification.counts.unread {
            payload.insert(
                "unread_count".to_owned(),
                Value::Number(unread.min(sdk::MAX_COUNT_VALUE).into()),
            );
        }
        if let Some(missed_calls) = notification.counts.missed_calls {
            payload.insert(
                "badge".to_owned(),
                Value::Number(missed_calls.min(sdk::MAX_COUNT_VALUE).into()),
            );
        }
    }

    // `content`, `flow_name`, `sender_display_name` etc. are no longer
    // copied here. Even under the visible profile, the visible
    // title/body is rendered by `derive_alert` and ends up in the
    // provider's notification block (e.g. `aps.alert`,
    // `android.notification`) where the gateway can shape it per
    // provider, NOT in the freeform data dictionary that the
    // sanitizer guards.
}

fn derive_alert(notification: &Notification) -> Option<(String, String)> {
    let sender = notification
        .sender_label()
        .map(str::to_owned)
        .unwrap_or_else(|| "New activity".to_owned());
    let room = notification.scope_name().map(ToOwned::to_owned);

    let title = room.clone().unwrap_or_else(|| sender.clone());
    let summary = match notification.wakeup_kind.as_deref() {
        Some("message") => message_summary(notification, &sender),
        Some("incoming_call") => {
            if let Some(push_hint) = notification.push_hint_text() {
                push_hint.to_owned()
            } else {
                if notification
                    .content
                    .as_ref()
                    .and_then(|content| content.get("offer"))
                    .and_then(Value::as_object)
                    .and_then(|offer| offer.get("sdp"))
                    .and_then(Value::as_str)
                    .is_some_and(|sdp| sdp.contains("m=video"))
                {
                    format!("{sender} is calling you")
                } else {
                    format!("{sender} started a voice call")
                }
            }
        }
        Some("member")
            if notification.user_is_target == Some(true)
                && notification.membership.as_deref() == Some("invite") =>
        {
            match room {
                Some(room) => format!("{sender} invited you to {room}"),
                None => format!("{sender} invited you"),
            }
        }
        Some(event_type) => {
            if let Some(body) = content_body(notification) {
                maybe_prefix_sender(room.is_some(), &sender, body)
            } else {
                format!("{sender} sent {event_type}")
            }
        }
        None => fallback_summary(notification, &sender),
    };

    let (title, _) = truncate_str(&title, TITLE_MAX_BYTES);
    let (summary, _) = truncate_str(&summary, BODY_MAX_BYTES);
    if title.is_empty() || summary.is_empty() {
        return None;
    }
    Some((title, summary))
}

fn message_summary(notification: &Notification, sender: &str) -> String {
    let has_room = notification.scope_name().is_some();
    let msgtype = notification
        .content
        .as_ref()
        .and_then(|content| content.get("msgtype"))
        .and_then(Value::as_str);
    match msgtype {
        Some("m.text") | Some("m.notice") | Some("m.encrypted") | None => {
            if let Some(body) = content_body(notification) {
                maybe_prefix_sender(has_room, sender, body)
            } else {
                format!("{sender} sent a message")
            }
        }
        Some("m.image") => format!("{sender} sent an image"),
        Some("m.file") => format!("{sender} sent a file"),
        Some("m.video") => format!("{sender} sent a video"),
        Some("m.audio") => format!("{sender} sent audio"),
        Some("m.location") => format!("{sender} shared a location"),
        Some("m.emote") => content_body(notification)
            .map(|body| format!("* {sender} {body}"))
            .unwrap_or_else(|| format!("{sender} sent an emote")),
        Some(other) => {
            if let Some(body) = content_body(notification) {
                maybe_prefix_sender(has_room, sender, body)
            } else {
                format!("{sender} sent {other}")
            }
        }
    }
}

fn fallback_summary(notification: &Notification, sender: &str) -> String {
    if let Some(body) = content_body(notification) {
        return maybe_prefix_sender(notification.scope_name().is_some(), sender, body);
    }

    match notification.counts.unread {
        Some(unread) if unread > 0 => format!("You have {unread} unread messages"),
        _ => format!("{sender} sent an update"),
    }
}

fn maybe_prefix_sender(has_room: bool, sender: &str, body: String) -> String {
    if has_room && sender != "New activity" {
        format!("{sender}: {body}")
    } else {
        body
    }
}

fn content_body(notification: &Notification) -> Option<String> {
    let text = notification.content_body()?;
    if text.is_empty() {
        return None;
    }
    let (text, _) = truncate_str(text, BODY_MAX_BYTES);
    Some(text)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::models::{Counts, Device, Notification, Tweaks};

    fn device() -> Device {
        Device {
            app_id: "com.example.cn".to_owned(),
            push_key: "push_key".to_owned(),
            data: None,
            tweaks: Tweaks::default(),
            push_decision: None,
        }
    }

    fn message_notification() -> Notification {
        Notification {
            flow_name: Some("Mission Control".to_owned()),
            realm_name: None,
            prio: None,
            membership: None,
            sender_display_name: Some("Major Tom".to_owned()),
            content: Some(
                json!({
                    "msgtype": "m.text",
                    "body": "Ground control to Major Tom",
                    "formatted_body": "<b>Ground control</b>"
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
            event_id: Some("cx:event:01JS0EV000000000000000000".to_owned()),
            message_id: Some("cx:message:01JS0MSG0000000000000000".to_owned()),
            flow_id: Some("cx:flow:01JS0FLOW000000000000000".to_owned()),
            realm_id: Some("cx:realm:01JS0SP000000000000000000".to_owned()),
            user_is_target: Some(true),
            push_target_id: Some("cx:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            recipient_service_did: None,
            delivery_binding_frontier: None,
            wakeup_kind: Some("message".to_owned()),
            sender: Some("@major:example.com".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
                highlight_count: Some(1),
            },
        }
    }

    #[test]
    fn builds_android_notification_payload() {
        let payload =
            build_android_notification_payload(&message_notification(), Map::new(), true).unwrap();

        // Title/body are derived from the (visible-profile) caller's
        // metadata. They go into the provider's notification block,
        // not the freeform `data` dict — so they're rendered here.
        assert_eq!(payload.title, "Mission Control");
        assert_eq!(payload.body, "Major Tom: Ground control to Major Tom");
        assert_eq!(payload.priority, AndroidPriority::High);

        // T4.3 — the freeform `data` dict MUST NOT carry stable
        // correlation identifiers any more. The client now derives
        // those from the e2ee wakeup material it pulls server-side.
        assert!(payload.data.get("flow_id").is_none());
        // TODO(realm-rework): SDK forbidden list still names the legacy
        // `space_id`; once it adds `realm_id`, this defense-in-depth
        // assertion stays in place to cover both.
        assert!(payload.data.get("space_id").is_none());
        assert!(payload.data.get("realm_id").is_none());
        assert!(payload.data.get("event_id").is_none());
        assert!(payload.data.get("message_id").is_none());
        assert!(payload.data.get("sender").is_none());
        assert!(payload.data.get("sender_display_name").is_none());
        assert!(payload.data.get("flow_name").is_none());
        assert!(payload.data.get("realm_name").is_none());
        assert!(payload.data.get("content").is_none());

        // Allowed blind-wakeup fields survive.
        assert_eq!(
            payload.data.get("push_target_id"),
            Some(&Value::String(
                "cx:pseudonym:push:01HYZ8Z000000000000000".to_owned()
            ))
        );
        assert_eq!(
            payload.data.get("wakeup_kind"),
            Some(&Value::String("message".to_owned()))
        );
        assert_eq!(
            payload.data.get("unread_count"),
            Some(&Value::Number(2.into()))
        );
        // missed_calls → badge (clamped at MAX_COUNT_VALUE)
        assert_eq!(payload.data.get("badge"), Some(&Value::Number(1.into())));
    }

    #[test]
    fn low_priority_maps_to_normal() {
        let mut notification = message_notification();
        notification.prio = Some("low".to_owned());

        let payload = build_android_notification_payload(&notification, Map::new(), true).unwrap();
        assert_eq!(payload.priority, AndroidPriority::Normal);
        assert_eq!(
            payload.data.get("prio"),
            Some(&Value::String("normal".to_owned()))
        );
    }

    #[test]
    fn invitation_uses_human_readable_summary() {
        let payload = build_android_notification_payload(
            &Notification {
                flow_name: Some("Nebula".to_owned()),
                realm_name: None,
                prio: None,
                membership: Some("invite".to_owned()),
                sender_display_name: Some("Major Tom".to_owned()),
                content: None,
                event_id: Some("cx:event:01JS0EV000000000000000000".to_owned()),
                message_id: None,
                flow_id: Some("cx:flow:01JS0FLOW000000000000000".to_owned()),
                realm_id: None,
                user_is_target: Some(true),
                push_target_id: Some("cx:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
                recipient_service_did: None,
                delivery_binding_frontier: None,
                wakeup_kind: Some("member".to_owned()),
                sender: Some("@major:example.com".to_owned()),
                push_hint: None,
                devices: vec![device()],
                counts: Counts::default(),
            },
            Map::new(),
            true,
        )
        .unwrap();

        assert_eq!(payload.title, "Nebula");
        assert_eq!(payload.body, "Major Tom invited you to Nebula");
    }
}
