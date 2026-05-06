use serde_json::{Map, Value};

use crate::models::Notification;

use super::truncate_str;

const TITLE_MAX_BYTES: usize = 128;
const BODY_MAX_BYTES: usize = 512;
const CONTENT_BODY_MAX_BYTES: usize = 1024;
const CONTENT_CIPHERTEXT_MAX_CHARS: usize = 2000;

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
    for (key, value) in [
        ("flow_id", notification.flow_id()),
        ("space_id", notification.space_id()),
        ("message_id", notification.message_id()),
        ("flow_name", notification.flow_name()),
        ("space_name", notification.space_name()),
        ("membership", notification.membership.as_deref()),
        ("event_id", notification.event_id.as_deref()),
        ("sender", notification.sender.as_deref()),
        (
            "sender_display_name",
            notification.sender_display_name.as_deref(),
        ),
        ("type", notification.r#type.as_deref()),
        ("push_hint", notification.push_hint.as_deref()),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            let (value, _) = truncate_str(value, CONTENT_BODY_MAX_BYTES);
            payload.insert(key.to_owned(), Value::String(value));
        }
    }

    if notification.user_is_target == Some(true) {
        payload.insert("user_is_target".to_owned(), Value::Bool(true));
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
        if let Some(unread) = notification.counts.unread {
            payload.insert("unread".to_owned(), Value::Number(unread.into()));
        }
        if let Some(missed_calls) = notification.counts.missed_calls {
            payload.insert(
                "missed_calls".to_owned(),
                Value::Number(missed_calls.into()),
            );
        }
        if let Some(highlight_count) = notification.counts.highlight_count {
            payload.insert(
                "highlight_count".to_owned(),
                Value::Number(highlight_count.into()),
            );
        }
    }

    if let Some(content) = &notification.content {
        payload.insert(
            "content".to_owned(),
            Value::Object(sanitized_content(content)),
        );
    }
}

fn sanitized_content(content: &Map<String, Value>) -> Map<String, Value> {
    let mut content = content.clone();
    content.remove("formatted_body");

    if let Some(body) = content.get_mut("body")
        && let Some(text) = body.as_str()
    {
        let (truncated, _) = truncate_str(text, CONTENT_BODY_MAX_BYTES);
        *body = Value::String(truncated);
    }

    let drop_ciphertext = content
        .get("ciphertext")
        .and_then(Value::as_str)
        .is_some_and(|ciphertext| ciphertext.chars().count() > CONTENT_CIPHERTEXT_MAX_CHARS);
    if drop_ciphertext {
        content.remove("ciphertext");
    }

    content
}

fn derive_alert(notification: &Notification) -> Option<(String, String)> {
    let sender = notification
        .sender_label()
        .map(str::to_owned)
        .unwrap_or_else(|| "New activity".to_owned());
    let room = notification.scope_name().map(ToOwned::to_owned);

    let title = room.clone().unwrap_or_else(|| sender.clone());
    let summary = match notification.r#type.as_deref() {
        Some("cx.message.create") | Some("cx.message.revise") => {
            message_summary(notification, &sender)
        }
        Some("cx.call.signal") => {
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
        Some("cx.space.member")
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
            pushkey: "pushkey".to_owned(),
            pushkey_ts: 42,
            data: None,
            tweaks: Tweaks::default(),
        }
    }

    fn message_notification() -> Notification {
        Notification {
            flow_name: Some("Mission Control".to_owned()),
            space_name: None,
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
            space_id: Some("cx:space:01JS0SP000000000000000000".to_owned()),
            user_is_target: Some(true),
            r#type: Some("cx.message.create".to_owned()),
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

        assert_eq!(payload.title, "Mission Control");
        assert_eq!(payload.body, "Major Tom: Ground control to Major Tom");
        assert_eq!(payload.priority, AndroidPriority::High);
        assert_eq!(
            payload.data.get("flow_id"),
            Some(&Value::String(
                "cx:flow:01JS0FLOW000000000000000".to_owned()
            ))
        );
        assert_eq!(payload.data.get("unread"), Some(&Value::Number(2.into())));
        assert_eq!(
            payload.data.get("highlight_count"),
            Some(&Value::Number(1.into()))
        );
        assert_eq!(
            payload
                .data
                .get("content")
                .and_then(Value::as_object)
                .unwrap()
                .get("formatted_body"),
            None
        );
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
                space_name: None,
                prio: None,
                membership: Some("invite".to_owned()),
                sender_display_name: Some("Major Tom".to_owned()),
                content: None,
                event_id: Some("cx:event:01JS0EV000000000000000000".to_owned()),
                message_id: None,
                flow_id: Some("cx:flow:01JS0FLOW000000000000000".to_owned()),
                space_id: None,
                user_is_target: Some(true),
                r#type: Some("cx.space.member".to_owned()),
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
