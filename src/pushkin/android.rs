use serde_json::{Map, Value};

use super::{build_blind_routing_data, sanitized_provider_payload, truncate_str};
use crate::models::Notification;

const TITLE_MAX_BYTES: usize = 128;
const BODY_MAX_BYTES: usize = 512;

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
        priority: if notification.is_low_priority() {
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
    payload.extend(build_blind_routing_data(notification));

    payload.insert(
        "priority".to_owned(),
        Value::String(
            if notification.is_low_priority() {
                "normal"
            } else {
                "high"
            }
            .to_owned(),
        ),
    );

    if send_badge_counts {
        // §5.1 — bucket the absolute counts (0 / 1 / 2-5 / 6+) before
        // they reach the provider. A bare clamp still let `unread = 37`
        // ride the wire as a per-`push_target_id` activity correlator;
        // bucketing destroys the exact figure while preserving ordering.
        if let Some(unread) = notification.counts.unread {
            payload.insert(
                "unread_count".to_owned(),
                Value::Number(crate::sanitize::bucket_count(unread).into()),
            );
        }
        if let Some(missed_calls) = notification.counts.missed_calls {
            payload.insert(
                "badge".to_owned(),
                Value::Number(crate::sanitize::bucket_count(missed_calls).into()),
            );
        }
    }

    // `content`, `flow_title`, `sender_actor_display_name` etc. are no longer
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
    let scope_title = notification.scope_title().map(ToOwned::to_owned);

    let title = scope_title.clone().unwrap_or_else(|| sender.clone());
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
            match scope_title {
                Some(scope_title) => format!("{sender} invited you to {scope_title}"),
                None => format!("{sender} invited you"),
            }
        }
        Some(event_type) => {
            if let Some(body) = content_body(notification) {
                maybe_prefix_sender(scope_title.is_some(), &sender, body)
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
    let has_scope = notification.scope_title().is_some();
    let msgtype = notification
        .content
        .as_ref()
        .and_then(|content| content.get("msgtype"))
        .and_then(Value::as_str);
    match msgtype {
        Some("m.text") | Some("m.notice") | Some("m.encrypted") | None => {
            if let Some(body) = content_body(notification) {
                maybe_prefix_sender(has_scope, sender, body)
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
                maybe_prefix_sender(has_scope, sender, body)
            } else {
                format!("{sender} sent {other}")
            }
        }
    }
}

fn fallback_summary(notification: &Notification, sender: &str) -> String {
    if let Some(body) = content_body(notification) {
        return maybe_prefix_sender(notification.scope_title().is_some(), sender, body);
    }

    // §5.1 minimization — never render the absolute unread integer into
    // the provider-visible alert text. Even on the visible profile the
    // provider can read this string, so the count is bucketed to the
    // same coarse phrasing the wire data uses.
    match notification.counts.unread {
        Some(unread) if unread >= crate::sanitize::BUCKET_SIX_PLUS => {
            format!(
                "You have {}+ unread messages",
                crate::sanitize::BUCKET_SIX_PLUS
            )
        }
        Some(unread) if unread > 1 => "You have several unread messages".to_owned(),
        Some(1) => "You have a new message".to_owned(),
        _ => format!("{sender} sent an update"),
    }
}

fn maybe_prefix_sender(has_scope: bool, sender: &str, body: String) -> String {
    if has_scope && sender != "New activity" {
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
    use crate::models::{Counts, Device, Notification, RoutingMetadata, Tweaks};

    fn device() -> Device {
        Device {
            app_id: "com.example.cn".to_owned(),
            push_key: "push_key".to_owned(),
            data: None,
            tweaks: Tweaks::default(),
            push_decision: None,
            target_actor_id: None,
        }
    }

    fn message_notification() -> Notification {
        Notification {
            flow_title: Some("Mission Control".to_owned()),
            realm_title: None,
            priority: None,
            membership: None,
            sender_actor_display_name: Some("Major Tom".to_owned()),
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
            event_id: Some("ck:event:01JS0EV000000000000000000".to_owned()),
            message_id: Some("ck:message:01JS0MSG0000000000000000".to_owned()),
            flow_id: Some("ck:flow:01JS0FLOW000000000000000".to_owned()),
            routing_metadata: Some(RoutingMetadata {
                realm_id: Some("ck:realm:01JS0SP000000000000000000".to_owned()),
                ..Default::default()
            }),
            user_is_target: Some(true),
            push_target_id: Some("ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            wakeup_kind: Some("message".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Counts {
                unread: Some(2),
                missed_calls: Some(1),
                highlight_count: Some(1),
            },
            ..Default::default()
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
        // SDK + local R23 sanitizers cover both the renamed security
        // id (`realm_id`) AND the renamed container id (`space_id`).
        assert!(payload.data.get("space_id").is_none());
        assert!(payload.data.get("realm_id").is_none());
        // CKP-0007 — Circle routing identifiers never appear in the
        // android freeform `data` dict.
        assert!(payload.data.get("circle_id").is_none());
        assert!(payload.data.get("effective_scope").is_none());
        assert!(payload.data.get("scope_circle_id").is_none());
        assert!(payload.data.get("event_id").is_none());
        assert!(payload.data.get("message_id").is_none());
        assert!(payload.data.get("sender").is_none());
        assert!(payload.data.get("sender_actor_display_name").is_none());
        assert!(payload.data.get("flow_title").is_none());
        assert!(payload.data.get("realm_title").is_none());
        assert!(payload.data.get("content").is_none());

        // Allowed blind-wakeup fields survive.
        assert_eq!(
            payload.data.get("push_target_id"),
            Some(&Value::String(
                "ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()
            ))
        );
        assert_eq!(
            payload.data.get("wakeup_kind"),
            Some(&Value::String("message".to_owned()))
        );
        // §5.1 — counts are bucketed (0 / 1 / 2-5 / 6+). unread=2 falls
        // in the `2-5` bucket whose representative value is 5; the exact
        // figure never reaches the wire.
        assert_eq!(
            payload.data.get("unread_count"),
            Some(&Value::Number(5.into()))
        );
        // missed_calls=1 → `1` bucket → badge 1.
        assert_eq!(payload.data.get("badge"), Some(&Value::Number(1.into())));
    }

    #[test]
    fn low_priority_maps_to_normal() {
        let mut notification = message_notification();
        notification.priority = Some("low".to_owned());

        let payload = build_android_notification_payload(&notification, Map::new(), true).unwrap();
        assert_eq!(payload.priority, AndroidPriority::Normal);
        assert_eq!(
            payload.data.get("priority"),
            Some(&Value::String("normal".to_owned()))
        );
    }

    #[test]
    fn invitation_uses_human_readable_summary() {
        let payload = build_android_notification_payload(
            &Notification {
                flow_title: Some("Nebula".to_owned()),
                realm_title: None,
                priority: None,
                membership: Some("invite".to_owned()),
                sender_actor_display_name: Some("Major Tom".to_owned()),
                content: None,
                event_id: Some("ck:event:01JS0EV000000000000000000".to_owned()),
                message_id: None,
                flow_id: Some("ck:flow:01JS0FLOW000000000000000".to_owned()),
                user_is_target: Some(true),
                push_target_id: Some("ck:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
                wakeup_kind: Some("member".to_owned()),
                push_hint: None,
                devices: vec![device()],
                counts: Counts::default(),
                ..Default::default()
            },
            Map::new(),
            true,
        )
        .unwrap();

        assert_eq!(payload.title, "Nebula");
        assert_eq!(payload.body, "Major Tom invited you to Nebula");
    }
}
