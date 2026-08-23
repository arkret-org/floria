use arkret_models_integration::PushNotificationEnvelope;
use serde_json::{Map, Value};

use super::{
    build_blind_routing_data, notification_badge_count, notification_unread_increment,
    sanitized_provider_payload, truncate_str,
};
use crate::models::NotificationExt;

const TITLE_MAX_BYTES: usize = 128;
const BODY_MAX_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AndroidNotificationPayload {
    pub title: Option<String>,
    pub body: Option<String>,
    pub data: Map<String, Value>,
    pub priority: AndroidPriority,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AndroidPriority {
    Normal,
    High,
}

pub(super) fn build_android_notification_payload(
    notification: &PushNotificationEnvelope,
    mut provider_payload: Map<String, Value>,
    allow_visible_notification: bool,
    send_badge_counts: bool,
) -> Option<AndroidNotificationPayload> {
    merge_notification_data(&mut provider_payload, notification, send_badge_counts);

    // T4.3 - last-line-of-defence sanitization. Even if a caller went
    // around the notify ingress (e.g. retry queue re-dispatch with
    // stale payload) we MUST NOT ship a forbidden field on the wire.
    let provider_payload = match sanitized_provider_payload(provider_payload) {
        Ok(payload) => payload,
        Err(rejection) => {
            tracing::warn!(
                rejection = %rejection,
                "dropping android push payload due to provider sanitizer rejection"
            );
            return None;
        }
    };

    let (title, body) = if allow_visible_notification {
        let (title, body) = derive_alert(notification)?;
        (Some(title), Some(body))
    } else {
        (None, None)
    };
    Some(AndroidNotificationPayload {
        title,
        body,
        data: provider_payload,
        priority: if notification.is_low_priority() {
            AndroidPriority::Normal
        } else {
            AndroidPriority::High
        },
    })
}

fn merge_notification_data(
    payload: &mut Map<String, Value>,
    notification: &PushNotificationEnvelope,
    send_badge_counts: bool,
) {
    // T4.3 - only emit fields that the SDK blind-wakeup contract allows.
    // `event_id` / `message_id` / `strand_id` / `realm_id` / sender / names
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
        if let Some(unread_increment) = notification_unread_increment(notification) {
            payload.insert(
                "unread_count".to_owned(),
                Value::Number(unread_increment.into()),
            );
        }
        if let Some(badge) = notification_badge_count(notification) {
            payload.insert("badge".to_owned(), Value::Number(badge.into()));
        }
    }

    // `content`, `strand_title`, `sender_actor_display_name` etc. are no longer
    // copied here. Even under the visible profile, the visible
    // title/body is rendered by `derive_alert` and ends up in the
    // provider's notification block (e.g. `aps.alert`,
    // `android.notification`) where the gateway can shape it per
    // provider, NOT in the freeform data dictionary that the
    // sanitizer guards.
}

fn derive_alert(notification: &PushNotificationEnvelope) -> Option<(String, String)> {
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
                format!("{sender} started a voice call")
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
        Some(event_type) => format!("{sender} sent {event_type}"),
        None => fallback_summary(notification, &sender),
    };

    let (title, _) = truncate_str(&title, TITLE_MAX_BYTES);
    let (summary, _) = truncate_str(&summary, BODY_MAX_BYTES);
    if title.is_empty() || summary.is_empty() {
        return None;
    }
    Some((title, summary))
}

fn message_summary(notification: &PushNotificationEnvelope, sender: &str) -> String {
    let _ = notification;
    format!("{sender} sent a message")
}

fn fallback_summary(notification: &PushNotificationEnvelope, sender: &str) -> String {
    match notification_unread_increment(notification) {
        Some(unread_increment) if unread_increment >= crate::sanitize::BUCKET_TWENTY_ONE_PLUS => {
            "You have 21+ unread messages".to_owned()
        }
        Some(unread_increment) if unread_increment >= 6 => {
            "You have 6-20 unread messages".to_owned()
        }
        Some(unread_increment) if unread_increment > 1 => {
            "You have several unread messages".to_owned()
        }
        Some(1) => "You have a new message".to_owned(),
        _ => format!("{sender} sent an update"),
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_integration::{
        PushCounts, PushDeviceRoute, PushNotificationEnvelope, PushRouteTokens,
    };

    use super::*;

    fn device() -> PushDeviceRoute {
        PushDeviceRoute {
            device_id: arkret_wire::DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001")
                .unwrap(),
            app_id: Some("com.example.cn".to_owned()),
            push_key: Some(arkret_models_integration::PushKey::new("push_key").unwrap()),
            platform: None,
            target_route_token: None,
            visible_notification_opt_in: false,
        }
    }

    fn message_notification() -> PushNotificationEnvelope {
        PushNotificationEnvelope {
            strand_title: Some("Mission Control".to_owned()),
            realm_title: None,
            priority: None,
            membership: None,
            sender_actor_display_name: Some("Major Tom".to_owned()),
            event_id: Some(
                arkret_wire::EventId::new("ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS")
                    .unwrap(),
            ),
            message_id: Some(
                arkret_wire::MessageId::new(
                    "ak:message:AevYtAp_mjd9pPNtsNoiquL8rnoJUC0S0gYtV6_SwmD1",
                )
                .unwrap(),
            ),
            strand_id: Some(
                arkret_wire::StrandId::new(
                    "ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD",
                )
                .unwrap(),
            ),
            route_tokens: Some(PushRouteTokens {
                realm_route_token: Some(
                    arkret_models_integration::PushRouteToken::new("realm_route_token_000000001")
                        .unwrap(),
                ),
                ..Default::default()
            }),
            user_is_target: Some(true),
            push_target_id: Some("ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
            wakeup_kind: Some("message".to_owned()),
            push_hint: None,
            devices: vec![device()],
            counts: Some(PushCounts {
                badge: Some(arkret_models_integration::PushCountIndicator::Bucket(
                    "2-5".to_owned(),
                )),
                unread_increment: Some(2),
                missed_call: Some(arkret_models_integration::PushCountIndicator::Present(true)),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn builds_android_notification_payload() {
        let payload =
            build_android_notification_payload(&message_notification(), Map::new(), true, true)
                .unwrap();

        // Title/body are derived from the (visible-profile) caller's
        // metadata. They go into the provider's notification block,
        // not the freeform `data` dict — so they're rendered here.
        assert_eq!(payload.title.as_deref(), Some("Mission Control"));
        assert_eq!(payload.body.as_deref(), Some("Major Tom sent a message"));
        assert_eq!(payload.priority, AndroidPriority::High);

        // T4.3 — the freeform `data` dict MUST NOT carry stable
        // correlation identifiers any more. The client now derives
        // those from the e2ee wakeup material it pulls server-side.
        assert!(payload.data.get("strand_id").is_none());
        // SDK + local R23 sanitizers cover both the renamed security
        // id (`realm_id`) AND the renamed container id (`space_id`).
        assert!(payload.data.get("space_id").is_none());
        assert!(payload.data.get("realm_id").is_none());
        // AKP-0007 — Circle routing identifiers never appear in the
        // android freeform `data` dict.
        assert!(payload.data.get("circle_id").is_none());
        assert!(payload.data.get("effective_scope").is_none());
        assert!(payload.data.get("scope_circle_id").is_none());
        assert!(payload.data.get("event_id").is_none());
        assert!(payload.data.get("message_id").is_none());
        assert!(payload.data.get("sender").is_none());
        assert!(payload.data.get("sender_actor_display_name").is_none());
        assert!(payload.data.get("strand_title").is_none());
        assert!(payload.data.get("realm_title").is_none());
        assert!(payload.data.get("content").is_none());

        // Allowed blind-wakeup fields survive.
        assert_eq!(
            payload.data.get("push_target_id"),
            Some(&Value::String(
                "ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()
            ))
        );
        assert_eq!(
            payload.data.get("wakeup_kind"),
            Some(&Value::String("message".to_owned()))
        );
        // unread_increment travels as a bucketed count; badge is reduced
        // to a boolean unread indicator.
        assert_eq!(
            payload.data.get("unread_count"),
            Some(&Value::Number(5.into()))
        );
        assert_eq!(payload.data.get("badge"), Some(&Value::Number(1.into())));
    }

    #[test]
    fn low_priority_maps_to_normal() {
        let mut notification = message_notification();
        notification.priority = Some("low".to_owned());

        let payload =
            build_android_notification_payload(&notification, Map::new(), true, true).unwrap();
        assert_eq!(payload.priority, AndroidPriority::Normal);
        assert_eq!(
            payload.data.get("priority"),
            Some(&Value::String("normal".to_owned()))
        );
    }

    #[test]
    fn invitation_uses_human_readable_summary() {
        let payload = build_android_notification_payload(
            &PushNotificationEnvelope {
                strand_title: Some("Nebula".to_owned()),
                realm_title: None,
                priority: None,
                membership: Some("invite".to_owned()),
                sender_actor_display_name: Some("Major Tom".to_owned()),
                event_id: Some(
                    arkret_wire::EventId::new(
                        "ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
                    )
                    .unwrap(),
                ),
                message_id: None,
                strand_id: Some(
                    arkret_wire::StrandId::new(
                        "ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD",
                    )
                    .unwrap(),
                ),
                user_is_target: Some(true),
                push_target_id: Some("ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()),
                wakeup_kind: Some("member".to_owned()),
                push_hint: None,
                devices: vec![device()],
                counts: Some(PushCounts::default()),
                ..Default::default()
            },
            Map::new(),
            true,
            true,
        )
        .unwrap();

        assert_eq!(payload.title.as_deref(), Some("Nebula"));
        assert_eq!(
            payload.body.as_deref(),
            Some("Major Tom invited you to Nebula")
        );
    }

    #[test]
    fn blind_payload_is_data_only() {
        let payload =
            build_android_notification_payload(&message_notification(), Map::new(), false, true)
                .unwrap();

        assert_eq!(payload.title, None);
        assert_eq!(payload.body, None);
        assert_eq!(
            payload.data.get("push_target_id"),
            Some(&Value::String(
                "ak:pseudonym:push:01HYZ8Z000000000000000".to_owned()
            ))
        );
        assert_eq!(
            payload.data.get("wakeup_kind"),
            Some(&Value::String("message".to_owned()))
        );
    }
}
