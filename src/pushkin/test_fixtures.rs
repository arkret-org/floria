//! Shared provider-test fixtures.
//!
//! Every provider test asserts the same canonical envelope against a different
//! provider payload builder. Keeping one fixture here means a wire-shape change
//! is made once instead of once per provider, and a provider test cannot drift
//! onto an envelope the others no longer use.

use arkret_models_integration::{
    PushCountIndicator, PushCounts, PushDeviceRoute, PushKey, PushNotificationEnvelope,
    PushRouteToken, PushRouteTokens,
};
use arkret_wire::{DeviceId, EventId, MessageId, PushTargetId, StrandId};

/// The canonical single-device route every provider test dispatches to,
/// parameterized only by the provider-specific app id and push key.
pub(crate) fn device(app_id: &str, push_key: &str) -> PushDeviceRoute {
    PushDeviceRoute {
        device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap(),
        app_id: Some(app_id.to_owned()),
        push_key: Some(PushKey::new(push_key).unwrap()),
        platform: None,
        target_route_token: None,
        visible_notification_opt_in: false,
    }
}

/// The canonical notification envelope every provider test renders.
///
/// `priority` and `user_is_target` are the only axes providers vary, so they
/// stay explicit parameters instead of being copied into per-provider clones.
pub(crate) fn notification(
    devices: Vec<PushDeviceRoute>,
    priority: Option<&str>,
    user_is_target: Option<bool>,
) -> PushNotificationEnvelope {
    PushNotificationEnvelope {
        strand_title: Some("Mission Control".to_owned()),
        realm_title: None,
        priority: priority.map(ToOwned::to_owned),
        membership: None,
        sender_actor_display_name: Some("Major Tom".to_owned()),
        event_id: Some(
            EventId::new("ak:event:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS").unwrap(),
        ),
        message_id: Some(
            MessageId::new("ak:message:AevYtAp_mjd9pPNtsNoiquL8rnoJUC0S0gYtV6_SwmD1").unwrap(),
        ),
        strand_id: Some(
            StrandId::new("ak:strand:AZfy3leHQNK3ezr_x4HPHq09HrnS3Eb6wM-IwyFH8fQD").unwrap(),
        ),
        route_tokens: Some(PushRouteTokens {
            realm_route_token: Some(PushRouteToken::new("realm_route_token_000000001").unwrap()),
            ..Default::default()
        }),
        user_is_target,
        push_target_id: Some(
            PushTargetId::new("ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8")
                .unwrap(),
        ),
        wakeup_kind: Some("message".to_owned()),
        push_hint: None,
        devices,
        counts: Some(PushCounts {
            badge: Some(PushCountIndicator::Bucket("2-5".to_owned())),
            unread_increment: Some(2),
            missed_call: Some(PushCountIndicator::Present(true)),
        }),
        ..Default::default()
    }
}
