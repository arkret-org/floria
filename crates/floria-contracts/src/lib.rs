//! Wire contract for floria's private internal account-lifecycle endpoints.
//!
//! `/_floria/internal/*` is an implementation-private (non-`ak.`) rail between
//! a Principal Server (soland) and the floria push gateway. Per the
//! account-lifecycle spec §7.1 "Push route 行的完成判据", the Principal Server
//! MUST notify the gateway over a registered internal channel and obtain a
//! processing result before the Push-route fanout row counts as complete.
//! This crate is that channel's audited contract: both sides depend on these
//! exact types instead of re-declaring the JSON shape by hand.
//!
//! Endpoint: `POST /_floria/internal/account_deactivate_fanout`
//! (see [`ACCOUNT_DEACTIVATE_FANOUT_PATH`]), protected by floria's
//! `http.internal_auth` bearer profile.
//!
//! Compatibility rules:
//! - The request ([`AccountDeactivateFanoutBroadcast`]) is `deny_unknown_fields`: the consumer
//!   (floria) fails closed on producer drift, so new request fields require a coordinated release.
//! - The response ([`AccountDeactivateFanoutAck`]) intentionally tolerates unknown fields on the
//!   consumer (soland) side, so the gateway may add ack fields without breaking older producers.

use serde::{Deserialize, Serialize};

/// Route of the internal deactivation fanout endpoint on the push gateway.
pub const ACCOUNT_DEACTIVATE_FANOUT_PATH: &str = "/_floria/internal/account_deactivate_fanout";

/// Broadcast envelope the Principal Server sends to every push gateway when a
/// deactivation fanout starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeactivateFanoutBroadcast {
    /// Stable id the producer uses to deduplicate retries. Echoed back in
    /// the ack response. The gateway records the first-seen result per
    /// `fanout_id`, so a replay returns the recorded result unchanged; a
    /// re-evaluation after a `partially_completed` ack requires a fresh id.
    pub fanout_id: String,
    /// DID of the principal whose footprint is being torn down. floria
    /// never learns realm contents — only the actor identity.
    pub actor_id: String,
    /// Per-device unbind targets. Empty list means "every device for
    /// this actor"; floria still answers honestly about how many cells
    /// it saw.
    #[serde(default)]
    pub devices: Vec<DeactivateFanoutDevice>,
    /// Optional producer-supplied reason — purely diagnostic, not echoed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One per-device unbind target inside [`AccountDeactivateFanoutBroadcast`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeactivateFanoutDevice {
    pub device_id: String,
    /// Optional explicit push_key_hash hint so floria can match an
    /// unbind target faster when the actor has many cells. The hint is
    /// validated as a `pkh_*` shape; bare push tokens are NEVER carried
    /// across this hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_key_hash: Option<String>,
}

/// Outcome a push gateway reports back to the Principal Server for a fanout.
///
/// `partially_completed` is reserved for the case where floria observed at
/// least one cell it could not drain (e.g. queue subsystem momentarily
/// unavailable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeactivateFanoutOutcome {
    Completed,
    PartiallyCompleted,
    /// The producer is permitted to retry the broadcast; floria saw nothing
    /// to do for the requested actor.
    NoOp,
}

impl DeactivateFanoutOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::PartiallyCompleted => "partially_completed",
            Self::NoOp => "no_op",
        }
    }
}

/// Ack response floria emits back to the Principal Server after processing a
/// deactivation fanout. Carries an honest accounting of what was touched so
/// the producer's fanout-state machine can step forward.
///
/// Deliberately **not** `deny_unknown_fields`: the gateway may grow ack
/// fields, and the producer must keep accepting older-known shapes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountDeactivateFanoutAck {
    pub fanout_id: String,
    pub outcome: DeactivateFanoutOutcome,
    /// Number of per-actor bindings unbound (typically 1; can be > 1
    /// if the same actor had multiple service-bound bindings).
    pub actor_bindings_unbound: usize,
    /// Number of per-device bindings unbound.
    pub device_bindings_unbound: usize,
    /// Number of queued to-device messages drained as part of the
    /// unbind.
    pub messages_drained: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_wire_shape_round_trips() {
        let wire = serde_json::json!({
            "fanout_id": "fanout-1",
            "actor_id": "did:web:alice.example",
            "devices": [
                {"device_id": "device-a", "push_key_hash": "pkh_0123456789ab"},
                {"device_id": "device-b"}
            ],
            "reason": "admin_deactivation"
        });
        let broadcast: AccountDeactivateFanoutBroadcast =
            serde_json::from_value(wire.clone()).expect("broadcast parses");
        assert_eq!(broadcast.fanout_id, "fanout-1");
        assert_eq!(broadcast.devices.len(), 2);
        assert_eq!(
            broadcast.devices[0].push_key_hash.as_deref(),
            Some("pkh_0123456789ab")
        );
        let back = serde_json::to_value(&broadcast).expect("broadcast serializes");
        assert_eq!(back, wire);
    }

    #[test]
    fn broadcast_defaults_devices_and_reason() {
        let broadcast: AccountDeactivateFanoutBroadcast = serde_json::from_value(
            serde_json::json!({"fanout_id": "fanout-1", "actor_id": "did:web:alice.example"}),
        )
        .expect("minimal broadcast parses");
        assert!(broadcast.devices.is_empty());
        assert!(broadcast.reason.is_none());
    }

    #[test]
    fn broadcast_rejects_unknown_fields() {
        let result =
            serde_json::from_value::<AccountDeactivateFanoutBroadcast>(serde_json::json!({
                "fanout_id": "fanout-1",
                "actor_id": "did:web:alice.example",
                "surprise": true
            }));
        assert!(result.is_err(), "unknown request field must fail closed");
    }

    #[test]
    fn outcome_tokens_are_pinned() {
        for (outcome, token) in [
            (DeactivateFanoutOutcome::Completed, "completed"),
            (
                DeactivateFanoutOutcome::PartiallyCompleted,
                "partially_completed",
            ),
            (DeactivateFanoutOutcome::NoOp, "no_op"),
        ] {
            assert_eq!(outcome.as_str(), token);
            assert_eq!(
                serde_json::to_value(outcome).expect("serializes"),
                serde_json::json!(token)
            );
            let back: DeactivateFanoutOutcome =
                serde_json::from_value(serde_json::json!(token)).expect("parses");
            assert_eq!(back, outcome);
        }
    }

    #[test]
    fn ack_round_trips_and_tolerates_unknown_fields() {
        let ack: AccountDeactivateFanoutAck = serde_json::from_value(serde_json::json!({
            "fanout_id": "fanout-1",
            "outcome": "completed",
            "actor_bindings_unbound": 1,
            "device_bindings_unbound": 2,
            "messages_drained": 3,
            "future_field": {"ignored": true}
        }))
        .expect("ack with unknown fields parses");
        assert_eq!(ack.outcome, DeactivateFanoutOutcome::Completed);
        assert_eq!(ack.messages_drained, 3);
        let wire = serde_json::to_value(&ack).expect("ack serializes");
        assert_eq!(wire["outcome"], serde_json::json!("completed"));
        assert_eq!(wire["device_bindings_unbound"], serde_json::json!(2));
    }
}
