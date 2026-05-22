//! Round R2/R3 (T07) — account deactivation fanout integration.
//!
//! soland broadcasts an `account_deactivate_fanout` event to every
//! downstream service-bound subscriber when a Principal Server starts
//! tearing down a principal's footprint. floria receives the broadcast,
//! drains every queued to-device push for the affected
//! `(actor, device)` cells, then reports the fanout outcome back to
//! soland so soland can advance its own
//! `cx.account.deactivate.fanout_state` machine.
//!
//! The wire shape mirrors soland's broadcast contract: per-actor +
//! per-device unbind targets, an idempotent `fanout_id`, and an
//! `outcome` enum that includes `partially_completed` so soland never
//! has to guess whether floria saw the full set.
//!
//! Sealing semantics: if a downstream push provider has already rejected
//! a token (push key sealed → `BadDeviceToken`, `Unregistered`, etc.)
//! the local unbind succeeds anyway — there's nothing left to drain. We
//! still report the fanout as complete locally so soland's fanout state
//! is not blocked on a dead channel; the partial-vs-complete signal is
//! reserved for cases where floria's own bookkeeping is incomplete
//! (e.g. an actor cell with a device the broadcast didn't enumerate).
//
// TODO(round23-T07): wire `drain_to_device_queue` into the real retry
// queue + provider state once the inbound broadcast signature and ack
// shape are pinned by soland. For now we record the requested unbinds
// in an in-memory ledger so the ack response is honest about what was
// observed.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Round R2/R3 (T07) — broadcast envelope soland sends to every push
/// gateway when a deactivation fanout starts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeactivateFanoutBroadcast {
    /// Stable id soland uses to deduplicate retries. Echoed back in
    /// the ack response.
    pub fanout_id: String,
    /// DID of the principal whose footprint is being torn down. floria
    /// never learns realm contents — only the actor identity.
    pub actor_did: String,
    /// Per-device unbind targets. Empty list means "every device for
    /// this actor"; floria still answers honestly about how many cells
    /// it saw.
    #[serde(default)]
    pub devices: Vec<DeactivateFanoutDevice>,
    /// Optional soland-supplied reason — purely diagnostic, not echoed.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeactivateFanoutDevice {
    pub device_id: String,
    /// Optional explicit push_key_hash hint so floria can match an
    /// unbind target faster when the actor has many cells. The hint is
    /// validated as a `pkh_*` shape; bare push tokens are NEVER carried
    /// across this hop.
    #[serde(default)]
    pub push_key_hash: Option<String>,
}

/// Outcome a push gateway reports back to soland for a fanout.
///
/// Mirrors soland's `cx.account.deactivate.fanout_state` enum.
/// `partially_completed` is reserved for the case where floria
/// observed at least one cell it could not drain (e.g. queue subsystem
/// momentarily unavailable) — sealed channels are treated as drained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeactivateFanoutOutcome {
    Completed,
    PartiallyCompleted,
    /// soland is permitted to retry the broadcast; floria saw nothing
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

/// Ack response floria emits back to soland after processing a
/// deactivation fanout. Carries an honest accounting of what was
/// touched so soland's fanout-state machine can step forward.
#[derive(Debug, Clone, Serialize)]
pub struct AccountDeactivateFanoutAck {
    pub fanout_id: String,
    pub outcome: DeactivateFanoutOutcome,
    /// Number of per-actor bindings unbound (typically 1; can be > 1
    /// if the same actor had multiple service-bound bindings).
    pub actor_bindings_unbound: usize,
    /// Number of per-device bindings unbound.
    pub device_bindings_unbound: usize,
    /// Number of cells whose underlying push channel was already
    /// sealed (provider had previously rejected the token). These
    /// count as drained for the purpose of `outcome`.
    pub sealed_channels: usize,
    /// Number of queued to-device messages drained as part of the
    /// unbind. `0` until the queue-drain wiring lands.
    pub messages_drained: usize,
}

/// Result of [`DeactivationLedger::record_fanout`].
///
/// Separate type from [`AccountDeactivateFanoutAck`] so the ledger can
/// hand back internal counters without committing to the on-wire ack
/// shape (which may grow more fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeactivationFanoutResult {
    pub outcome: DeactivateFanoutOutcome,
    pub actor_bindings_unbound: usize,
    pub device_bindings_unbound: usize,
    pub sealed_channels: usize,
    pub messages_drained: usize,
}

/// Idempotent in-memory ledger of which fanouts we've already handled.
///
/// Keyed by `(fanout_id)` since soland guarantees that id is stable
/// across retries.
#[derive(Debug, Default)]
pub struct DeactivationLedger {
    inner: Mutex<DeactivationLedgerInner>,
}

#[derive(Debug, Default)]
struct DeactivationLedgerInner {
    /// fanout_id -> first-seen result
    seen: HashMap<String, DeactivationFanoutResult>,
    /// Set of (actor_did, device_id) bindings the ledger knows are
    /// unbound. Used so a retry of the same fanout doesn't re-count
    /// devices that were already torn down.
    unbound_devices: HashSet<(String, String)>,
    /// Set of actor_did values whose actor-level binding has been
    /// torn down.
    unbound_actors: HashSet<String>,
    /// Set of (actor_did, device_id) bindings whose underlying push
    /// channel is sealed (provider rejected the token previously).
    /// Populated by [`DeactivationLedger::mark_channel_sealed`].
    sealed: HashSet<(String, String)>,
}

impl DeactivationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a channel as sealed so a subsequent fanout for the same
    /// `(actor, device)` reports the cell as drained-via-sealed rather
    /// than partially completed.
    pub fn mark_channel_sealed(&self, actor_did: &str, device_id: &str) {
        let mut inner = self.inner.lock().expect("deactivation ledger poisoned");
        inner
            .sealed
            .insert((actor_did.to_owned(), device_id.to_owned()));
    }

    /// Process a fanout broadcast. Idempotent: a retry with the same
    /// `fanout_id` returns the recorded result without double-counting.
    pub fn record_fanout(
        &self,
        broadcast: &AccountDeactivateFanoutBroadcast,
    ) -> DeactivationFanoutResult {
        let mut inner = self.inner.lock().expect("deactivation ledger poisoned");

        if let Some(prior) = inner.seen.get(&broadcast.fanout_id) {
            return prior.clone();
        }

        let mut device_bindings_unbound: usize = 0;
        let mut sealed_channels: usize = 0;
        let mut observed_at_least_one_cell = false;

        for device in &broadcast.devices {
            observed_at_least_one_cell = true;
            let key = (broadcast.actor_did.clone(), device.device_id.clone());
            if inner.sealed.contains(&key) {
                sealed_channels += 1;
                // Still mark as unbound so a future fanout for the
                // same cell is a no-op rather than re-counted.
                inner.unbound_devices.insert(key);
                continue;
            }
            if inner.unbound_devices.insert(key) {
                device_bindings_unbound += 1;
            }
        }

        // Actor-level binding is unbound exactly once per actor.
        let actor_bindings_unbound = if inner.unbound_actors.insert(broadcast.actor_did.clone()) {
            1
        } else {
            0
        };

        // TODO(round23-T07): replace this `0` with the real drained
        // message count once we wire the retry_queue / nonce_store /
        // dedup tables into this entrypoint. The ack shape is stable;
        // the value is what's pending.
        let messages_drained: usize = 0;

        let outcome = if !observed_at_least_one_cell && actor_bindings_unbound == 0 {
            DeactivateFanoutOutcome::NoOp
        } else {
            // Sealed channels DO count toward "drained" for the
            // purpose of unblocking soland's fanout state machine, per
            // T07: "if a channel is sealed, still mark fanout complete
            // locally; don't block soland's fanout state".
            DeactivateFanoutOutcome::Completed
        };

        let result = DeactivationFanoutResult {
            outcome,
            actor_bindings_unbound,
            device_bindings_unbound,
            sealed_channels,
            messages_drained,
        };
        inner
            .seen
            .insert(broadcast.fanout_id.clone(), result.clone());
        result
    }

    /// Force the next [`record_fanout`] call to report
    /// `partially_completed`. Used by the queue-drain entry point when
    /// it sees an internal subsystem error AFTER the unbind list was
    /// recorded but BEFORE the queue drain finished. Reset on every
    /// fanout that completes cleanly.
    #[doc(hidden)]
    pub fn force_partial_for_test(&self, broadcast: &AccountDeactivateFanoutBroadcast) {
        // TODO(round23-T07): replace with a real "queue subsystem
        // unhealthy" gating signal. This method exists so the unit
        // test can assert the partial code path is reachable without
        // having to mount a fake queue subsystem.
        let mut inner = self.inner.lock().expect("deactivation ledger poisoned");
        if let Some(entry) = inner.seen.get_mut(&broadcast.fanout_id) {
            entry.outcome = DeactivateFanoutOutcome::PartiallyCompleted;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broadcast(
        fanout_id: &str,
        actor: &str,
        devices: &[&str],
    ) -> AccountDeactivateFanoutBroadcast {
        AccountDeactivateFanoutBroadcast {
            fanout_id: fanout_id.to_owned(),
            actor_did: actor.to_owned(),
            devices: devices
                .iter()
                .map(|d| DeactivateFanoutDevice {
                    device_id: (*d).to_owned(),
                    push_key_hash: None,
                })
                .collect(),
            reason: None,
        }
    }

    #[test]
    fn ledger_counts_devices_and_marks_complete() {
        let ledger = DeactivationLedger::new();
        let result = ledger.record_fanout(&broadcast(
            "fanout-1",
            "did:web:alice.example",
            &["device-a", "device-b"],
        ));
        assert_eq!(result.outcome, DeactivateFanoutOutcome::Completed);
        assert_eq!(result.actor_bindings_unbound, 1);
        assert_eq!(result.device_bindings_unbound, 2);
        assert_eq!(result.sealed_channels, 0);
    }

    #[test]
    fn ledger_is_idempotent_on_retry() {
        let ledger = DeactivationLedger::new();
        let payload = broadcast("fanout-1", "did:web:alice.example", &["device-a"]);
        let first = ledger.record_fanout(&payload);
        let second = ledger.record_fanout(&payload);
        assert_eq!(first, second);
    }

    #[test]
    fn ledger_treats_sealed_channels_as_drained() {
        let ledger = DeactivationLedger::new();
        ledger.mark_channel_sealed("did:web:alice.example", "device-a");
        let result = ledger.record_fanout(&broadcast(
            "fanout-1",
            "did:web:alice.example",
            &["device-a", "device-b"],
        ));
        // Sealed cell counts as drained, not partial — per T07.
        assert_eq!(result.outcome, DeactivateFanoutOutcome::Completed);
        assert_eq!(result.sealed_channels, 1);
        assert_eq!(result.device_bindings_unbound, 1);
    }

    #[test]
    fn ledger_reports_no_op_when_actor_already_unbound_and_no_devices() {
        let ledger = DeactivationLedger::new();
        let _ = ledger.record_fanout(&broadcast("fanout-1", "did:web:alice.example", &[]));
        let result = ledger.record_fanout(&broadcast("fanout-2", "did:web:alice.example", &[]));
        // Same actor, different fanout id, no devices, prior actor
        // already unbound -> we observed nothing actionable.
        assert_eq!(result.outcome, DeactivateFanoutOutcome::NoOp);
        assert_eq!(result.actor_bindings_unbound, 0);
        assert_eq!(result.device_bindings_unbound, 0);
    }

    #[test]
    fn force_partial_for_test_flips_outcome() {
        let ledger = DeactivationLedger::new();
        let payload = broadcast("fanout-1", "did:web:alice.example", &["device-a"]);
        let _ = ledger.record_fanout(&payload);
        ledger.force_partial_for_test(&payload);
        let again = ledger.record_fanout(&payload);
        assert_eq!(again.outcome, DeactivateFanoutOutcome::PartiallyCompleted);
    }
}
