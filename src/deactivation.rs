//! Round R2/R3 (T07) — account deactivation fanout integration.
//!
//! soland broadcasts an `account_deactivate_fanout` event to every
//! downstream service-bound subscriber when a Principal Server starts
//! tearing down a principal's footprint. floria receives the broadcast,
//! drains every queued to-device push for the affected
//! `(actor, device)` cells, then reports the fanout outcome back to
//! soland so soland can advance its own
//! `ck.account.deactivate.fanout_state` machine.
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
//! (e.g. the queue subsystem is unreachable during the drain).
//!
//! When configured with PostgreSQL, floria drains the local
//! `storage.deactivation_queue_table` by deleting queued rows for the
//! actor, optionally narrowed to the broadcast's device ids /
//! push-key hashes. The expected table columns are:
//! `actor_id text`, `device_id text`, and `push_key_hash text`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use postgres::NoTls;
use postgres::types::ToSql;
use serde::{Deserialize, Serialize};

use crate::auth::redact_url_credentials;
use crate::postgres_support::SqlTableName;

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
    pub actor_id: String,
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
/// Mirrors soland's `ck.account.deactivate.fanout_state` enum.
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

pub trait DeactivationQueueDrain: std::fmt::Debug + Send + Sync {
    fn drain(&self, broadcast: &AccountDeactivateFanoutBroadcast) -> Result<usize>;
}

#[derive(Debug, Clone)]
pub struct PostgresDeactivationQueueDrain {
    postgres_url: String,
    table: SqlTableName,
    target_label: String,
}

impl PostgresDeactivationQueueDrain {
    pub fn new(postgres_url: impl Into<String>, table: impl AsRef<str>) -> Result<Self> {
        let postgres_url = postgres_url.into();
        let table = SqlTableName::parse(table.as_ref(), "storage.deactivation_queue_table")?;
        Ok(Self {
            target_label: redact_url_credentials(&postgres_url),
            postgres_url,
            table,
        })
    }

    fn connect(&self) -> Result<postgres::Client> {
        postgres::Client::connect(&self.postgres_url, NoTls).with_context(|| {
            format!(
                "failed to connect to PostgreSQL deactivation queue {}",
                self.target_label
            )
        })
    }
}

impl DeactivationQueueDrain for PostgresDeactivationQueueDrain {
    fn drain(&self, broadcast: &AccountDeactivateFanoutBroadcast) -> Result<usize> {
        let mut client = self.connect()?;
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&broadcast.actor_id];
        let sql = if broadcast.devices.is_empty() {
            format!("DELETE FROM {} WHERE actor_id = $1", self.table.as_sql())
        } else {
            let mut clauses = Vec::new();
            for device in &broadcast.devices {
                let index = params.len() + 1;
                clauses.push(format!("device_id = ${index}"));
                params.push(&device.device_id);
                if let Some(push_key_hash) = device
                    .push_key_hash
                    .as_ref()
                    .filter(|value| !value.trim().is_empty())
                {
                    let index = params.len() + 1;
                    clauses.push(format!("push_key_hash = ${index}"));
                    params.push(push_key_hash);
                }
            }
            format!(
                "DELETE FROM {} WHERE actor_id = $1 AND ({})",
                self.table.as_sql(),
                clauses.join(" OR ")
            )
        };
        client
            .execute(&sql, &params)
            .with_context(|| {
                format!(
                    "failed to drain deactivation queue table {}",
                    self.table.as_sql()
                )
            })
            .map(|count| count as usize)
    }
}

/// Idempotent in-memory ledger of which fanouts we've already handled.
///
/// Keyed by `(fanout_id)` since soland guarantees that id is stable
/// across retries.
pub struct DeactivationLedger {
    inner: Mutex<DeactivationLedgerInner>,
    queue_drain: Option<Arc<dyn DeactivationQueueDrain>>,
}

impl std::fmt::Debug for DeactivationLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeactivationLedger")
            .field("inner", &self.inner)
            .field("queue_drain", &self.queue_drain.is_some())
            .finish()
    }
}

impl Default for DeactivationLedger {
    fn default() -> Self {
        Self {
            inner: Mutex::new(DeactivationLedgerInner::default()),
            queue_drain: None,
        }
    }
}

#[derive(Debug, Default)]
struct DeactivationLedgerInner {
    /// fanout_id -> first-seen result
    seen: HashMap<String, DeactivationFanoutResult>,
    /// Set of (actor_id, device_id) bindings the ledger knows are
    /// unbound. Used so a retry of the same fanout doesn't re-count
    /// devices that were already torn down.
    unbound_devices: HashSet<(String, String)>,
    /// Set of actor_id values whose actor-level binding has been
    /// torn down.
    unbound_actors: HashSet<String>,
    /// Set of (actor_id, device_id) bindings whose underlying push
    /// channel is sealed (provider rejected the token previously).
    /// Populated by [`DeactivationLedger::mark_channel_sealed`].
    sealed: HashSet<(String, String)>,
}

impl DeactivationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_queue_drain(queue_drain: Arc<dyn DeactivationQueueDrain>) -> Self {
        Self {
            inner: Mutex::new(DeactivationLedgerInner::default()),
            queue_drain: Some(queue_drain),
        }
    }

    /// Mark a channel as sealed so a subsequent fanout for the same
    /// `(actor, device)` reports the cell as drained-via-sealed rather
    /// than partially completed.
    pub fn mark_channel_sealed(&self, actor_id: &str, device_id: &str) {
        let mut inner = self.inner.lock().expect("deactivation ledger poisoned");
        inner
            .sealed
            .insert((actor_id.to_owned(), device_id.to_owned()));
    }

    /// Process a fanout broadcast. Idempotent: a retry with the same
    /// `fanout_id` returns the recorded result without double-counting.
    pub fn record_fanout(
        &self,
        broadcast: &AccountDeactivateFanoutBroadcast,
    ) -> DeactivationFanoutResult {
        {
            let inner = self.inner.lock().expect("deactivation ledger poisoned");
            if let Some(prior) = inner.seen.get(&broadcast.fanout_id) {
                return prior.clone();
            }
        }

        let drain_result = self
            .queue_drain
            .as_ref()
            .map(|drain| drain.drain(broadcast));
        let mut inner = self.inner.lock().expect("deactivation ledger poisoned");

        if let Some(prior) = inner.seen.get(&broadcast.fanout_id) {
            return prior.clone();
        }

        let mut device_bindings_unbound: usize = 0;
        let mut sealed_channels: usize = 0;
        let mut observed_at_least_one_cell = false;

        for device in &broadcast.devices {
            observed_at_least_one_cell = true;
            let key = (broadcast.actor_id.clone(), device.device_id.clone());
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
        let actor_bindings_unbound = if inner.unbound_actors.insert(broadcast.actor_id.clone()) {
            1
        } else {
            0
        };

        let (messages_drained, drain_failed) = match drain_result {
            Some(Ok(count)) => (count, false),
            Some(Err(error)) => {
                tracing::warn!(
                    error = %error,
                    fanout_id = %broadcast.fanout_id,
                    actor_id = %broadcast.actor_id,
                    "deactivation queue drain failed"
                );
                (0, true)
            }
            None => (0, false),
        };

        let outcome = if drain_failed {
            DeactivateFanoutOutcome::PartiallyCompleted
        } else if !observed_at_least_one_cell && actor_bindings_unbound == 0 {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestDrain {
        result: Result<usize>,
    }

    impl DeactivationQueueDrain for TestDrain {
        fn drain(&self, _broadcast: &AccountDeactivateFanoutBroadcast) -> Result<usize> {
            match &self.result {
                Ok(count) => Ok(*count),
                Err(error) => Err(anyhow::anyhow!(error.to_string())),
            }
        }
    }

    fn broadcast(
        fanout_id: &str,
        actor: &str,
        devices: &[&str],
    ) -> AccountDeactivateFanoutBroadcast {
        AccountDeactivateFanoutBroadcast {
            fanout_id: fanout_id.to_owned(),
            actor_id: actor.to_owned(),
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
    fn ledger_reports_drained_message_count_from_queue_drain() {
        let ledger = DeactivationLedger::with_queue_drain(Arc::new(TestDrain { result: Ok(3) }));
        let result = ledger.record_fanout(&broadcast(
            "fanout-1",
            "did:web:alice.example",
            &["device-a"],
        ));
        assert_eq!(result.outcome, DeactivateFanoutOutcome::Completed);
        assert_eq!(result.messages_drained, 3);
    }

    #[test]
    fn ledger_reports_partial_when_queue_drain_fails() {
        let ledger = DeactivationLedger::with_queue_drain(Arc::new(TestDrain {
            result: Err(anyhow::anyhow!("queue unavailable")),
        }));
        let result = ledger.record_fanout(&broadcast(
            "fanout-1",
            "did:web:alice.example",
            &["device-a"],
        ));
        assert_eq!(result.outcome, DeactivateFanoutOutcome::PartiallyCompleted);
        assert_eq!(result.messages_drained, 0);
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
}
