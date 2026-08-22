use std::sync::Arc;

use crate::deactivation::{
    AccountDeactivateFanoutAck, AccountDeactivateFanoutBroadcast, DeactivationLedger,
};

#[derive(Debug, Clone)]
pub struct InProcessBroadcastBus {
    deactivation_ledger: Option<Arc<DeactivationLedger>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastError {
    DeactivationLedgerUnavailable,
    WorkerJoinFailed,
}

impl BroadcastError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::DeactivationLedgerUnavailable => {
                "deactivation ledger is not configured on this push gateway"
            }
            Self::WorkerJoinFailed => "background broadcast worker failed",
        }
    }
}

impl InProcessBroadcastBus {
    pub fn new(deactivation_ledger: Option<Arc<DeactivationLedger>>) -> Self {
        Self {
            deactivation_ledger,
        }
    }

    pub fn account_deactivate_fanout(
        &self,
        broadcast: &AccountDeactivateFanoutBroadcast,
    ) -> Result<AccountDeactivateFanoutAck, BroadcastError> {
        let Some(ledger) = self.deactivation_ledger.as_ref() else {
            return Err(BroadcastError::DeactivationLedgerUnavailable);
        };
        let result = ledger.record_fanout(broadcast);
        Ok(AccountDeactivateFanoutAck {
            fanout_id: broadcast.fanout_id.clone(),
            outcome: result.outcome,
            actor_bindings_unbound: result.actor_bindings_unbound,
            device_bindings_unbound: result.device_bindings_unbound,
            messages_drained: result.messages_drained,
        })
    }

    pub async fn account_deactivate_fanout_async(
        self: &Arc<Self>,
        broadcast: &AccountDeactivateFanoutBroadcast,
    ) -> Result<AccountDeactivateFanoutAck, BroadcastError> {
        let bus = Arc::clone(self);
        let broadcast = broadcast.clone();
        tokio::task::spawn_blocking(move || bus.account_deactivate_fanout(&broadcast))
            .await
            .unwrap_or(Err(BroadcastError::WorkerJoinFailed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deactivation::DeactivateFanoutDevice;

    #[test]
    fn bus_processes_deactivation_fanout() {
        let ledger = Arc::new(DeactivationLedger::new());
        let bus = InProcessBroadcastBus::new(Some(ledger));
        let ack = bus
            .account_deactivate_fanout(&AccountDeactivateFanoutBroadcast {
                fanout_id: "fanout-1".to_owned(),
                actor_id: "did:web:alice.example".to_owned(),
                devices: vec![DeactivateFanoutDevice {
                    device_id: "device-a".to_owned(),
                    push_key_hash: None,
                }],
                reason: None,
            })
            .unwrap();
        assert_eq!(ack.messages_drained, 0);
        assert_eq!(ack.device_bindings_unbound, 1);
    }
}
