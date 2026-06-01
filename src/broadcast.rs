use std::sync::Arc;

use serde::Serialize;

use crate::deactivation::{
    AccountDeactivateFanoutAck, AccountDeactivateFanoutBroadcast, DeactivationLedger,
};
use crate::push_contact_cache::{ConsentRevokeBroadcast, PushContactCache};

#[derive(Debug, Clone)]
pub struct InProcessBroadcastBus {
    deactivation_ledger: Option<Arc<DeactivationLedger>>,
    push_contact_cache: Option<Arc<PushContactCache>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BroadcastError {
    DeactivationLedgerUnavailable,
    PushContactCacheUnavailable,
}

impl BroadcastError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::DeactivationLedgerUnavailable => {
                "deactivation ledger is not configured on this push gateway"
            }
            Self::PushContactCacheUnavailable => {
                "push contact cache is not configured on this push gateway"
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ConsentRevokeAck {
    pub broadcast_id: String,
    pub scope: &'static str,
    pub entries_evicted: usize,
}

impl InProcessBroadcastBus {
    pub fn new(
        deactivation_ledger: Option<Arc<DeactivationLedger>>,
        push_contact_cache: Option<Arc<PushContactCache>>,
    ) -> Self {
        Self {
            deactivation_ledger,
            push_contact_cache,
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
            sealed_channels: result.sealed_channels,
            messages_drained: result.messages_drained,
        })
    }

    pub fn consent_revoke(
        &self,
        broadcast: &ConsentRevokeBroadcast,
    ) -> Result<ConsentRevokeAck, BroadcastError> {
        let Some(cache) = self.push_contact_cache.as_ref() else {
            return Err(BroadcastError::PushContactCacheUnavailable);
        };
        Ok(ConsentRevokeAck {
            broadcast_id: broadcast.broadcast_id.clone(),
            scope: ConsentRevokeBroadcast::SUPPORTED_SCOPE,
            entries_evicted: cache.invalidate_principal(&broadcast.principal_id),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deactivation::DeactivateFanoutDevice;
    use crate::push_contact_cache::PsiVerdict;

    #[test]
    fn bus_processes_deactivation_fanout() {
        let ledger = Arc::new(DeactivationLedger::new());
        let bus = InProcessBroadcastBus::new(Some(ledger), None);
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

    #[test]
    fn bus_processes_consent_revoke() {
        let cache = Arc::new(PushContactCache::in_memory());
        cache.insert("did:web:alice.example", "psi-1", PsiVerdict::Allowed);
        let bus = InProcessBroadcastBus::new(None, Some(cache));
        let ack = bus
            .consent_revoke(&ConsentRevokeBroadcast {
                broadcast_id: "bcast-1".to_owned(),
                principal_id: "did:web:alice.example".to_owned(),
                scope: "any".to_owned(),
                reason: None,
            })
            .unwrap();
        assert_eq!(ack.entries_evicted, 1);
    }
}
