//! Persistent channel store for the relay-side payment layer.
//!
//! This module owns the canonical per-channel state on top of a
//! `cdk_spilman::SpilmanStorage` backend. Funding, balance, and lifecycle
//! state are durable; per-session ownership stays in memory because it is
//! tied to live H2 connections and is naturally released on restart.
//!
//! The `cdk_spilman` bridge host and the `RelayPayments` implementation both
//! delegate state access to `ChannelStore` so that mutations stay explicit and
//! testable rather than being scattered across bridge callbacks.

use crate::payments::ChannelUnit;
use cdk_spilman::{
    configurable_host::{ClosedDataView, SpilmanStorage},
    ChannelFunding, ChannelState, ClosingData, PaymentProof,
};
use monad_common::protocol::LinkedChannelStatus;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub(crate) struct StoredChannel {
    pub(crate) funding: ChannelFunding,
    pub(crate) latest_payment: PaymentProof,
    pub(crate) state: ChannelState,
    pub(crate) closing_data: Option<ClosingData>,
    pub(crate) unit: ChannelUnit,
    pub(crate) capacity_raw: u64,
}

#[derive(Debug, Default)]
pub(crate) struct OwnershipState {
    owners: HashMap<String, Option<[u8; 32]>>,
}

#[derive(Clone)]
pub(crate) struct ChannelStore {
    storage: Arc<dyn SpilmanStorage>,
    ownership: Arc<Mutex<OwnershipState>>,
}

impl fmt::Debug for ChannelStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelStore").finish_non_exhaustive()
    }
}

impl ChannelStore {
    pub(crate) fn new(storage: Arc<dyn SpilmanStorage>) -> Self {
        Self {
            storage,
            ownership: Arc::new(Mutex::new(OwnershipState::default())),
        }
    }

    fn ownership_lock(&self) -> Result<std::sync::MutexGuard<'_, OwnershipState>, String> {
        self.ownership
            .lock()
            .map_err(|_| "channel store ownership mutex poisoned".to_string())
    }

    pub(crate) fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
    ) -> Result<(), String> {
        self.storage.save_funding(channel_id, funding)?;
        // SqliteStorage::save_funding only stores the funding payload; the
        // initial payment proof must be stored separately so that later
        // get_balance calls return a real balance + signature.
        self.storage.update_balance(channel_id, initial_payment)?;
        Ok(())
    }

    pub(crate) fn get_channel(&self, channel_id: &str) -> Result<Option<StoredChannel>, String> {
        let funding = match self.storage.get_funding(channel_id) {
            Some(f) => f,
            None => return Ok(None),
        };

        let metadata = parse_channel_metadata(&funding.params_json)
            .map_err(|e| format!("corrupt stored channel params for {channel_id}: {e}"))?;

        let latest_payment = self
            .storage
            .get_balance(channel_id)
            .unwrap_or(PaymentProof {
                balance: 0,
                signature: String::new(),
            });

        let state = self.storage.get_state(channel_id);
        let closing_data = self.storage.get_closing_data(channel_id);

        Ok(Some(StoredChannel {
            funding,
            latest_payment,
            state,
            closing_data,
            unit: metadata.0,
            capacity_raw: metadata.1,
        }))
    }

    pub(crate) fn record_payment(
        &self,
        channel_id: &str,
        payment: PaymentProof,
    ) -> Result<(), String> {
        self.storage.update_balance(channel_id, payment)
    }

    /// Set the owner of a channel to `session_id`. Returns the previous owner
    /// if it was a different session (i.e. an eviction).
    pub(crate) fn set_channel_owner(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<Option<[u8; 32]>, String> {
        let mut ownership = self.ownership_lock()?;
        let evicted = match ownership.owners.get(channel_id).copied().flatten() {
            Some(owner) if owner != session_id => Some(owner),
            _ => None,
        };
        ownership
            .owners
            .insert(channel_id.to_string(), Some(session_id));
        Ok(evicted)
    }

    pub(crate) fn release_channel_owner(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), String> {
        let mut ownership = self.ownership_lock()?;
        if let Some(Some(owner)) = ownership.owners.get(channel_id) {
            if *owner == session_id {
                ownership.owners.insert(channel_id.to_string(), None);
            }
        }
        Ok(())
    }

    pub(crate) fn mark_channel_closing(
        &self,
        channel_id: &str,
        expiry_timestamp: u64,
        payment: PaymentProof,
    ) -> Result<(), String> {
        self.storage.mark_closing(
            channel_id,
            ClosingData {
                expiry_timestamp,
                balance: payment.balance,
                signature: payment.signature,
            },
        )
    }

    pub(crate) fn mark_channel_closed(
        &self,
        channel_id: &str,
        data: ClosedDataView,
    ) -> Result<(), String> {
        self.storage.mark_closed(channel_id, data)
    }

    pub(crate) fn channel_state(&self, channel_id: &str) -> Option<ChannelState> {
        Some(self.storage.get_state(channel_id))
    }

    pub(crate) fn closed_data(&self, channel_id: &str) -> Option<ClosedDataView> {
        self.storage.get_closed_data(channel_id)
    }

    pub(crate) fn linked_channel_status(&self, channel_id: &str) -> Option<LinkedChannelStatus> {
        let channel = self.get_channel(channel_id).ok()??;
        Some(LinkedChannelStatus {
            channel_id: channel_id.to_string(),
            balance_raw: channel.latest_payment.balance,
            capacity_raw: channel.capacity_raw,
            unit: channel.unit.as_str().to_string(),
        })
    }
}

fn parse_channel_metadata(params_json: &str) -> Result<(ChannelUnit, u64), String> {
    let params: serde_json::Value = serde_json::from_str(params_json)
        .map_err(|e| format!("invalid channel params json: {e}"))?;
    let unit = params["unit"]
        .as_str()
        .ok_or_else(|| "missing unit in stored params".to_string())?;
    let capacity = params["capacity"]
        .as_u64()
        .ok_or_else(|| "missing capacity in stored params".to_string())?;
    ChannelUnit::from_str(unit)
        .map(|unit| (unit, capacity))
        .map_err(|e| format!("unsupported unit: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk_spilman::configurable_host::SqliteStorage;
    use std::sync::Arc;

    fn dummy_funding(channel_id: &str) -> ChannelFunding {
        ChannelFunding {
            params_json: serde_json::json!({
                "channel_id": channel_id,
                "unit": "sat",
                "capacity": 100,
                "mint": "https://test.mint",
                "keyset_id": format!("00{channel_id}"),
                "receiver_pubkey": "0000000000000000000000000000000000000000000000000000000000000001",
                "sender_pubkey": "0000000000000000000000000000000000000000000000000000000000000002",
            })
            .to_string(),
            funding_proofs_json: "[]".to_string(),
            channel_secret_hex: "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            keyset_info_json: "{}".to_string(),
        }
    }

    fn payment_proof(balance: u64) -> PaymentProof {
        PaymentProof {
            balance,
            signature: "sig".to_string(),
        }
    }

    #[test]
    fn channel_state_survives_sqlite_reopen() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let path = temp.path().to_str().unwrap().to_string();

        // First store instance: fund and pay.
        {
            let storage = Arc::new(SqliteStorage::open(&path).unwrap());
            let store = ChannelStore::new(storage);
            store
                .save_funding("chan1", dummy_funding("chan1"), payment_proof(0))
                .unwrap();
            store.record_payment("chan1", payment_proof(5_000)).unwrap();

            let channel = store.get_channel("chan1").unwrap().unwrap();
            assert_eq!(channel.latest_payment.balance, 5_000);
            assert_eq!(channel.unit, ChannelUnit::Sat);
            assert_eq!(channel.capacity_raw, 100);
        }

        // Second store instance: read back from disk.
        {
            let storage = Arc::new(SqliteStorage::open(&path).unwrap());
            let store = ChannelStore::new(storage);
            let channel = store.get_channel("chan1").unwrap().unwrap();
            assert_eq!(channel.latest_payment.balance, 5_000);
            assert_eq!(channel.unit, ChannelUnit::Sat);
            assert_eq!(channel.capacity_raw, 100);
        }
    }
}
