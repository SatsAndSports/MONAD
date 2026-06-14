//! In-memory channel store for the relay-side payment layer.
//!
//! This module owns the canonical per-channel state: funding, latest payment,
//! open/closing/closed state, raw capacity, unit, and per-session ownership.
//!
//! The `cdk_spilman` bridge host and the `RelayPayments` implementation both
//! delegate state access to `ChannelStore` so that mutations stay explicit and
//! testable rather than being scattered across bridge callbacks.

use crate::payments::ChannelUnit;
use cdk_spilman::{ChannelFunding, ChannelState, ClosingData, PaymentProof};
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
    pub(crate) owner: Option<[u8; 32]>,
}

#[derive(Debug, Default)]
pub(crate) struct StoredState {
    pub(crate) channels: HashMap<String, StoredChannel>,
}

#[derive(Clone)]
pub(crate) struct ChannelStore {
    inner: Arc<Mutex<StoredState>>,
}

impl fmt::Debug for ChannelStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelStore").finish_non_exhaustive()
    }
}

impl ChannelStore {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StoredState::default())),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, StoredState>, String> {
        self.inner
            .lock()
            .map_err(|_| "channel store mutex poisoned".to_string())
    }

    pub(crate) fn save_funding(
        &self,
        channel_id: &str,
        funding: ChannelFunding,
        initial_payment: PaymentProof,
        unit: ChannelUnit,
        capacity_raw: u64,
    ) -> Result<(), String> {
        let mut state = self.lock()?;
        state.channels.insert(
            channel_id.to_string(),
            StoredChannel {
                funding,
                latest_payment: initial_payment,
                state: ChannelState::Open,
                closing_data: None,
                unit,
                capacity_raw,
                owner: None,
            },
        );
        Ok(())
    }

    pub(crate) fn get_channel(&self, channel_id: &str) -> Option<StoredChannel> {
        self.lock().ok()?.channels.get(channel_id).cloned()
    }

    pub(crate) fn record_payment(
        &self,
        channel_id: &str,
        payment: PaymentProof,
    ) -> Result<(), String> {
        let mut state = self.lock()?;
        let channel = state
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| format!("unknown channel: {channel_id}"))?;
        channel.latest_payment = payment;
        Ok(())
    }

    /// Set the owner of a channel to `session_id`. Returns the previous owner
    /// if it was a different session (i.e. an eviction).
    pub(crate) fn set_channel_owner(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<Option<[u8; 32]>, String> {
        let mut state = self.lock()?;
        let channel = state
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| format!("unknown channel: {channel_id}"))?;
        let evicted = match channel.owner {
            Some(owner) if owner != session_id => Some(owner),
            _ => None,
        };
        channel.owner = Some(session_id);
        Ok(evicted)
    }

    pub(crate) fn release_channel_owner(
        &self,
        channel_id: &str,
        session_id: [u8; 32],
    ) -> Result<(), String> {
        let mut state = self.lock()?;
        if let Some(channel) = state.channels.get_mut(channel_id) {
            if channel.owner == Some(session_id) {
                channel.owner = None;
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
        let mut state = self.lock()?;
        let channel = state
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| format!("unknown channel: {channel_id}"))?;
        channel.state = ChannelState::Closing;
        channel.closing_data = Some(ClosingData {
            expiry_timestamp,
            balance: payment.balance,
            signature: payment.signature,
        });
        Ok(())
    }

    pub(crate) fn mark_channel_closed(&self, channel_id: &str) -> Result<(), String> {
        let mut state = self.lock()?;
        let channel = state
            .channels
            .get_mut(channel_id)
            .ok_or_else(|| format!("unknown channel: {channel_id}"))?;
        channel.state = ChannelState::Closed;
        channel.closing_data = None;
        Ok(())
    }

    pub(crate) fn linked_channel_status(&self, channel_id: &str) -> Option<LinkedChannelStatus> {
        let state = self.lock().ok()?;
        let channel = state.channels.get(channel_id)?;
        Some(LinkedChannelStatus {
            channel_id: channel_id.to_string(),
            balance_raw: channel.latest_payment.balance,
            capacity_raw: channel.capacity_raw,
            unit: channel.unit.as_str().to_string(),
        })
    }
}
