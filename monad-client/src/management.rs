//! Process-local client controls. The payment driver remains the only funder.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ClientControls {
    pub enabled: bool,
    pub automatic_provisioning: bool,
}

impl Default for ClientControls {
    fn default() -> Self {
        Self {
            enabled: true,
            automatic_provisioning: true,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HopSnapshot {
    pub session_id: String,
    pub label: String,
    pub waiting_for_manual_funding: bool,
    pub waiting_for_relay_admission: bool,
    pub provisioning: bool,
    pub linked_channel: Option<monad_common::protocol::LinkedChannelStatus>,
    pub paused: bool,
    pub total_paid_msats: u64,
    pub remaining_msats: i64,
    pub funding_error: Option<String>,
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
}

/// A handle belongs to one configured client, not to its shared wallet.
#[derive(Debug)]
pub struct ClientManagement {
    controls: watch::Sender<ClientControls>,
    hops: Mutex<BTreeMap<String, Arc<HopManagement>>>,
    changed: watch::Sender<u64>,
    running: Mutex<bool>,
    pub events: monad_management::events::EventLog,
}

impl Default for ClientManagement {
    fn default() -> Self {
        Self {
            controls: watch::channel(ClientControls::default()).0,
            hops: Mutex::new(BTreeMap::new()),
            changed: watch::channel(0).0,
            running: Mutex::new(false),
            events: Default::default(),
        }
    }
}

impl ClientManagement {
    pub fn controls(&self) -> ClientControls {
        *self.controls.borrow()
    }

    pub fn set_automatic_provisioning(&self, enabled: bool) {
        self.controls
            .send_modify(|c| c.automatic_provisioning = enabled);
        self.notify();
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<(), &'static str> {
        let running = self.running.lock().unwrap();
        if enabled && !self.controls().enabled && *running {
            return Err("client is still disabling");
        }
        self.controls.send_modify(|c| c.enabled = enabled);
        self.notify();
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        *self.running.lock().unwrap()
    }

    pub(crate) fn begin_run(&self) -> bool {
        let mut running = self.running.lock().unwrap();
        if !self.controls().enabled {
            return false;
        }
        assert!(
            !*running,
            "client management handle already has a runtime owner"
        );
        *running = true;
        true
    }

    pub(crate) fn finish_run(&self) {
        *self.running.lock().unwrap() = false;
        self.notify();
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<ClientControls> {
        self.controls.subscribe()
    }

    pub fn changes(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    pub(crate) fn notify(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn hops(&self) -> Vec<HopSnapshot> {
        self.hops
            .lock()
            .unwrap()
            .values()
            .map(|h| {
                let mut snapshot = h.state.lock().unwrap().snapshot.clone();
                let (inbound, outbound) = h.counters.lock().unwrap().snapshot();
                snapshot.inbound_bytes = inbound;
                snapshot.outbound_bytes = outbound;
                snapshot
            })
            .collect()
    }

    /// Session ID is the generation token. There is no transferable provisioning
    /// credit: requests for an old session cannot fund its replacement.
    pub fn provision_once(&self, session_id: &str) -> Result<(), &'static str> {
        let controls = self.controls.borrow();
        if !controls.enabled {
            return Err("client is disabled");
        }
        if controls.automatic_provisioning {
            return Err("automatic provisioning is enabled");
        }
        let hops = self.hops.lock().unwrap();
        let hop = hops.get(session_id).ok_or("session is no longer active")?;
        let mut state = hop.state.lock().unwrap();
        if state.manual_requested || state.snapshot.provisioning {
            return Err("provisioning is already in progress");
        }
        if !state.snapshot.waiting_for_manual_funding {
            return Err("session is not waiting for manual funding");
        }
        state.manual_requested = true;
        state.snapshot.funding_error = None;
        drop(state);
        drop(hops);
        drop(controls);
        self.notify();
        Ok(())
    }

    pub(crate) fn waiting_for_funding(&self, session_id: &str) -> bool {
        self.hops.lock().unwrap().get(session_id).is_some_and(|h| {
            let state = h.state.lock().unwrap();
            state.snapshot.waiting_for_manual_funding || state.snapshot.waiting_for_relay_admission
        })
    }

    pub(crate) fn register(self: &Arc<Self>, session_id: [u8; 32], label: &str) -> HopLease {
        let id = hex::encode(session_id);
        let hop = Arc::new(HopManagement {
            counters: Default::default(),
            state: Mutex::new(HopState {
                snapshot: HopSnapshot {
                    session_id: id.clone(),
                    label: label.to_owned(),
                    waiting_for_manual_funding: false,
                    waiting_for_relay_admission: false,
                    provisioning: false,
                    linked_channel: None,
                    paused: true,
                    total_paid_msats: 0,
                    remaining_msats: 0,
                    funding_error: None,
                    inbound_bytes: 0,
                    outbound_bytes: 0,
                },
                manual_requested: false,
            }),
        });
        self.hops.lock().unwrap().insert(id.clone(), hop.clone());
        self.notify();
        HopLease {
            owner: self.clone(),
            id,
            hop,
        }
    }
}

#[derive(Debug)]
struct HopState {
    snapshot: HopSnapshot,
    manual_requested: bool,
}

#[derive(Debug)]
pub(crate) struct HopManagement {
    state: Mutex<HopState>,
    pub(crate) counters: Mutex<monad_common::proxy::CleartextByteCounters>,
}

pub(crate) struct HopLease {
    pub(crate) owner: Arc<ClientManagement>,
    id: String,
    pub(crate) hop: Arc<HopManagement>,
}

impl Drop for HopLease {
    fn drop(&mut self) {
        let mut hops = self.owner.hops.lock().unwrap();
        if hops
            .get(&self.id)
            .is_some_and(|h| Arc::ptr_eq(h, &self.hop))
        {
            hops.remove(&self.id);
        }
        drop(hops);
        self.owner.notify();
    }
}

impl HopManagement {
    pub(crate) fn begin_provisioning(&self, owner: &ClientManagement) -> bool {
        let controls = owner.controls.borrow();
        let mut state = self.state.lock().unwrap();
        if !controls.enabled {
            return false;
        }
        let manual = std::mem::take(&mut state.manual_requested);
        if !controls.automatic_provisioning && !manual {
            state.snapshot.waiting_for_manual_funding = true;
            state.snapshot.provisioning = false;
            drop(state);
            drop(controls);
            owner.notify();
            return false;
        }
        state.snapshot.waiting_for_manual_funding = false;
        state.snapshot.provisioning = true;
        state.snapshot.funding_error = None;
        drop(state);
        drop(controls);
        owner.notify();
        true
    }

    pub(crate) fn provisioning_finished(&self) {
        self.state.lock().unwrap().snapshot.provisioning = false;
    }

    pub(crate) fn safe_provisioning_failure(&self) {
        let mut state = self.state.lock().unwrap();
        state.snapshot.funding_error = Some("no available compatible funding offer".to_owned());
        state.snapshot.waiting_for_manual_funding = true;
    }

    pub(crate) fn relay_admission_refused(&self, owner: &ClientManagement) {
        let manual = !owner.controls().automatic_provisioning;
        let mut state = self.state.lock().unwrap();
        state.snapshot.funding_error = Some("relay is not accepting this new channel".into());
        state.snapshot.waiting_for_relay_admission = manual;
        drop(state);
        owner.notify();
    }

    pub(crate) fn status(
        &self,
        linked: Option<monad_common::protocol::LinkedChannelStatus>,
        paused: bool,
        paid: u64,
        remaining: i64,
    ) {
        let mut state = self.state.lock().unwrap();
        if linked.is_some() {
            state.snapshot.waiting_for_relay_admission = false;
        }
        state.snapshot.linked_channel = linked;
        state.snapshot.paused = paused;
        state.snapshot.total_paid_msats = paid;
        state.snapshot.remaining_msats = remaining;
        if !paused {
            state.snapshot.waiting_for_manual_funding = false;
        }
    }
}

#[cfg(test)]
#[path = "management_tests.rs"]
mod tests;
