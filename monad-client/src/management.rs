//! Process-local client controls. The payment driver remains the only funder.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

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
    pub introduced_in_route_generation: u64,
    pub label: String,
    pub funding: HopFundingState,
    pub linked_channel: Option<monad_common::protocol::LinkedChannelStatus>,
    pub paused: bool,
    pub total_paid_msats: u64,
    pub remaining_msats: i64,
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HopFundingState {
    AwaitingStatus,
    AwaitingFunding,
    WaitingForManualFunding {
        error: Option<String>,
    },
    Provisioning,
    Linking {
        channel_id: String,
    },
    WaitingForRelayAdmission {
        rejection: monad_common::rejection::Rejection,
    },
    Paying {
        channel_id: String,
    },
    Ready,
    Blocked {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientFailureStage {
    Connect,
    Route,
    FailureWatcher,
    SuffixRebuild,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClientFailure {
    pub stage: ClientFailureStage,
    pub message: String,
    pub hop: Option<usize>,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ClientLifecycle {
    Stopped,
    Disabled,
    Starting,
    Connecting {
        attempt: u32,
        reconnect: bool,
    },
    WaitingForAdmission {
        attempt: u32,
        reconnect: bool,
        wait: crate::admission::AdmissionWait,
    },
    Active,
    RebuildingSuffix {
        failed_hop: usize,
        preserved_hops: usize,
    },
    RetryBackoff {
        attempt: u32,
        retry_at_unix_ms: u64,
    },
    BlockedByPolicy {
        refusal: crate::admission::RouteRefusal,
    },
    Disabling,
    Failed {
        failure: ClientFailure,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ClientRuntimeSnapshot {
    pub revision: u64,
    pub run_generation: u64,
    pub route_generation: u64,
    pub transitioned_at_unix_ms: u64,
    pub lifecycle: ClientLifecycle,
    pub last_failure: Option<ClientFailure>,
    pub last_exit_failure: Option<ExitFailure>,
}

impl Default for ClientRuntimeSnapshot {
    fn default() -> Self {
        Self {
            revision: 0,
            run_generation: 0,
            route_generation: 0,
            transitioned_at_unix_ms: now_unix_ms(),
            lifecycle: ClientLifecycle::Stopped,
            last_failure: None,
            last_exit_failure: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ExitFailure {
    pub session_id: String,
    pub route_generation: u64,
    pub destination: String,
    pub rejection: monad_common::rejection::Rejection,
}

#[derive(Debug, Default)]
struct ClientRuntimeState {
    snapshot: ClientRuntimeSnapshot,
    running: bool,
}

/// A handle belongs to one configured client, not to its shared wallet.
#[derive(Debug)]
pub struct ClientManagement {
    controls: watch::Sender<ClientControls>,
    hops: Mutex<BTreeMap<String, Arc<HopManagement>>>,
    changed: watch::Sender<u64>,
    runtime: Mutex<ClientRuntimeState>,
    pub events: monad_management::events::EventLog,
}

impl Default for ClientManagement {
    fn default() -> Self {
        Self {
            controls: watch::channel(ClientControls::default()).0,
            hops: Mutex::new(BTreeMap::new()),
            changed: watch::channel(0).0,
            runtime: Default::default(),
            events: Default::default(),
        }
    }
}

impl ClientManagement {
    pub fn runtime_snapshot(&self) -> ClientRuntimeSnapshot {
        self.runtime.lock().unwrap().snapshot.clone()
    }

    fn update_runtime(
        &self,
        run_generation: u64,
        update: impl FnOnce(&mut ClientRuntimeSnapshot) -> bool,
    ) -> Option<ClientRuntimeSnapshot> {
        let mut runtime = self.runtime.lock().unwrap();
        if runtime.snapshot.run_generation != run_generation || !update(&mut runtime.snapshot) {
            return None;
        }
        runtime.snapshot.revision = runtime.snapshot.revision.wrapping_add(1);
        runtime.snapshot.transitioned_at_unix_ms = now_unix_ms();
        Some(runtime.snapshot.clone())
    }

    fn record_lifecycle(&self, snapshot: &ClientRuntimeSnapshot) {
        self.events.record(
            "client_lifecycle_changed",
            serde_json::json!({
                "revision": snapshot.revision,
                "run_generation": snapshot.run_generation,
                "route_generation": snapshot.route_generation,
                "lifecycle": snapshot.lifecycle,
            }),
        );
        self.notify();
    }

    pub(crate) fn connecting(&self, run_generation: u64, attempt: u32, reconnect: bool) {
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            snapshot.lifecycle = ClientLifecycle::Connecting { attempt, reconnect };
            true
        }) {
            self.record_lifecycle(&snapshot);
        }
    }

    pub(crate) fn waiting_for_admission(
        &self,
        run_generation: u64,
        wait: crate::admission::AdmissionWait,
    ) {
        let mut refusal_event = None;
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            let (attempt, reconnect) = match &snapshot.lifecycle {
                ClientLifecycle::Connecting { attempt, reconnect }
                | ClientLifecycle::WaitingForAdmission {
                    attempt, reconnect, ..
                } => (*attempt, *reconnect),
                _ => return false,
            };
            let changed_refusal = !matches!(
                &snapshot.lifecycle,
                ClientLifecycle::WaitingForAdmission { wait: current, .. }
                    if current.refusal == wait.refusal
            );
            if changed_refusal {
                refusal_event = Some(wait.refusal.clone());
            }
            snapshot.lifecycle = ClientLifecycle::WaitingForAdmission {
                attempt,
                reconnect,
                wait,
            };
            true
        }) {
            if let Some(refusal) = refusal_event {
                self.events.record(
                    "route_refused",
                    serde_json::json!({
                        "revision": snapshot.revision,
                        "run_generation": run_generation,
                        "refusal": refusal,
                    }),
                );
            }
            self.record_lifecycle(&snapshot);
        }
    }

    pub(crate) fn clear_admission_wait(&self, run_generation: u64) {
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            let ClientLifecycle::WaitingForAdmission {
                attempt, reconnect, ..
            } = &snapshot.lifecycle
            else {
                return false;
            };
            snapshot.lifecycle = ClientLifecycle::Connecting {
                attempt: *attempt,
                reconnect: *reconnect,
            };
            true
        }) {
            self.record_lifecycle(&snapshot);
        }
    }

    pub(crate) fn active(&self, run_generation: u64) {
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            snapshot.route_generation = snapshot.route_generation.wrapping_add(1);
            snapshot.lifecycle = ClientLifecycle::Active;
            snapshot.last_exit_failure = None;
            true
        }) {
            self.record_lifecycle(&snapshot);
        }
    }

    pub(crate) fn rebuilding_suffix(
        &self,
        run_generation: u64,
        failed_hop: usize,
        preserved_hops: usize,
    ) {
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            snapshot.lifecycle = ClientLifecycle::RebuildingSuffix {
                failed_hop,
                preserved_hops,
            };
            true
        }) {
            self.record_lifecycle(&snapshot);
        }
    }

    pub(crate) fn retry_backoff(&self, run_generation: u64, attempt: u32, retry_at_unix_ms: u64) {
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            snapshot.lifecycle = ClientLifecycle::RetryBackoff {
                attempt,
                retry_at_unix_ms,
            };
            true
        }) {
            self.record_lifecycle(&snapshot);
        }
    }

    pub(crate) fn blocked_by_policy(
        &self,
        run_generation: u64,
        refusal: crate::admission::RouteRefusal,
    ) {
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            snapshot.lifecycle = ClientLifecycle::BlockedByPolicy {
                refusal: refusal.clone(),
            };
            true
        }) {
            self.events.record(
                "route_refused",
                serde_json::json!({
                    "revision": snapshot.revision,
                    "run_generation": run_generation,
                    "refusal": refusal,
                }),
            );
            self.record_lifecycle(&snapshot);
        }
    }

    pub(crate) fn record_failure(&self, run_generation: u64, failure: ClientFailure) {
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            snapshot.last_failure = Some(failure.clone());
            true
        }) {
            self.events.record(
                "client_failure",
                serde_json::json!({
                    "revision": snapshot.revision,
                    "run_generation": run_generation,
                    "route_generation": snapshot.route_generation,
                    "failure": failure,
                }),
            );
            self.notify();
        }
    }

    pub(crate) fn failed(&self, run_generation: u64, failure: ClientFailure) {
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            snapshot.last_failure = Some(failure.clone());
            snapshot.lifecycle = ClientLifecycle::Failed {
                failure: failure.clone(),
            };
            true
        }) {
            self.events.record(
                "client_failure",
                serde_json::json!({
                    "revision": snapshot.revision,
                    "run_generation": run_generation,
                    "route_generation": snapshot.route_generation,
                    "failure": failure,
                }),
            );
            self.record_lifecycle(&snapshot);
        }
    }

    pub(crate) fn note_exit_result(
        &self,
        session: &[u8; 32],
        destination: &str,
        error: Option<&std::io::Error>,
    ) {
        let failure = error
            .and_then(monad_common::rejection::Rejection::from_io)
            .cloned();
        let Some(failure) = failure else {
            return;
        };
        let session_id = hex::encode(session);
        let Some(route_generation) = self
            .hops
            .lock()
            .unwrap()
            .get(&session_id)
            .map(|hop| hop.route_generation)
        else {
            return;
        };
        let failure = ExitFailure {
            session_id,
            route_generation,
            destination: destination.to_owned(),
            rejection: failure,
        };
        let runtime = self.runtime.lock().unwrap().snapshot.clone();
        if route_generation != runtime.route_generation {
            return;
        }
        let run_generation = runtime.run_generation;
        if let Some(snapshot) = self.update_runtime(run_generation, |snapshot| {
            if snapshot.route_generation != route_generation {
                return false;
            }
            snapshot.last_exit_failure = Some(failure.clone());
            true
        }) {
            self.events.record(
                "exit_refused",
                serde_json::json!({
                    "revision": snapshot.revision,
                    "run_generation": run_generation,
                    "route_generation": snapshot.route_generation,
                    "failure": failure,
                }),
            );
            self.notify();
        }
    }
    pub fn controls(&self) -> ClientControls {
        *self.controls.borrow()
    }

    pub fn set_automatic_provisioning(&self, enabled: bool) {
        self.controls
            .send_modify(|c| c.automatic_provisioning = enabled);
        self.notify();
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<(), &'static str> {
        let mut runtime = self.runtime.lock().unwrap();
        if enabled && !self.controls().enabled && runtime.running {
            return Err("client is still disabling");
        }
        self.controls.send_modify(|c| c.enabled = enabled);
        if !enabled && runtime.running {
            runtime.snapshot.revision = runtime.snapshot.revision.wrapping_add(1);
            runtime.snapshot.transitioned_at_unix_ms = now_unix_ms();
            runtime.snapshot.lifecycle = ClientLifecycle::Disabling;
            let snapshot = runtime.snapshot.clone();
            drop(runtime);
            self.record_lifecycle(&snapshot);
            return Ok(());
        }
        if !enabled {
            runtime.snapshot.revision = runtime.snapshot.revision.wrapping_add(1);
            runtime.snapshot.transitioned_at_unix_ms = now_unix_ms();
            runtime.snapshot.lifecycle = ClientLifecycle::Disabled;
            let snapshot = runtime.snapshot.clone();
            drop(runtime);
            self.record_lifecycle(&snapshot);
            return Ok(());
        }
        if !runtime.running && matches!(runtime.snapshot.lifecycle, ClientLifecycle::Disabled) {
            runtime.snapshot.revision = runtime.snapshot.revision.wrapping_add(1);
            runtime.snapshot.transitioned_at_unix_ms = now_unix_ms();
            runtime.snapshot.lifecycle = ClientLifecycle::Stopped;
            let snapshot = runtime.snapshot.clone();
            drop(runtime);
            self.record_lifecycle(&snapshot);
            return Ok(());
        }
        drop(runtime);
        self.notify();
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.runtime.lock().unwrap().running
    }

    pub(crate) fn begin_run(&self) -> Option<u64> {
        let mut runtime = self.runtime.lock().unwrap();
        if !self.controls().enabled {
            return None;
        }
        assert!(
            !runtime.running,
            "client management handle already has a runtime owner"
        );
        runtime.running = true;
        runtime.snapshot.revision = runtime.snapshot.revision.wrapping_add(1);
        runtime.snapshot.run_generation = runtime.snapshot.run_generation.wrapping_add(1);
        runtime.snapshot.route_generation = 0;
        runtime.snapshot.transitioned_at_unix_ms = now_unix_ms();
        runtime.snapshot.lifecycle = ClientLifecycle::Starting;
        runtime.snapshot.last_failure = None;
        runtime.snapshot.last_exit_failure = None;
        let snapshot = runtime.snapshot.clone();
        drop(runtime);
        self.record_lifecycle(&snapshot);
        Some(snapshot.run_generation)
    }

    pub(crate) fn finish_run(&self, run_generation: u64) {
        let mut runtime = self.runtime.lock().unwrap();
        if runtime.snapshot.run_generation != run_generation {
            return;
        }
        runtime.running = false;
        runtime.snapshot.revision = runtime.snapshot.revision.wrapping_add(1);
        runtime.snapshot.transitioned_at_unix_ms = now_unix_ms();
        runtime.snapshot.lifecycle = if !self.controls().enabled {
            ClientLifecycle::Disabled
        } else if matches!(runtime.snapshot.lifecycle, ClientLifecycle::Failed { .. }) {
            runtime.snapshot.lifecycle.clone()
        } else {
            ClientLifecycle::Stopped
        };
        runtime.snapshot.last_exit_failure = None;
        let snapshot = runtime.snapshot.clone();
        drop(runtime);
        self.record_lifecycle(&snapshot);
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
        if state.manual_requested || state.snapshot.funding == HopFundingState::Provisioning {
            return Err("provisioning is already in progress");
        }
        if !matches!(
            state.snapshot.funding,
            HopFundingState::WaitingForManualFunding { .. }
        ) {
            return Err("session is not waiting for manual funding");
        }
        state.manual_requested = true;
        state.snapshot.funding = HopFundingState::WaitingForManualFunding { error: None };
        drop(state);
        drop(hops);
        drop(controls);
        self.notify();
        Ok(())
    }

    pub(crate) fn waiting_for_funding(&self, session_id: &str) -> bool {
        self.hops.lock().unwrap().get(session_id).is_some_and(|h| {
            let state = h.state.lock().unwrap();
            matches!(
                state.snapshot.funding,
                HopFundingState::WaitingForManualFunding { .. }
                    | HopFundingState::WaitingForRelayAdmission { .. }
            )
        })
    }

    pub(crate) fn register(self: &Arc<Self>, session_id: [u8; 32], label: &str) -> HopLease {
        let id = hex::encode(session_id);
        let runtime = self.runtime_snapshot();
        let route_generation = runtime.route_generation.saturating_add(u64::from(matches!(
            runtime.lifecycle,
            ClientLifecycle::Starting
                | ClientLifecycle::Connecting { .. }
                | ClientLifecycle::WaitingForAdmission { .. }
                | ClientLifecycle::RebuildingSuffix { .. }
                | ClientLifecycle::RetryBackoff { .. }
        )));
        let hop = Arc::new(HopManagement {
            session_id: id.clone(),
            route_generation,
            counters: Default::default(),
            state: Mutex::new(HopState {
                snapshot: HopSnapshot {
                    session_id: id.clone(),
                    introduced_in_route_generation: route_generation,
                    label: label.to_owned(),
                    funding: HopFundingState::AwaitingStatus,
                    linked_channel: None,
                    paused: true,
                    total_paid_msats: 0,
                    remaining_msats: 0,
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
    session_id: String,
    route_generation: u64,
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
    fn set_funding(&self, owner: &ClientManagement, funding: HopFundingState) {
        let mut state = self.state.lock().unwrap();
        if state.snapshot.funding == funding {
            return;
        }
        state.snapshot.funding = funding.clone();
        drop(state);
        owner.events.record(
            "hop_funding_changed",
            serde_json::json!({"session_id": self.session_id, "funding": funding}),
        );
        owner.notify();
    }

    pub(crate) fn begin_provisioning(&self, owner: &ClientManagement) -> bool {
        let controls = owner.controls.borrow();
        let mut state = self.state.lock().unwrap();
        if !controls.enabled {
            return false;
        }
        let manual = std::mem::take(&mut state.manual_requested);
        if !controls.automatic_provisioning && !manual {
            let error = match &state.snapshot.funding {
                HopFundingState::WaitingForManualFunding { error } => error.clone(),
                _ => None,
            };
            state.snapshot.funding = HopFundingState::WaitingForManualFunding { error };
            drop(state);
            drop(controls);
            owner.notify();
            return false;
        }
        state.snapshot.funding = HopFundingState::Provisioning;
        drop(state);
        drop(controls);
        owner.notify();
        true
    }

    pub(crate) fn provisioning_finished(&self, owner: &ClientManagement) {
        self.set_funding(owner, HopFundingState::AwaitingFunding);
    }

    pub(crate) fn safe_provisioning_failure(&self, owner: &ClientManagement) {
        self.set_funding(
            owner,
            HopFundingState::WaitingForManualFunding {
                error: Some("no available compatible funding offer".to_owned()),
            },
        );
    }

    pub(crate) fn relay_admission_refused(&self, owner: &ClientManagement) {
        self.set_funding(
            owner,
            HopFundingState::WaitingForRelayAdmission {
                rejection: monad_common::rejection::RejectionCode::ChannelAdmissionDisabled
                    .rejection(),
            },
        );
    }

    pub(crate) fn channel_admitted(&self, owner: &ClientManagement) {
        let was_waiting = {
            matches!(
                self.state.lock().unwrap().snapshot.funding,
                HopFundingState::WaitingForRelayAdmission { .. }
            )
        };
        if was_waiting {
            self.set_funding(owner, HopFundingState::AwaitingFunding);
        }
    }

    pub(crate) fn linking(&self, owner: &ClientManagement, channel_id: String) {
        self.set_funding(owner, HopFundingState::Linking { channel_id });
    }

    pub(crate) fn paying(&self, owner: &ClientManagement, channel_id: String) {
        self.set_funding(owner, HopFundingState::Paying { channel_id });
    }

    pub(crate) fn blocked(&self, owner: &ClientManagement, message: String) {
        self.set_funding(owner, HopFundingState::Blocked { message });
    }

    pub(crate) fn status(
        &self,
        owner: &ClientManagement,
        linked: Option<monad_common::protocol::LinkedChannelStatus>,
        paused: bool,
        paid: u64,
        remaining: i64,
    ) {
        let mut state = self.state.lock().unwrap();
        let previous_funding = state.snapshot.funding.clone();
        state.snapshot.linked_channel = linked;
        state.snapshot.paused = paused;
        state.snapshot.total_paid_msats = paid;
        state.snapshot.remaining_msats = remaining;
        if !paused {
            state.snapshot.funding = HopFundingState::Ready;
        } else if !matches!(
            state.snapshot.funding,
            HopFundingState::WaitingForManualFunding { .. }
                | HopFundingState::Provisioning
                | HopFundingState::Linking { .. }
                | HopFundingState::WaitingForRelayAdmission { .. }
                | HopFundingState::Paying { .. }
                | HopFundingState::Blocked { .. }
        ) {
            state.snapshot.funding = HopFundingState::AwaitingFunding;
        }
        let funding = state.snapshot.funding.clone();
        drop(state);
        if funding != previous_funding {
            owner.events.record(
                "hop_funding_changed",
                serde_json::json!({"session_id": self.session_id, "funding": funding}),
            );
        }
        owner.notify();
    }
}

#[cfg(test)]
#[path = "management_tests.rs"]
mod tests;
