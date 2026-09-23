use monad_common::protocol::ServerMessage;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;

/// Process-local overrides. Disabling preserves the three admission settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RelayControls {
    pub enabled: bool,
    pub accept_new_sessions: bool,
    pub accept_new_tunnels: bool,
    pub accept_new_channels: bool,
}

impl Default for RelayControls {
    fn default() -> Self {
        Self {
            enabled: true,
            accept_new_sessions: true,
            accept_new_tunnels: true,
            accept_new_channels: true,
        }
    }
}

#[derive(Debug, Default)]
struct Admission {
    controls: RelayControls,
    generation: CancellationToken,
    active_runs: usize,
}

#[derive(Debug, Clone)]
struct RegisteredSession {
    terminate: CancellationToken,
    control_tx: Option<mpsc::UnboundedSender<ServerMessage>>,
}

#[derive(Debug, Default)]
pub struct SessionRegistry {
    inner: Mutex<HashMap<[u8; 32], RegisteredSession>>,
    admission: Mutex<Admission>,
    drained: Notify,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_session(&self, session_id: [u8; 32], terminate: CancellationToken) {
        // Admission and disable use the same lock order. A registration racing
        // disable is either included in cancellation or rejected here.
        let admission = self.admission.lock().unwrap();
        if !admission.controls.enabled || !admission.controls.accept_new_sessions {
            terminate.cancel();
            return;
        }
        if let Ok(mut inner) = self.inner.lock() {
            inner.insert(
                session_id,
                RegisteredSession {
                    terminate,
                    control_tx: None,
                },
            );
        }
    }

    pub fn deregister_session(&self, session_id: &[u8; 32]) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.remove(session_id);
        }
        self.drained.notify_waiters();
    }

    pub fn controls(&self) -> RelayControls {
        self.admission.lock().unwrap().controls
    }

    /// Atomically replace runtime policy. False `enabled` requests cancellation;
    /// use `wait_disabled` to observe cleanup completion before re-enabling.
    pub fn set_controls(&self, controls: RelayControls) -> Result<(), &'static str> {
        let mut admission = self.admission.lock().unwrap();
        let inner = self.inner.lock().unwrap();
        if controls.enabled && !admission.controls.enabled {
            if admission.active_runs != 0 || !inner.is_empty() {
                return Err("relay is still disabling");
            }
            admission.generation = CancellationToken::new();
        }
        admission.controls = controls;
        if !controls.enabled {
            admission.generation.cancel();
            for session in inner.values() {
                session.terminate.cancel();
            }
        }
        Ok(())
    }

    /// Own pending handshake and session work, including its drop cleanup.
    /// Disabling wakes this future even before a session ID is registered.
    pub async fn run_admitted(&self, work: impl std::future::Future<Output = ()>) {
        let generation = {
            let mut admission = self.admission.lock().unwrap();
            if !admission.controls.enabled || !admission.controls.accept_new_sessions {
                return;
            }
            admission.active_runs += 1;
            admission.generation.clone()
        };
        struct RunGuard<'a>(&'a SessionRegistry);
        impl Drop for RunGuard<'_> {
            fn drop(&mut self) {
                self.0.admission.lock().unwrap().active_runs -= 1;
                self.0.drained.notify_waiters();
            }
        }
        let _guard = RunGuard(self);
        tokio::select! {
            biased;
            _ = generation.cancelled() => {},
            () = work => {},
        }
    }

    pub async fn wait_disabled(&self) -> Result<(), &'static str> {
        loop {
            let changed = self.drained.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let admission = self.admission.lock().unwrap();
                if admission.controls.enabled {
                    return Err("relay is enabled");
                }
                if admission.active_runs == 0 && self.inner.lock().unwrap().is_empty() {
                    return Ok(());
                }
            }
            changed.await;
        }
    }

    /// Serialize synchronous admission/publication with control changes. Never
    /// hold this guard across an await or across the lifetime of a data tunnel.
    pub(crate) fn with_controls<T>(&self, f: impl FnOnce(RelayControls) -> T) -> T {
        let admission = self.admission.lock().unwrap();
        f(admission.controls)
    }

    pub fn register_control(&self, session_id: [u8; 32], tx: mpsc::UnboundedSender<ServerMessage>) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(registered) = inner.get_mut(&session_id) {
                registered.control_tx = Some(tx);
            }
        }
    }

    pub fn deregister_control(&self, session_id: &[u8; 32]) {
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(registered) = inner.get_mut(session_id) {
                registered.control_tx = None;
            }
        }
    }

    pub fn notify(&self, session_id: &[u8; 32], msg: ServerMessage) -> bool {
        let tx = match self.inner.lock() {
            Ok(inner) => inner
                .get(session_id)
                .and_then(|registered| registered.control_tx.clone()),
            Err(_) => None,
        };

        if let Some(tx) = tx {
            tx.send(msg).is_ok()
        } else {
            false
        }
    }

    pub fn terminate(&self, session_id: &[u8; 32]) -> bool {
        let terminate = match self.inner.lock() {
            Ok(inner) => inner
                .get(session_id)
                .map(|registered| registered.terminate.clone()),
            Err(_) => None,
        };

        if let Some(terminate) = terminate {
            terminate.cancel();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests;
