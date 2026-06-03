use monad_common::protocol::ServerMessage;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
struct RegisteredSession {
    terminate: CancellationToken,
    control_tx: Option<mpsc::UnboundedSender<ServerMessage>>,
}

#[derive(Debug, Default)]
pub struct SessionRegistry {
    inner: Mutex<HashMap<[u8; 32], RegisteredSession>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_session(&self, session_id: [u8; 32], terminate: CancellationToken) {
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
