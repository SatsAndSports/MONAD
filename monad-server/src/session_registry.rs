use monad_common::protocol::ServerMessage;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;

#[derive(Debug, Default)]
pub struct SessionRegistry {
    inner: Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<ServerMessage>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, session_id: [u8; 32], tx: mpsc::UnboundedSender<ServerMessage>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.insert(session_id, tx);
        }
    }

    pub fn deregister(&self, session_id: &[u8; 32]) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.remove(session_id);
        }
    }

    pub fn notify(&self, session_id: &[u8; 32], msg: ServerMessage) -> bool {
        let tx = match self.inner.lock() {
            Ok(inner) => inner.get(session_id).cloned(),
            Err(_) => None,
        };

        if let Some(tx) = tx {
            tx.send(msg).is_ok()
        } else {
            false
        }
    }
}
