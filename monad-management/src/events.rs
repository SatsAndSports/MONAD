use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::VecDeque, sync::Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub sequence: u64,
    pub kind: String,
    pub data: Value,
}

#[derive(Debug, Default)]
pub struct EventLog {
    inner: Mutex<(u64, VecDeque<Event>)>,
}

impl EventLog {
    pub fn record(&self, kind: &str, data: Value) {
        let mut inner = self.inner.lock().unwrap();
        inner.0 += 1;
        let sequence = inner.0;
        if inner.1.len() == 512 {
            inner.1.pop_front();
        }
        inner.1.push_back(Event {
            sequence,
            kind: kind.into(),
            data,
        });
    }

    pub fn snapshot(&self) -> Vec<Event> {
        self.inner.lock().unwrap().1.iter().cloned().collect()
    }
}
