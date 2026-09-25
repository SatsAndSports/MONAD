use monad_management::{Backend, Command};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::Notify;

#[derive(Default)]
struct GatedBackend {
    calls: AtomicUsize,
    gate: Notify,
}

#[async_trait::async_trait]
impl Backend for GatedBackend {
    async fn snapshot(&self) -> Result<Value, String> {
        Ok(json!({"calls": self.calls.load(Ordering::SeqCst)}))
    }
    async fn execute(&self, _: &Command) -> Result<Value, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.gate.notified().await;
        Ok(json!({"finished": true}))
    }
}

#[tokio::test]
async fn unix_commands_are_generation_bound_idempotent_and_owned() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("management.sock");
        let backend = Arc::new(GatedBackend::default());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(monad_management::serve_unix(
            path.clone(),
            backend.clone(),
            async {
                let _ = stopped.await;
            },
        ));
        let client = monad_management::unix_client(path.clone()).unwrap();
        let snapshot: Value = loop {
            if let Ok(response) = client.get("http://localhost/v1/snapshot").send().await {
                break response.json().await.unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        };
        let mut command = Command {
            generation: snapshot["generation"].as_str().unwrap().into(),
            request_id: "one".into(),
            instance: "test".into(),
            action: "gate".into(),
            arguments: json!({"private_test_argument": "must-not-be-broadcast"}),
        };
        let response = client
            .post("http://localhost/v1/commands")
            .json(&command)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 202);
        drop(response); // Caller goes away; the operation still belongs to server.
        assert_eq!(
            client
                .post("http://localhost/v1/commands")
                .json(&command)
                .send()
                .await
                .unwrap()
                .status(),
            202
        );
        command.action = "different".into();
        assert_eq!(
            client
                .post("http://localhost/v1/commands")
                .json(&command)
                .send()
                .await
                .unwrap()
                .status(),
            409
        );
        command.generation = "old-process".into();
        assert_eq!(
            client
                .post("http://localhost/v1/commands")
                .json(&command)
                .send()
                .await
                .unwrap()
                .status(),
            409
        );
        backend.gate.notify_one();
        loop {
            let operation: Value = client
                .get("http://localhost/v1/operations/one")
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if operation["state"] == "succeeded" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        let snapshot: Value = client
            .get("http://localhost/v1/snapshot")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let events = snapshot["operation_events"].as_array().unwrap();
        assert_eq!(events.len(), 3, "duplicate submission emits no acceptance");
        assert_eq!(
            events
                .iter()
                .map(|e| e["data"]["state"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["queued", "running", "succeeded"]
        );
        assert!(!serde_json::to_string(events)
            .unwrap()
            .contains("must-not-be-broadcast"));
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(!path.exists());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unix_bind_preserves_existing_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("existing");
    std::fs::write(&path, b"do not remove").unwrap();
    assert!(
        monad_management::serve_unix(path.clone(), Arc::new(GatedBackend::default()), async {})
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(path).unwrap(), b"do not remove");
}

#[test]
fn event_history_is_bounded_and_keeps_sequence_gaps_visible() {
    let log = monad_management::events::EventLog::default();
    for n in 0..600 {
        log.record("payment", json!({"n": n}));
    }
    let events = log.snapshot();
    assert_eq!(events.len(), 512);
    assert_eq!(events.first().unwrap().sequence, 89);
    assert_eq!(events.last().unwrap().sequence, 600);
}
