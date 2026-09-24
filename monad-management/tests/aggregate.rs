use monad_management::{
    aggregate::{self, Aggregator},
    events::EventLog,
    Backend, Command,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Default)]
struct Runtime {
    calls: AtomicUsize,
    events: EventLog,
}
#[async_trait::async_trait]
impl Backend for Runtime {
    async fn snapshot(&self) -> Result<Value, String> {
        Ok(
            json!({"kind": "relays", "instances": {"relay": {"events": self.events.snapshot(), "calls": self.calls.load(Ordering::SeqCst)}}}),
        )
    }
    async fn execute(&self, _: &Command) -> Result<Value, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.events
            .record("payment_accepted", json!({"delta_msats": 7}));
        Ok(json!({"ok": true}))
    }
}

async fn next_event(
    response: &mut reqwest::Response,
    buffer: &mut String,
) -> (String, String, Value) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(end) = buffer.find("\n\n") {
                let frame = buffer[..end].to_owned();
                buffer.drain(..end + 2);
                let field = |name: &str| {
                    frame
                        .lines()
                        .find_map(|line| line.strip_prefix(name))
                        .unwrap_or("")
                        .trim()
                        .to_owned()
                };
                let kind = field("event:");
                if kind.is_empty() {
                    continue;
                }
                return (
                    field("id:"),
                    kind,
                    serde_json::from_str(&field("data:")).unwrap(),
                );
            }
            let bytes = response
                .chunk()
                .await
                .unwrap()
                .expect("SSE ended unexpectedly");
            buffer.push_str(std::str::from_utf8(&bytes).unwrap());
        }
    })
    .await
    .unwrap()
}

async fn wait_view(
    client: &reqwest::Client,
    base: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Value {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let view: Value = client
                .get(format!("{base}/v1/snapshot"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if predicate(&view) {
                return view;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn tcp_sse_aggregates_replays_forwards_and_survives_process_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("runtime.sock");
    let runtime = Arc::new(Runtime::default());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let process = tokio::spawn(monad_management::serve_unix(
        path.clone(),
        runtime.clone(),
        async {
            let _ = stopped.await;
        },
    ));
    let aggregate = Aggregator::new(BTreeMap::from([
        ("live".into(), path.display().to_string()),
        (
            "missing".into(),
            dir.path().join("missing.sock").display().to_string(),
        ),
    ]))
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let (stop_api, stopped_api) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(aggregate::serve(listener, aggregate, async {
        let _ = stopped_api.await;
    }));
    let client = reqwest::Client::new();
    let view = wait_view(&client, &base, |v| v["processes"]["live"]["online"] == true).await;
    assert_eq!(view["processes"]["missing"]["online"], false);
    let generation = view["processes"]["live"]["generation"].clone();
    let mut sse = client
        .get(format!("{base}/v1/events?process=live"))
        .send()
        .await
        .unwrap();
    assert_eq!(sse.headers()["content-type"], "text/event-stream");
    let mut buffer = String::new();
    assert_eq!(next_event(&mut sse, &mut buffer).await.1, "reset");
    let request = json!({"generation": generation, "request_id": "payment", "instance": "relay", "action": "test", "arguments": {}});
    assert_eq!(
        client
            .post(format!("{base}/v1/processes/live/commands"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        202
    );
    let payment_id = loop {
        let (id, kind, data) = next_event(&mut sse, &mut buffer).await;
        if kind == "payment_accepted" {
            assert_eq!(data["event"]["data"]["delta_msats"], 7);
            break id;
        }
    };
    let operation: Value = client
        .get(format!("{base}/v1/processes/live/operations/payment"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(operation["state"], "succeeded");
    assert_eq!(
        client
            .post(format!("{base}/v1/processes/live/commands"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        202
    );
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
    drop(sse);
    let mut replay = client
        .get(format!("{base}/v1/events"))
        .header("Last-Event-ID", payment_id)
        .send()
        .await
        .unwrap();
    assert_ne!(next_event(&mut replay, &mut String::new()).await.1, "reset");
    stop.send(()).unwrap();
    process.await.unwrap().unwrap();
    wait_view(&client, &base, |v| {
        v["processes"]["live"]["online"] == false
    })
    .await;
    let (stop2, stopped2) = tokio::sync::oneshot::channel();
    let process2 = tokio::spawn(monad_management::serve_unix(
        path.clone(),
        Arc::new(Runtime::default()),
        async {
            let _ = stopped2.await;
        },
    ));
    wait_view(&client, &base, |v| {
        v["processes"]["live"]["online"] == true
            && v["processes"]["live"]["generation"] != generation
    })
    .await;
    assert_eq!(
        client
            .post(format!("{base}/v1/processes/live/commands"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    // A subscriber deliberately stops reading. Root shutdown must still finish.
    let _slow = client
        .get(format!("{base}/v1/events"))
        .send()
        .await
        .unwrap();
    stop_api.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let _rebound = tokio::net::TcpListener::bind(addr).await.unwrap();
    let direct = monad_management::unix_client(path).unwrap();
    assert_eq!(
        direct
            .get("http://localhost/v1/snapshot")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    stop2.send(()).unwrap();
    process2.await.unwrap().unwrap();
}
