//! Headless process management protocol and bounded operation ownership.
use axum::{
    extract::{rejection::JsonRejection, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;

pub mod aggregate;
pub mod events;

pub const COMMAND_BODY_LIMIT: usize = 128 * 1024;
const MAX_OPERATIONS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub generation: String,
    pub request_id: String,
    pub instance: String,
    pub action: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub request: Command,
    pub state: String,
    pub result: Option<Value>,
    pub error: Option<String>,
    #[serde(skip)]
    request_fingerprint: [u8; 32],
}

#[async_trait::async_trait]
pub trait Backend: Send + Sync + 'static {
    async fn snapshot(&self) -> Result<Value, String>;
    /// Only return public, secret-free results and errors.
    async fn execute(&self, command: &Command) -> Result<Value, String>;
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    struct Idle;
    #[async_trait::async_trait]
    impl Backend for Idle {
        async fn snapshot(&self) -> Result<Value, String> {
            Ok(json!({}))
        }
        async fn execute(&self, _: &Command) -> Result<Value, String> {
            Ok(json!({}))
        }
    }

    #[tokio::test]
    async fn queue_rejection_has_no_operation_and_can_be_resubmitted() {
        let (service, mut receiver) = Service::new(Arc::new(Idle));
        let request = |id: usize| Command {
            generation: service.generation.clone(),
            request_id: id.to_string(),
            instance: "test".into(),
            action: "test".into(),
            arguments: json!({}),
        };
        for id in 0..64 {
            let _ = command(State(service.clone()), Ok(Json(request(id))))
                .await
                .unwrap();
        }
        let (status, body) = command(State(service.clone()), Ok(Json(request(64))))
            .await
            .unwrap_err();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["code"], "command_not_admitted");
        assert!(!service.operations.lock().unwrap().contains_key("64"));
        receiver.recv().await.unwrap();
        let _ = command(State(service.clone()), Ok(Json(request(64))))
            .await
            .unwrap();
        assert!(service.operations.lock().unwrap().contains_key("64"));
    }
}

pub struct Service {
    pub generation: String,
    backend: Arc<dyn Backend>,
    operations: Mutex<BTreeMap<String, Operation>>,
    commands: mpsc::Sender<Command>,
    operation_events: events::EventLog,
}

impl Service {
    pub fn new(backend: Arc<dyn Backend>) -> (Arc<Self>, mpsc::Receiver<Command>) {
        let (commands, receiver) = mpsc::channel(64);
        (
            Arc::new(Self {
                generation: hex::encode(rand::random::<[u8; 16]>()),
                backend,
                operations: Mutex::new(BTreeMap::new()),
                commands,
                operation_events: Default::default(),
            }),
            receiver,
        )
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/v1/snapshot", get(snapshot))
            .route("/v1/commands", post(command))
            .route("/v1/operations/{id}", get(operation))
            .with_state(self.clone())
            .layer(axum::extract::DefaultBodyLimit::max(COMMAND_BODY_LIMIT))
    }

    /// Owned bounded executor, independent of HTTP request lifetimes. Disable
    /// remains actionable while another command waits for mint/funding progress.
    pub async fn run(self: Arc<Self>, mut receiver: mpsc::Receiver<Command>) {
        use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
        let mut active = FuturesUnordered::new();
        loop {
            tokio::select! {
                command = receiver.recv(), if active.len() < 16 => {
                    let Some(command) = command else { break; };
                    let service = self.clone();
                    active.push(async move { service.execute(command).await }.boxed());
                }
                Some(()) = active.next(), if !active.is_empty() => {}
            }
        }
    }

    async fn execute(&self, command: Command) {
        if let Some(op) = self.operations.lock().unwrap().get_mut(&command.request_id) {
            op.state = "running".into();
            self.record_operation(op);
        }
        let result = self.backend.execute(&command).await;
        let mut operations = self.operations.lock().unwrap();
        let op = operations
            .get_mut(&command.request_id)
            .expect("operation retained");
        match result {
            Ok(value) => {
                op.state = "succeeded".into();
                op.result = Some(value);
            }
            Err(error) => {
                op.state = "failed".into();
                op.error = Some(error);
            }
        }
        self.record_operation(op);
    }

    fn record_operation(&self, op: &Operation) {
        // Arguments are caller-controlled and may contain secrets. Broadcast
        // only identifiers and the backend's explicitly public result/error.
        self.operation_events.record(
            "operation_updated",
            json!({
                "request_id": op.request.request_id, "instance": op.request.instance,
                "action": op.request.action, "state": op.state,
                "result": op.result, "error": op.error,
            }),
        );
    }
}

type ApiError = (StatusCode, Json<Value>);
fn error(status: StatusCode, message: &str) -> ApiError {
    (status, Json(json!({"error": message})))
}

#[derive(Default, Deserialize)]
struct SnapshotQuery {
    after: Option<String>,
}

async fn snapshot(
    State(service): State<Arc<Service>>,
    Query(query): Query<SnapshotQuery>,
) -> Result<Json<Value>, ApiError> {
    let after: BTreeMap<String, u64> = match query.after {
        Some(value) if value.len() <= 16384 => serde_json::from_str(&value)
            .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid event cursors"))?,
        Some(_) => return Err(error(StatusCode::BAD_REQUEST, "event cursors too large")),
        None => BTreeMap::new(),
    };
    let mut data = service
        .backend
        .snapshot()
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, &e))?;
    if let Some(instances) = data["instances"].as_object_mut() {
        for (name, instance) in instances {
            if let Some(events) = instance["events"].as_array_mut() {
                let oldest = events.first().and_then(|event| event["sequence"].as_u64());
                if let Some(cursor) = after.get(name) {
                    events.retain(|e| e["sequence"].as_u64().is_some_and(|n| n > *cursor));
                }
                instance["events_oldest_sequence"] = serde_json::json!(oldest);
            }
        }
    }
    Ok(Json(json!({"generation": service.generation, "data": data,
            "operation_events": service.operation_events.snapshot()})))
}

async fn command(
    State(service): State<Arc<Service>>,
    payload: Result<Json<Command>, JsonRejection>,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    let Json(command) = payload.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "management command exceeds the 128 KiB request limit",
            )
        } else {
            error(StatusCode::BAD_REQUEST, "invalid management command JSON")
        }
    })?;
    if command.generation != service.generation {
        return Err(error(StatusCode::CONFLICT, "stale process generation"));
    }
    if command.request_id.is_empty() || command.request_id.len() > 128 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "request_id must be 1..128 bytes",
        ));
    }
    let request_fingerprint = Sha256::digest(
        serde_json::to_vec(&command)
            .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid management command JSON"))?,
    )
    .into();
    let mut operations = service.operations.lock().unwrap();
    if let Some(existing) = operations.get(&command.request_id) {
        if existing.request_fingerprint != request_fingerprint {
            return Err(error(
                StatusCode::CONFLICT,
                "request_id already used for a different command",
            ));
        }
        return Ok((StatusCode::ACCEPTED, Json(existing.clone())));
    }
    // Never evict idempotency records and accidentally replay a money operation.
    // This deliberately bounded alpha service refuses new commands when full.
    if operations.len() >= MAX_OPERATIONS {
        return Err(error(
            StatusCode::TOO_MANY_REQUESTS,
            "operation history capacity reached",
        ));
    }
    let public_request = Command {
        generation: command.generation.clone(),
        request_id: command.request_id.clone(),
        instance: command.instance.clone(),
        action: command.action.clone(),
        arguments: Value::Null,
    };
    let op = Operation {
        request: public_request,
        state: "queued".into(),
        result: None,
        error: None,
        request_fingerprint,
    };
    service.commands.try_send(command.clone()).map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "command executor unavailable or busy", "code": "command_not_admitted"})),
        )
    })?;
    operations.insert(command.request_id, op.clone());
    service.record_operation(&op);
    Ok((StatusCode::ACCEPTED, Json(op)))
}

async fn operation(
    State(service): State<Arc<Service>>,
    Path(id): Path<String>,
) -> Result<Json<Operation>, ApiError> {
    service
        .operations
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "operation not found"))
}

/// Binding never removes an existing file/socket. An operator must explicitly
/// resolve stale paths after an ungraceful process death.
pub async fn serve_unix(
    path: PathBuf,
    backend: Arc<dyn Backend>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> std::io::Result<()> {
    let listener = tokio::net::UnixListener::bind(&path)?;
    // Only unlink our own inode, including cancellation/drop paths.
    use std::os::unix::fs::MetadataExt;
    struct SocketPath {
        path: PathBuf,
        inode: u64,
        device: u64,
    }
    impl Drop for SocketPath {
        fn drop(&mut self) {
            if let Ok(meta) = std::fs::symlink_metadata(&self.path) {
                if meta.ino() == self.inode && meta.dev() == self.device {
                    let _ = std::fs::remove_file(&self.path);
                }
            }
        }
    }
    let meta = std::fs::symlink_metadata(&path)?;
    let _path = SocketPath {
        path,
        inode: meta.ino(),
        device: meta.dev(),
    };
    let (service, receiver) = Service::new(backend);
    let server = serve_owned(listener, service.router(), shutdown);
    tokio::pin!(server);
    let executor = service.run(receiver);
    tokio::pin!(executor);
    tokio::select! {
        result = &mut server => result,
        () = &mut executor => Err(std::io::Error::other("management executor stopped")),
    }
}

/// HTTP connection futures are directly owned, including long-lived SSE bodies.
/// Shutdown/drop closes slow subscribers rather than waiting for them to drain.
pub async fn serve_owned<L: axum::serve::Listener>(
    mut listener: L,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> std::io::Result<()> {
    use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt};
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        server::conn::auto::Builder,
        service::TowerToHyperService,
    };
    let mut connections = FuturesUnordered::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => return Ok(()),
            Some(()) = connections.next(), if !connections.is_empty() => {},
            (stream, _) = listener.accept(), if connections.len() < 128 => {
                let router = router.clone();
                connections.push(async move {
                    let builder = Builder::new(TokioExecutor::new());
                    let _ = builder.serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(router)).await;
                }.boxed());
            }
        }
    }
}

pub fn unix_client(path: impl Into<PathBuf>) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .unix_socket(path.into())
        .timeout(std::time::Duration::from_secs(3))
        .build()
}
