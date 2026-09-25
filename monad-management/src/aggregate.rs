//! One loopback HTTP/SSE service for independently running local processes.
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive},
        Html, IntoResponse, Redirect, Response, Sse,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::{
    stream::{self, FuturesUnordered},
    Stream, StreamExt,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

const HISTORY: usize = 512;

#[derive(Clone)]
struct Record {
    sequence: u64,
    kind: String,
    process: String,
    data: Value,
}

#[derive(Default)]
struct View {
    sequence: u64,
    processes: BTreeMap<String, Value>,
    history: VecDeque<Record>,
}

pub struct Aggregator {
    epoch: String,
    clients: BTreeMap<String, reqwest::Client>,
    view: Mutex<View>,
    changed: watch::Sender<u64>,
}

impl Aggregator {
    pub fn new(processes: BTreeMap<String, String>) -> Result<Arc<Self>, reqwest::Error> {
        let clients = processes
            .into_iter()
            .map(|(name, path)| crate::unix_client(path).map(|c| (name, c)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut view = View::default();
        for name in clients.keys() {
            view.processes.insert(
                name.clone(),
                json!({"online": false, "data": null, "last_success_unix_ms": null}),
            );
        }
        Ok(Arc::new(Self {
            epoch: hex::encode(rand::random::<[u8; 16]>()),
            clients,
            view: Mutex::new(view),
            changed: watch::channel(0).0,
        }))
    }

    pub fn snapshot(&self) -> Value {
        let view = self.view.lock().unwrap();
        json!({"epoch": self.epoch, "sequence": view.sequence, "processes": view.processes})
    }

    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/", get(root))
            .route("/mints", get(mints))
            .route("/assets/mints.css", get(mints_css))
            .route("/assets/mints.js", get(mints_js))
            .route("/v1/snapshot", get(snapshot))
            .route("/v1/events", get(events))
            .route("/v1/processes/{name}/commands", post(command))
            .route("/v1/processes/{name}/operations/{id}", get(operation))
            .with_state(self.clone())
            .layer(axum::extract::DefaultBodyLimit::max(16 * 1024))
    }

    fn publish(&self, process: &str, kind: &str, data: Value, current: Option<Value>) {
        let mut view = self.view.lock().unwrap();
        if let Some(current) = current {
            view.processes.insert(process.to_owned(), current);
        }
        view.sequence += 1;
        let sequence = view.sequence;
        if view.history.len() == HISTORY {
            view.history.pop_front();
        }
        view.history.push_back(Record {
            sequence,
            kind: kind.into(),
            process: process.into(),
            data,
        });
        self.changed.send_replace(sequence);
    }

    async fn poll_process(self: Arc<Self>, name: String, client: reqwest::Client) {
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut generation = String::new();
        let mut seen = BTreeMap::<String, u64>::new();
        let mut operation_cursor = 0u64;
        loop {
            tick.tick().await;
            let result = async {
                let response = client
                    .get("http://localhost/v1/snapshot")
                    .query(&[("after", serde_json::to_string(&seen).unwrap())])
                    .send()
                    .await?
                    .error_for_status()?;
                response.json::<Value>().await
            }
            .await;
            let mut snapshot = match result {
                Ok(snapshot)
                    if snapshot["generation"].is_string() && snapshot["data"].is_object() =>
                {
                    snapshot
                }
                _ => {
                    let mut previous = self.view.lock().unwrap().processes[&name].clone();
                    if previous["online"] == true || previous.get("error").is_none() {
                        previous["online"] = json!(false);
                        previous["error"] = json!("process unavailable");
                        self.publish(
                            &name,
                            "snapshot",
                            json!({"process": name, "state": previous}),
                            Some(previous.clone()),
                        );
                    }
                    continue;
                }
            };
            let next_generation = snapshot["generation"].as_str().unwrap().to_owned();
            if generation != next_generation {
                // The response may have been filtered with the prior process's
                // cursors. Refetch without those cursors before publishing it.
                let was_known = !generation.is_empty();
                seen.clear();
                operation_cursor = 0;
                generation = next_generation;
                if was_known {
                    continue;
                }
            }
            if let Some(events) = snapshot["operation_events"].as_array() {
                if let Some(first) = events.first().and_then(|e| e["sequence"].as_u64()) {
                    if first > operation_cursor.saturating_add(1) {
                        self.publish(
                            &name,
                            "source_gap",
                            json!({"process": name,
                            "generation": generation, "source": "operations"}),
                            None,
                        );
                    }
                }
                for event in events {
                    if let Some(sequence) = event["sequence"].as_u64() {
                        if sequence > operation_cursor {
                            operation_cursor = sequence;
                            self.publish(
                                &name,
                                "operation_updated",
                                json!({
                                "process": name, "generation": generation,
                                "event": event}),
                                None,
                            );
                        }
                    }
                }
            }
            if let Some(instances) = snapshot["data"]["instances"].as_object_mut() {
                for (instance, state) in instances {
                    let events = state
                        .as_object_mut()
                        .and_then(|s| s.remove("events"))
                        .unwrap_or(json!([]));
                    let after = seen.entry(instance.clone()).or_default();
                    if let Some(events) = events.as_array() {
                        if let Some(first) = events.first().and_then(|e| e["sequence"].as_u64()) {
                            if first > after.saturating_add(1) {
                                self.publish(&name, "source_gap", json!({"process": name, "instance": instance, "generation": generation, "after": after, "oldest_available": first}), None);
                            }
                        }
                        for event in events {
                            let Some(sequence) = event["sequence"].as_u64() else {
                                continue;
                            };
                            if sequence <= *after {
                                continue;
                            }
                            *after = sequence;
                            let kind = event["kind"].as_str().unwrap_or("runtime_event");
                            self.publish(&name, kind, json!({"process": name, "instance": instance, "generation": generation, "event": event}), None);
                        }
                    }
                }
            }
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let current = json!({"online": true, "generation": generation, "data": snapshot["data"], "last_success_unix_ms": timestamp});
            self.publish(
                &name,
                "snapshot",
                json!({"process": name, "state": current}),
                Some(current.clone()),
            );
        }
    }

    /// Dropping this future drops all process pollers; it owns no detached tasks.
    pub async fn poll(self: Arc<Self>) {
        let mut work = FuturesUnordered::new();
        for (name, client) in &self.clients {
            work.push(self.clone().poll_process(name.clone(), client.clone()));
        }
        if work.is_empty() {
            std::future::pending::<()>().await;
        }
        while work.next().await.is_some() {}
    }

    fn next(&self, cursor: Option<u64>, process: Option<&str>) -> Option<(u64, String, Value)> {
        let view = self.view.lock().unwrap();
        let reset = cursor.is_none_or(|n| {
            n > view.sequence
                || view
                    .history
                    .front()
                    .is_some_and(|e| n.saturating_add(1) < e.sequence)
        });
        if reset {
            let processes: BTreeMap<_, _> = view
                .processes
                .iter()
                .filter(|(name, _)| process.is_none_or(|p| p == name.as_str()))
                .collect();
            return Some((
                view.sequence,
                "reset".into(),
                json!({"epoch": self.epoch, "sequence": view.sequence, "processes": processes}),
            ));
        }
        view.history
            .iter()
            .find(|e| e.sequence > cursor.unwrap())
            .map(|e| {
                if process.is_some_and(|p| p != e.process) {
                    (e.sequence, "cursor".into(), Value::Null)
                } else {
                    (e.sequence, e.kind.clone(), e.data.clone())
                }
            })
    }
}

async fn root() -> Redirect {
    Redirect::temporary("/mints")
}

async fn mints() -> Response {
    let mut response = Html(include_str!("ui/mints.html")).into_response();
    let headers = response.headers_mut();
    headers.insert(
        "content-security-policy",
        "default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    headers.insert("cache-control", "no-store".parse().unwrap());
    response
}

async fn mints_css() -> impl IntoResponse {
    (
        [
            ("content-type", "text/css; charset=utf-8"),
            ("cache-control", "no-store"),
        ],
        include_str!("ui/mints.css"),
    )
}

async fn mints_js() -> impl IntoResponse {
    (
        [
            ("content-type", "text/javascript; charset=utf-8"),
            ("cache-control", "no-store"),
        ],
        include_str!("ui/mints.js"),
    )
}

async fn snapshot(State(state): State<Arc<Aggregator>>) -> Json<Value> {
    Json(state.snapshot())
}

#[derive(Deserialize)]
struct EventQuery {
    process: Option<String>,
}

async fn events(
    State(state): State<Arc<Aggregator>>,
    headers: HeaderMap,
    Query(query): Query<EventQuery>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, &'static str)> {
    if query
        .process
        .as_ref()
        .is_some_and(|p| !state.clients.contains_key(p))
    {
        return Err((StatusCode::NOT_FOUND, "unknown process"));
    }
    let cursor = headers
        .get("last-event-id")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split_once(':'))
        .and_then(|(epoch, seq)| {
            if epoch == state.epoch {
                seq.parse::<u64>().ok()
            } else {
                None
            }
        });
    let changes = state.changed.subscribe();
    let stream = stream::unfold(
        (state, changes, cursor, query.process),
        |(state, mut changes, mut cursor, process)| async move {
            loop {
                changes.borrow_and_update();
                if let Some((sequence, kind, data)) = state.next(cursor, process.as_deref()) {
                    cursor = Some(sequence);
                    // Filtered events still advance the cursor without allocating an
                    // unbounded per-subscriber backlog.
                    if kind == "cursor" {
                        continue;
                    }
                    let event = Event::default()
                        .id(format!("{}:{sequence}", state.epoch))
                        .event(kind)
                        .data(data.to_string());
                    return Some((Ok(event), (state, changes, cursor, process)));
                }
                if changes.changed().await.is_err() {
                    return None;
                }
            }
        },
    );
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(5))))
}

async fn command(
    State(state): State<Arc<Aggregator>>,
    Path(name): Path<String>,
    Json(command): Json<crate::Command>,
) -> (StatusCode, Json<Value>) {
    let Some(client) = state.clients.get(&name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown process"})),
        );
    };
    forward(client.post("http://localhost/v1/commands").json(&command)).await
}

async fn operation(
    State(state): State<Arc<Aggregator>>,
    Path((name, id)): Path<(String, String)>,
) -> (StatusCode, Json<Value>) {
    let Some(client) = state.clients.get(&name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "unknown process"})),
        );
    };
    let mut url = reqwest::Url::parse("http://localhost/v1/operations/").unwrap();
    url.path_segments_mut().unwrap().pop_if_empty().push(&id);
    forward(client.get(url)).await
}

async fn forward(request: reqwest::RequestBuilder) -> (StatusCode, Json<Value>) {
    match request.send().await {
        Ok(response) => {
            let status = response.status();
            match response.json().await {
                Ok(value) => (status, Json(value)),
                Err(_) => (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": "invalid process response"})),
                ),
            }
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(
                json!({"error": "process unavailable; command outcome may be unknown; retry the identical request_id"}),
            ),
        ),
    }
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<Aggregator>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> std::io::Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "management TCP listener must bind loopback",
        ));
    }
    let server = crate::serve_owned(listener, state.router(), shutdown);
    tokio::pin!(server);
    let poll = state.poll();
    tokio::pin!(poll);
    tokio::select! {
        result = &mut server => result,
        () = &mut poll => Err(std::io::Error::other("process pollers stopped")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_replay_resets_after_gap_and_replays_in_order() {
        let state = Aggregator::new(BTreeMap::new()).unwrap();
        for n in 0..600 {
            state.publish("p", "payment", json!({"n": n}), None);
        }
        let (seq, kind, _) = state.next(Some(1), None).unwrap();
        assert_eq!((seq, kind.as_str()), (600, "reset"));
        let (seq, kind, data) = state.next(Some(599), None).unwrap();
        assert_eq!((seq, kind.as_str()), (600, "payment"));
        assert_eq!(data["n"], 599);
        assert!(state.next(Some(600), None).is_none());
        assert_eq!(state.next(Some(601), None).unwrap().1, "reset");
    }
}
