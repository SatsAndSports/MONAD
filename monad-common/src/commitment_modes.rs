//! Admission policy is separate from a channel's authenticated parameters.
pub use cdk_spilman::CommitmentMode;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ModePolicyWire")]
pub struct ModePolicy {
    pub accepted: Vec<CommitmentMode>,
    pub preferred: CommitmentMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModePolicyWire {
    accepted: Vec<CommitmentMode>,
    preferred: CommitmentMode,
}

impl TryFrom<ModePolicyWire> for ModePolicy {
    type Error = &'static str;
    fn try_from(wire: ModePolicyWire) -> Result<Self, Self::Error> {
        if wire.accepted.is_empty()
            || wire.accepted.len() > 2
            || (wire.accepted.len() == 2 && wire.accepted[0] == wire.accepted[1])
            || !wire.accepted.contains(&wire.preferred)
        {
            return Err("accepted modes must be nonempty and unique; preferred must be accepted");
        }
        Ok(Self {
            accepted: wire.accepted,
            preferred: wire.preferred,
        })
    }
}

impl Default for ModePolicy {
    fn default() -> Self {
        Self {
            accepted: vec![CommitmentMode::Ordinary],
            preferred: CommitmentMode::Ordinary,
        }
    }
}

impl ModePolicy {
    pub fn dual_mode() -> Self {
        Self {
            accepted: vec![CommitmentMode::Ordinary, CommitmentMode::Rerandomized],
            preferred: CommitmentMode::Rerandomized,
        }
    }
    pub fn intersect(&self, supports: impl Fn(CommitmentMode) -> bool) -> Option<Self> {
        let accepted: Vec<_> = self
            .accepted
            .iter()
            .copied()
            .filter(|&mode| supports(mode))
            .collect();
        let preferred = if accepted.contains(&self.preferred) {
            self.preferred
        } else {
            *accepted.first()?
        };
        Some(Self {
            accepted,
            preferred,
        })
    }
}

pub fn deserialize_mint_policies<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, ModePolicy>, D::Error> {
    let entries = BTreeMap::<String, ModePolicy>::deserialize(deserializer)?;
    let mut normalized = BTreeMap::new();
    for (mint, policy) in entries {
        if normalized
            .insert(mint.trim_end_matches('/').to_owned(), policy)
            .is_some()
        {
            return Err(serde::de::Error::custom(
                "duplicate normalized mint mode policy",
            ));
        }
    }
    Ok(normalized)
}

/// A session owns this immutable snapshot. Ordinary swaps are baseline Cashu;
/// rerandomized swaps require the optional NUT-03 capability to be confirmed.
#[derive(Debug, Clone, Default)]
pub struct SessionModePolicy {
    pub default: ModePolicy,
    pub overrides: BTreeMap<String, ModePolicy>,
    pub rerandomized_mints: BTreeSet<String>,
}

impl SessionModePolicy {
    pub fn requires_discovery(&self, mint: &str) -> bool {
        self.overrides
            .get(mint.trim_end_matches('/'))
            .unwrap_or(&self.default)
            .accepted
            .contains(&CommitmentMode::Rerandomized)
    }
    pub fn offer(&self, mint: &str) -> Option<ModePolicy> {
        let mint = mint.trim_end_matches('/');
        self.overrides
            .get(mint)
            .unwrap_or(&self.default)
            .intersect(|mode| {
                mode == CommitmentMode::Ordinary || self.rerandomized_mints.contains(mint)
            })
    }
    pub fn accepts(&self, mint: &str, mode: CommitmentMode) -> bool {
        self.offer(mint)
            .is_some_and(|offer| offer.accepted.contains(&mode))
    }
}

#[derive(Debug, Default)]
struct Entry {
    value: Mutex<Option<(Instant, Result<bool, String>)>>,
    refresh: tokio::sync::Mutex<()>,
}

/// Independent process-local discovery. Positive/negative observations live for
/// five minutes; failures remain Unknown and retry after 30 seconds. Expired
/// positives are never used after refresh failure. No keys/proofs are persisted.
#[derive(Debug, Default)]
pub struct MintModeCache {
    entries: Mutex<BTreeMap<String, Arc<Entry>>>,
}

fn fresh(entry: &Entry) -> Option<Result<bool, String>> {
    let cached = entry.value.lock().unwrap();
    let (at, value) = cached.as_ref()?;
    let ttl = if value.is_ok() { 300 } else { 30 };
    (at.elapsed() < Duration::from_secs(ttl)).then(|| value.clone())
}

impl MintModeCache {
    pub fn cached(&self, mint: &str) -> Option<Result<bool, String>> {
        self.entries
            .lock()
            .unwrap()
            .get(mint.trim_end_matches('/'))
            .and_then(|entry| fresh(entry))
    }
    pub async fn discover(&self, mint: &str) -> Result<bool, String> {
        let mint = mint.trim_end_matches('/');
        let entry = self
            .entries
            .lock()
            .unwrap()
            .entry(mint.into())
            .or_default()
            .clone();
        if let Some(value) = fresh(&entry) {
            return value;
        }
        let _refresh = entry.refresh.lock().await;
        if let Some(value) = fresh(&entry) {
            return value;
        }
        let value = fetch(mint).await;
        *entry.value.lock().unwrap() = Some((Instant::now(), value.clone()));
        value
    }
    pub fn supported_mints(&self) -> BTreeSet<String> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, entry)| matches!(fresh(entry), Some(Ok(true))))
            .map(|(mint, _)| mint.clone())
            .collect()
    }
}

async fn fetch(mint: &str) -> Result<bool, String> {
    let invalid = || "mint rerandomization capability is unknown/unavailable".to_string();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| invalid())?;
    let mut response = client
        .get(format!("{}/v1/info", mint.trim_end_matches('/')))
        .send()
        .await
        .map_err(|_| invalid())?
        .error_for_status()
        .map_err(|_| invalid())?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
        if body.len() + chunk.len() > 64 * 1024 {
            return Err(invalid());
        }
        body.extend_from_slice(&chunk);
    }
    let info: serde_json::Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
    let nuts = info
        .get("nuts")
        .and_then(|v| v.as_object())
        .ok_or_else(invalid)?;
    let Some(swap) = nuts.get("3") else {
        return Ok(false);
    };
    let swap = swap.as_object().ok_or_else(invalid)?;
    match swap.get("rerandomize") {
        None => Ok(false),
        Some(value) => value.as_bool().ok_or_else(invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn policy_is_strict_and_empty_intersections_are_not_offers() {
        for value in [
            serde_json::json!({"accepted":[], "preferred":"ordinary"}),
            serde_json::json!({"accepted":["ordinary","ordinary"], "preferred":"ordinary"}),
            serde_json::json!({"accepted":["ordinary"], "preferred":"rerandomized"}),
            serde_json::json!({"accepted":["unknown"], "preferred":"unknown"}),
        ] {
            assert!(serde_json::from_value::<ModePolicy>(value).is_err());
        }
        let only = ModePolicy {
            accepted: vec![CommitmentMode::Rerandomized],
            preferred: CommitmentMode::Rerandomized,
        };
        let policy = SessionModePolicy {
            default: ModePolicy::dual_mode(),
            overrides: BTreeMap::from([("only".into(), only)]),
            rerandomized_mints: BTreeSet::from(["supported".into()]),
        };
        assert_eq!(
            policy.offer("supported").unwrap().preferred,
            CommitmentMode::Rerandomized
        );
        assert_eq!(policy.offer("unknown").unwrap(), ModePolicy::default());
        assert!(policy.offer("only").is_none());
        assert!(policy.accepts("supported", CommitmentMode::Ordinary));
    }

    #[test]
    fn configuration_defaults_prefer_rerandomized_and_validate_overrides() {
        let policy: crate::config::RelayChannelPolicyConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(policy.commitment_modes, ModePolicy::dual_mode());
        let policy: crate::config::RelayChannelPolicyConfig = serde_yaml::from_str("mint_commitment_modes:\n  https://mint/:\n    accepted: [ordinary]\n    preferred: ordinary\n").unwrap();
        assert_eq!(
            policy.mint_commitment_modes["https://mint"],
            ModePolicy::default()
        );
        for yaml in [
            "commitment_modes: {accepted: [ordinary], preferred: rerandomized}",
            "mint_commitment_modes:\n  https://mint: {accepted: [ordinary], preferred: ordinary}\n  https://mint/: {accepted: [ordinary], preferred: ordinary}",
        ] { assert!(serde_yaml::from_str::<crate::config::RelayChannelPolicyConfig>(yaml).is_err()); }
    }

    #[tokio::test]
    async fn capability_singleflight_expiry_and_unknown_do_not_turn_into_unsupported() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mint = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let server = tokio::spawn(async move {
            for body in [
                r#"{"nuts":{"3":{"rerandomize":true}}}"#,
                r#"{"nuts":{"3":{"rerandomize":"invalid"}}}"#,
                r#"{"nuts":{}}"#,
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0; 4096];
                let mut header = Vec::new();
                loop {
                    let count = stream.read(&mut buf).await.unwrap();
                    assert!(count > 0);
                    header.extend_from_slice(&buf[..count]);
                    assert!(header.len() <= 16384);
                    if header.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                }
                count.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let cache = Arc::new(MintModeCache::default());
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let mint = mint.clone();
            tasks.spawn(async move { cache.discover(&mint).await });
        }
        while let Some(result) = tasks.join_next().await {
            assert_eq!(result.unwrap(), Ok(true));
        }
        assert_eq!(cache.discover(&format!("{mint}/")).await, Ok(true));
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let frozen = SessionModePolicy {
            default: ModePolicy::dual_mode(),
            overrides: BTreeMap::new(),
            rerandomized_mints: cache.supported_mints(),
        };
        let age = |seconds| {
            let entry = cache.entries.lock().unwrap()[&mint].clone();
            entry.value.lock().unwrap().as_mut().unwrap().0 =
                Instant::now() - Duration::from_secs(seconds);
        };
        age(301);
        assert!(cache.supported_mints().is_empty());
        assert!(cache.discover(&mint).await.is_err());
        assert!(cache.discover(&mint).await.is_err());
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert!(frozen.accepts(&mint, CommitmentMode::Rerandomized));
        age(31);
        assert_eq!(cache.discover(&mint).await, Ok(false));
        age(31);
        assert_eq!(cache.discover(&mint).await, Ok(false));
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        assert!(cache.supported_mints().is_empty());
        server.await.unwrap();
    }
}
