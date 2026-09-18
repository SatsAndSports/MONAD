use crate::listener::TrustedMintUnits;
use crate::wallet_manager::RelayWalletManager;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{watch, Mutex, Semaphore, TryAcquireError};
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration, Instant};

const MAX_REFRESH_MINT_URL_LEN: usize = 2048;
const MAX_REFRESH_UNIT_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeysetRefreshOutcome {
    Refreshed,
    SkippedCooldown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeysetRefreshError {
    TargetTooLarge,
    UntrustedMint,
    UntrustedUnit,
    Busy,
    Timeout,
    RefreshFailed(String),
}

impl std::fmt::Display for KeysetRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetTooLarge => write!(f, "keyset refresh target too large"),
            Self::UntrustedMint => write!(f, "keyset refresh mint is not trusted"),
            Self::UntrustedUnit => write!(f, "keyset refresh unit is not trusted for mint"),
            Self::Busy => write!(f, "keyset refresh service is busy"),
            Self::Timeout => write!(f, "keyset refresh timed out"),
            Self::RefreshFailed(message) => write!(f, "keyset refresh failed: {message}"),
        }
    }
}

impl std::error::Error for KeysetRefreshError {}

#[async_trait]
pub(crate) trait KeysetRefresher: Send + Sync {
    async fn refresh_mint(&self, mint_url: &str) -> Result<(), String>;
}

#[async_trait]
impl KeysetRefresher for RelayWalletManager {
    async fn refresh_mint(&self, mint_url: &str) -> Result<(), String> {
        self.refresh_all_keysets_for_mint_into_shared_cache(mint_url)
            .await
    }
}

#[derive(Debug, Clone)]
pub struct KeysetRefreshConfig {
    pub refresh_cooldown: Duration,
    pub timeout: Duration,
    pub max_concurrent_refreshes: usize,
}

impl Default for KeysetRefreshConfig {
    fn default() -> Self {
        Self {
            refresh_cooldown: Duration::from_secs(60),
            timeout: Duration::from_secs(5),
            max_concurrent_refreshes: 2,
        }
    }
}

#[derive(Debug, Default)]
struct MintRefreshState {
    last_attempt_started: Option<Instant>,
    in_flight: Option<watch::Receiver<Option<RefreshResult>>>,
}

type RefreshResult = Result<KeysetRefreshOutcome, KeysetRefreshError>;

#[derive(Debug, Default)]
struct MintRefreshSlot {
    state: Mutex<MintRefreshState>,
}

pub struct RelayKeysetRefreshCoordinator {
    refresher: Arc<dyn KeysetRefresher>,
    trusted_mint_units: TrustedMintUnits,
    slots: Mutex<BTreeMap<String, Arc<MintRefreshSlot>>>,
    global_semaphore: Arc<Semaphore>,
    tasks: Mutex<JoinSet<()>>,
    shutting_down: AtomicBool,
    config: KeysetRefreshConfig,
}

impl RelayKeysetRefreshCoordinator {
    pub fn new(
        wallet_manager: Arc<RelayWalletManager>,
        trusted_mint_units: TrustedMintUnits,
    ) -> Self {
        Self::with_config(
            wallet_manager,
            trusted_mint_units,
            KeysetRefreshConfig::default(),
        )
    }

    pub fn with_config(
        wallet_manager: Arc<RelayWalletManager>,
        trusted_mint_units: TrustedMintUnits,
        config: KeysetRefreshConfig,
    ) -> Self {
        Self::with_refresher(wallet_manager, trusted_mint_units, config)
    }

    pub(crate) fn with_refresher(
        refresher: Arc<dyn KeysetRefresher>,
        trusted_mint_units: TrustedMintUnits,
        config: KeysetRefreshConfig,
    ) -> Self {
        Self {
            refresher,
            trusted_mint_units,
            slots: Mutex::new(BTreeMap::new()),
            global_semaphore: Arc::new(Semaphore::new(config.max_concurrent_refreshes.max(1))),
            tasks: Mutex::new(JoinSet::new()),
            shutting_down: AtomicBool::new(false),
            config,
        }
    }

    pub(crate) async fn refresh_mint_unit(&self, mint_url: &str, unit: &str) -> RefreshResult {
        self.validate_request(mint_url, unit)?;
        let mut tasks = self.tasks.lock().await;
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                tracing::error!(%error, "keyset refresh coordinator task failed");
            }
        }
        if self.shutting_down.load(Ordering::Acquire) {
            return Err(KeysetRefreshError::RefreshFailed(
                "keyset refresh coordinator is shutting down".to_string(),
            ));
        }
        let slot = self.slot_for_mint(mint_url).await;
        let mut state = slot.state.lock().await;
        let now = Instant::now();

        if let Some(receiver) = &state.in_flight {
            let receiver = receiver.clone();
            drop(tasks);
            drop(state);
            return wait_for_refresh_result(receiver).await;
        }
        if state
            .last_attempt_started
            .is_some_and(|last| now.duration_since(last) < self.config.refresh_cooldown)
        {
            return Ok(KeysetRefreshOutcome::SkippedCooldown);
        }

        let permit = match self.global_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => return Err(KeysetRefreshError::Busy),
            Err(TryAcquireError::Closed) => {
                return Err(KeysetRefreshError::RefreshFailed(
                    "refresh semaphore closed".to_string(),
                ))
            }
        };
        state.last_attempt_started = Some(now);
        let (result_tx, result_rx) = watch::channel(None);
        state.in_flight = Some(result_rx.clone());
        drop(state);

        let refresher = self.refresher.clone();
        let mint_url = mint_url.to_string();
        let refresh_timeout = self.config.timeout;
        tasks.spawn(async move {
            let mut refresh_tasks = JoinSet::new();
            refresh_tasks.spawn(async move {
                let _permit = permit;
                match timeout(refresh_timeout, refresher.refresh_mint(&mint_url)).await {
                    Ok(Ok(())) => Ok(KeysetRefreshOutcome::Refreshed),
                    Ok(Err(error)) => Err(KeysetRefreshError::RefreshFailed(error)),
                    Err(_) => Err(KeysetRefreshError::Timeout),
                }
            });
            let result = match refresh_tasks.join_next().await {
                Some(Ok(result)) => result,
                None => Err(KeysetRefreshError::RefreshFailed(
                    "refresh task ended without a result".to_string(),
                )),
                Some(Err(error)) => Err(KeysetRefreshError::RefreshFailed(format!(
                    "refresh task failed: {error}"
                ))),
            };
            result_tx.send_replace(Some(result));
            slot.state.lock().await.in_flight = None;
        });
        drop(tasks);

        wait_for_refresh_result(result_rx).await
    }

    pub async fn shutdown_and_drain(&self) {
        self.shutting_down.store(true, Ordering::Release);
        self.global_semaphore.close();
        let mut tasks = self.tasks.lock().await;
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                if !error.is_cancelled() {
                    tracing::error!(%error, "keyset refresh coordinator task failed while draining");
                }
            }
        }
    }

    fn validate_request(&self, mint_url: &str, unit: &str) -> Result<(), KeysetRefreshError> {
        if mint_url.len() > MAX_REFRESH_MINT_URL_LEN || unit.len() > MAX_REFRESH_UNIT_LEN {
            return Err(KeysetRefreshError::TargetTooLarge);
        }
        let trusted_units = self
            .trusted_mint_units
            .get(mint_url)
            .ok_or(KeysetRefreshError::UntrustedMint)?;
        if !trusted_units.contains(unit) {
            return Err(KeysetRefreshError::UntrustedUnit);
        }
        Ok(())
    }

    async fn slot_for_mint(&self, mint_url: &str) -> Arc<MintRefreshSlot> {
        let mut slots = self.slots.lock().await;
        slots
            .entry(mint_url.to_string())
            .or_insert_with(|| Arc::new(MintRefreshSlot::default()))
            .clone()
    }
}

async fn wait_for_refresh_result(
    mut receiver: watch::Receiver<Option<RefreshResult>>,
) -> RefreshResult {
    loop {
        if let Some(result) = receiver.borrow().clone() {
            return result;
        }
        receiver.changed().await.map_err(|_| {
            KeysetRefreshError::RefreshFailed("refresh task ended without a result".to_string())
        })?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    struct CountingRefresher {
        calls: AtomicUsize,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        delay: Duration,
        result: std::sync::Mutex<Result<(), String>>,
        started: Notify,
    }

    struct PanicOnceRefresher {
        calls: AtomicUsize,
    }

    struct GatedRefresher {
        calls: AtomicUsize,
        started: Notify,
        release: Notify,
        completed: AtomicBool,
    }

    #[async_trait]
    impl KeysetRefresher for GatedRefresher {
        async fn refresh_mint(&self, _mint_url: &str) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            self.release.notified().await;
            self.completed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl KeysetRefresher for PanicOnceRefresher {
        async fn refresh_mint(&self, _mint_url: &str) -> Result<(), String> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("deterministic refresh panic");
            }
            Ok(())
        }
    }

    impl CountingRefresher {
        fn new(delay: Duration, result: Result<(), String>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                delay,
                result: std::sync::Mutex::new(result),
                started: Notify::new(),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn max_in_flight(&self) -> usize {
            self.max_in_flight.load(Ordering::SeqCst)
        }
    }

    struct InFlightGuard<'a>(&'a AtomicUsize);

    impl Drop for InFlightGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl KeysetRefresher for CountingRefresher {
        async fn refresh_mint(&self, _mint_url: &str) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            let in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            let _guard = InFlightGuard(&self.in_flight);
            update_max(&self.max_in_flight, in_flight);
            tokio::time::sleep(self.delay).await;
            self.result.lock().unwrap().clone()
        }
    }

    fn update_max(max: &AtomicUsize, candidate: usize) {
        let mut current = max.load(Ordering::SeqCst);
        while candidate > current {
            match max.compare_exchange(current, candidate, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return,
                Err(next) => current = next,
            }
        }
    }

    fn trusted(units: &[(&str, &[&str])]) -> TrustedMintUnits {
        units
            .iter()
            .map(|(mint, units)| {
                (
                    (*mint).to_string(),
                    units.iter().map(|unit| (*unit).to_string()).collect(),
                )
            })
            .collect()
    }

    fn config() -> KeysetRefreshConfig {
        KeysetRefreshConfig {
            refresh_cooldown: Duration::from_secs(60),
            timeout: Duration::from_secs(5),
            max_concurrent_refreshes: 2,
        }
    }

    #[tokio::test]
    async fn coordinator_success_cooldown_skips_second_fetch() {
        let refresher = CountingRefresher::new(Duration::ZERO, Ok(()));
        let coordinator = RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint", &["sat"])]),
            config(),
        );

        assert_eq!(
            coordinator.refresh_mint_unit("https://mint", "sat").await,
            Ok(KeysetRefreshOutcome::Refreshed)
        );
        assert_eq!(
            coordinator.refresh_mint_unit("https://mint", "sat").await,
            Ok(KeysetRefreshOutcome::SkippedCooldown)
        );
        assert_eq!(refresher.calls(), 1);
    }

    #[tokio::test]
    async fn coordinator_failure_cooldown_skips_second_fetch() {
        let refresher = CountingRefresher::new(Duration::ZERO, Err("boom".to_string()));
        let coordinator = RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint", &["sat"])]),
            config(),
        );

        assert_eq!(
            coordinator.refresh_mint_unit("https://mint", "sat").await,
            Err(KeysetRefreshError::RefreshFailed("boom".to_string()))
        );
        assert_eq!(
            coordinator.refresh_mint_unit("https://mint", "sat").await,
            Ok(KeysetRefreshOutcome::SkippedCooldown)
        );
        assert_eq!(refresher.calls(), 1);
    }

    #[tokio::test]
    async fn coordinator_singleflights_same_mint() {
        let refresher = CountingRefresher::new(Duration::from_millis(50), Ok(()));
        let coordinator = RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint", &["sat"])]),
            config(),
        );

        let (first, second) = tokio::join!(
            coordinator.refresh_mint_unit("https://mint", "sat"),
            coordinator.refresh_mint_unit("https://mint", "sat"),
        );

        assert_eq!(first, Ok(KeysetRefreshOutcome::Refreshed));
        assert_eq!(second, Ok(KeysetRefreshOutcome::Refreshed));
        assert_eq!(refresher.calls(), 1);
        assert_eq!(refresher.max_in_flight(), 1);
    }

    #[tokio::test]
    async fn coordinator_shares_same_mint_failure() {
        let refresher = CountingRefresher::new(Duration::from_millis(50), Err("boom".to_string()));
        let coordinator = RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint", &["sat"])]),
            config(),
        );

        let (first, second) = tokio::join!(
            coordinator.refresh_mint_unit("https://mint", "sat"),
            coordinator.refresh_mint_unit("https://mint", "sat"),
        );

        let expected = Err(KeysetRefreshError::RefreshFailed("boom".to_string()));
        assert_eq!(first, expected);
        assert_eq!(second, expected);
        assert_eq!(refresher.calls(), 1);
    }

    #[tokio::test]
    async fn coordinator_times_out_slow_refresh() {
        let refresher = CountingRefresher::new(Duration::from_millis(200), Ok(()));
        let mut config = config();
        config.timeout = Duration::from_millis(20);
        let coordinator = RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint", &["sat"])]),
            config,
        );

        assert_eq!(
            coordinator.refresh_mint_unit("https://mint", "sat").await,
            Err(KeysetRefreshError::Timeout)
        );
        assert_eq!(
            coordinator.refresh_mint_unit("https://mint", "sat").await,
            Ok(KeysetRefreshOutcome::SkippedCooldown)
        );
        assert_eq!(refresher.calls(), 1);
    }

    #[tokio::test]
    async fn coordinator_global_saturation_is_busy_without_starting_cooldown() {
        let refresher = CountingRefresher::new(Duration::from_millis(50), Ok(()));
        let mut config = config();
        config.refresh_cooldown = Duration::ZERO;
        config.max_concurrent_refreshes = 1;
        let coordinator = RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint-a", &["sat"]), ("https://mint-b", &["sat"])]),
            config,
        );

        let (first, second) = tokio::join!(
            coordinator.refresh_mint_unit("https://mint-a", "sat"),
            coordinator.refresh_mint_unit("https://mint-b", "sat"),
        );

        assert!(matches!(
            (&first, &second),
            (
                Ok(KeysetRefreshOutcome::Refreshed),
                Err(KeysetRefreshError::Busy)
            ) | (
                Err(KeysetRefreshError::Busy),
                Ok(KeysetRefreshOutcome::Refreshed)
            )
        ));
        let busy_mint = if first == Err(KeysetRefreshError::Busy) {
            "https://mint-a"
        } else {
            "https://mint-b"
        };
        assert_eq!(
            coordinator.refresh_mint_unit(busy_mint, "sat").await,
            Ok(KeysetRefreshOutcome::Refreshed)
        );
        assert_eq!(refresher.calls(), 2);
        assert_eq!(refresher.max_in_flight(), 1);
    }

    #[tokio::test]
    async fn coordinator_refresh_survives_initiating_caller_cancellation() {
        let refresher = CountingRefresher::new(Duration::from_millis(50), Ok(()));
        let coordinator = Arc::new(RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint", &["sat"])]),
            config(),
        ));
        let started = refresher.started.notified();
        let task_coordinator = coordinator.clone();
        let task = tokio::spawn(async move {
            task_coordinator
                .refresh_mint_unit("https://mint", "sat")
                .await
        });
        started.await;
        task.abort();

        assert_eq!(
            coordinator.refresh_mint_unit("https://mint", "sat").await,
            Ok(KeysetRefreshOutcome::Refreshed)
        );
        assert_eq!(refresher.calls(), 1);
    }

    #[tokio::test]
    async fn coordinator_recovers_after_refresh_task_panics() {
        let refresher = Arc::new(PanicOnceRefresher {
            calls: AtomicUsize::new(0),
        });
        let mut config = config();
        config.refresh_cooldown = Duration::ZERO;
        let coordinator = RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint", &["sat"])]),
            config,
        );

        let first = coordinator.refresh_mint_unit("https://mint", "sat").await;
        assert!(matches!(
            first,
            Err(KeysetRefreshError::RefreshFailed(message))
                if message.contains("refresh task failed")
        ));
        assert_eq!(
            coordinator.refresh_mint_unit("https://mint", "sat").await,
            Ok(KeysetRefreshOutcome::Refreshed)
        );
        assert_eq!(refresher.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn coordinator_rejects_policy_and_size_without_fetch() {
        let refresher = CountingRefresher::new(Duration::ZERO, Ok(()));
        let coordinator = RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint", &["sat"])]),
            config(),
        );

        assert_eq!(
            coordinator
                .refresh_mint_unit("https://other-mint", "sat")
                .await,
            Err(KeysetRefreshError::UntrustedMint)
        );
        assert_eq!(
            coordinator.refresh_mint_unit("https://mint", "usd").await,
            Err(KeysetRefreshError::UntrustedUnit)
        );
        let long_mint = "x".repeat(MAX_REFRESH_MINT_URL_LEN + 1);
        assert_eq!(
            coordinator.refresh_mint_unit(&long_mint, "sat").await,
            Err(KeysetRefreshError::TargetTooLarge)
        );
        let long_unit = "x".repeat(MAX_REFRESH_UNIT_LEN + 1);
        assert_eq!(
            coordinator
                .refresh_mint_unit("https://mint", &long_unit)
                .await,
            Err(KeysetRefreshError::TargetTooLarge)
        );
        assert_eq!(refresher.calls(), 0);
    }

    #[tokio::test]
    async fn coordinator_shutdown_drains_refresh_and_rejects_new_work() {
        let refresher = Arc::new(GatedRefresher {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            release: Notify::new(),
            completed: AtomicBool::new(false),
        });
        let coordinator = Arc::new(RelayKeysetRefreshCoordinator::with_refresher(
            refresher.clone(),
            trusted(&[("https://mint", &["sat"])]),
            config(),
        ));
        let refresh_coordinator = coordinator.clone();
        let refresh = tokio::spawn(async move {
            refresh_coordinator
                .refresh_mint_unit("https://mint", "sat")
                .await
        });
        refresher.started.notified().await;

        let shutdown_coordinator = coordinator.clone();
        let mut shutdown = tokio::spawn(async move {
            shutdown_coordinator.shutdown_and_drain().await;
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                .await
                .is_err(),
            "shutdown returned before the owned refresh completed"
        );
        refresher.release.notify_one();
        shutdown.await.unwrap();
        assert_eq!(refresh.await.unwrap(), Ok(KeysetRefreshOutcome::Refreshed));
        assert!(refresher.completed.load(Ordering::SeqCst));
        assert_eq!(refresher.calls.load(Ordering::SeqCst), 1);

        let error = coordinator
            .refresh_mint_unit("https://mint", "sat")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            KeysetRefreshError::RefreshFailed(message) if message.contains("shutting down")
        ));
        assert_eq!(refresher.calls.load(Ordering::SeqCst), 1);
    }
}
