use crate::listener::TrustedMintUnits;
use crate::wallet_manager::RelayWalletManager;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
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
    RequestTooLarge,
    UntrustedMint,
    UntrustedUnit,
    Timeout,
    RefreshFailed(String),
}

impl std::fmt::Display for KeysetRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestTooLarge => write!(f, "keyset refresh request too large"),
            Self::UntrustedMint => write!(f, "keyset refresh mint is not trusted"),
            Self::UntrustedUnit => write!(f, "keyset refresh unit is not trusted for mint"),
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
    pub success_cooldown: Duration,
    pub failure_cooldown: Duration,
    pub timeout: Duration,
    pub max_concurrent_refreshes: usize,
}

impl Default for KeysetRefreshConfig {
    fn default() -> Self {
        Self {
            success_cooldown: Duration::from_secs(60),
            failure_cooldown: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
            max_concurrent_refreshes: 2,
        }
    }
}

#[derive(Debug, Default)]
struct MintRefreshState {
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
}

#[derive(Debug, Default)]
struct MintRefreshSlot {
    state: Mutex<MintRefreshState>,
}

pub struct RelayKeysetRefreshCoordinator {
    refresher: Arc<dyn KeysetRefresher>,
    trusted_mint_units: TrustedMintUnits,
    slots: Mutex<BTreeMap<String, Arc<MintRefreshSlot>>>,
    global_semaphore: Semaphore,
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
            global_semaphore: Semaphore::new(config.max_concurrent_refreshes.max(1)),
            config,
        }
    }

    pub(crate) async fn refresh_mint_unit(
        &self,
        mint_url: &str,
        unit: &str,
    ) -> Result<KeysetRefreshOutcome, KeysetRefreshError> {
        self.validate_request(mint_url, unit)?;
        let slot = self.slot_for_mint(mint_url).await;
        let mut state = slot.state.lock().await;
        let now = Instant::now();

        if state
            .last_success
            .is_some_and(|last| now.duration_since(last) < self.config.success_cooldown)
            || state
                .last_failure
                .is_some_and(|last| now.duration_since(last) < self.config.failure_cooldown)
        {
            return Ok(KeysetRefreshOutcome::SkippedCooldown);
        }

        let _permit = self.global_semaphore.acquire().await.map_err(|_| {
            KeysetRefreshError::RefreshFailed("refresh semaphore closed".to_string())
        })?;
        let result = timeout(self.config.timeout, self.refresher.refresh_mint(mint_url)).await;

        match result {
            Ok(Ok(())) => {
                state.last_success = Some(Instant::now());
                Ok(KeysetRefreshOutcome::Refreshed)
            }
            Ok(Err(error)) => {
                state.last_failure = Some(Instant::now());
                Err(KeysetRefreshError::RefreshFailed(error))
            }
            Err(_) => {
                state.last_failure = Some(Instant::now());
                Err(KeysetRefreshError::Timeout)
            }
        }
    }

    fn validate_request(&self, mint_url: &str, unit: &str) -> Result<(), KeysetRefreshError> {
        if mint_url.len() > MAX_REFRESH_MINT_URL_LEN || unit.len() > MAX_REFRESH_UNIT_LEN {
            return Err(KeysetRefreshError::RequestTooLarge);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingRefresher {
        calls: AtomicUsize,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        delay: Duration,
        result: std::sync::Mutex<Result<(), String>>,
    }

    impl CountingRefresher {
        fn new(delay: Duration, result: Result<(), String>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                delay,
                result: std::sync::Mutex::new(result),
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
            success_cooldown: Duration::from_secs(60),
            failure_cooldown: Duration::from_secs(60),
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
        assert_eq!(second, Ok(KeysetRefreshOutcome::SkippedCooldown));
        assert_eq!(refresher.calls(), 1);
        assert_eq!(refresher.max_in_flight(), 1);
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
        assert_eq!(refresher.calls(), 1);
    }

    #[tokio::test]
    async fn coordinator_global_semaphore_limits_cross_mint_concurrency() {
        let refresher = CountingRefresher::new(Duration::from_millis(50), Ok(()));
        let mut config = config();
        config.success_cooldown = Duration::ZERO;
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

        assert_eq!(first, Ok(KeysetRefreshOutcome::Refreshed));
        assert_eq!(second, Ok(KeysetRefreshOutcome::Refreshed));
        assert_eq!(refresher.calls(), 2);
        assert_eq!(refresher.max_in_flight(), 1);
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
            Err(KeysetRefreshError::RequestTooLarge)
        );
        let long_unit = "x".repeat(MAX_REFRESH_UNIT_LEN + 1);
        assert_eq!(
            coordinator
                .refresh_mint_unit("https://mint", &long_unit)
                .await,
            Err(KeysetRefreshError::RequestTooLarge)
        );
        assert_eq!(refresher.calls(), 0);
    }
}
