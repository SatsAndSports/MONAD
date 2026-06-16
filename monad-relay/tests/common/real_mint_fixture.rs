//! Shared in-memory Cashu mint fixture for real-crypto integration tests.
//!
//! The mint is created once and reused across tests. Each test still gets its
//! own relay, SQLite backing store, wallet, and channels.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use cdk::mint::Mint;
use cdk_spilman_test_mint::TestMintHelper;
use monad_relay::listener::SpilmanMintCache;
use tokio::sync::OnceCell;

use super::signing_wallet::TestSigningWallet;

const TEST_MINT_URL: &str = "https://test-mint.invalid";
const TEST_UNIT: &str = "sat";

/// Real mint metadata shared across the relay integration test suite.
pub struct SharedRealMint {
    mint: Arc<Mint>,
    keyset_id: String,
    keyset_info_json: String,
    mint_cache: SpilmanMintCache,
    trusted_mint_units: BTreeMap<String, BTreeSet<String>>,
}

impl SharedRealMint {
    /// The shared mint instance.
    pub fn mint(&self) -> Arc<Mint> {
        Arc::clone(&self.mint)
    }

    /// Cache describing this mint/keyset for relay advertisement.
    pub fn mint_cache(&self) -> SpilmanMintCache {
        self.mint_cache.clone()
    }

    /// Trusted mint/unit map for relay config.
    pub fn trusted_mint_units(&self) -> BTreeMap<String, BTreeSet<String>> {
        self.trusted_mint_units.clone()
    }

    /// Build a wallet that signs payments for `receiver_pubkey_hex` using this
    /// shared mint.
    pub async fn wallet_for(&self, receiver_pubkey_hex: String) -> TestSigningWallet {
        TestSigningWallet::new(
            self.mint(),
            receiver_pubkey_hex,
            TEST_MINT_URL.to_string(),
            self.keyset_id.clone(),
            self.keyset_info_json.clone(),
        )
        .await
    }
}

static SHARED_MINT: OnceCell<Arc<SharedRealMint>> = OnceCell::const_new();

/// Get the shared real-mint fixture, creating it on first call.
pub async fn shared_real_mint() -> Arc<SharedRealMint> {
    SHARED_MINT
        .get_or_init(|| async {
            let helper = TestMintHelper::new()
                .await
                .expect("failed to create test mint");
            let mint = helper.mint();
            let keyset_id = helper.keyset_id().to_string();
            let keyset_info_json = helper
                .keyset_info_json()
                .expect("failed to get keyset info JSON");

            let mint_cache = SpilmanMintCache {
                advertised: BTreeMap::from([(
                    TEST_MINT_URL.to_string(),
                    BTreeMap::from([(TEST_UNIT.to_string(), vec![keyset_id.clone()])]),
                )]),
                keyset_info_json_by_mint: BTreeMap::from([(
                    TEST_MINT_URL.to_string(),
                    BTreeMap::from([(keyset_id.clone(), keyset_info_json.clone())]),
                )]),
            };

            let trusted_mint_units = BTreeMap::from([(
                TEST_MINT_URL.to_string(),
                BTreeSet::from([TEST_UNIT.to_string()]),
            )]);

            Arc::new(SharedRealMint {
                mint,
                keyset_id,
                keyset_info_json,
                mint_cache,
                trusted_mint_units,
            })
        })
        .await
        .clone()
}
