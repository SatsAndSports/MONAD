use super::{
    funding::run_policy_cycle,
    policy::{FundingStrategy, Intent, View},
    reducer::{Event, Phase},
    state::*,
    PaymentPolicy,
};
use crate::wallet::*;
use monad_common::{
    control_exchange::PendingRequest,
    protocol::{ChannelLinkRequest, ChannelPaymentRequest, LinkedChannelStatus},
    proxy::CleartextByteCounters,
    session::SessionPricing,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn fixture(wallet: Arc<dyn MonadWallet>) -> (SessionDriverConfig, DriverState) {
    let offer = RelayPaymentOffer {
        receiver_pubkey: "receiver".into(),
        mint_url: "https://mint".into(),
        unit: "msat".into(),
        negotiated_keyset_versions: ["v1".to_string()].into(),
        funding_keyset_recovery_window_secs: 86400,
        minimum_channel_lifetime_secs: 3600,
        in_bytes_per_millisat: 1,
        out_bytes_per_millisat: 1,
    };
    let config = SessionDriverConfig {
        wallet,
        hop_label: "replacement".into(),
        payment_policy: PaymentPolicy::default(),
        management: None,
        conn: RelayConnectionHandles {
            session_id: [1; 32],
            pricing_handle: Arc::default(),
            spilman_info_handle: Arc::default(),
            cashu_spilman_protocol_version_handle: Arc::default(),
            cashu_spilman_keyset_versions_handle: Arc::default(),
            cleartext_byte_counters: CleartextByteCounters::default(),
        },
    };
    let mut state = DriverState {
        intended_channel_id: Some("A".into()),
        intended_channel_keyset_id: Some("0000000000000001".into()),
        intended_offer: Some(offer),
        cashu_spilman_keyset_versions: Some(["v1".to_string()].into()),
        established_pricing: Some(SessionPricing::new(1, 1)),
        local_session_paid_msats: 100,
        relay_snapshot: Some(RelaySnapshot {
            receiver_pubkey: "receiver".into(),
            advertisements: vec![monad_common::protocol::PaymentOption {
                mint_url: "https://mint".into(),
                unit: "msat".into(),
                funding_keyset_recovery_window_secs: 86400,
                minimum_channel_lifetime_secs: 3600,
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }],
            linked_channel: Some(LinkedChannelStatus {
                channel_id: "A".into(),
                unit: "msat".into(),
                capacity_raw: 1000,
                balance_raw: 100,
            }),
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: 100,
            remaining_milli_sats: 100,
            paused: false,
        }),
        ..Default::default()
    };
    state.exchange.phase = Phase::Active;
    (config, state)
}

struct Once(std::cell::Cell<Option<Intent>>);
impl FundingStrategy for Once {
    fn decide(&self, _: &View) -> Intent {
        self.0.take().unwrap_or(Intent::Wait)
    }
}

#[tokio::test]
async fn failed_link_preparation_releases_candidate_and_does_not_retry_excluded_intent() {
    for retry in [false, true] {
        let wallet = Arc::new(MockWallet::new());
        wallet.insert_channel(channel("A", Some([1; 32]))).unwrap();
        wallet.insert_channel(channel("B", Some([1; 32]))).unwrap();
        let (config, mut state) = fixture(wallet.clone());
        let mut invalid_offer = state.intended_offer.clone().unwrap();
        invalid_offer.receiver_pubkey = "wrong-receiver".into();
        state.acquired = Some((wallet.get_channel("B").unwrap(), invalid_offer.clone()));
        if retry {
            state.intended_channel_id = Some("B".into());
            state.intended_offer = Some(invalid_offer);
            state.relay_snapshot.as_mut().unwrap().linked_channel = None;
        }
        let (client, _peer) = tokio::io::duplex(4096);
        let (mut h2, connection) = h2::client::handshake(client).await.unwrap();
        let task = tokio::spawn(connection);
        let (_, mut send) = h2
            .send_request(
                http::Request::builder()
                    .method("POST")
                    .uri("http://monad/control")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        run_policy_cycle(
            &config,
            &mut state,
            &mut send,
            false,
            &Once(Some(Intent::LinkAcquired).into()),
        )
        .await
        .unwrap();
        assert!(state.acquired.is_none());
        assert!(state.exchange.is_empty());
        assert_eq!(
            state.intended_channel_id.as_deref(),
            if retry { None } else { Some("A") }
        );
        assert!(state.session_excluded_channels.contains("B"));
        assert_eq!(wallet.attachment("B").unwrap(), None);
        assert_eq!(wallet.attachment("A").unwrap(), Some([1; 32]));
        task.abort();
        let _ = task.await;
    }
}

fn channel(id: &str, attached: Option<[u8; 32]>) -> WalletChannel {
    WalletChannel {
        channel_id: id.into(),
        state: WalletChannelState::Open,
        receiver_pubkey: "receiver".into(),
        mint_url: "https://mint".into(),
        unit: "msat".into(),
        keyset_id: "0000000000000001".into(),
        attached_session_id: attached,
        capacity_msats: 1000,
        current_signed_balance_msats: if id == "A" { 100 } else { 0 },
        expiry_timestamp: u64::MAX,
    }
}

#[tokio::test]
async fn acquire_reserves_candidate_without_linking_and_can_release_it() {
    let wallet = Arc::new(MockWallet::new());
    wallet.insert_channel(channel("A", Some([1; 32]))).unwrap();
    wallet.insert_channel(channel("B", None)).unwrap();
    wallet.insert_channel(channel("C", Some([2; 32]))).unwrap();
    let (config, mut state) = fixture(wallet.clone());
    let (client, _peer) = tokio::io::duplex(65536);
    let (mut h2, connection) = h2::client::handshake(client).await.unwrap();
    let task = tokio::spawn(connection);
    let (_, mut send) = h2
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri("http://monad/control")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    run_policy_cycle(
        &config,
        &mut state,
        &mut send,
        false,
        &Once(Some(Intent::AcquireChannel).into()),
    )
    .await
    .unwrap();
    assert_eq!(state.acquired.as_ref().unwrap().0.channel_id, "B");
    assert_eq!(state.intended_channel_id.as_deref(), Some("A"));
    assert!(state.exchange.is_empty());
    assert_eq!(wallet.attachment("B").unwrap(), Some([1; 32]));
    assert!(wallet.attach_channel_to_session("B", [3; 32]).is_err());
    assert_eq!(wallet.attachment("C").unwrap(), Some([2; 32]));
    run_policy_cycle(
        &config,
        &mut state,
        &mut send,
        false,
        &Once(Some(Intent::ReleaseAcquired).into()),
    )
    .await
    .unwrap();
    assert!(state.acquired.is_none());
    assert_eq!(wallet.attachment("B").unwrap(), None);
    assert_eq!(wallet.attachment("A").unwrap(), Some([1; 32]));
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn replacement_executor_preserves_old_owner_on_rejection_and_releases_on_success() {
    use super::funding::{apply_channel_evicted, apply_server_error, finish_replacement};
    use super::reducer::{channel_step, ChannelEvent};
    use monad_common::protocol::{ServerErrorCode, ServerMessage};
    for (accepted, evicted) in [(true, false), (false, false), (false, true)] {
        let wallet = Arc::new(MockWallet::new());
        wallet.insert_channel(channel("A", Some([1; 32]))).unwrap();
        wallet.insert_channel(channel("B", Some([1; 32]))).unwrap();
        let (config, mut state) = fixture(wallet.clone());
        let offer = state.intended_offer.clone().unwrap();
        channel_step(
            &mut state,
            ChannelEvent::Acquired(wallet.get_channel("B").unwrap(), offer.clone()),
        );
        // Select B exactly as the link-submission executor does, retaining A.
        state.acquired.take();
        channel_step(
            &mut state,
            ChannelEvent::LinkSelected {
                channel_id: "B".into(),
                keyset_id: "0000000000000001".into(),
                offer,
            },
        );
        state
            .exchange
            .step(Event::Submit(PendingRequest::Link {
                channel_id: "B".into(),
            }))
            .unwrap();
        state.exchange.step(Event::Submitted).unwrap();
        if evicted {
            apply_channel_evicted(&config, &mut state, "A".into()).await;
        }
        if !accepted {
            state
                .exchange
                .step(Event::Accept(ServerMessage::Error {
                    code: ServerErrorCode::LinkKeysetRefreshBusy,
                    message: "busy".into(),
                }))
                .unwrap();
            apply_server_error(&config, &mut state, ServerErrorCode::LinkKeysetRefreshBusy)
                .await
                .unwrap();
        }
        finish_replacement(&config, &mut state, accepted)
            .await
            .unwrap();
        assert_eq!(
            state.intended_channel_id.as_deref(),
            if accepted {
                Some("B")
            } else if evicted {
                None
            } else {
                Some("A")
            }
        );
        assert_eq!(
            wallet.attachment("A").unwrap(),
            if accepted || evicted {
                None
            } else {
                Some([1; 32])
            }
        );
        assert_eq!(wallet.attachment("B").unwrap(), Some([1; 32]));
        if !accepted {
            assert_eq!(state.acquired.as_ref().unwrap().0.channel_id, "B");
        }
        terminate_session(&config, &mut state).await;
        assert_eq!(wallet.attachment("B").unwrap(), None);
        assert_eq!(
            wallet
                .get_channel("A")
                .unwrap()
                .current_signed_balance_msats,
            100
        );
    }
}

#[derive(Default)]
struct CountingWallet(AtomicUsize);
impl CountingWallet {
    fn called<T>(&self) -> Result<T, WalletError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(WalletError::Backend("unexpected wallet access".into()))
    }
}
impl MonadWallet for CountingWallet {
    fn list_channels(&self) -> Result<Vec<WalletChannel>, WalletError> {
        self.called()
    }
    fn get_channel(&self, _: &str) -> Result<WalletChannel, WalletError> {
        self.called()
    }
    fn get_channel_accounting(&self, _: &str) -> Result<WalletChannelAccounting, WalletError> {
        self.called()
    }
    fn attach_channel_to_session(&self, _: &str, _: [u8; 32]) -> Result<(), WalletError> {
        self.called()
    }
    fn detach_channel_from_session(&self, _: &str, _: [u8; 32]) -> Result<(), WalletError> {
        self.called()
    }
    fn force_detach_channel(&self, _: &str) -> Result<(), WalletError> {
        self.called()
    }
    fn mark_channel_unusable(&self, _: &str) -> Result<(), WalletError> {
        self.called()
    }
    fn provision_channel(&self, _: &RelayPaymentOffer, _: u64) -> Result<String, WalletError> {
        self.called()
    }
    fn build_link_request(
        &self,
        _: &str,
        _: &RelayPaymentOffer,
    ) -> Result<ChannelLinkRequest, WalletError> {
        self.called()
    }
    fn build_channel_payment(
        &self,
        _: &str,
        _: &RelayPaymentOffer,
        _: u64,
        _: u64,
    ) -> Result<ChannelPaymentRequest, WalletError> {
        self.called()
    }
}

#[tokio::test]
async fn funded_ticks_and_busy_ticks_never_access_wallet() {
    let wallet = Arc::new(CountingWallet::default());
    let config = SessionDriverConfig {
        wallet: wallet.clone(),
        hop_label: "counting".into(),
        payment_policy: PaymentPolicy::default(),
        management: None,
        conn: RelayConnectionHandles {
            session_id: [1; 32],
            pricing_handle: Arc::default(),
            spilman_info_handle: Arc::default(),
            cashu_spilman_protocol_version_handle: Arc::default(),
            cashu_spilman_keyset_versions_handle: Arc::default(),
            cleartext_byte_counters: CleartextByteCounters::default(),
        },
    };
    let mut state = DriverState {
        intended_channel_id: Some("A".into()),
        established_pricing: Some(SessionPricing::new(1, 1)),
        local_session_paid_msats: 20_000_000,
        relay_snapshot: Some(RelaySnapshot {
            receiver_pubkey: "receiver".into(),
            advertisements: vec![],
            linked_channel: Some(LinkedChannelStatus {
                channel_id: "A".into(),
                unit: "msat".into(),
                capacity_raw: 100_000_000,
                balance_raw: 20_000_000,
            }),
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: 20_000_000,
            remaining_milli_sats: 20_000_000,
            paused: false,
        }),
        ..Default::default()
    };
    state.exchange.phase = Phase::Active;
    let (client, _peer) = tokio::io::duplex(4096);
    let (mut h2, connection) = h2::client::handshake(client).await.unwrap();
    let task = tokio::spawn(connection);
    let (_, mut send) = h2
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri("http://monad/control")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    for _ in 0..100 {
        run_policy_cycle(
            &config,
            &mut state,
            &mut send,
            false,
            &config.payment_policy,
        )
        .await
        .unwrap();
    }
    struct MustNotEvaluate;
    impl FundingStrategy for MustNotEvaluate {
        fn decide(&self, _: &View) -> Intent {
            panic!("policy evaluated while request pending")
        }
    }
    for request in [
        PendingRequest::Link {
            channel_id: "A".into(),
        },
        PendingRequest::Payment {
            channel_id: "A".into(),
            balance_raw: 1,
            minimum_increment_msats: 1,
        },
        PendingRequest::Unlink {
            channel_id: "A".into(),
        },
        PendingRequest::Status,
    ] {
        state.exchange.ordinary = super::reducer::Ordinary::Idle;
        state.exchange.step(Event::Submit(request)).unwrap();
        state.exchange.step(Event::Submitted).unwrap();
        for _ in 0..100 {
            run_policy_cycle(&config, &mut state, &mut send, false, &MustNotEvaluate)
                .await
                .unwrap();
        }
    }
    assert_eq!(wallet.0.load(Ordering::SeqCst), 0);
    task.abort();
    let _ = task.await;
}
