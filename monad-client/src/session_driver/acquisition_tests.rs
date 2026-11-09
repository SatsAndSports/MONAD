//! Acquisition runs off the executor while still holding the ordinary slot.
use super::acquisition::{
    run_acquisition, AcquisitionGate, AcquisitionOutcome, AcquisitionRequest,
};
use super::executor_tests::{channel, complete_acquisition, fixture, CountingWallet, Once};
use super::funding::{apply_channel_evicted, run_policy_cycle};
use super::policy::{FundingStrategy, Intent, View};
use super::PaymentPolicy;
use crate::wallet::*;
use monad_common::commitment_modes::ModePolicy;
use monad_common::control_codec::{send_json_line, try_decode_json_line};
use monad_common::protocol::{
    ChannelLinkRequest, ChannelPaymentRequest, ClientMessage, MintUnitAdvertisement, ServerMessage,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use tokio::time::timeout;

const SESSION: [u8; 32] = [9; 32];

#[derive(Clone, Copy, PartialEq, Eq)]
enum SlowStep {
    /// Optional mint capability discovery (`/v1/info` in the real wallet).
    Discovery,
    /// Opening swap and its keyset metadata work.
    Provisioning,
}

/// Mock wallet whose mint-dependent step blocks until the test releases it.
struct SlowMintWallet {
    inner: MockWallet,
    step: SlowStep,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    release: Mutex<mpsc::Receiver<()>>,
    slow_calls: AtomicUsize,
}

impl SlowMintWallet {
    fn new(step: SlowStep) -> (Arc<Self>, mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let wallet = Arc::new(Self {
            inner: MockWallet::new(),
            step,
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(release_rx),
            slow_calls: AtomicUsize::new(0),
        });
        (wallet, entered_rx, release_tx)
    }

    fn wait_for_mint(&self) {
        self.slow_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().unwrap().take() {
            entered.send(()).unwrap();
        }
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(30))
            .expect("test released slow mint step");
    }
}

impl MonadWallet for SlowMintWallet {
    fn supports_commitment_mode(
        &self,
        _mint: &str,
        mode: cdk_spilman::CommitmentMode,
    ) -> Result<bool, WalletError> {
        if mode == cdk_spilman::CommitmentMode::Ordinary {
            return Ok(true);
        }
        if self.step == SlowStep::Discovery {
            self.wait_for_mint();
        }
        Ok(false)
    }
    fn list_channels(&self) -> Result<Vec<WalletChannel>, WalletError> {
        self.inner.list_channels()
    }
    fn get_channel(&self, id: &str) -> Result<WalletChannel, WalletError> {
        self.inner.get_channel(id)
    }
    fn get_channel_accounting(&self, id: &str) -> Result<WalletChannelAccounting, WalletError> {
        self.inner.get_channel_accounting(id)
    }
    fn attach_channel_to_session(&self, id: &str, session: [u8; 32]) -> Result<(), WalletError> {
        self.inner.attach_channel_to_session(id, session)
    }
    fn detach_channel_from_session(&self, id: &str, session: [u8; 32]) -> Result<(), WalletError> {
        self.inner.detach_channel_from_session(id, session)
    }
    fn force_detach_channel(&self, id: &str) -> Result<(), WalletError> {
        self.inner.force_detach_channel(id)
    }
    fn mark_channel_unusable(&self, id: &str) -> Result<(), WalletError> {
        self.inner.mark_channel_unusable(id)
    }
    fn provision_channel(
        &self,
        offer: &RelayPaymentOffer,
        target: u64,
    ) -> Result<String, WalletError> {
        if self.step == SlowStep::Provisioning {
            self.wait_for_mint();
        }
        self.inner.provision_channel(offer, target)
    }
    fn build_link_request(
        &self,
        id: &str,
        offer: &RelayPaymentOffer,
    ) -> Result<ChannelLinkRequest, WalletError> {
        self.inner.build_link_request(id, offer)
    }
    fn build_channel_payment(
        &self,
        id: &str,
        offer: &RelayPaymentOffer,
        latest: u64,
        next: u64,
    ) -> Result<ChannelPaymentRequest, WalletError> {
        self.inner.build_channel_payment(id, offer, latest, next)
    }
}

fn initial_status() -> ServerMessage {
    ServerMessage::SessionStatus {
        receiver_pubkey: "receiver".into(),
        advertisements: BTreeMap::from([(
            "https://mint".into(),
            BTreeMap::from([(
                "msat".into(),
                MintUnitAdvertisement {
                    // Dual mode makes the ordinary fallback depend on discovery.
                    commitment_modes: ModePolicy::dual_mode(),
                    funding_keyset_recovery_window_secs: 86_400,
                    minimum_channel_lifetime_secs: 3600,
                },
            )]),
        )]),
        linked_channel: None,
        active_in_rate: 1,
        active_out_rate: 1,
        session_total_bytes_in: 0,
        session_total_bytes_out: 0,
        total_paid_millisats: 0,
        remaining_milli_sats: 0,
        paused: true,
        open_connects: 0,
        total_connects: 0,
        failed_connects: 0,
    }
}

/// Relay side of one control stream, driven by the test.
struct Relay {
    send: h2::SendStream<bytes::Bytes>,
    recv: h2::RecvStream,
    buf: Vec<u8>,
    _tasks: tokio::task::JoinSet<()>,
}

impl Relay {
    async fn next(&mut self) -> Option<ClientMessage> {
        loop {
            if let Some(message) = try_decode_json_line::<ClientMessage>(&mut self.buf).unwrap() {
                return Some(message);
            }
            let data = self.recv.data().await?.ok()?;
            self.recv
                .flow_control()
                .release_capacity(data.len())
                .unwrap();
            self.buf.extend_from_slice(&data);
        }
    }
}

struct Session {
    relay: Relay,
    driver: tokio::task::JoinHandle<()>,
    conn: monad_common::session::RelayConnection,
}

async fn start_session(wallet: Arc<dyn MonadWallet>) -> Session {
    let (client, server) = tokio::io::duplex(1 << 16);
    let (relay_tx, relay_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        let mut h2 = h2::server::handshake(server).await.unwrap();
        let (request, mut respond) = h2.accept().await.unwrap().unwrap();
        let send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        tasks.spawn(async move { while h2.accept().await.is_some() {} });
        let _ = relay_tx.send(Relay {
            send,
            recv: request.into_body(),
            buf: Vec::new(),
            _tasks: tasks,
        });
    });
    let (mut conn, h2_driver) =
        monad_common::session::RelayConnection::from_transport_stream(client, SESSION)
            .await
            .unwrap();
    conn.set_cashu_spilman_keyset_versions(Some(BTreeSet::from(["v1".to_string()])))
        .await;
    conn.add_driver(h2_driver);
    let (driver, _ready, _failed) =
        super::start_session_payment_driver(&conn, wallet, "slow mint", PaymentPolicy::default())
            .await
            .unwrap();
    let mut relay = relay_rx.await.unwrap();
    send_json_line(&mut relay.send, &initial_status())
        .await
        .unwrap();
    Session {
        relay,
        driver,
        conn,
    }
}

fn wait_entered(entered: &mpsc::Receiver<()>) {
    entered
        .recv_timeout(Duration::from_secs(10))
        .expect("acquisition reached the slow mint step");
}

/// A slow mint must not stop heartbeats, and must not let timer ticks start a
/// competing acquisition. After the mint answers, the executor links the
/// worker's candidate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_mint_step_keeps_heartbeat_responsive_and_acquisition_serialized() {
    for step in [SlowStep::Discovery, SlowStep::Provisioning] {
        let (wallet, entered, release) = SlowMintWallet::new(step);
        let mut session = start_session(wallet.clone()).await;
        tokio::task::spawn_blocking(move || wait_entered(&entered))
            .await
            .unwrap();

        // Heartbeat interval is 5s; the only message while blocked is a Ping.
        let ping = timeout(Duration::from_secs(10), session.relay.next())
            .await
            .expect("heartbeat continued during slow mint I/O")
            .unwrap();
        let ClientMessage::Ping { nonce } = ping else {
            panic!("expected Ping while acquisition is blocked, got {ping:?}");
        };
        send_json_line(&mut session.relay.send, &ServerMessage::Pong { nonce })
            .await
            .unwrap();
        assert!(!session.driver.is_finished());
        assert_eq!(wallet.slow_calls.load(Ordering::SeqCst), 1);
        assert!(wallet.list_channels().unwrap().is_empty());

        release.send(()).unwrap();
        let link = timeout(Duration::from_secs(10), session.relay.next())
            .await
            .unwrap()
            .unwrap();
        let ClientMessage::ChannelLink { channel_id, .. } = link else {
            panic!("expected ChannelLink after acquisition, got {link:?}");
        };
        let channels = wallet.list_channels().unwrap();
        assert_eq!(channels.len(), 1, "exactly one channel provisioned");
        assert_eq!(channels[0].channel_id, channel_id);
        assert_eq!(
            channels[0].commitment_mode,
            cdk_spilman::CommitmentMode::Ordinary
        );
        assert_eq!(channels[0].attached_session_id, Some(SESSION));
        assert_eq!(wallet.slow_calls.load(Ordering::SeqCst), 1);

        session.driver.abort();
        let _ = session.driver.await;
        assert_eq!(
            wallet.get_channel(&channel_id).unwrap().attached_session_id,
            None
        );
        session.conn.shutdown().await;
    }
}

/// Session end during a slow step waits for the worker, sends no link, and
/// leaves no attachment; the provisioned channel stays reusable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_end_during_slow_provisioning_awaits_worker_and_releases_candidate() {
    let (wallet, entered, release) = SlowMintWallet::new(SlowStep::Provisioning);
    let mut session = start_session(wallet.clone()).await;
    tokio::task::spawn_blocking(move || wait_entered(&entered))
        .await
        .unwrap();
    session
        .relay
        .send
        .send_data(bytes::Bytes::new(), true)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !session.driver.is_finished(),
        "cleanup must await, not detach, running wallet work"
    );
    release.send(()).unwrap();
    timeout(Duration::from_secs(10), &mut session.driver)
        .await
        .unwrap()
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), session.relay.next())
            .await
            .map_or(true, |message| !matches!(
                message,
                Some(ClientMessage::ChannelLink { .. })
            )),
        "no link after session end"
    );
    let channels = wallet.list_channels().unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].state, WalletChannelState::Open);
    assert_eq!(channels[0].attached_session_id, None);
    session.conn.shutdown().await;
}

/// Abort drops the driver future without its awaited cleanup. The drop guard
/// must wait for the running worker so attachment cleanup cannot miss it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_during_slow_provisioning_waits_for_worker_before_cleanup() {
    let (wallet, entered, release) = SlowMintWallet::new(SlowStep::Provisioning);
    let session = start_session(wallet.clone()).await;
    tokio::task::spawn_blocking(move || wait_entered(&entered))
        .await
        .unwrap();
    let released = Arc::new(AtomicBool::new(false));
    let releaser = {
        let released = released.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            released.store(true, Ordering::SeqCst);
            release.send(()).unwrap();
        })
    };
    session.driver.abort();
    let _ = timeout(Duration::from_secs(10), session.driver)
        .await
        .unwrap();
    assert!(
        released.load(Ordering::SeqCst),
        "aborted driver finished before its wallet worker"
    );
    releaser.join().unwrap();
    let channels = wallet.list_channels().unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[0].attached_session_id, None);
    session.conn.shutdown().await;
}

struct MustNotEvaluate;
impl FundingStrategy for MustNotEvaluate {
    fn decide(&self, _: &View) -> Intent {
        panic!("policy evaluated while acquisition holds the ordinary slot")
    }
}

async fn control_send() -> (
    h2::SendStream<bytes::Bytes>,
    tokio::task::JoinHandle<()>,
    tokio::io::DuplexStream,
) {
    let (client, peer) = tokio::io::duplex(4096);
    let (mut h2, connection) = h2::client::handshake(client).await.unwrap();
    let task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let (_, send) = h2
        .send_request(
            http::Request::builder()
                .method("POST")
                .uri("http://monad/control")
                .body(())
                .unwrap(),
            false,
        )
        .unwrap();
    (send, task, peer)
}

/// Eviction processed while the worker ran wins over its stale candidate, and
/// no funding decision is evaluated until the report is applied.
#[tokio::test]
async fn candidate_evicted_during_acquisition_is_released_not_linked() {
    let wallet = Arc::new(MockWallet::new());
    wallet.insert_channel(channel("A", Some([1; 32]))).unwrap();
    wallet.insert_channel(channel("B", None)).unwrap();
    let (config, mut state) = fixture(wallet.clone());
    let (mut send, task, _peer) = control_send().await;
    run_policy_cycle(
        &config,
        &mut state,
        &mut send,
        false,
        &Once(Some(Intent::AcquireChannel).into()),
    )
    .await
    .unwrap();
    assert!(state.acquisition.is_some());
    for _ in 0..10 {
        run_policy_cycle(&config, &mut state, &mut send, false, &MustNotEvaluate)
            .await
            .unwrap();
    }
    apply_channel_evicted(&config, &mut state, "B".into()).await;
    complete_acquisition(&config, &mut state).await;
    assert!(state.exchange.is_empty());
    assert!(state.acquired.is_none());
    assert!(!state.channel_authority.contains_key("B"));
    assert_eq!(wallet.attachment("B").unwrap(), None);
    assert_eq!(wallet.attachment("A").unwrap(), Some([1; 32]));
    task.abort();
}

/// Cancellation observed before the worker starts prevents any wallet access.
#[test]
fn cancelled_worker_does_not_touch_wallet() {
    let wallet = Arc::new(CountingWallet::default());
    let gate = Arc::new(AcquisitionGate::default());
    gate.cancel();
    let report = run_acquisition(AcquisitionRequest {
        wallet: wallet.clone(),
        gate,
        session_id: SESSION,
        hop_label: "cancelled".into(),
        receiver_pubkey: "receiver".into(),
        advertisements: vec![],
        versions: BTreeSet::from(["v1".to_string()]),
        excluded: BTreeSet::new(),
        funding_token_target_msats: 1,
        management: None,
    });
    assert!(matches!(report.outcome, AcquisitionOutcome::Cancelled));
    assert!(report.excluded.is_empty());
    assert_eq!(wallet.0.load(Ordering::SeqCst), 0);
}
