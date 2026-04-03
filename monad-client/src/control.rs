use bytes::Bytes;
use cdk_spilman::{
    ConfigurableClientHost, MemoryClientStorage, Payment, ReqwestClientNetworking,
    SpilmanClientBridge,
};
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::protocol::{ClientMessage, MintUnitKeysets, ServerMessage};
use monad_common::session::{
    RelayConnection, SessionChannelInfo, SessionPricing, SessionSpilmanInfo,
};
use std::io;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, warn};

const CLIENT_VERSION: u8 = 0;

/// Provides a Cashu token to fund a Spilman channel for a session.
///
/// Called once per session when `SessionParams` arrives. The implementation
/// can mint tokens on demand (tests), prompt the user (production), or
/// return `None` to fall back to `FakePayment`.
pub trait SessionFundingProvider: Send + Sync + 'static {
    /// Called once per session when `SessionParams` arrive.
    ///
    /// Returns a Cashu token string to fund a Spilman channel for this session,
    /// or `None` to fall back to `FakePayment`.
    fn provide_channel_token(
        &self,
        hop_label: &str,
        session_id: &[u8; 32],
        receiver_pubkey: &str,
        mint_url: &str,
        unit: &str,
        keyset_id: &str,
    ) -> Option<String>;
}

/// Default funding provider that never provides a token — always uses `FakePayment`.
pub struct FakePaymentProvider {
    pub fake_payment_millisats: u64,
}

impl SessionFundingProvider for FakePaymentProvider {
    fn provide_channel_token(
        &self,
        _hop_label: &str,
        _session_id: &[u8; 32],
        _receiver_pubkey: &str,
        _mint_url: &str,
        _unit: &str,
        _keyset_id: &str,
    ) -> Option<String> {
        None
    }
}

/// Interactive funding provider that prompts the user for a Cashu token on stdin.
pub struct StdinFundingProvider;

impl SessionFundingProvider for StdinFundingProvider {
    fn provide_channel_token(
        &self,
        hop_label: &str,
        session_id: &[u8; 32],
        _receiver_pubkey: &str,
        mint_url: &str,
        unit: &str,
        keyset_id: &str,
    ) -> Option<String> {
        use std::io::Write;

        let session_hex: String = session_id.iter().map(|b| format!("{b:02x}")).collect();

        tokio::task::block_in_place(|| {
            let stdout = std::io::stdout();
            let stdin = std::io::stdin();
            let mut out = stdout.lock();

            let _ = writeln!(out, "--- Channel funding requested ---");
            let _ = writeln!(out, "  Hop:      {hop_label}");
            let _ = writeln!(out, "  Session:  {session_hex}");
            let _ = writeln!(out, "  Mint:     {mint_url}");
            let _ = writeln!(out, "  Unit:     {unit}");
            let _ = writeln!(out, "  Keyset:   {keyset_id}");
            let _ = write!(out, "Paste a Cashu token (or press Enter to skip): ");
            let _ = out.flush();

            let mut line = String::new();
            if stdin.read_line(&mut line).is_err() {
                return None;
            }
            let token = line.trim().to_string();
            if token.is_empty() { None } else { Some(token) }
        })
    }
}

type SessionBridge =
    SpilmanClientBridge<ConfigurableClientHost<MemoryClientStorage>, ReqwestClientNetworking>;

struct SessionChannelRuntime {
    _bridge: SessionBridge,
    channel_id: String,
    capacity: u64,
}

fn encode_client_message(message: &ClientMessage) -> io::Result<Bytes> {
    let bytes = serde_json::to_vec(message)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("json error: {e}")))?;
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');
    Ok(Bytes::from(frame))
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ClientMessage,
) -> io::Result<()> {
    let frame = encode_client_message(message)?;
    h2_send.reserve_capacity(frame.len());
    wait_for_send_capacity(h2_send).await?;
    h2_send
        .send_data(frame, false)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 send error: {e}")))
}

fn io_other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn pick_advertised_keyset(mints_units_keysets: &MintUnitKeysets) -> Option<(String, String, String)> {
    for (mint_url, unit_map) in mints_units_keysets {
        if let Some(keysets) = unit_map.get("sat") {
            if let Some(keyset_id) = keysets.first() {
                return Some((mint_url.clone(), "sat".to_string(), keyset_id.clone()));
            }
        }
    }

    for (mint_url, unit_map) in mints_units_keysets {
        if let Some((unit, keysets)) = unit_map.iter().next() {
            if let Some(keyset_id) = keysets.first() {
                return Some((mint_url.clone(), unit.clone(), keyset_id.clone()));
            }
        }
    }

    None
}

fn fetch_session_spilman_info(
    receiver_pubkey: String,
    mints_units_keysets: MintUnitKeysets,
) -> io::Result<Option<SessionSpilmanInfo>> {
    let Some((mint_url, unit, keyset_id)) = pick_advertised_keyset(&mints_units_keysets) else {
        return Ok(None);
    };

    let client_host = ConfigurableClientHost::new_in_memory();
    let networking = ReqwestClientNetworking::new();
    let bridge = SpilmanClientBridge::new(client_host, networking);

    let keyset_info_json = bridge
        .fetch_keyset_info(&mint_url, &keyset_id)
        .map_err(|e| io_other(format!("fetch keyset info from {mint_url}: {e}")))?;

    Ok(Some(SessionSpilmanInfo {
        receiver_pubkey,
        mint_url,
        unit,
        keyset_id,
        keyset_info_json,
    }))
}

fn open_spilman_channel(
    spilman_info: &SessionSpilmanInfo,
    token: &str,
) -> io::Result<(SessionChannelRuntime, String)> {
    use cashu::nuts::SecretKey;

    let sender_secret = SecretKey::generate();
    let mut client_host = ConfigurableClientHost::new_in_memory();
    client_host.add_key(sender_secret.clone());
    let networking = ReqwestClientNetworking::new();
    let bridge = SpilmanClientBridge::new(client_host, networking);

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let open_result = bridge
        .open_channel_from_token(
            token,
            &spilman_info.receiver_pubkey,
            &sender_secret.public_key().to_hex(),
            now_secs + 3600,
            &spilman_info.keyset_info_json,
            64,
        )
        .map_err(|e| io_other(format!("open Spilman channel: {e}")))?;

    let channel_id = open_result.channel_id;
    let capacity = open_result.capacity;
    let funding_payment: Payment = bridge
        .create_payment_with_funding(&channel_id, 0)
        .map_err(|e| io_other(format!("create funding registration payment: {e}")))?;
    let payment_json = serde_json::to_string(&funding_payment)
        .map_err(|e| io_other(format!("serialize funding registration payment: {e}")))?;

    Ok((
        SessionChannelRuntime {
            _bridge: bridge,
            channel_id,
            capacity,
        },
        payment_json,
    ))
}

async fn run_control_task(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    fake_payment_millisats: u64,
    session_id: [u8; 32],
    hop_label: String,
    funding_provider: Arc<dyn SessionFundingProvider>,
    ready_tx: oneshot::Sender<()>,
    pricing_handle: Arc<RwLock<Option<SessionPricing>>>,
    spilman_info_handle: Arc<RwLock<Option<SessionSpilmanInfo>>>,
    channel_info_handle: Arc<RwLock<Option<SessionChannelInfo>>>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut ready_tx = Some(ready_tx);
    let mut pending_channel: Option<SessionChannelRuntime> = None;
    let mut _active_channel: Option<SessionChannelRuntime> = None;

    // Send Hello as the first message on the control stream.
    send_control_message(&mut h2_send, &ClientMessage::Hello { version: CLIENT_VERSION }).await?;

    while let Some(chunk) = h2_recv.data().await {
        let data = chunk
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 recv error: {e}")))?;
        let len = data.len();
        let _ = h2_recv.flow_control().release_capacity(len);
        buf.extend_from_slice(&data);

        while let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=newline_pos).collect();
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }

            let message: ServerMessage = serde_json::from_slice(line)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("json error: {e}")))?;
            match message {
                ServerMessage::SessionParams {
                    version,
                    in_bytes_per_millisat,
                    out_bytes_per_millisat,
                    receiver_pubkey,
                    mints_units_keysets,
                } => {
                    let pricing = SessionPricing::new(
                        version,
                        in_bytes_per_millisat,
                        out_bytes_per_millisat,
                    );
                    info!(
                        "session params: version={} in_bytes_per_millisat={} out_bytes_per_millisat={} lcm={}",
                        pricing.version,
                        pricing.in_bytes_per_millisat,
                        pricing.out_bytes_per_millisat,
                        pricing.pricing_lcm,
                    );
                    *pricing_handle.write().await = Some(pricing);

                    // Fetch and verify keyset info from the advertised mint.
                    let spilman_info =
                        match fetch_session_spilman_info(receiver_pubkey, mints_units_keysets) {
                            Ok(Some(info)) => {
                                info!(
                                    mint = %info.mint_url,
                                    unit = %info.unit,
                                    keyset_id = %info.keyset_id,
                                    "fetched session Spilman keyset info"
                                );
                                *spilman_info_handle.write().await = Some(info.clone());
                                Some(info)
                            }
                            Ok(None) => {
                                info!("server advertised no usable Spilman keysets");
                                None
                            }
                            Err(e) => {
                                warn!("failed to fetch session Spilman keyset info: {e}");
                                None
                            }
                        };

                    // Ask the funding provider for a token and open a channel.
                    if let Some(ref info) = spilman_info {
                        if let Some(token) = funding_provider.provide_channel_token(
                            &hop_label,
                            &session_id,
                            &info.receiver_pubkey,
                            &info.mint_url,
                            &info.unit,
                            &info.keyset_id,
                        ) {
                            match open_spilman_channel(info, &token) {
                                Ok((channel_runtime, payment_json)) => {
                                    info!(
                                        channel_id = %channel_runtime.channel_id,
                                        capacity = channel_runtime.capacity,
                                        "opened Spilman channel for session; sending funding registration"
                                    );
                                    pending_channel = Some(channel_runtime);
                                    send_control_message(
                                        &mut h2_send,
                                        &ClientMessage::ChannelFunding { payment_json },
                                    )
                                    .await?;
                                }
                                Err(e) => {
                                    warn!("failed to open Spilman channel: {e}");
                                }
                            }
                        }
                    }
                }
                ServerMessage::Error { message } => {
                    if pending_channel.is_some() {
                        pending_channel = None;
                    }
                    warn!("control error: {message}");
                }
                ServerMessage::ChannelFundingAccepted {
                    channel_id,
                    capacity,
                } => {
                    match pending_channel.take() {
                        Some(channel_runtime) if channel_runtime.channel_id == channel_id => {
                            if channel_runtime.capacity != capacity {
                                warn!(
                                    channel_id = %channel_id,
                                    client_capacity = channel_runtime.capacity,
                                    server_capacity = capacity,
                                    "channel funding ack capacity differed from client view"
                                );
                            }
                            *channel_info_handle.write().await = Some(SessionChannelInfo {
                                channel_id: channel_runtime.channel_id.clone(),
                                capacity,
                            });
                            info!(channel_id = %channel_id, capacity, "server accepted session channel funding");
                            _active_channel = Some(channel_runtime);
                        }
                        Some(channel_runtime) => {
                            warn!(
                                expected_channel_id = %channel_runtime.channel_id,
                                got_channel_id = %channel_id,
                                "received funding ack for unexpected channel"
                            );
                            pending_channel = Some(channel_runtime);
                        }
                        None => {
                            warn!(channel_id = %channel_id, "received unexpected channel funding ack");
                        }
                    }
                }
                ServerMessage::SessionStatus {
                    session_total_in,
                    session_total_out,
                    total_paid_millisats,
                    remaining_milli_sats,
                    paused,
                } => {
                    info!(
                        "session status: paused={} balance={} paid={} in={} out={}",
                        paused,
                        remaining_milli_sats,
                        total_paid_millisats,
                        session_total_in,
                        session_total_out
                    );

                    if paused && remaining_milli_sats <= 0 {
                        info!(
                            "session paused; sending fake payment of {} millisats",
                            fake_payment_millisats
                        );
                        send_control_message(
                            &mut h2_send,
                            &ClientMessage::FakePayment {
                                milli_sats: fake_payment_millisats,
                            },
                        )
                        .await?;
                    } else if !paused {
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

/// Start a control task for a session.
///
/// The control task sends `Hello`, receives `SessionParams`, fetches keyset
/// info from the advertised mint, optionally opens a Spilman channel via the
/// funding provider, and sends `FakePayment` whenever the session is paused.
pub async fn start_control_task(
    conn: &RelayConnection,
    fake_payment_millisats: u64,
    hop_label: &str,
    funding_provider: Arc<dyn SessionFundingProvider>,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    let (control_send, control_recv) = conn.open_control().await?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let session_id = *conn.session_id();
    let hop_label = hop_label.to_string();
    let pricing_handle = conn.session_pricing_handle();
    let spilman_info_handle = conn.session_spilman_info_handle();
    let channel_info_handle = conn.session_channel_info_handle();

    let handle = tokio::spawn(async move {
        if let Err(e) = run_control_task(
            control_send,
            control_recv,
            fake_payment_millisats,
            session_id,
            hop_label,
            funding_provider,
            ready_tx,
            pricing_handle,
            spilman_info_handle,
            channel_info_handle,
        )
        .await
        {
            warn!("control task ended with error: {e}");
        }
    });

    Ok((handle, ready_rx))
}

/// Start a control task that only uses `FakePayment` (no Spilman channel).
///
/// Convenience wrapper around [`start_control_task`] with a [`FakePaymentProvider`].
pub async fn start_fake_payment_controller(
    conn: &RelayConnection,
    fake_payment_millisats: u64,
    hop_label: &str,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    let provider = Arc::new(FakePaymentProvider { fake_payment_millisats });
    start_control_task(conn, fake_payment_millisats, hop_label, provider).await
}
