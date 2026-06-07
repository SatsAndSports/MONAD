use bytes::Bytes;
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::protocol::ClientMessage;
use monad_common::protocol::ServerMessage;
use monad_common::session::RelayConnection;
use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::session_fsm::{
    ClientSessionEffect, ClientSessionEvent, ClientSessionState, ControlOpInFlight,
    FundingBlockedReason, SessionSnapshot, WalletOpKind,
};
use crate::wallet::{select_channel, MonadWallet, RelayPaymentOffer, WalletChannel, WalletError};

fn encode_client_message(message: &monad_common::protocol::ClientMessage) -> io::Result<Bytes> {
    let bytes =
        serde_json::to_vec(message).map_err(|e| io::Error::other(format!("json error: {e}")))?;
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');
    Ok(Bytes::from(frame))
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &monad_common::protocol::ClientMessage,
) -> io::Result<()> {
    let frame = encode_client_message(message)?;
    h2_send.reserve_capacity(frame.len());
    wait_for_send_capacity(h2_send).await?;
    h2_send
        .send_data(frame, false)
        .map_err(|e| io::Error::other(format!("h2 send error: {e}")))
}

struct SessionDriverConfig {
    wallet: Arc<dyn MonadWallet>,
    conn: RelayConnectionProxy,
    hop_label: String,
}

pub async fn start_session_payment_driver(
    conn: &RelayConnection,
    wallet: Arc<dyn MonadWallet>,
    hop_label: &str,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    let (control_send, control_recv) = conn.open_control().await?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let config = SessionDriverConfig {
        wallet,
        conn: RelayConnectionProxy::from(conn),
        hop_label: hop_label.to_string(),
    };

    let handle = tokio::spawn(async move {
        if let Err(e) = run_session_driver(control_send, control_recv, ready_tx, config).await {
            warn!("session payment driver ended with error: {e}");
        }
    });

    Ok((handle, ready_rx))
}

struct RelayConnectionProxy {
    session_id: [u8; 32],
    pricing_handle:
        std::sync::Arc<tokio::sync::RwLock<Option<monad_common::session::SessionPricing>>>,
    spilman_info_handle:
        std::sync::Arc<tokio::sync::RwLock<Option<monad_common::session::SessionSpilmanInfo>>>,
}

impl From<&RelayConnection> for RelayConnectionProxy {
    fn from(conn: &RelayConnection) -> Self {
        Self {
            session_id: *conn.session_id(),
            pricing_handle: conn.session_pricing_handle(),
            spilman_info_handle: conn.session_spilman_info_handle(),
        }
    }
}

fn validate_session_pricing(
    established_pricing: &mut Option<monad_common::session::SessionPricing>,
    candidate: monad_common::session::SessionPricing,
) -> io::Result<()> {
    if let Some(previous) = established_pricing {
        if *previous != candidate {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "protocol violation: relay changed active session pricing from in={} out={} to in={} out={}",
                    previous.in_bytes_per_millisat,
                    previous.out_bytes_per_millisat,
                    candidate.in_bytes_per_millisat,
                    candidate.out_bytes_per_millisat,
                ),
            ));
        }
    } else {
        *established_pricing = Some(candidate);
    }

    Ok(())
}

fn validate_event_invariants(
    state: &ClientSessionState,
    event: &ClientSessionEvent,
) -> io::Result<()> {
    let payment_in_flight = matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Payment { .. })
    );

    let message = match event {
        ClientSessionEvent::ChannelPaymentBuilt { .. } if state.active_channel_id.is_none() => {
            Some("ChannelPaymentBuilt received without active channel".to_string())
        }
        ClientSessionEvent::ChannelPaymentBuilt { .. } if payment_in_flight => {
            Some("ChannelPaymentBuilt received while payment op already in flight".to_string())
        }
        _ => None,
    };

    if let Some(message) = message {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("client session invariant violation: {message}"),
        ));
    }

    Ok(())
}

fn relay_linked_channel_id(state: &ClientSessionState) -> Option<&str> {
    state
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.linked_channel.as_ref())
        .map(|channel| channel.channel_id.as_str())
}

fn session_is_paused(state: &ClientSessionState) -> bool {
    state
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.paused)
}

fn relay_confirms_active_channel(state: &ClientSessionState) -> bool {
    state.active_channel_id.is_some()
        && state.active_channel_id.as_deref() == relay_linked_channel_id(state)
}

fn set_blocked_reason(
    config: &SessionDriverConfig,
    state: &mut ClientSessionState,
    ready_tx: &Option<oneshot::Sender<()>>,
    reason: FundingBlockedReason,
    detail: &str,
) -> io::Result<()> {
    warn!(
        "{} funding blocked: {:?} ({detail})",
        config.hop_label, reason
    );
    state.funding_blocked_reason = Some(reason.clone());
    if ready_tx.is_some() {
        return Err(io::Error::other(format!(
            "session funding blocked before readiness: {:?} ({detail})",
            reason,
        )));
    }
    Ok(())
}

async fn send_channel_link(
    config: &SessionDriverConfig,
    state: &mut ClientSessionState,
    h2_send: &mut h2::SendStream<Bytes>,
    channel_id: String,
    offer: RelayPaymentOffer,
    payment_json: String,
) -> io::Result<()> {
    send_control_message(h2_send, &ClientMessage::ChannelLink { payment_json }).await?;
    state.active_channel_id = Some(channel_id.clone());
    state.active_offer = Some(offer.clone());
    *config.conn.spilman_info_handle.write().await =
        Some(monad_common::session::SessionSpilmanInfo {
            receiver_pubkey: offer.receiver_pubkey.clone(),
            mint_url: offer.mint_url.clone(),
            unit: offer.unit.clone(),
            keyset_id: offer
                .accepted_keyset_ids
                .first()
                .cloned()
                .unwrap_or_default(),
            keyset_info_json: String::new(),
        });
    state.control_op_in_flight = Some(ControlOpInFlight::Link { channel_id });
    Ok(())
}

async fn try_link_channel(
    config: &SessionDriverConfig,
    state: &mut ClientSessionState,
    h2_send: &mut h2::SendStream<Bytes>,
    ready_tx: &Option<oneshot::Sender<()>>,
    channel: WalletChannel,
    offer: RelayPaymentOffer,
) -> io::Result<bool> {
    let channel_id = channel.channel_id.clone();
    if let Err(error) = config
        .wallet
        .attach_channel_to_session(&channel_id, config.conn.session_id)
    {
        if matches!(error, WalletError::Backend(_)) {
            set_blocked_reason(
                config,
                state,
                ready_tx,
                FundingBlockedReason::Acquire,
                &error.to_string(),
            )?;
            return Ok(false);
        }
        if exclude_channel_for_link_failure(&error) {
            state.session_excluded_channels.insert(channel_id.clone());
        }
        return Ok(true);
    }

    match config.wallet.build_link_request(&channel_id, &offer) {
        Ok(payment_json) => {
            send_channel_link(config, state, h2_send, channel_id, offer, payment_json).await?;
            Ok(false)
        }
        Err(error) => {
            let _ = config
                .wallet
                .detach_channel_from_session(&channel_id, config.conn.session_id);
            if matches!(error, WalletError::Backend(_)) {
                set_blocked_reason(
                    config,
                    state,
                    ready_tx,
                    FundingBlockedReason::LinkBuild,
                    &error.to_string(),
                )?;
                return Ok(false);
            }
            if exclude_channel_for_link_failure(&error) {
                state.session_excluded_channels.insert(channel_id.clone());
            }
            Ok(true)
        }
    }
}

fn exclude_channel_for_link_failure(error: &WalletError) -> bool {
    matches!(
        error,
        WalletError::NotFound
            | WalletError::NotOpen
            | WalletError::AttachedToDifferentSession { .. }
            | WalletError::InsufficientCapacity { .. }
            | WalletError::ChannelUnusable
            | WalletError::OfferMismatch(_)
    )
}

async fn maybe_ensure_linked_channel(
    config: &SessionDriverConfig,
    state: &mut ClientSessionState,
    h2_send: &mut h2::SendStream<Bytes>,
    ready_tx: &Option<oneshot::Sender<()>>,
) -> io::Result<()> {
    if state.terminated || state.funding_blocked_reason.is_some() || !session_is_paused(state) {
        return Ok(());
    }
    if matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Link { .. })
    ) || matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Payment { .. })
    ) {
        return Ok(());
    }
    if relay_confirms_active_channel(state) {
        return Ok(());
    }

    loop {
        if let (Some(channel_id), Some(offer)) =
            (state.active_channel_id.clone(), state.active_offer.clone())
        {
            let channel = match config.wallet.get_channel(&channel_id) {
                Ok(channel) => channel,
                Err(error) => {
                    if matches!(error, WalletError::Backend(_)) {
                        set_blocked_reason(
                            config,
                            state,
                            ready_tx,
                            FundingBlockedReason::Acquire,
                            &error.to_string(),
                        )?;
                        return Ok(());
                    }
                    state.session_excluded_channels.insert(channel_id.clone());
                    state.active_channel_id = None;
                    state.active_offer = None;
                    let _ = config
                        .wallet
                        .detach_channel_from_session(&channel_id, config.conn.session_id);
                    continue;
                }
            };
            if !try_link_channel(config, state, h2_send, ready_tx, channel, offer).await? {
                return Ok(());
            }
            state.active_channel_id = None;
            state.active_offer = None;
            continue;
        }

        match choose_channel_and_offer(config.wallet.as_ref(), state, config.conn.session_id) {
            Ok(Some((channel, offer))) => {
                if !try_link_channel(config, state, h2_send, ready_tx, channel, offer).await? {
                    return Ok(());
                }
            }
            Ok(None) => {
                let Some(snapshot) = state.snapshot.as_ref() else {
                    return Ok(());
                };
                let Some(advertisement) = snapshot.advertisements.first() else {
                    return Ok(());
                };
                let offer = RelayPaymentOffer::from_advertisement(
                    snapshot.receiver_pubkey.clone(),
                    advertisement,
                );
                let channel_id = match config.wallet.provision_channel(
                    &offer,
                    crate::session_fsm::DEFAULT_PROVISIONED_CHANNEL_CAPACITY_MSATS,
                ) {
                    Ok(channel_id) => channel_id,
                    Err(error) => {
                        if matches!(error, WalletError::Backend(_)) {
                            set_blocked_reason(
                                config,
                                state,
                                ready_tx,
                                FundingBlockedReason::Acquire,
                                &error.to_string(),
                            )?;
                            return Ok(());
                        }
                        return Ok(());
                    }
                };
                let channel = match config.wallet.get_channel(&channel_id) {
                    Ok(channel) => channel,
                    Err(error) => {
                        if matches!(error, WalletError::Backend(_)) {
                            set_blocked_reason(
                                config,
                                state,
                                ready_tx,
                                FundingBlockedReason::Acquire,
                                &error.to_string(),
                            )?;
                        }
                        return Ok(());
                    }
                };
                if !try_link_channel(config, state, h2_send, ready_tx, channel, offer).await? {
                    return Ok(());
                }
            }
            Err(error) => {
                if matches!(error, WalletError::Backend(_)) {
                    set_blocked_reason(
                        config,
                        state,
                        ready_tx,
                        FundingBlockedReason::Acquire,
                        &error.to_string(),
                    )?;
                }
                return Ok(());
            }
        }
    }
}

fn pre_ready_blocked_error(
    ready_tx: &Option<oneshot::Sender<()>>,
    previous_blocked_reason: Option<FundingBlockedReason>,
    event: &ClientSessionEvent,
    next_state: &ClientSessionState,
) -> Option<io::Error> {
    if ready_tx.is_none()
        || previous_blocked_reason == next_state.funding_blocked_reason
        || next_state.funding_blocked_reason.is_none()
    {
        return None;
    }

    let blocked_reason = next_state.funding_blocked_reason.as_ref().unwrap();
    let detail = match event {
        ClientSessionEvent::WalletOperationFailed { error, .. } => format!(" ({error})"),
        _ => String::new(),
    };

    Some(io::Error::other(format!(
        "session funding blocked before readiness: {:?}{detail}",
        blocked_reason,
    )))
}

async fn run_session_driver(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    ready_tx: oneshot::Sender<()>,
    config: SessionDriverConfig,
) -> io::Result<()> {
    // Bootstrap stays outside the client reducer. Once the control stream is
    // open, the relay immediately sends the first SessionStatus and only then
    // do we start the reducer.
    let mut buf = Vec::new();
    let mut state = ClientSessionState::new();
    let mut ready_tx = Some(ready_tx);
    let mut established_pricing = None;

    while let Some(chunk) = h2_recv.data().await {
        let data = chunk.map_err(|e| io::Error::other(format!("h2 recv error: {e}")))?;
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
                .map_err(|e| io::Error::other(format!("json error: {e}")))?;
            let event = match message {
                ServerMessage::SessionStatus {
                    receiver_pubkey,
                    advertisements,
                    linked_channel,
                    active_in_rate,
                    active_out_rate,
                    session_total_in,
                    session_total_out,
                    total_paid_millisats,
                    remaining_milli_sats,
                    paused,
                    open_connects,
                    total_connects,
                } => {
                    let pricing =
                        monad_common::session::SessionPricing::new(active_in_rate, active_out_rate);
                    validate_session_pricing(&mut established_pricing, pricing)?;
                    let due_now = pricing.amount_due_millisats(session_total_in, session_total_out);
                    info!(
                        "{} session status: open_connects={} total_connects={} paused={} balance={} paid={} due={} linked={:?}",
                        config.hop_label,
                        open_connects,
                        total_connects,
                        paused,
                        remaining_milli_sats,
                        total_paid_millisats,
                        due_now,
                        linked_channel.as_ref().map(|channel| &channel.channel_id),
                    );
                    ClientSessionEvent::SessionStatusReceived {
                        snapshot: SessionSnapshot {
                            receiver_pubkey,
                            advertisements,
                            linked_channel,
                            remaining_milli_sats,
                            paused,
                        },
                        pricing,
                    }
                }
                ServerMessage::ChannelEvicted { channel_id } => {
                    warn!(
                        "{} channel {channel_id} evicted from this session",
                        config.hop_label
                    );
                    ClientSessionEvent::ChannelEvicted { channel_id }
                }
                ServerMessage::Error { code, message } => {
                    warn!("{} control error: {message}", config.hop_label);
                    ClientSessionEvent::ServerError { code, message }
                }
            };

            let terminate =
                process_client_event(&config, &mut state, event, &mut h2_send, &mut ready_tx)
                    .await?;
            if terminate {
                return Ok(());
            }
        }
    }

    let _ = process_client_event(
        &config,
        &mut state,
        ClientSessionEvent::ControlDetached,
        &mut h2_send,
        &mut ready_tx,
    )
    .await?;

    Ok(())
}

async fn process_client_event(
    config: &SessionDriverConfig,
    state: &mut ClientSessionState,
    initial_event: ClientSessionEvent,
    h2_send: &mut h2::SendStream<Bytes>,
    ready_tx: &mut Option<oneshot::Sender<()>>,
) -> io::Result<bool> {
    // Run a small local event queue so wallet/build effects can feed their
    // result-events back into the same serialized reducer pass.
    let mut pending = VecDeque::from([initial_event]);
    let mut terminate = false;

    while let Some(event) = pending.pop_front() {
        let event_for_logging = event.clone();
        if let Err(err) = validate_event_invariants(state, &event_for_logging) {
            error!(
                "{} invariant violation: event={:?} op={:?} active_channel={:?} blocked={:?}: {}",
                config.hop_label,
                event_for_logging,
                state.control_op_in_flight,
                state.active_channel_id,
                state.funding_blocked_reason,
                err,
            );
            return Err(err);
        }
        let previous_control_op = state.control_op_in_flight.clone();
        let previous_blocked_reason = state.funding_blocked_reason.clone();
        let (next_state, effects) = crate::session_fsm::step(state.clone(), event);
        log_control_state_transition(
            config,
            &event_for_logging,
            previous_control_op,
            previous_blocked_reason.clone(),
            &next_state,
        );
        if let Some(err) = pre_ready_blocked_error(
            ready_tx,
            previous_blocked_reason,
            &event_for_logging,
            &next_state,
        ) {
            warn!("{} {err}", config.hop_label);
            return Err(err);
        }
        *state = next_state;

        for effect in effects {
            match effect {
                ClientSessionEffect::UpdatePricingHandle(pricing) => {
                    *config.conn.pricing_handle.write().await = Some(pricing);
                }
                ClientSessionEffect::UpdateSpilmanInfoHandle(info) => {
                    *config.conn.spilman_info_handle.write().await = info;
                }
                ClientSessionEffect::BuildChannelPayment {
                    channel_id,
                    offer,
                    latest_server_balance_raw,
                    next_balance_raw,
                } => match config.wallet.build_channel_payment(
                    &channel_id,
                    &offer,
                    latest_server_balance_raw,
                    next_balance_raw,
                ) {
                    Ok(payment_json) => {
                        pending.push_back(ClientSessionEvent::ChannelPaymentBuilt { payment_json })
                    }
                    Err(error) => pending.push_back(ClientSessionEvent::WalletOperationFailed {
                        kind: WalletOpKind::PreparePayment { channel_id },
                        error,
                    }),
                },
                ClientSessionEffect::DetachChannel { channel_id } => {
                    let _ = config
                        .wallet
                        .detach_channel_from_session(&channel_id, config.conn.session_id);
                }
                ClientSessionEffect::MarkChannelUnusable { channel_id } => {
                    let _ = config.wallet.mark_channel_unusable(&channel_id);
                }
                ClientSessionEffect::SendControl(message) => {
                    send_control_message(h2_send, &message).await?;
                }
                ClientSessionEffect::SignalUsable => {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
                ClientSessionEffect::EndSession => {
                    terminate = true;
                }
            }
        }

        maybe_ensure_linked_channel(config, state, h2_send, ready_tx).await?;
    }

    Ok(terminate)
}

fn log_control_state_transition(
    config: &SessionDriverConfig,
    event: &ClientSessionEvent,
    previous_control_op: Option<ControlOpInFlight>,
    previous_blocked_reason: Option<FundingBlockedReason>,
    next_state: &ClientSessionState,
) {
    if previous_control_op != next_state.control_op_in_flight {
        debug!(
            "{} control op transition: {:?} -> {:?}",
            config.hop_label, previous_control_op, next_state.control_op_in_flight,
        );
    }

    if previous_blocked_reason != next_state.funding_blocked_reason {
        if let Some(reason) = &next_state.funding_blocked_reason {
            match event {
                ClientSessionEvent::WalletOperationFailed { error, .. } => {
                    warn!(
                        "{} funding blocked: {:?} ({error})",
                        config.hop_label, reason,
                    );
                }
                _ => {
                    warn!("{} funding blocked: {:?}", config.hop_label, reason,);
                }
            }
        }
    }
}

fn choose_channel_and_offer(
    wallet: &dyn MonadWallet,
    state: &ClientSessionState,
    session_id: [u8; 32],
) -> Result<Option<(crate::wallet::WalletChannel, RelayPaymentOffer)>, WalletError> {
    let Some(snapshot) = state.snapshot.as_ref() else {
        return Ok(None);
    };
    let channels = wallet
        .list_channels()?
        .into_iter()
        .filter(|channel| {
            !state
                .session_excluded_channels
                .contains(&channel.channel_id)
        })
        .collect::<Vec<_>>();
    for advertisement in &snapshot.advertisements {
        let offer =
            RelayPaymentOffer::from_advertisement(snapshot.receiver_pubkey.clone(), advertisement);
        if let Some(channel) = select_channel(&channels, &offer, session_id) {
            return Ok(Some((channel, offer)));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{
        pre_ready_blocked_error, relay_confirms_active_channel, validate_event_invariants,
        validate_session_pricing,
    };
    use crate::session_fsm::{
        ClientSessionEvent, ClientSessionState, ControlOpInFlight, FundingBlockedReason,
        WalletOpKind,
    };
    use monad_common::protocol::LinkedChannelStatus;
    use monad_common::session::SessionPricing;
    use std::io;
    use tokio::sync::oneshot;

    #[test]
    fn relay_confirms_active_channel_matches_ids() {
        let mut state = ClientSessionState::new();
        state.active_channel_id = Some("chan-a".to_string());
        state.snapshot = Some(crate::session_fsm::SessionSnapshot {
            receiver_pubkey: "receiver".to_string(),
            advertisements: vec![],
            linked_channel: Some(LinkedChannelStatus {
                channel_id: "chan-a".to_string(),
                balance_raw: 0,
                capacity_raw: 100,
                unit: "msat".to_string(),
            }),
            remaining_milli_sats: 0,
            paused: true,
        });

        assert!(relay_confirms_active_channel(&state));
    }

    #[test]
    fn validate_session_pricing_allows_initial_and_matching_rates() {
        let mut established = None;
        let pricing = SessionPricing::new(1, 2);

        validate_session_pricing(&mut established, pricing).unwrap();
        validate_session_pricing(&mut established, pricing).unwrap();

        assert_eq!(established, Some(pricing));
    }

    #[test]
    fn validate_session_pricing_rejects_rate_change() {
        let mut established = Some(SessionPricing::new(1, 2));
        let err =
            validate_session_pricing(&mut established, SessionPricing::new(3, 2)).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("protocol violation: relay changed active session pricing"));
    }

    #[test]
    fn validate_session_pricing_rejects_changed_rates_after_initial_baseline() {
        let mut established = None;

        validate_session_pricing(&mut established, SessionPricing::new(1, 1)).unwrap();
        let err = validate_session_pricing(&mut established, SessionPricing::new(2, 1))
            .expect_err("later pricing change should be rejected");

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("protocol violation: relay changed active session pricing"));
    }

    #[test]
    fn validate_event_invariants_rejects_payment_built_without_active_channel() {
        let err = validate_event_invariants(
            &ClientSessionState::new(),
            &ClientSessionEvent::ChannelPaymentBuilt {
                payment_json: "{}".to_string(),
            },
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("ChannelPaymentBuilt received without active channel"));
    }

    #[test]
    fn validate_event_invariants_rejects_payment_built_while_payment_in_flight() {
        let mut state = ClientSessionState::new();
        state.active_channel_id = Some("chan-a".to_string());
        state.control_op_in_flight = Some(ControlOpInFlight::Payment {
            channel_id: "chan-a".to_string(),
        });

        let err = validate_event_invariants(
            &state,
            &ClientSessionEvent::ChannelPaymentBuilt {
                payment_json: "{}".to_string(),
            },
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("payment op already in flight"));
    }

    #[test]
    fn pre_ready_blocked_error_fires_when_session_newly_blocks_before_readiness() {
        let (ready_tx, _ready_rx) = oneshot::channel();
        let next_state = ClientSessionState {
            funding_blocked_reason: Some(FundingBlockedReason::Acquire),
            ..ClientSessionState::new()
        };

        let err = pre_ready_blocked_error(
            &Some(ready_tx),
            None,
            &ClientSessionEvent::WalletOperationFailed {
                kind: WalletOpKind::PreparePayment {
                    channel_id: "chan-a".to_string(),
                },
                error: crate::wallet::WalletError::Backend("wallet down".to_string()),
            },
            &next_state,
        )
        .expect("pre-ready blocked session should fail fast");

        assert!(err
            .to_string()
            .contains("session funding blocked before readiness"));
        assert!(err.to_string().contains("Acquire"));
    }

    #[test]
    fn pre_ready_blocked_error_does_not_fire_after_readiness() {
        let next_state = ClientSessionState {
            funding_blocked_reason: Some(FundingBlockedReason::PaymentBuild),
            ..ClientSessionState::new()
        };

        let err = pre_ready_blocked_error(
            &None,
            None,
            &ClientSessionEvent::WalletOperationFailed {
                kind: WalletOpKind::PreparePayment {
                    channel_id: "chan-a".to_string(),
                },
                error: crate::wallet::WalletError::Backend("wallet down".to_string()),
            },
            &next_state,
        );

        assert!(err.is_none());
    }
}
