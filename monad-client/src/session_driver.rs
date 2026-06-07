use bytes::Bytes;
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::protocol::{LinkedChannelStatus, ServerMessage};
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
use crate::wallet::{select_channel, MonadWallet, RelayPaymentOffer, WalletError};

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
    let acquire_in_flight = matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::AcquireChannel)
    );
    let payment_in_flight = matches!(
        state.control_op_in_flight,
        Some(ControlOpInFlight::Payment { .. })
    );

    let message = match event {
        ClientSessionEvent::ChannelSelected { .. }
        | ClientSessionEvent::ChannelProvisioned { .. }
        | ClientSessionEvent::NoSelectableChannel
        | ClientSessionEvent::RelayLinkedChannelAdopted { .. }
        | ClientSessionEvent::RelayLinkedChannelUnavailable { .. }
        | ClientSessionEvent::LinkRequestBuilt { .. }
            if !acquire_in_flight =>
        {
            Some(format!("{:?} received without acquire op in flight", event))
        }
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
                ClientSessionEffect::SelectChannel => {
                    match choose_channel_and_offer(
                        config.wallet.as_ref(),
                        state,
                        config.conn.session_id,
                    ) {
                        Ok(Some((channel, offer))) => pending
                            .push_back(ClientSessionEvent::ChannelSelected { channel, offer }),
                        Ok(None) => pending.push_back(ClientSessionEvent::NoSelectableChannel),
                        Err(error) => {
                            pending.push_back(ClientSessionEvent::WalletOperationFailed {
                                kind: WalletOpKind::AcquireChannel,
                                error,
                            })
                        }
                    }
                }
                ClientSessionEffect::ProvisionChannel {
                    offer,
                    capacity_msats,
                } => match config.wallet.provision_channel(&offer, capacity_msats) {
                    Ok(channel_id) => match config.wallet.get_channel(&channel_id) {
                        Ok(channel) => pending
                            .push_back(ClientSessionEvent::ChannelProvisioned { channel, offer }),
                        Err(error) => {
                            pending.push_back(ClientSessionEvent::WalletOperationFailed {
                                kind: WalletOpKind::ProvisionChannel,
                                error,
                            })
                        }
                    },
                    Err(error) => pending.push_back(ClientSessionEvent::WalletOperationFailed {
                        kind: WalletOpKind::ProvisionChannel,
                        error,
                    }),
                },
                ClientSessionEffect::PrepareLink { channel, offer } => {
                    let channel_id = channel.channel_id.clone();
                    let result = config
                        .wallet
                        .attach_channel_to_session(&channel_id, config.conn.session_id)
                        .and_then(|_| config.wallet.build_link_request(&channel_id, &offer));
                    match result {
                        Ok(payment_json) => {
                            pending.push_back(ClientSessionEvent::LinkRequestBuilt {
                                channel_id,
                                payment_json,
                            })
                        }
                        Err(error) => {
                            let _ = config
                                .wallet
                                .detach_channel_from_session(&channel_id, config.conn.session_id);
                            pending.push_back(ClientSessionEvent::WalletOperationFailed {
                                kind: WalletOpKind::PrepareLink { channel_id },
                                error,
                            });
                        }
                    }
                }
                ClientSessionEffect::InspectLinkedChannel {
                    linked_channel,
                    receiver_pubkey,
                    advertisements,
                } => {
                    if let Some((channel_id, offer)) = inspect_and_adopt_linked_channel(
                        config.wallet.as_ref(),
                        config.conn.session_id,
                        &linked_channel,
                        &receiver_pubkey,
                        &advertisements,
                    ) {
                        pending.push_back(ClientSessionEvent::RelayLinkedChannelAdopted {
                            linked_channel,
                            channel_id,
                            offer,
                        });
                    } else {
                        pending.push_back(ClientSessionEvent::RelayLinkedChannelUnavailable {
                            _linked_channel: linked_channel,
                        });
                    }
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

fn inspect_and_adopt_linked_channel(
    wallet: &dyn MonadWallet,
    session_id: [u8; 32],
    linked_channel: &LinkedChannelStatus,
    receiver_pubkey: &str,
    advertisements: &[monad_common::protocol::KeysetAdvertisement],
) -> Option<(String, RelayPaymentOffer)> {
    let channel = wallet.get_channel(&linked_channel.channel_id).ok()?;
    let offer = advertisements.iter().find_map(|advertisement| {
        let offer =
            RelayPaymentOffer::from_advertisement(receiver_pubkey.to_string(), advertisement);
        if channel.receiver_pubkey == offer.receiver_pubkey
            && channel.mint_url == offer.mint_url
            && channel.unit == offer.unit
            && offer
                .accepted_keyset_ids
                .iter()
                .any(|keyset| keyset == &channel.keyset_id)
        {
            Some(offer)
        } else {
            None
        }
    })?;

    wallet
        .attach_channel_to_session(&linked_channel.channel_id, session_id)
        .ok()?;
    Some((linked_channel.channel_id.clone(), offer))
}

#[cfg(test)]
mod tests {
    use super::{
        inspect_and_adopt_linked_channel, pre_ready_blocked_error, validate_event_invariants,
        validate_session_pricing,
    };
    use crate::session_fsm::{
        ClientSessionEvent, ClientSessionState, ControlOpInFlight, FundingBlockedReason,
        WalletOpKind,
    };
    use crate::wallet::{MockWallet, RelayPaymentOffer, WalletChannel, WalletChannelState};
    use monad_common::protocol::{KeysetAdvertisement, LinkedChannelStatus};
    use monad_common::session::SessionPricing;
    use std::io;
    use tokio::sync::oneshot;

    fn channel(id: &str) -> WalletChannel {
        WalletChannel {
            channel_id: id.to_string(),
            state: WalletChannelState::Open,
            receiver_pubkey: "receiver".to_string(),
            mint_url: "https://mint".to_string(),
            unit: "msat".to_string(),
            keyset_id: "keyset-a".to_string(),
            attached_session_id: None,
            capacity_msats: 100,
            current_signed_balance_msats: 0,
        }
    }

    #[test]
    fn inspect_and_adopt_linked_channel_returns_matching_offer() {
        let wallet = MockWallet::new();
        wallet.insert_channel(channel("chan-a")).unwrap();

        let adopted = inspect_and_adopt_linked_channel(
            &wallet,
            [1; 32],
            &LinkedChannelStatus {
                channel_id: "chan-a".to_string(),
                balance_raw: 0,
                capacity_raw: 100,
                unit: "msat".to_string(),
            },
            "receiver",
            &[KeysetAdvertisement {
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                keyset_ids: vec!["keyset-a".to_string()],
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }],
        )
        .unwrap();

        assert_eq!(adopted.0, "chan-a");
        assert_eq!(
            adopted.1,
            RelayPaymentOffer {
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                accepted_keyset_ids: vec!["keyset-a".to_string()],
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }
        );
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
    fn validate_event_invariants_rejects_channel_selected_without_acquire() {
        let err = validate_event_invariants(
            &ClientSessionState::new(),
            &ClientSessionEvent::ChannelSelected {
                channel: channel("chan-a"),
                offer: RelayPaymentOffer {
                    receiver_pubkey: "receiver".to_string(),
                    mint_url: "https://mint".to_string(),
                    unit: "msat".to_string(),
                    accepted_keyset_ids: vec!["keyset-a".to_string()],
                    in_bytes_per_millisat: 1,
                    out_bytes_per_millisat: 1,
                },
            },
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("ChannelSelected"));
    }

    #[test]
    fn validate_event_invariants_allows_channel_selected_during_acquire() {
        let mut state = ClientSessionState::new();
        state.control_op_in_flight = Some(ControlOpInFlight::AcquireChannel);

        validate_event_invariants(
            &state,
            &ClientSessionEvent::ChannelSelected {
                channel: channel("chan-a"),
                offer: RelayPaymentOffer {
                    receiver_pubkey: "receiver".to_string(),
                    mint_url: "https://mint".to_string(),
                    unit: "msat".to_string(),
                    accepted_keyset_ids: vec!["keyset-a".to_string()],
                    in_bytes_per_millisat: 1,
                    out_bytes_per_millisat: 1,
                },
            },
        )
        .unwrap();
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
                kind: WalletOpKind::AcquireChannel,
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
