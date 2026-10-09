use monad_common::session::RelayConnection;
use std::io;
use std::sync::Arc;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::wallet::MonadWallet;

struct SessionAttachments {
    wallet: Arc<dyn MonadWallet>,
    session_id: [u8; 32],
}

impl Drop for SessionAttachments {
    fn drop(&mut self) {
        // The driver is the only writer for this session. Its synchronous wallet
        // calls have finished before drop, even if abort arrived in block_in_place.
        // Scan by owner rather than intended_channel_id: attach precedes sending
        // ChannelLink, which can be cancelled before intended bookkeeping.
        match self.wallet.list_channels() {
            Ok(channels) => {
                for channel in channels {
                    if channel.attached_session_id == Some(self.session_id) {
                        if let Err(error) = self
                            .wallet
                            .detach_channel_from_session(&channel.channel_id, self.session_id)
                        {
                            warn!(channel_id = %channel.channel_id, %error, "session attachment cleanup failed");
                        }
                    }
                }
            }
            Err(error) => warn!(%error, "session attachment cleanup could not list channels"),
        }
    }
}

mod funding;
mod payment;
mod runtime;
mod state;

use self::runtime::run_session_driver;
use self::state::{RelayConnectionHandles, SessionDriverConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentPolicy {
    /// Desired funding-token value when provisioning a new channel.
    pub channel_funding_token_target_msats: u64,
    /// Target positive remaining balance the client tries to restore whenever
    /// funding is needed.
    pub target_topup_buffer_msats: u64,
    /// Lower bound for a normal individual topup. A smaller non-zero payment is
    /// still allowed if that is exactly what fills the current channel to
    /// capacity.
    pub minimum_topup_msats: u64,
}

impl Default for PaymentPolicy {
    fn default() -> Self {
        Self {
            channel_funding_token_target_msats: 1_000_000,
            target_topup_buffer_msats: 10_000_000,
            minimum_topup_msats: 0,
        }
    }
}

pub async fn start_session_payment_driver(
    conn: &RelayConnection,
    wallet: Arc<dyn MonadWallet>,
    hop_label: &str,
    payment_policy: PaymentPolicy,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>, watch::Receiver<bool>)> {
    start_managed_session_payment_driver(conn, wallet, hop_label, payment_policy, None).await
}

pub async fn start_managed_session_payment_driver(
    conn: &RelayConnection,
    wallet: Arc<dyn MonadWallet>,
    hop_label: &str,
    payment_policy: PaymentPolicy,
    management: Option<Arc<crate::management::ClientManagement>>,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>, watch::Receiver<bool>)> {
    let (control_send, control_recv) = conn.open_control().await?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let (failed_tx, failed_rx) = watch::channel(false);
    let lease = management
        .as_ref()
        .map(|m| m.register(*conn.session_id(), hop_label));
    if let Some(lease) = &lease {
        *lease.hop.counters.lock().unwrap() = conn.cleartext_byte_counters();
    }
    let config = SessionDriverConfig {
        wallet,
        conn: RelayConnectionHandles::from(conn),
        hop_label: hop_label.to_string(),
        payment_policy,
        management: lease.as_ref().map(|l| (l.owner.clone(), l.hop.clone())),
    };

    let attachments = SessionAttachments {
        wallet: config.wallet.clone(),
        session_id: *conn.session_id(),
    };
    let handle = tokio::spawn(async move {
        let _lease = lease;
        let _attachments = attachments;
        let result = run_session_driver(control_send, control_recv, ready_tx, config).await;
        if let Err(e) = result {
            warn!("session payment driver ended with error: {e}");
        }
        let _ = failed_tx.send(true);
    });

    Ok((handle, ready_rx, failed_rx))
}

#[cfg(test)]
mod tests {
    use super::funding::{
        defer_link_after_refresh_error, link_refresh_retry_delay, LINK_REFRESH_BUSY_RETRY_DELAY,
        LINK_REFRESH_RETRY_COOLDOWN,
    };
    use super::payment::{
        channel_signed_balance_raw, exclude_on_wallet_error, plan_payment_topup,
        raw_amount_to_msats, reconcile_payment_topup, requested_delta_msats,
        server_error_invalidates_channel, server_error_rejects_intended_channel,
        validate_linked_channel_balance_against_wallet, validate_session_pricing,
        validate_session_status_baseline_against_local_counters, PaymentTopupPlan,
    };
    use super::state::{
        current_spilman_info, pre_ready_blocked_error, relay_confirms_intended_channel,
        set_link_in_flight, ControlOpInFlight, DriverState, FundingBlockedReason, RelaySnapshot,
    };
    use super::PaymentPolicy;
    use crate::wallet::WalletError;
    use http::{Method, Request};
    use monad_common::protocol::{LinkedChannelStatus, PaymentOption, ServerErrorCode};
    use monad_common::proxy::CleartextByteCounters;
    use monad_common::session::SessionPricing;
    use std::io;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::time::Instant;

    fn snapshot(paused: bool) -> RelaySnapshot {
        RelaySnapshot {
            receiver_pubkey: "receiver".to_string(),
            advertisements: vec![PaymentOption {
                funding_keyset_recovery_window_secs: 86_400,
                minimum_channel_lifetime_secs: 3600,
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }],
            linked_channel: None,
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: if paused { 0 } else { 10 },
            remaining_milli_sats: if paused { 0 } else { 10 },
            paused,
        }
    }

    #[tokio::test]
    async fn fatal_keyset_error_ends_driver_without_invalidating_wallet_channel() {
        use crate::wallet::{MockWallet, MonadWallet, WalletChannel, WalletChannelState};
        use monad_common::control_codec::{send_json_line, try_decode_json_line};
        use monad_common::protocol::{ClientMessage, ServerMessage};
        for abort in [false, true] {
            let wallet = Arc::new(MockWallet::new());
            wallet
                .insert_channel(WalletChannel {
                    channel_id: "channel".to_string(),
                    state: WalletChannelState::Open,
                    receiver_pubkey: "receiver".to_string(),
                    mint_url: "https://mint".to_string(),
                    unit: "msat".to_string(),
                    keyset_id: "0000000000000001".to_string(),
                    attached_session_id: None,
                    capacity_msats: 1000,
                    current_signed_balance_msats: 0,
                    expiry_timestamp: u64::MAX,
                })
                .unwrap();
            let (client, server) = tokio::io::duplex(4096);
            let (stop, stopped) = oneshot::channel::<()>();
            let (linked, linked_rx) = oneshot::channel();
            let server_task = tokio::spawn(async move {
                let mut server = h2::server::handshake(server).await.unwrap();
                let (request, mut respond) = server.accept().await.unwrap().unwrap();
                let mut recv = request.into_body();
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let driver = tokio::spawn(async move { while server.accept().await.is_some() {} });
                send_json_line(
                    &mut send,
                    &ServerMessage::SessionStatus {
                        receiver_pubkey: "receiver".to_string(),
                        advertisements: std::collections::BTreeMap::from([(
                            "https://mint".into(),
                            std::collections::BTreeMap::from([(
                                "msat".into(),
                                monad_common::protocol::MintUnitAdvertisement {
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
                    },
                )
                .await
                .unwrap();
                let mut buf = Vec::new();
                loop {
                    let data = recv.data().await.unwrap().unwrap();
                    recv.flow_control().release_capacity(data.len()).unwrap();
                    buf.extend_from_slice(&data);
                    if let Some(message) = try_decode_json_line::<ClientMessage>(&mut buf).unwrap()
                    {
                        assert!(matches!(message, ClientMessage::ChannelLink { .. }));
                        break;
                    }
                }
                linked.send(()).unwrap();
                if !abort {
                    send_json_line(
                        &mut send,
                        &ServerMessage::Error {
                            code: ServerErrorCode::LinkKeysetVersionNotNegotiated,
                            message: "unnegotiated funding".to_string(),
                        },
                    )
                    .await
                    .unwrap();
                }
                // Keep the stream open: termination must be caused by the error, not EOF.
                let _ = stopped.await;
                driver.abort();
                let _ = driver.await;
            });
            let (mut conn, driver) =
                monad_common::session::RelayConnection::from_transport_stream(client, [1; 32])
                    .await
                    .unwrap();
            conn.set_cashu_spilman_keyset_versions(Some(std::collections::BTreeSet::from([
                "v1".to_string()
            ])))
            .await;
            conn.add_driver(driver);
            let (handle, ready, failed) = super::start_session_payment_driver(
                &conn,
                wallet.clone(),
                "fatal test",
                PaymentPolicy::default(),
            )
            .await
            .unwrap();
            linked_rx.await.unwrap();
            if abort {
                conn.add_task(handle);
                conn.close().await;
            } else {
                tokio::time::timeout(Duration::from_secs(2), handle)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(*failed.borrow());
            }
            assert!(ready.await.is_err());
            let channel = wallet.get_channel("channel").unwrap();
            assert_eq!(channel.state, WalletChannelState::Open);
            assert_eq!(channel.attached_session_id, None);
            wallet
                .attach_channel_to_session("channel", [2; 32])
                .unwrap();
            let _ = stop.send(());
            server_task.await.unwrap();
            conn.shutdown().await;
        }
    }

    #[test]
    fn attachment_guard_covers_pre_intended_window_and_preserves_siblings() {
        use crate::wallet::{MockWallet, MonadWallet, WalletChannel, WalletChannelState};
        let wallet = Arc::new(MockWallet::new());
        for (id, owner) in [("ours", [1; 32]), ("sibling", [2; 32])] {
            wallet
                .insert_channel(WalletChannel {
                    channel_id: id.to_string(),
                    state: WalletChannelState::Open,
                    receiver_pubkey: "receiver".to_string(),
                    mint_url: "https://mint".to_string(),
                    unit: "msat".to_string(),
                    keyset_id: "0000000000000001".to_string(),
                    attached_session_id: Some(owner),
                    capacity_msats: 1000,
                    current_signed_balance_msats: 0,
                    expiry_timestamp: u64::MAX,
                })
                .unwrap();
        }
        drop(super::SessionAttachments {
            wallet: wallet.clone(),
            session_id: [1; 32],
        });
        assert_eq!(
            wallet.get_channel("ours").unwrap().attached_session_id,
            None
        );
        assert_eq!(
            wallet.get_channel("sibling").unwrap().attached_session_id,
            Some([2; 32])
        );
        wallet.attach_channel_to_session("ours", [3; 32]).unwrap();
        drop(super::SessionAttachments {
            wallet: wallet.clone(),
            session_id: [1; 32],
        });
        assert_eq!(
            wallet.get_channel("ours").unwrap().attached_session_id,
            Some([3; 32])
        );
    }

    #[tokio::test]
    async fn driver_attributes_responses_and_rejects_shortchanging_without_rollback() {
        use crate::wallet::{MockWallet, MonadWallet, WalletChannel, WalletChannelState};
        use monad_common::control_codec::{send_json_line, try_decode_json_line};
        use monad_common::protocol::{ClientMessage, ServerMessage};
        fn status(paid: u64, linked: bool, balance: u64) -> ServerMessage {
            serde_json::from_value(serde_json::json!({
                "type":"SessionStatus", "receiver_pubkey":"receiver",
                "advertisements":{"https://mint":{"msat":{"minimum_channel_lifetime_secs":3600,"funding_keyset_recovery_window_secs":86400}}},
                "linked_channel":if linked { serde_json::json!({"channel_id":"channel","balance_raw":balance,"capacity_raw":1000,"unit":"msat"}) } else { serde_json::Value::Null },
                "bytes_in_per_msat":1,"bytes_out_per_msat":1,"session_total_bytes_in":0,"session_total_bytes_out":0,
                "total_paid_millisats":paid,"remaining_milli_sats":paid,"paused":paid==0,
                "open_connects":0,"total_connects":0,"failed_connects":0
            })).unwrap()
        }
        async fn next(recv: &mut h2::RecvStream, buf: &mut Vec<u8>) -> ClientMessage {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Some(message) = try_decode_json_line(buf).unwrap() {
                        return message;
                    }
                    let data = recv.data().await.unwrap().unwrap();
                    recv.flow_control().release_capacity(data.len()).unwrap();
                    buf.extend_from_slice(&data);
                }
            })
            .await
            .unwrap()
        }
        for shortchange in [true, false] {
            let wallet = Arc::new(MockWallet::new());
            wallet
                .insert_channel(WalletChannel {
                    channel_id: "channel".into(),
                    state: WalletChannelState::Open,
                    receiver_pubkey: "receiver".into(),
                    mint_url: "https://mint".into(),
                    unit: "msat".into(),
                    keyset_id: "0000000000000001".into(),
                    attached_session_id: None,
                    capacity_msats: 1000,
                    current_signed_balance_msats: 0,
                    expiry_timestamp: u64::MAX,
                })
                .unwrap();
            let (client, server) = tokio::io::duplex(4096);
            let (stop, stopped) = oneshot::channel();
            let server = tokio::spawn(async move {
                let mut h2 = h2::server::handshake(server).await.unwrap();
                let (request, mut response) = h2.accept().await.unwrap().unwrap();
                let mut recv = request.into_body();
                let mut send = response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut tasks = tokio::task::JoinSet::new();
                tasks.spawn(async move { while h2.accept().await.is_some() {} });
                send_json_line(
                    &mut send,
                    &ServerMessage::ExtensionNotification(
                        monad_common::protocol::ExtensionNotification {
                            name: "example.before_initial".into(),
                            rest: serde_json::Map::from_iter([(
                                "anything".into(),
                                serde_json::json!({"optional": null}),
                            )]),
                        },
                    ),
                )
                .await
                .unwrap();
                send_json_line(&mut send, &status(0, false, 0))
                    .await
                    .unwrap();
                let mut buf = Vec::new();
                assert!(matches!(
                    next(&mut recv, &mut buf).await,
                    ClientMessage::ChannelLink { .. }
                ));
                send_json_line(
                    &mut send,
                    &ServerMessage::Pong {
                        nonce: "interleaved".into(),
                    },
                )
                .await
                .unwrap();
                send_json_line(
                    &mut send,
                    &ServerMessage::ExtensionNotification(
                        monad_common::protocol::ExtensionNotification {
                            name: "example.between_requests".into(),
                            rest: serde_json::Map::from_iter([
                                ("data".into(), serde_json::json!([1, null])),
                                ("future_member".into(), serde_json::json!(false)),
                            ]),
                        },
                    ),
                )
                .await
                .unwrap();
                send_json_line(&mut send, &status(0, true, 0))
                    .await
                    .unwrap();
                assert!(matches!(
                    next(&mut recv, &mut buf).await,
                    ClientMessage::ChannelPayment { .. }
                ));
                send_json_line(
                    &mut send,
                    &ServerMessage::ChannelReleaseRequested {
                        channel_id: "other".into(),
                    },
                )
                .await
                .unwrap();
                send_json_line(
                    &mut send,
                    &status(if shortchange { 9 } else { 10 }, true, 10),
                )
                .await
                .unwrap();
                if !shortchange {
                    // Neither empty-FIFO response may mutate state or terminate.
                    send_json_line(&mut send, &status(0, true, 0))
                        .await
                        .unwrap();
                    send_json_line(
                        &mut send,
                        &ServerMessage::Error {
                            code: ServerErrorCode::ChannelClosed,
                            message: "untrusted".into(),
                        },
                    )
                    .await
                    .unwrap();
                    send_json_line(
                        &mut send,
                        &ServerMessage::ChannelReleaseRequested {
                            channel_id: "channel".into(),
                        },
                    )
                    .await
                    .unwrap();
                    assert!(matches!(
                        next(&mut recv, &mut buf).await,
                        ClientMessage::ChannelUnlink { .. }
                    ));
                    send_json_line(&mut send, &status(10, false, 0))
                        .await
                        .unwrap();
                    send_json_line(
                        &mut send,
                        &ServerMessage::Error {
                            code: ServerErrorCode::ControlInvalidMessage,
                            message: "fatal even without requests".into(),
                        },
                    )
                    .await
                    .unwrap();
                }
                // Keep the stream alive so only protocol handling ends the driver.
                let _ = stopped.await;
                tasks.shutdown().await;
            });
            let (mut conn, driver) =
                monad_common::session::RelayConnection::from_transport_stream(client, [1; 32])
                    .await
                    .unwrap();
            conn.set_cashu_spilman_keyset_versions(Some(std::collections::BTreeSet::from([
                "v1".into()
            ])))
            .await;
            conn.add_driver(driver);
            let (handle, ready, failed) = super::start_session_payment_driver(
                &conn,
                wallet.clone(),
                "ordered test",
                PaymentPolicy {
                    target_topup_buffer_msats: 10,
                    minimum_topup_msats: 0,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(3), handle)
                .await
                .unwrap()
                .unwrap();
            assert!(*failed.borrow());
            assert_eq!(ready.await.is_err(), shortchange);
            assert_eq!(
                wallet
                    .get_channel("channel")
                    .unwrap()
                    .current_signed_balance_msats,
                10
            );
            assert_eq!(wallet.successful_payment_build_count("channel").unwrap(), 1);
            let _ = stop.send(());
            server.await.unwrap();
            conn.shutdown().await;
        }
    }

    #[test]
    fn relay_confirms_active_channel_matches_ids() {
        let state = DriverState {
            intended_channel_id: Some("chan-a".to_string()),
            relay_snapshot: Some(RelaySnapshot {
                receiver_pubkey: "receiver".to_string(),
                advertisements: vec![],
                linked_channel: Some(LinkedChannelStatus {
                    channel_id: "chan-a".to_string(),
                    balance_raw: 0,
                    capacity_raw: 100,
                    unit: "msat".to_string(),
                }),
                session_total_bytes_in: 0,
                session_total_bytes_out: 0,
                total_paid_millisats: 0,
                remaining_milli_sats: 0,
                paused: true,
            }),
            ..DriverState::default()
        };

        assert!(relay_confirms_intended_channel(&state));
    }

    #[test]
    fn intended_spilman_info_uses_selected_channel_keyset() {
        let mut state = DriverState::default();
        set_link_in_flight(
            &mut state,
            "channel".to_string(),
            "0000000000000002".to_string(),
            crate::wallet::RelayPaymentOffer {
                funding_keyset_recovery_window_secs: 86_400,
                minimum_channel_lifetime_secs: 3600,
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "sat".to_string(),
                negotiated_keyset_versions: std::collections::BTreeSet::from(["v1".to_string()]),
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            },
        );

        assert_eq!(
            current_spilman_info(&state).unwrap().keyset_id,
            "0000000000000002"
        );
    }

    #[test]
    fn transient_link_refresh_errors_preserve_channel_and_back_off() {
        for code in [
            ServerErrorCode::LinkKeysetRefreshRateLimited,
            ServerErrorCode::LinkKeysetRefreshFailed,
            ServerErrorCode::LinkKeysetRefreshBusy,
        ] {
            assert!(!server_error_rejects_intended_channel(&code));
        }
        assert_eq!(
            link_refresh_retry_delay(&ServerErrorCode::LinkKeysetRefreshRateLimited),
            Some(LINK_REFRESH_RETRY_COOLDOWN)
        );
        assert_eq!(
            link_refresh_retry_delay(&ServerErrorCode::LinkKeysetRefreshFailed),
            Some(LINK_REFRESH_RETRY_COOLDOWN)
        );
        assert_eq!(
            link_refresh_retry_delay(&ServerErrorCode::LinkKeysetRefreshBusy),
            Some(LINK_REFRESH_BUSY_RETRY_DELAY)
        );

        let now = Instant::now();
        let mut state = DriverState {
            intended_channel_id: Some("channel".to_string()),
            control_op_in_flight: Some(ControlOpInFlight::Link {
                channel_id: "channel".to_string(),
            }),
            ..DriverState::default()
        };
        assert!(defer_link_after_refresh_error(
            &mut state,
            &ServerErrorCode::LinkKeysetRefreshRateLimited,
            now,
        ));
        assert_eq!(state.intended_channel_id.as_deref(), Some("channel"));
        assert_eq!(
            state.funding_retry_not_before,
            Some(now + LINK_REFRESH_RETRY_COOLDOWN)
        );
    }

    #[test]
    fn exclusions_and_invalid_zero_signature_reject_without_global_invalidation() {
        for code in [
            ServerErrorCode::LinkInvalidZeroBalanceSignature,
            ServerErrorCode::ChannelEvictedFromSession,
            ServerErrorCode::ChannelRetiredAtRelay,
            ServerErrorCode::LinkChannelRetired,
        ] {
            assert!(server_error_rejects_intended_channel(&code));
            assert!(!server_error_invalidates_channel(&code));
        }
    }

    #[test]
    fn channel_signed_balance_raw_matches_msat_and_sat_units() {
        let msat_channel = crate::wallet::WalletChannel {
            channel_id: "chan-msat".to_string(),
            state: crate::wallet::WalletChannelState::Open,
            receiver_pubkey: "receiver".to_string(),
            mint_url: "https://mint".to_string(),
            unit: "msat".to_string(),
            keyset_id: "keyset-a".to_string(),
            attached_session_id: None,
            capacity_msats: 10,
            current_signed_balance_msats: 7,
            expiry_timestamp: u64::MAX,
        };
        let sat_channel = crate::wallet::WalletChannel {
            channel_id: "chan-sat".to_string(),
            state: crate::wallet::WalletChannelState::Open,
            receiver_pubkey: "receiver".to_string(),
            mint_url: "https://mint".to_string(),
            unit: "sat".to_string(),
            keyset_id: "keyset-a".to_string(),
            attached_session_id: None,
            capacity_msats: 2_000,
            current_signed_balance_msats: 1_001,
            expiry_timestamp: u64::MAX,
        };

        assert_eq!(channel_signed_balance_raw(&msat_channel).unwrap(), 7);
        assert_eq!(channel_signed_balance_raw(&sat_channel).unwrap(), 2);
    }

    #[test]
    fn raw_amount_to_msats_matches_msat_and_sat_units() {
        assert_eq!(raw_amount_to_msats("msat", 7).unwrap(), 7);
        assert_eq!(raw_amount_to_msats("sat", 2).unwrap(), 2_000);
    }

    #[test]
    fn validate_linked_channel_balance_rejects_relay_balance_above_local_signed_balance() {
        let wallet = crate::wallet::MockWallet::new();
        wallet
            .insert_channel(crate::wallet::WalletChannel {
                channel_id: "chan-a".to_string(),
                state: crate::wallet::WalletChannelState::Open,
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                keyset_id: "keyset-a".to_string(),
                attached_session_id: None,
                capacity_msats: 100,
                current_signed_balance_msats: 7,
                expiry_timestamp: u64::MAX,
            })
            .unwrap();
        let state = DriverState {
            intended_channel_id: Some("chan-a".to_string()),
            relay_snapshot: Some(RelaySnapshot {
                receiver_pubkey: "receiver".to_string(),
                advertisements: vec![],
                linked_channel: Some(LinkedChannelStatus {
                    channel_id: "chan-a".to_string(),
                    balance_raw: 8,
                    capacity_raw: 100,
                    unit: "msat".to_string(),
                }),
                session_total_bytes_in: 0,
                session_total_bytes_out: 0,
                total_paid_millisats: 0,
                remaining_milli_sats: 0,
                paused: true,
            }),
            local_session_paid_msats: 7,
            ..DriverState::default()
        };

        let mut state = state;
        let err = validate_linked_channel_balance_against_wallet(&wallet, &mut state).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(
            "relay reported linked balance_raw=8 above client local signed balance_raw=7"
        ));
    }

    #[test]
    fn validate_session_status_baseline_rejects_relay_overreported_outbound_usage() {
        let counters = CleartextByteCounters::default();
        counters.note_outbound(4);
        let state = DriverState {
            relay_snapshot: Some(RelaySnapshot {
                session_total_bytes_out: 5,
                ..snapshot(true)
            }),
            ..DriverState::default()
        };

        let err =
            validate_session_status_baseline_against_local_counters(&state, &counters).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(
            "relay reported session_total_bytes_out=5 above client local outbound total=4"
        ));
    }

    #[test]
    fn relay_paid_credit_only_reconciles_upward() {
        let counters = CleartextByteCounters::default();
        let mut state = DriverState {
            local_session_paid_msats: 10,
            established_pricing: Some(SessionPricing::new(1, 1)),
            ..DriverState::default()
        };
        for (reported, expected) in [(9, 10), (11, 11), (11, 11), (8, 11), (15, 15)] {
            super::state::apply_session_status(
                &mut state,
                RelaySnapshot {
                    total_paid_millisats: reported,
                    // Relay traffic/remaining claims do not size payments.
                    session_total_bytes_in: 999,
                    remaining_milli_sats: -999,
                    ..snapshot(true)
                },
            );
            validate_session_status_baseline_against_local_counters(&state, &counters).unwrap();
            assert_eq!(state.local_session_paid_msats, expected);
            assert_eq!(
                super::payment::compute_estimated_remaining(&state, &counters).unwrap(),
                Some(expected as i64)
            );
        }
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
    fn requested_delta_targets_buffer_from_negative_remaining() {
        assert_eq!(
            requested_delta_msats(-5, PaymentPolicy::default().target_topup_buffer_msats),
            PaymentPolicy::default().target_topup_buffer_msats + 5
        );
    }

    #[test]
    fn payment_plan_returns_no_payment_when_remaining_above_target() {
        let linked = LinkedChannelStatus {
            channel_id: "chan-a".to_string(),
            balance_raw: 0,
            capacity_raw: 100,
            unit: "msat".to_string(),
        };

        assert_eq!(
            plan_payment_topup(
                10_000_001,
                PaymentPolicy::default().target_topup_buffer_msats,
                0,
                &linked,
            )
            .unwrap(),
            PaymentTopupPlan::NoPaymentNeeded,
        );
    }

    #[test]
    fn payment_plan_applies_minimum_topup_floor() {
        let linked = LinkedChannelStatus {
            channel_id: "chan-a".to_string(),
            balance_raw: 0,
            capacity_raw: 10_000,
            unit: "msat".to_string(),
        };

        assert_eq!(
            plan_payment_topup(
                9_999_500,
                PaymentPolicy::default().target_topup_buffer_msats,
                1_000,
                &linked,
            )
            .unwrap(),
            PaymentTopupPlan::Pay {
                requested_delta_msats: 1_000,
                next_balance_raw: 1_000,
                reaches_capacity: false,
            },
        );
    }

    #[test]
    fn payment_plan_allows_under_minimum_when_filling_capacity() {
        let linked = LinkedChannelStatus {
            channel_id: "chan-a".to_string(),
            balance_raw: 95,
            capacity_raw: 100,
            unit: "msat".to_string(),
        };

        assert_eq!(
            plan_payment_topup(
                -5,
                PaymentPolicy::default().target_topup_buffer_msats,
                1_000,
                &linked,
            )
            .unwrap(),
            PaymentTopupPlan::Pay {
                requested_delta_msats: 5,
                next_balance_raw: 100,
                reaches_capacity: true,
            },
        );
    }

    #[test]
    fn payment_plan_rounds_up_sat_unit() {
        let linked = LinkedChannelStatus {
            channel_id: "chan-a".to_string(),
            balance_raw: 0,
            capacity_raw: 100,
            unit: "sat".to_string(),
        };

        assert_eq!(
            plan_payment_topup(
                9_999_500,
                PaymentPolicy::default().target_topup_buffer_msats,
                750,
                &linked,
            )
            .unwrap(),
            PaymentTopupPlan::Pay {
                requested_delta_msats: 1_000,
                next_balance_raw: 1,
                reaches_capacity: false,
            },
        );
    }

    #[test]
    fn payment_plan_reports_exhausted_channel() {
        let linked = LinkedChannelStatus {
            channel_id: "chan-a".to_string(),
            balance_raw: 100,
            capacity_raw: 100,
            unit: "msat".to_string(),
        };

        assert_eq!(
            plan_payment_topup(
                -5,
                PaymentPolicy::default().target_topup_buffer_msats,
                0,
                &linked,
            )
            .unwrap(),
            PaymentTopupPlan::ExhaustedChannel,
        );
    }

    #[test]
    fn payment_plan_sat_fills_capacity_from_below_minimum() {
        // Balance is 95 sat raw = 95_000 msat signed. Capacity is 100 sat raw.
        // The channel can accept 5 sat raw = 5_000 msat more. The policy asks for
        // at least 1_000 msat minimum topup, but the real fill is only 5_000 msat,
        // which is below the minimum in msat terms yet exactly fills capacity.
        let linked = LinkedChannelStatus {
            channel_id: "chan-a".to_string(),
            balance_raw: 95,
            capacity_raw: 100,
            unit: "sat".to_string(),
        };

        assert_eq!(
            plan_payment_topup(
                -5,
                PaymentPolicy::default().target_topup_buffer_msats,
                1_000,
                &linked,
            )
            .unwrap(),
            PaymentTopupPlan::Pay {
                requested_delta_msats: 5_000,
                next_balance_raw: 100,
                reaches_capacity: true,
            },
        );
    }

    #[test]
    fn payment_plan_zero_minimum_still_refills_when_below_target() {
        let linked = LinkedChannelStatus {
            channel_id: "chan-a".to_string(),
            balance_raw: 0,
            capacity_raw: 10_000,
            unit: "msat".to_string(),
        };

        // Estimated remaining is just 499 msat below target, minimum is 0.
        // The refill should be exactly the 499 msat gap.
        assert_eq!(
            plan_payment_topup(
                9_999_501,
                PaymentPolicy::default().target_topup_buffer_msats,
                0,
                &linked,
            )
            .unwrap(),
            PaymentTopupPlan::Pay {
                requested_delta_msats: 499,
                next_balance_raw: 499,
                reaches_capacity: false,
            },
        );
    }

    #[test]
    fn payment_plan_rejects_unsupported_unit() {
        let linked = LinkedChannelStatus {
            channel_id: "chan-a".to_string(),
            balance_raw: 0,
            capacity_raw: 10_000,
            unit: "btc".to_string(),
        };

        let err = plan_payment_topup(
            9_999_500,
            PaymentPolicy::default().target_topup_buffer_msats,
            1_000,
            &linked,
        )
        .unwrap_err();

        assert!(matches!(err, WalletError::OfferMismatch(_)));
    }

    #[test]
    fn payment_replays_signed_high_water_and_accounts_actual_delta() {
        let linked = LinkedChannelStatus {
            channel_id: "recover".to_string(),
            balance_raw: 3_460,
            capacity_raw: 30_000,
            unit: "msat".to_string(),
        };

        assert_eq!(
            reconcile_payment_topup(3_960, 4_444, &linked).unwrap(),
            (4_444, 984, false),
        );
    }

    #[test]
    fn estimated_remaining_uses_local_counter_deltas() {
        let counters = CleartextByteCounters::default();
        counters.note_inbound(4);
        counters.note_outbound(6);
        let state = DriverState {
            relay_snapshot: Some(RelaySnapshot {
                session_total_bytes_out: 2,
                total_paid_millisats: 20,
                ..snapshot(true)
            }),
            established_pricing: Some(SessionPricing::new(1, 1)),
            local_session_paid_msats: 20,
            ..DriverState::default()
        };

        assert_eq!(
            super::payment::compute_estimated_remaining(&state, &counters).unwrap(),
            Some(10)
        );
    }

    #[test]
    fn estimated_remaining_uses_directional_rates() {
        let counters = CleartextByteCounters::default();
        counters.note_inbound(14);
        counters.note_outbound(19);
        let state = DriverState {
            established_pricing: Some(SessionPricing::new(2, 5)),
            local_session_paid_msats: 20,
            ..DriverState::default()
        };

        assert_eq!(
            super::payment::compute_estimated_remaining(&state, &counters).unwrap(),
            Some(9)
        );
    }

    #[test]
    fn pre_ready_blocked_error_fires_when_session_newly_blocks_before_readiness() {
        let (ready_tx, _ready_rx) = oneshot::channel();
        let next_state = DriverState {
            funding_blocked_reason: Some(FundingBlockedReason::ChannelAcquire),
            ..DriverState::default()
        };

        let err = pre_ready_blocked_error(&Some(ready_tx), None, &next_state)
            .expect("pre-ready blocked session should fail fast");

        assert!(err
            .to_string()
            .contains("session funding blocked before readiness"));
        assert!(err.to_string().contains("ChannelAcquire"));
    }

    #[test]
    fn pre_ready_blocked_error_fires_for_link_request_build() {
        let (ready_tx, _ready_rx) = oneshot::channel();
        let next_state = DriverState {
            funding_blocked_reason: Some(FundingBlockedReason::LinkRequestBuild),
            ..DriverState::default()
        };

        let err = pre_ready_blocked_error(&Some(ready_tx), None, &next_state)
            .expect("pre-ready blocked session should fail fast");

        assert!(err.to_string().contains("LinkRequestBuild"));
    }

    #[test]
    fn pre_ready_blocked_error_fires_for_payment_request_build() {
        let (ready_tx, _ready_rx) = oneshot::channel();
        let next_state = DriverState {
            funding_blocked_reason: Some(FundingBlockedReason::PaymentRequestBuild),
            ..DriverState::default()
        };

        let err = pre_ready_blocked_error(&Some(ready_tx), None, &next_state)
            .expect("pre-ready blocked session should fail fast");

        assert!(err.to_string().contains("PaymentRequestBuild"));
    }

    #[test]
    fn pre_ready_blocked_error_does_not_fire_after_readiness() {
        let next_state = DriverState {
            funding_blocked_reason: Some(FundingBlockedReason::PaymentRequestBuild),
            ..DriverState::default()
        };

        let err = pre_ready_blocked_error(&None, None, &next_state);

        assert!(err.is_none());
    }

    #[test]
    fn exclude_on_wallet_error_marks_expected_errors() {
        assert!(exclude_on_wallet_error(&WalletError::NotFound));
        assert!(exclude_on_wallet_error(&WalletError::NotOpen));
        assert!(exclude_on_wallet_error(
            &WalletError::AttachedToDifferentSession { current: [1; 32] }
        ));
        assert!(exclude_on_wallet_error(
            &WalletError::InsufficientCapacity {
                requested: 1,
                capacity: 1
            }
        ));
        assert!(exclude_on_wallet_error(&WalletError::ChannelUnusable));
        assert!(exclude_on_wallet_error(&WalletError::OfferMismatch(
            "nope".to_string()
        )));
        assert!(!exclude_on_wallet_error(
            &WalletError::NoCompatibleActiveKeyset {
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
            }
        ));
        assert!(!exclude_on_wallet_error(&WalletError::Backend(
            "boom".to_string()
        )));
    }

    #[test]
    fn unpaused_status_definition_is_authoritative() {
        let state = DriverState {
            relay_snapshot: Some(snapshot(false)),
            ..DriverState::default()
        };
        assert!(!state.relay_snapshot.as_ref().unwrap().paused);
    }

    #[test]
    fn payment_wrong_channel_keeps_intended_channel() {
        let code = ServerErrorCode::PaymentWrongChannel;
        assert!(!server_error_rejects_intended_channel(&code));
    }

    #[test]
    fn unavailable_pricing_and_unrepresentable_estimates_are_distinct() {
        let counters = CleartextByteCounters::default();
        let mut state = DriverState::default();
        assert_eq!(
            super::payment::compute_estimated_remaining(&state, &counters).unwrap(),
            None
        );
        state.established_pricing = Some(SessionPricing::new(1, 1));
        state.local_session_paid_msats = i64::MAX as u64 + 1;
        assert_eq!(
            super::payment::compute_estimated_remaining(&state, &counters)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        state.local_session_paid_msats = 0;
        counters.note_outbound(usize::MAX);
        counters.note_inbound(usize::MAX);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            super::payment::compute_estimated_remaining(&state, &counters)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    #[cfg(target_pointer_width = "64")]
    async fn numeric_preflight_fails_before_signing_or_sending() {
        use super::state::{RelayConnectionHandles, SessionDriverConfig};
        use crate::wallet::{
            MockWallet, MonadWallet, RelayPaymentOffer, WalletChannel, WalletChannelState,
        };
        for invalid_estimate in [false, true] {
            let wallet = Arc::new(MockWallet::new());
            wallet
                .insert_channel(WalletChannel {
                    channel_id: "channel".into(),
                    state: WalletChannelState::Open,
                    receiver_pubkey: "receiver".into(),
                    mint_url: "https://mint".into(),
                    unit: "msat".into(),
                    keyset_id: "keyset-a".into(),
                    attached_session_id: Some([0; 32]),
                    capacity_msats: u64::MAX,
                    current_signed_balance_msats: 0,
                    expiry_timestamp: u64::MAX,
                })
                .unwrap();
            let counters = CleartextByteCounters::default();
            // Fits i64 as an estimate, but the proposed refill overflows u64.
            if !invalid_estimate {
                counters.note_outbound(usize::try_from(i64::MAX as u64 + 1).unwrap());
            }
            let mut state = DriverState {
                intended_channel_id: Some("channel".into()),
                intended_offer: Some(RelayPaymentOffer {
                    funding_keyset_recovery_window_secs: 86_400,
                    minimum_channel_lifetime_secs: 3600,
                    receiver_pubkey: "receiver".into(),
                    mint_url: "https://mint".into(),
                    unit: "msat".into(),
                    negotiated_keyset_versions: std::collections::BTreeSet::from(["v1".into()]),
                    in_bytes_per_millisat: 1,
                    out_bytes_per_millisat: 1,
                }),
                relay_snapshot: Some(RelaySnapshot {
                    linked_channel: Some(LinkedChannelStatus {
                        channel_id: "channel".into(),
                        balance_raw: 0,
                        capacity_raw: u64::MAX,
                        unit: "msat".into(),
                    }),
                    ..snapshot(false)
                }),
                local_session_paid_msats: u64::MAX - 10,
                established_pricing: Some(SessionPricing::new(1, 1)),
                ..Default::default()
            };
            let config = SessionDriverConfig {
                wallet: wallet.clone(),
                conn: RelayConnectionHandles {
                    session_id: [0; 32],
                    pricing_handle: Arc::new(tokio::sync::RwLock::new(None)),
                    spilman_info_handle: Arc::new(tokio::sync::RwLock::new(None)),
                    cashu_spilman_protocol_version_handle: Arc::new(tokio::sync::RwLock::new(None)),
                    cashu_spilman_keyset_versions_handle: Arc::new(tokio::sync::RwLock::new(None)),
                    cleartext_byte_counters: counters,
                },
                hop_label: "test".into(),
                payment_policy: PaymentPolicy {
                    target_topup_buffer_msats: u64::MAX,
                    ..Default::default()
                },
                management: None,
            };
            let (client, _server) = tokio::io::duplex(64);
            let (mut h2, connection) = h2::client::handshake(client).await.unwrap();
            let driver = tokio::spawn(connection);
            let (_, mut send) = h2
                .send_request(
                    Request::builder()
                        .method(Method::POST)
                        .uri("http://monad/control")
                        .body(())
                        .unwrap(),
                    false,
                )
                .unwrap();
            let error =
                super::funding::maybe_progress_payment(&config, &mut state, &mut send, false)
                    .await
                    .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains(if invalid_estimate {
                "remaining credit"
            } else {
                "payment total"
            }));
            assert_eq!(wallet.successful_payment_build_count("channel").unwrap(), 0);
            assert_eq!(
                wallet
                    .get_channel("channel")
                    .unwrap()
                    .current_signed_balance_msats,
                0
            );
            assert_eq!(state.local_session_paid_msats, u64::MAX - 10);
            driver.abort();
            let _ = driver.await;
        }
    }

    #[tokio::test]
    async fn rejection_never_rolls_back_locally_recorded_payment() {
        use super::state::{set_payment_in_flight, RelayConnectionHandles, SessionDriverConfig};
        use crate::wallet::MockWallet;

        let counters = CleartextByteCounters::default();
        counters.note_outbound(100);
        let config = SessionDriverConfig {
            wallet: Arc::new(MockWallet::new()),
            conn: RelayConnectionHandles {
                session_id: [0; 32],
                pricing_handle: Arc::new(tokio::sync::RwLock::new(None)),
                spilman_info_handle: Arc::new(tokio::sync::RwLock::new(None)),
                cashu_spilman_protocol_version_handle: Arc::new(tokio::sync::RwLock::new(None)),
                cashu_spilman_keyset_versions_handle: Arc::new(tokio::sync::RwLock::new(None)),
                cleartext_byte_counters: counters.clone(),
            },
            hop_label: "test".into(),
            payment_policy: PaymentPolicy::default(),
            management: None,
        };
        for code in [
            ServerErrorCode::PaymentInvalid,
            ServerErrorCode::PaymentNoNewFunds,
            ServerErrorCode::PaymentWrongChannel,
            ServerErrorCode::PaymentConflict,
            ServerErrorCode::NumericLimitExceeded,
            ServerErrorCode::ChannelClosed,
            ServerErrorCode::InternalError,
        ] {
            let mut state = DriverState {
                local_session_paid_msats: 2000,
                established_pricing: Some(SessionPricing::new(1, 1)),
                relay_snapshot: Some(snapshot(true)),
                ..Default::default()
            };
            set_payment_in_flight(&mut state, "channel".into(), 2000);
            super::funding::apply_server_error(&config, &mut state, code).await;
            assert_eq!(state.local_session_paid_msats, 2000, "{code:?}");
            assert_eq!(
                super::payment::compute_estimated_remaining(&state, &counters).unwrap(),
                Some(1900),
                "{code:?} must not authorize replacement payment"
            );
        }
    }

    #[test]
    fn exhausted_channel_reselection_uses_local_credit_without_unsolicited_status() {
        use super::state::{RelayConnectionHandles, SessionDriverConfig};
        use crate::wallet::{MockWallet, MonadWallet, WalletChannelState};

        let wallet = Arc::new(MockWallet::new());
        wallet
            .insert_channel(crate::wallet::WalletChannel {
                channel_id: "exhausted".to_string(),
                state: WalletChannelState::Open,
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                keyset_id: "keyset-a".to_string(),
                attached_session_id: Some([0; 32]),
                capacity_msats: 100,
                current_signed_balance_msats: 100,
                expiry_timestamp: u64::MAX,
            })
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut state = DriverState {
            intended_channel_id: Some("exhausted".to_string()),
            intended_offer: Some(crate::wallet::RelayPaymentOffer {
                funding_keyset_recovery_window_secs: 86_400,
                minimum_channel_lifetime_secs: 3600,
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                negotiated_keyset_versions: std::collections::BTreeSet::from(["v1".to_string()]),
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }),
            relay_snapshot: Some(RelaySnapshot {
                receiver_pubkey: "receiver".to_string(),
                advertisements: vec![PaymentOption {
                    funding_keyset_recovery_window_secs: 86_400,
                    minimum_channel_lifetime_secs: 3600,
                    mint_url: "https://mint".to_string(),
                    unit: "msat".to_string(),
                    in_bytes_per_millisat: 1,
                    out_bytes_per_millisat: 1,
                }],
                linked_channel: Some(LinkedChannelStatus {
                    channel_id: "exhausted".to_string(),
                    balance_raw: 100,
                    capacity_raw: 100,
                    unit: "msat".to_string(),
                }),
                session_total_bytes_in: 0,
                session_total_bytes_out: 99,
                total_paid_millisats: 100,
                remaining_milli_sats: 1,
                paused: false,
            }),
            established_pricing: Some(SessionPricing::new(1, 1)),
            local_session_paid_msats: 100,
            ..DriverState::default()
        };
        let counters = CleartextByteCounters::default();
        counters.note_outbound(99);
        let config = SessionDriverConfig {
            wallet: wallet.clone(),
            conn: RelayConnectionHandles {
                session_id: [0; 32],
                pricing_handle: Arc::new(tokio::sync::RwLock::new(None)),
                spilman_info_handle: Arc::new(tokio::sync::RwLock::new(None)),
                cashu_spilman_protocol_version_handle: Arc::new(tokio::sync::RwLock::new(None)),
                cashu_spilman_keyset_versions_handle: Arc::new(tokio::sync::RwLock::new(None)),
                cleartext_byte_counters: counters,
            },
            hop_label: "test".to_string(),
            payment_policy: PaymentPolicy::default(),
            management: None,
        };

        let result = rt.block_on(async {
            // We need a real h2::SendStream because maybe_progress_payment takes
            // one by reference. The exhausted-channel branch abandons the
            // intended channel and returns before writing anything, so the
            // stream never has to be driven.
            let (client, _server) = tokio::io::duplex(64);
            let (mut h2_client, connection) = h2::client::handshake(client).await.unwrap();
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let request = Request::builder()
                .method(Method::POST)
                .uri("http://monad/control")
                .body(())
                .unwrap();
            let (_response, mut h2_send) = h2_client.send_request(request, false).unwrap();

            super::funding::maybe_progress_payment(&config, &mut state, &mut h2_send, false)
                .await
                .unwrap();
            assert_eq!(state.intended_channel_id.as_deref(), Some("exhausted"));
            assert_eq!(
                wallet.get_channel("exhausted").unwrap().state,
                WalletChannelState::Open
            );
            assert_eq!(wallet.attachment("exhausted").unwrap(), Some([0; 32]));
            assert!(!state.session_excluded_channels.contains("exhausted"));
            assert_eq!(
                wallet.successful_payment_build_count("exhausted").unwrap(),
                0
            );

            config.conn.cleartext_byte_counters.note_outbound(2);
            super::funding::maybe_progress_payment(&config, &mut state, &mut h2_send, false).await
        });

        assert!(result.is_ok());
        assert!(
            state.intended_channel_id.is_none(),
            "exhausted intended channel should be cleared after relay pause"
        );
        assert_eq!(
            wallet.get_channel("exhausted").unwrap().state,
            WalletChannelState::Closing
        );
        assert_eq!(wallet.attachment("exhausted").unwrap(), None);
        assert!(state.session_excluded_channels.contains("exhausted"));
    }
}
