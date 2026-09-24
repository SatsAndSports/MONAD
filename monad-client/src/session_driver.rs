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
        raw_amount_to_msats, requested_delta_msats, server_error_rejects_intended_channel,
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
    use monad_common::protocol::{KeysetAdvertisement, LinkedChannelStatus, ServerErrorCode};
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
            advertisements: vec![KeysetAdvertisement {
                funding_keyset_recovery_window_secs: 86_400,
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                keyset_ids: vec!["0000000000000001".to_string()],
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }],
            linked_channel: None,
            session_total_in: 0,
            session_total_out: 0,
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
                        advertisements: snapshot(true).advertisements,
                        linked_channel: None,
                        active_in_rate: 1,
                        active_out_rate: 1,
                        session_total_in: 0,
                        session_total_out: 0,
                        total_paid_millisats: 0,
                        remaining_milli_sats: 0,
                        paused: true,
                        open_connects: 0,
                        total_connects: 0,
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
                session_total_in: 0,
                session_total_out: 0,
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
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "sat".to_string(),
                preferred_keyset_ids: vec!["0000000000000001".to_string()],
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
                session_total_in: 0,
                session_total_out: 0,
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
                session_total_out: 5,
                ..snapshot(true)
            }),
            ..DriverState::default()
        };

        let err =
            validate_session_status_baseline_against_local_counters(&state, &counters).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err
            .to_string()
            .contains("relay reported session_total_out=5 above client local outbound total=4"));
    }

    #[test]
    fn validate_session_status_baseline_rejects_relay_paid_above_local_authorized_total() {
        let counters = CleartextByteCounters::default();
        let state = DriverState {
            relay_snapshot: Some(RelaySnapshot {
                total_paid_millisats: 11,
                ..snapshot(true)
            }),
            local_session_paid_msats: 10,
            ..DriverState::default()
        };

        let err =
            validate_session_status_baseline_against_local_counters(&state, &counters).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(
            "relay reported total_paid_millisats=11 above client locally authorized total=10"
        ));
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
    fn estimated_remaining_uses_local_counter_deltas() {
        let counters = CleartextByteCounters::default();
        counters.note_inbound(4);
        counters.note_outbound(6);
        let state = DriverState {
            relay_snapshot: Some(RelaySnapshot {
                session_total_out: 2,
                total_paid_millisats: 20,
                ..snapshot(true)
            }),
            established_pricing: Some(SessionPricing::new(1, 1)),
            local_session_paid_msats: 20,
            ..DriverState::default()
        };

        assert_eq!(
            super::payment::compute_estimated_remaining(&state, &counters),
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
            super::payment::compute_estimated_remaining(&state, &counters),
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
    fn maybe_progress_payment_abandons_exhausted_channel() {
        use super::state::{RelayConnectionHandles, SessionDriverConfig};
        use crate::wallet::{MockWallet, WalletChannelState};

        let wallet = MockWallet::new();
        wallet
            .insert_channel(crate::wallet::WalletChannel {
                channel_id: "exhausted".to_string(),
                state: WalletChannelState::Open,
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                keyset_id: "keyset-a".to_string(),
                attached_session_id: None,
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
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                preferred_keyset_ids: vec!["keyset-a".to_string()],
                negotiated_keyset_versions: std::collections::BTreeSet::from(["v1".to_string()]),
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }),
            relay_snapshot: Some(RelaySnapshot {
                receiver_pubkey: "receiver".to_string(),
                advertisements: vec![KeysetAdvertisement {
                    funding_keyset_recovery_window_secs: 86_400,
                    mint_url: "https://mint".to_string(),
                    unit: "msat".to_string(),
                    keyset_ids: vec!["keyset-a".to_string()],
                    in_bytes_per_millisat: 1,
                    out_bytes_per_millisat: 1,
                }],
                linked_channel: Some(LinkedChannelStatus {
                    channel_id: "exhausted".to_string(),
                    balance_raw: 100,
                    capacity_raw: 100,
                    unit: "msat".to_string(),
                }),
                session_total_in: 0,
                session_total_out: 0,
                total_paid_millisats: 100,
                remaining_milli_sats: 0,
                paused: true,
            }),
            established_pricing: Some(SessionPricing::new(1, 1)),
            local_session_paid_msats: 100,
            ..DriverState::default()
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

            super::funding::maybe_progress_payment(
                &SessionDriverConfig {
                    wallet: Arc::new(wallet),
                    conn: RelayConnectionHandles {
                        session_id: [0; 32],
                        pricing_handle: Arc::new(tokio::sync::RwLock::new(None)),
                        spilman_info_handle: Arc::new(tokio::sync::RwLock::new(None)),
                        cashu_spilman_protocol_version_handle: Arc::new(tokio::sync::RwLock::new(
                            None,
                        )),
                        cashu_spilman_keyset_versions_handle: Arc::new(tokio::sync::RwLock::new(
                            None,
                        )),
                        cleartext_byte_counters: CleartextByteCounters::default(),
                    },
                    hop_label: "test".to_string(),
                    payment_policy: PaymentPolicy::default(),
                    management: None,
                },
                &mut state,
                &mut h2_send,
                false,
            )
            .await
        });

        assert!(result.is_ok());
        assert!(
            state.intended_channel_id.is_none(),
            "exhausted intended channel should be cleared"
        );
    }
}
