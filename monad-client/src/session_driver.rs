use monad_common::session::RelayConnection;
use std::io;
use std::sync::Arc;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::wallet::MonadWallet;

mod funding;
mod payment;
mod runtime;
mod state;

use self::runtime::run_session_driver;
use self::state::{RelayConnectionHandles, SessionDriverConfig};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentPolicy {
    /// Loose-proof input budget used when provisioning a new channel.
    pub channel_input_budget_msats: u64,
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
            channel_input_budget_msats: 1_000_000,
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
    let (control_send, control_recv) = conn.open_control().await?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let (failed_tx, failed_rx) = watch::channel(false);
    let config = SessionDriverConfig {
        wallet,
        conn: RelayConnectionHandles::from(conn),
        hop_label: hop_label.to_string(),
        payment_policy,
    };

    let handle = tokio::spawn(async move {
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
    use super::funding::{keyset_refresh_hint_is_suppressed, KEYSET_REFRESH_HINT_RETRY_COOLDOWN};
    use super::payment::{
        channel_signed_balance_raw, exclude_on_wallet_error, plan_payment_topup,
        raw_amount_to_msats, requested_delta_msats, server_error_rejects_intended_channel,
        validate_linked_channel_balance_against_wallet, validate_session_pricing,
        validate_session_status_baseline_against_local_counters, PaymentTopupPlan,
    };
    use super::state::{
        apply_session_status, pre_ready_blocked_error, relay_confirms_intended_channel,
        set_keyset_refresh_in_flight, ControlOpInFlight, DriverState, FundingBlockedReason,
        KeysetRefreshHint, RelaySnapshot,
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
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                keyset_ids: vec!["keyset-a".to_string()],
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
        assert!(exclude_on_wallet_error(&WalletError::StaleRelayKeysets {
            mint_url: "https://mint".to_string(),
            unit: "msat".to_string(),
            accepted_keyset_ids: vec!["keyset-a".to_string()],
        }));
        assert!(!exclude_on_wallet_error(&WalletError::Backend(
            "boom".to_string()
        )));
    }

    #[test]
    fn session_status_clears_keyset_refresh_in_flight() {
        let hint = KeysetRefreshHint {
            mint_url: "https://mint".to_string(),
            unit: "msat".to_string(),
            accepted_keyset_ids: vec!["keyset-a".to_string()],
        };
        let mut state = DriverState::default();
        set_keyset_refresh_in_flight(&mut state, hint.clone());

        let resolved_payment = apply_session_status(&mut state, snapshot(true));

        assert!(!resolved_payment);
        assert!(state.control_op_in_flight.is_none());
        assert_eq!(state.last_keyset_refresh_hint, Some(hint));
        assert!(state.last_keyset_refresh_hint_at.is_some());
    }

    #[test]
    fn changed_advertisement_clears_last_keyset_refresh_hint() {
        let hint = KeysetRefreshHint {
            mint_url: "https://mint".to_string(),
            unit: "msat".to_string(),
            accepted_keyset_ids: vec!["keyset-a".to_string()],
        };
        let mut state = DriverState {
            control_op_in_flight: Some(ControlOpInFlight::RefreshKeysets(hint.clone())),
            last_keyset_refresh_hint: Some(hint),
            ..DriverState::default()
        };
        let mut updated = snapshot(true);
        updated.advertisements[0]
            .keyset_ids
            .push("keyset-b".to_string());

        let resolved_payment = apply_session_status(&mut state, updated);

        assert!(!resolved_payment);
        assert!(state.control_op_in_flight.is_none());
        assert!(state.last_keyset_refresh_hint.is_none());
        assert!(state.last_keyset_refresh_hint_at.is_none());
    }

    #[test]
    fn duplicate_keyset_refresh_hint_is_suppressed_within_cooldown() {
        let hint = KeysetRefreshHint {
            mint_url: "https://mint".to_string(),
            unit: "sat".to_string(),
            accepted_keyset_ids: vec!["keyset-a".to_string()],
        };
        let mut state = DriverState::default();
        set_keyset_refresh_in_flight(&mut state, hint.clone());

        assert!(keyset_refresh_hint_is_suppressed(&state, &hint));
    }

    #[test]
    fn same_keyset_refresh_hint_can_retry_after_cooldown() {
        let hint = KeysetRefreshHint {
            mint_url: "https://mint".to_string(),
            unit: "sat".to_string(),
            accepted_keyset_ids: vec!["keyset-a".to_string()],
        };
        let mut state = DriverState::default();
        set_keyset_refresh_in_flight(&mut state, hint.clone());
        state.last_keyset_refresh_hint_at =
            Some(Instant::now() - KEYSET_REFRESH_HINT_RETRY_COOLDOWN - Duration::from_secs(1));

        assert!(!keyset_refresh_hint_is_suppressed(&state, &hint));
    }

    #[test]
    fn changed_keyset_refresh_hint_is_not_suppressed() {
        let previous = KeysetRefreshHint {
            mint_url: "https://mint".to_string(),
            unit: "sat".to_string(),
            accepted_keyset_ids: vec!["keyset-a".to_string()],
        };
        let changed = KeysetRefreshHint {
            mint_url: "https://mint".to_string(),
            unit: "sat".to_string(),
            accepted_keyset_ids: vec!["keyset-b".to_string()],
        };
        let mut state = DriverState::default();
        set_keyset_refresh_in_flight(&mut state, previous);

        assert!(!keyset_refresh_hint_is_suppressed(&state, &changed));
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
                receiver_pubkey: "receiver".to_string(),
                mint_url: "https://mint".to_string(),
                unit: "msat".to_string(),
                accepted_keyset_ids: vec!["keyset-a".to_string()],
                in_bytes_per_millisat: 1,
                out_bytes_per_millisat: 1,
            }),
            relay_snapshot: Some(RelaySnapshot {
                receiver_pubkey: "receiver".to_string(),
                advertisements: vec![KeysetAdvertisement {
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
                        cleartext_byte_counters: CleartextByteCounters::default(),
                    },
                    hop_label: "test".to_string(),
                    payment_policy: PaymentPolicy::default(),
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
