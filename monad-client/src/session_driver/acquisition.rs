//! Channel acquisition worker.
//!
//! Selecting or provisioning a channel can wait on mint I/O: optional
//! capability discovery, keyset refresh, and opening swaps. The synchronous
//! wallet calls for that work run on a blocking thread so the session executor
//! keeps handling heartbeats, advisories and shutdown. Acquisition still
//! occupies the single ordinary-operation slot until the executor applies the
//! report: no payment, link or unlink can start concurrently.
//!
//! The worker never sends control messages or mutates driver state. It returns
//! a report that the executor validates against current session state.
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use monad_common::protocol::PaymentOption;

use super::payment::exclude_on_wallet_error;
use crate::wallet::{
    select_channel, MonadWallet, RelayPaymentOffer, WalletChannel, WalletChannelAccounting,
    WalletChannelState, WalletError,
};

/// Shared between the executor, its worker, and the driver's drop guard.
///
/// `busy` is held for the worker's whole wallet sequence. Cancellation is set
/// before waiting on `busy`, so a worker either finishes before cleanup scans
/// attachments or observes cancellation before touching the wallet.
#[derive(Debug, Default)]
pub(super) struct AcquisitionGate {
    cancelled: AtomicBool,
    busy: Mutex<()>,
}

impl AcquisitionGate {
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Synchronous cleanup used when the driver future is dropped without
    /// reaching its awaited cleanup (for example, task abort). It waits for a
    /// running worker so later attachment cleanup cannot race a late attach.
    pub(super) fn cancel_and_wait_blocking(&self) {
        self.cancel();
        if self.busy.try_lock().is_ok() {
            return;
        }
        let wait = || drop(self.busy.lock().unwrap_or_else(PoisonError::into_inner));
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(wait)
            }
            _ => wait(),
        }
    }
}

pub(super) struct AcquisitionRequest {
    pub(super) wallet: Arc<dyn MonadWallet>,
    pub(super) gate: Arc<AcquisitionGate>,
    pub(super) session_id: [u8; 32],
    pub(super) hop_label: String,
    pub(super) receiver_pubkey: String,
    pub(super) advertisements: Vec<PaymentOption>,
    pub(super) versions: BTreeSet<String>,
    /// Session exclusions at start, plus a relay-confirmed intended channel.
    pub(super) excluded: BTreeSet<String>,
    pub(super) funding_token_target_msats: u64,
    pub(super) management: Option<(
        Arc<crate::management::ClientManagement>,
        Arc<crate::management::HopManagement>,
    )>,
}

#[derive(Debug)]
pub(super) struct AcquisitionReport {
    /// Channels to exclude for the rest of the session.
    pub(super) excluded: BTreeSet<String>,
    pub(super) outcome: AcquisitionOutcome,
}

#[derive(Debug)]
pub(super) struct AcquiredChannel {
    pub(super) channel: WalletChannel,
    pub(super) offer: RelayPaymentOffer,
    pub(super) authority: WalletChannelAccounting,
}

#[derive(Debug)]
pub(super) enum AcquisitionOutcome {
    /// Attached to this session with captured accounting authority.
    Acquired(Box<AcquiredChannel>),
    /// A local wallet failure that blocks funding for this session.
    Blocked(String),
    /// Every advertised offer was safely unavailable.
    OffersUnavailable(WalletError),
    /// Nothing to apply (no candidate, manual funding, management disabled).
    Idle,
    /// Cleanup cancelled the worker before it attached a channel.
    Cancelled,
}

enum Attach {
    Done(AcquisitionOutcome),
    /// Candidate not usable for this session; try the next one.
    Skip {
        exclude_for_session: bool,
    },
}

pub(super) fn run_acquisition(request: AcquisitionRequest) -> AcquisitionReport {
    let _busy = request
        .gate
        .busy
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut excluded = BTreeSet::new();
    let outcome = acquire(&request, &mut excluded);
    AcquisitionReport { excluded, outcome }
}

fn acquire(request: &AcquisitionRequest, excluded: &mut BTreeSet<String>) -> AcquisitionOutcome {
    // Candidates skipped only for this acquisition (not session exclusions),
    // so a non-excludable attach failure cannot reselect the same channel.
    let mut skipped = BTreeSet::new();
    loop {
        if request.gate.is_cancelled() {
            return AcquisitionOutcome::Cancelled;
        }
        let unavailable = request
            .excluded
            .iter()
            .chain(excluded.iter())
            .chain(skipped.iter())
            .cloned()
            .collect::<BTreeSet<_>>();
        let candidate = match choose_channel_and_offer(request, &unavailable) {
            Ok(Some(candidate)) => {
                info!(
                    "{} selected existing channel {}",
                    request.hop_label, candidate.0.channel_id
                );
                candidate
            }
            Ok(None) => match provision(request) {
                Ok(Some(candidate)) => candidate,
                Ok(None) => return AcquisitionOutcome::Idle,
                Err(outcome) => return outcome,
            },
            Err(error) => return blocked_on_backend(error),
        };
        if request.gate.is_cancelled() {
            return AcquisitionOutcome::Cancelled;
        }
        let channel_id = candidate.0.channel_id.clone();
        match attach(request, candidate.0, candidate.1) {
            Attach::Done(outcome) => return outcome,
            Attach::Skip {
                exclude_for_session,
            } => {
                if exclude_for_session {
                    excluded.insert(channel_id);
                } else {
                    skipped.insert(channel_id);
                }
            }
        }
    }
}

fn blocked_on_backend(error: WalletError) -> AcquisitionOutcome {
    if matches!(error, WalletError::Backend(_)) {
        AcquisitionOutcome::Blocked(error.to_string())
    } else {
        AcquisitionOutcome::Idle
    }
}

fn choose_channel_and_offer(
    request: &AcquisitionRequest,
    unavailable: &BTreeSet<String>,
) -> Result<Option<(WalletChannel, RelayPaymentOffer)>, WalletError> {
    let wallet = request.wallet.as_ref();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let channels = wallet
        .list_channels()?
        .into_iter()
        .filter(|channel| !unavailable.contains(&channel.channel_id))
        .collect::<Vec<_>>();
    let preference = wallet.commitment_mode_preference();
    for advertisement in &request.advertisements {
        let offer = RelayPaymentOffer::from_advertisement(
            request.receiver_pubkey.clone(),
            advertisement,
            &request.versions,
        );
        let mut eligible = channels
            .iter()
            .filter(|channel| preference.is_none_or(|mode| mode == channel.commitment_mode))
            .cloned()
            .collect::<Vec<_>>();
        while let Some(channel) = select_channel(&eligible, &offer, request.session_id, now) {
            if wallet
                .supports_commitment_mode(&offer.mint_url, channel.commitment_mode)
                .unwrap_or(false)
            {
                return Ok(Some((channel, offer)));
            }
            // Unknown/unsupported optional capability makes this mode locally
            // ineligible, not globally unusable. Other accepted modes may reuse
            // funds. Only eligible candidates trigger capability discovery.
            eligible.retain(|other| other.commitment_mode != channel.commitment_mode);
        }
    }
    Ok(None)
}

pub(super) fn provisioning_offer_is_unavailable(error: &WalletError) -> bool {
    // These are the wallet's explicitly safe offer-local outcomes. Generic
    // backend failures can follow a reservation or ambiguous submission, so they
    // must stop traversal rather than funding a different offer.
    matches!(
        error,
        WalletError::NoCompatibleActiveKeyset { .. }
            | WalletError::InsufficientLooseProofFunds { .. }
            | WalletError::InputKeysetMetadataUnavailable { .. }
            | WalletError::TooManyInputProofs { .. }
            | WalletError::ProvisioningOfferUnavailable { .. }
            | WalletError::ProvisioningPreflight { .. }
    )
}

pub(super) fn provision_from_advertisements<F>(
    receiver_pubkey: &str,
    advertisements: &[PaymentOption],
    versions: &BTreeSet<String>,
    mut provision: F,
) -> Result<Option<(String, RelayPaymentOffer)>, WalletError>
where
    F: FnMut(&RelayPaymentOffer) -> Result<String, WalletError>,
{
    let mut unavailable = None;
    for advertisement in advertisements {
        let offer = RelayPaymentOffer::from_advertisement(
            receiver_pubkey.to_string(),
            advertisement,
            versions,
        );
        match provision(&offer) {
            Ok(channel_id) => return Ok(Some((channel_id, offer))),
            Err(error) if provisioning_offer_is_unavailable(&error) => unavailable = Some(error),
            Err(error) => return Err(error),
        }
    }
    match unavailable {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

/// Provision a new channel. `Ok(None)` means there is nothing to apply.
fn provision(
    request: &AcquisitionRequest,
) -> Result<Option<(WalletChannel, RelayPaymentOffer)>, AcquisitionOutcome> {
    if let Some((owner, hop)) = &request.management {
        if !hop.begin_provisioning(owner) {
            return Ok(None);
        }
    }
    let selected = provision_from_advertisements(
        &request.receiver_pubkey,
        &request.advertisements,
        &request.versions,
        |offer| {
            info!(
                "{} provisioning new channel for mint={} unit={}",
                request.hop_label, offer.mint_url, offer.unit
            );
            request
                .wallet
                .provision_session_channel(offer, request.funding_token_target_msats)
        },
    );
    let manual = request
        .management
        .as_ref()
        .filter(|(owner, _)| !owner.controls().automatic_provisioning);
    if let Some((owner, hop)) = &request.management {
        hop.provisioning_finished(owner);
    }
    let (channel_id, offer) = match selected {
        Ok(Some(selected)) => selected,
        Ok(None) => {
            if let Some((owner, hop)) = manual {
                hop.safe_provisioning_failure(owner);
            }
            return Ok(None);
        }
        Err(error) if provisioning_offer_is_unavailable(&error) => {
            if let Some((owner, hop)) = manual {
                hop.safe_provisioning_failure(owner);
                return Ok(None);
            }
            return Err(AcquisitionOutcome::OffersUnavailable(error));
        }
        Err(error) => return Err(blocked_on_backend(error)),
    };
    match request.wallet.get_channel(&channel_id) {
        Ok(channel) => Ok(Some((channel, offer))),
        Err(error) => Err(blocked_on_backend(error)),
    }
}

/// Reserve a candidate and capture its accounting authority.
fn attach(
    request: &AcquisitionRequest,
    channel: WalletChannel,
    offer: RelayPaymentOffer,
) -> Attach {
    let channel_id = channel.channel_id.clone();
    let wallet = request.wallet.as_ref();
    if let Err(error) = wallet.attach_channel_to_session(&channel_id, request.session_id) {
        if matches!(error, WalletError::Backend(_)) {
            return Attach::Done(AcquisitionOutcome::Blocked(error.to_string()));
        }
        return Attach::Skip {
            exclude_for_session: exclude_on_wallet_error(&error),
        };
    }
    let blocked = |detail: String| {
        let _ = wallet.detach_channel_from_session(&channel_id, request.session_id);
        Attach::Done(AcquisitionOutcome::Blocked(detail))
    };
    match wallet.get_channel_accounting(&channel_id) {
        Ok(authority)
            if authority.state == WalletChannelState::Open
                && authority.attached_session_id == Some(request.session_id)
                && authority.current_signed_balance_raw <= authority.capacity_raw =>
        {
            Attach::Done(AcquisitionOutcome::Acquired(Box::new(AcquiredChannel {
                channel,
                offer,
                authority,
            })))
        }
        Ok(_) => blocked("reserved channel accounting is inconsistent".into()),
        Err(error) => blocked(format!(
            "reserved channel accounting lookup failed: {error}"
        )),
    }
}
