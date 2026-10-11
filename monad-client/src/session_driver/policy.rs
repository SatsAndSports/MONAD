//! Funding strategy: no wallet, locks, clock reads, or I/O.
use super::PaymentPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Intent {
    Wait,
    AcquireChannel,
    LinkAcquired,
    Pay {
        requested_delta_msats: u64,
    },
    Unlink,
    #[allow(dead_code)] // Supported policy action; the default retains candidates.
    ReleaseAcquired,
    ReleaseExhausted,
    #[allow(dead_code)] // The default uses local counters rather than polling.
    RequestStatus,
}

pub(super) struct View {
    pub acquired: bool,
    pub linked: bool,
    pub release_requested: bool,
    pub paused: bool,
    pub relay_remaining: i64,
    pub estimated_remaining: Option<i64>,
    pub exhausted: bool,
    pub skip_payment: bool,
    pub retry_eligible: bool,
}

pub(super) trait FundingStrategy {
    fn decide(&self, view: &View) -> Intent;
}

impl FundingStrategy for PaymentPolicy {
    fn decide(&self, view: &View) -> Intent {
        if view.release_requested {
            return Intent::Unlink;
        }
        if !view.retry_eligible {
            return Intent::Wait;
        }
        if view.acquired {
            return Intent::LinkAcquired;
        }
        if !view.linked {
            return if view.paused || view.estimated_remaining.is_some_and(|v| v <= 0) {
                Intent::AcquireChannel
            } else {
                Intent::Wait
            };
        }
        if view.skip_payment {
            return Intent::Wait;
        }
        let Some(remaining) = view.estimated_remaining else {
            return Intent::Wait;
        };
        let wants_payment = view.paused
            || view.relay_remaining <= 0
            || i128::from(remaining) < i128::from(self.target_topup_buffer_msats);
        let gap = i128::from(self.target_topup_buffer_msats) - i128::from(remaining);
        if !wants_payment || gap <= 0 {
            return Intent::Wait;
        }
        if view.exhausted {
            return if remaining > 0 {
                Intent::Wait
            } else {
                Intent::ReleaseExhausted
            };
        }
        Intent::Pay {
            requested_delta_msats: (gap.min(i128::from(u64::MAX)) as u64)
                .max(self.minimum_topup_msats),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_preserves_threshold_minimum_and_exhaustion_rules() {
        let policy = PaymentPolicy {
            target_topup_buffer_msats: 100,
            minimum_topup_msats: 20,
            ..Default::default()
        };
        let mut view = View {
            acquired: false,
            linked: true,
            release_requested: false,
            paused: false,
            relay_remaining: 100,
            estimated_remaining: Some(100),
            exhausted: false,
            skip_payment: false,
            retry_eligible: true,
        };
        for (remaining, expected) in [
            (100, Intent::Wait),
            (101, Intent::Wait),
            (
                99,
                Intent::Pay {
                    requested_delta_msats: 20,
                },
            ),
            (
                -5,
                Intent::Pay {
                    requested_delta_msats: 105,
                },
            ),
        ] {
            view.estimated_remaining = Some(remaining);
            assert_eq!(policy.decide(&view), expected);
        }
        view.exhausted = true;
        view.estimated_remaining = Some(1);
        assert_eq!(policy.decide(&view), Intent::Wait);
        view.estimated_remaining = Some(0);
        assert_eq!(policy.decide(&view), Intent::ReleaseExhausted);
        view.linked = false;
        assert_eq!(policy.decide(&view), Intent::AcquireChannel);
        view.acquired = true;
        assert_eq!(policy.decide(&view), Intent::LinkAcquired);
        view.retry_eligible = false;
        assert_eq!(policy.decide(&view), Intent::Wait);
        view.release_requested = true;
        assert_eq!(policy.decide(&view), Intent::Unlink);
    }
}
