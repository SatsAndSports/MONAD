/// Default post-channel-expiry time reserved for funding proof recovery.
pub const DEFAULT_RECOVERY_WINDOW_SECS: u64 = 24 * 3600;

/// Minimum remaining lifetime at link/relink acceptance. Equality is allowed;
/// overflow is not. This does not impose an ongoing payment cutoff.
pub fn channel_covers_minimum_lifetime(now: u64, channel_expiry: u64, minimum: u64) -> bool {
    now.checked_add(minimum)
        .is_some_and(|required| channel_expiry >= required)
}

/// Admission only: never apply this policy to restore, refund, or close outputs.
pub fn funding_keyset_covers_channel(
    final_expiry: Option<u64>,
    channel_expiry: u64,
    recovery_window: u64,
) -> bool {
    match final_expiry {
        None => true,
        Some(0) => false,
        Some(expiry) => channel_expiry
            .checked_add(recovery_window)
            .is_some_and(|required| expiry >= required),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_lifetime_boundaries() {
        assert!(channel_covers_minimum_lifetime(100, 160, 60));
        assert!(!channel_covers_minimum_lifetime(100, 159, 60));
        assert!(!channel_covers_minimum_lifetime(101, 160, 60));
        assert!(channel_covers_minimum_lifetime(u64::MAX - 1, u64::MAX, 1));
        assert!(!channel_covers_minimum_lifetime(u64::MAX, u64::MAX, 1));
        assert!(!channel_covers_minimum_lifetime(100, 99, 0));
    }

    #[test]
    fn admission_boundaries() {
        assert!(funding_keyset_covers_channel(None, u64::MAX, 1));
        assert!(!funding_keyset_covers_channel(Some(0), 0, 0));
        assert!(funding_keyset_covers_channel(Some(150), 100, 50));
        assert!(!funding_keyset_covers_channel(Some(149), 100, 50));
        assert!(!funding_keyset_covers_channel(Some(u64::MAX), u64::MAX, 1));
    }
}
