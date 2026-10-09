//! Exact session billing arithmetic.
//!
//! The combined amount due is `ceil(bytes_in / in_rate + bytes_out / out_rate)`.
//! This module computes that value with integer quotient/remainder arithmetic so
//! implementations never round each direction separately, use floating point, or
//! saturate an LCM.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PricingError {
    #[error("billing rates must be positive: in={in_rate}, out={out_rate}")]
    ZeroRate { in_rate: u64, out_rate: u64 },
}

fn amount_due_millisats_unchecked(
    session_total_bytes_in: u64,
    session_total_bytes_out: u64,
    in_bytes_per_millisat: u64,
    out_bytes_per_millisat: u64,
) -> u128 {
    debug_assert!(in_bytes_per_millisat > 0);
    debug_assert!(out_bytes_per_millisat > 0);

    let whole_in = session_total_bytes_in / in_bytes_per_millisat;
    let remainder_in = session_total_bytes_in % in_bytes_per_millisat;
    let whole_out = session_total_bytes_out / out_bytes_per_millisat;
    let remainder_out = session_total_bytes_out % out_bytes_per_millisat;

    let extra = if remainder_in == 0 && remainder_out == 0 {
        0
    } else {
        let in_fraction = remainder_in as u128 * out_bytes_per_millisat as u128;
        let out_fraction = remainder_out as u128 * in_bytes_per_millisat as u128;
        let denominator = in_bytes_per_millisat as u128 * out_bytes_per_millisat as u128;
        // Equality is exactly one whole fractional millisat. Comparing this way
        // avoids a sum that could require one bit more than u128 for u64 inputs.
        if in_fraction <= denominator - out_fraction {
            1
        } else {
            2
        }
    };

    whole_in as u128 + whole_out as u128 + extra
}

/// Compute the exact combined amount due in millisats.
pub fn amount_due_millisats(
    session_total_bytes_in: u64,
    session_total_bytes_out: u64,
    in_bytes_per_millisat: u64,
    out_bytes_per_millisat: u64,
) -> Result<u128, PricingError> {
    if in_bytes_per_millisat == 0 || out_bytes_per_millisat == 0 {
        return Err(PricingError::ZeroRate {
            in_rate: in_bytes_per_millisat,
            out_rate: out_bytes_per_millisat,
        });
    }
    Ok(amount_due_millisats_unchecked(
        session_total_bytes_in,
        session_total_bytes_out,
        in_bytes_per_millisat,
        out_bytes_per_millisat,
    ))
}

/// Compute exact remaining session credit as a signed integer.
pub fn remaining_milli_sats(
    total_paid_millisats: u64,
    session_total_bytes_in: u64,
    session_total_bytes_out: u64,
    in_bytes_per_millisat: u64,
    out_bytes_per_millisat: u64,
) -> Result<i128, PricingError> {
    let due = amount_due_millisats(
        session_total_bytes_in,
        session_total_bytes_out,
        in_bytes_per_millisat,
        out_bytes_per_millisat,
    )?;
    Ok(total_paid_millisats as i128 - due as i128)
}

/// Convert exact remaining credit to the signed wire field without
/// approximation. `None` means the value is outside the representable range.
pub fn remaining_milli_sats_to_wire(remaining_milli_sats: i128) -> Option<i64> {
    i64::try_from(remaining_milli_sats).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_due(bytes_in: u64, bytes_out: u64, in_rate: u64, out_rate: u64) -> u128 {
        let numerator = bytes_in as u128 * out_rate as u128 + bytes_out as u128 * in_rate as u128;
        let denominator = in_rate as u128 * out_rate as u128;
        numerator.div_ceil(denominator)
    }

    fn assert_due(expected: u128, bytes_in: u64, bytes_out: u64, in_rate: u64, out_rate: u64) {
        assert_eq!(
            amount_due_millisats(bytes_in, bytes_out, in_rate, out_rate).unwrap(),
            expected,
            "bytes=({bytes_in},{bytes_out}) rates=({in_rate},{out_rate})"
        );
        if let Some(numerator) =
            (bytes_in as u128 * out_rate as u128).checked_add(bytes_out as u128 * in_rate as u128)
        {
            let denominator = in_rate as u128 * out_rate as u128;
            assert_eq!(
                amount_due_millisats(bytes_in, bytes_out, in_rate, out_rate).unwrap(),
                numerator.div_ceil(denominator),
                "reference mismatch"
            );
        }
    }

    #[test]
    fn rejects_zero_rates() {
        for (in_rate, out_rate) in [(0, 1), (1, 0), (0, 0)] {
            assert_eq!(
                amount_due_millisats(0, 0, in_rate, out_rate),
                Err(PricingError::ZeroRate { in_rate, out_rate })
            );
        }
    }

    #[test]
    fn handles_zero_and_exact_division() {
        assert_due(0, 0, 0, 1, 1);
        assert_due(0, 0, 0, u64::MAX, u64::MAX);
        assert_due(6, 6, 9, 2, 3);
        assert_due(2, 4, 0, 2, 7);
        assert_due(2, 0, 6, 7, 3);
    }

    #[test]
    fn rounds_the_combined_fraction_once() {
        // Each direction contributes 1 + 2/3; the combined fractional sum is
        // 4/3, so the result is 2 + ceil(4/3) = 4.
        assert_due(4, 5, 5, 3, 3);
        // Fractional contributions of 2/3 and 1/4 sum to 11/12.
        assert_due(1, 2, 1, 3, 4);
        // Fractional contributions of 3/4 and 1/2 sum to exactly one.
        assert_due(2, 3, 1, 4, 2);
        // Fractional contributions of 3/4 and 3/4 sum to 3/2.
        assert_due(2, 3, 3, 4, 4);
        assert_due(1, 1, 0, 3, 7);
        assert_due(1, 0, 1, 7, 3);
    }

    #[test]
    fn supports_asymmetric_and_extreme_inputs() {
        assert_due(5, 5, 11, 2, 7);
        assert_due(3, u64::MAX, u64::MAX, u64::MAX, u64::MAX - 1);
        assert_due(1, u64::MAX, 0, u64::MAX, 1);
        assert_due(2, u64::MAX, 1, u64::MAX, u64::MAX);
    }

    #[test]
    fn matches_reference_over_small_domain() {
        for in_rate in 1..=12_u64 {
            for out_rate in 1..=12_u64 {
                for bytes_in in 0..=40_u64 {
                    for bytes_out in 0..=40_u64 {
                        assert_eq!(
                            amount_due_millisats(bytes_in, bytes_out, in_rate, out_rate).unwrap(),
                            reference_due(bytes_in, bytes_out, in_rate, out_rate),
                            "bytes=({bytes_in},{bytes_out}) rates=({in_rate},{out_rate})"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn matches_reference_for_deterministic_large_samples() {
        let mut state = 0x9e3779b97f4a7c15_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2_000 {
            let in_rate = next() % 1_000_000 + 1;
            let out_rate = next() % 1_000_000 + 1;
            let bytes_in = next();
            let bytes_out = next();
            assert_eq!(
                amount_due_millisats(bytes_in, bytes_out, in_rate, out_rate).unwrap(),
                reference_due(bytes_in, bytes_out, in_rate, out_rate),
                "bytes=({bytes_in},{bytes_out}) rates=({in_rate},{out_rate})"
            );
        }
    }

    #[test]
    fn wire_conversion_is_exact_at_i64_boundaries() {
        assert_eq!(
            remaining_milli_sats_to_wire(i64::MAX as i128),
            Some(i64::MAX)
        );
        assert_eq!(
            remaining_milli_sats_to_wire(i64::MIN as i128),
            Some(i64::MIN)
        );
        assert_eq!(remaining_milli_sats_to_wire(i64::MAX as i128 + 1), None);
        assert_eq!(remaining_milli_sats_to_wire(i64::MIN as i128 - 1), None);
    }
}
