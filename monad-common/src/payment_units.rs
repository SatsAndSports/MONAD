//! Helpers for converting between millisatoshis and a channel's raw balance unit.
//!
//! Supported units:
//! - `msat` — one raw unit equals one millisatoshi.
//! - `sat`  — one raw unit equals 1_000 millisatoshis.
//!
//! Conversions from msats to raw units round up so that a positive msat delta
//! always produces a non-negative raw delta.

use std::io;

/// Convert a millisatoshi amount into the channel's raw balance unit.
pub fn msats_to_raw_units(unit: &str, amount_msats: u64) -> io::Result<u64> {
    match unit {
        "msat" => Ok(amount_msats),
        "sat" => Ok(amount_msats.div_ceil(1000)),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported unit: {other}"),
        )),
    }
}

/// Convert a raw balance-unit amount into millisatoshis.
pub fn raw_units_to_msats(unit: &str, amount_raw: u64) -> io::Result<u64> {
    match unit {
        "msat" => Ok(amount_raw),
        "sat" => amount_raw
            .checked_mul(1000)
            .ok_or_else(|| io::Error::other("raw amount overflow")),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported unit: {other}"),
        )),
    }
}
