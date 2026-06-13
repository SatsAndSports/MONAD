use std::io;

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
