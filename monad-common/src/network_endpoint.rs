use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Validate an endpoint immediately before a current TCP or QUIC dispatch.
///
/// Route addresses remain opaque until this boundary. Current transports require
/// an explicit nonzero numeric port and a DNS name, IPv4 address, or bracketed
/// IPv6 address.
pub fn validate_network_endpoint(endpoint: &str) -> io::Result<()> {
    let (host, port) = if let Some(bracketed) = endpoint.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or_else(|| invalid_endpoint("bracketed IPv6 endpoint is missing closing ]"))?;
        let port = suffix
            .strip_prefix(':')
            .ok_or_else(|| invalid_endpoint("bracketed IPv6 endpoint requires an explicit port"))?;
        if port.contains(':') || host.parse::<Ipv6Addr>().is_err() {
            return Err(invalid_endpoint("invalid bracketed IPv6 address"));
        }
        (host, port)
    } else {
        let (host, port) = endpoint
            .rsplit_once(':')
            .ok_or_else(|| invalid_endpoint("endpoint requires an explicit numeric port"))?;
        if host.contains(':') {
            return Err(invalid_endpoint(
                "IPv6 endpoints must use bracketed [address]:port syntax",
            ));
        }
        if host.parse::<Ipv4Addr>().is_err() && !valid_dns_name(host) {
            return Err(invalid_endpoint("endpoint host must be DNS or IPv4"));
        }
        (host, port)
    };

    if host.is_empty()
        || port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().ok().filter(|port| *port != 0).is_none()
    {
        return Err(invalid_endpoint(
            "endpoint port must be an explicit number between 1 and 65535",
        ));
    }

    Ok(())
}

fn valid_dns_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    !name.is_empty()
        && name.len() <= 253
        && !(name.contains('.')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.'))
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn invalid_endpoint(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_dns_ipv4_and_bracketed_ipv6_endpoints_are_valid() {
        for endpoint in [
            "localhost:9050",
            "relay.example.:00080",
            "127.0.0.1:1",
            "[::1]:9050",
            "[2001:db8::1]:65535",
        ] {
            validate_network_endpoint(endpoint).unwrap();
        }
    }

    #[test]
    fn portless_and_invalid_endpoints_are_rejected_before_dispatch() {
        for endpoint in [
            "localhost",
            "127.0.0.1",
            "::1",
            "[::1]",
            "host:0",
            "host:65536",
            "host:port",
            "999.0.0.1:9050",
        ] {
            let error = validate_network_endpoint(endpoint).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{endpoint}");
        }
    }
}
