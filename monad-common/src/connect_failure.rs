//! Typed local transport failures. These are not relay-reported refusals.
use crate::rejection::RejectionCode;
use std::{fmt, io, net::SocketAddr};

#[derive(Debug)]
pub struct ConnectFailure {
    pub code: RejectionCode,
    source: io::Error,
}
impl ConnectFailure {
    pub fn wrap(code: RejectionCode, source: io::Error) -> io::Error {
        io::Error::new(source.kind(), Self { code, source })
    }
    pub fn from_io(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
}
impl fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.rejection(), self.source)
    }
}
impl std::error::Error for ConnectFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub fn tcp_error_code(kind: io::ErrorKind) -> RejectionCode {
    match kind {
        io::ErrorKind::ConnectionRefused => RejectionCode::TcpConnectionRefused,
        io::ErrorKind::TimedOut => RejectionCode::TcpConnectTimedOut,
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
            RejectionCode::TcpDestinationUnreachable
        }
        _ => RejectionCode::TcpConnectFailed,
    }
}

pub async fn connect_tcp(target: &str) -> io::Result<tokio::net::TcpStream> {
    connect_tcp_resolved(async {
        tokio::net::lookup_host(target)
            .await
            .map(|addresses| addresses.collect())
    })
    .await
}

async fn connect_tcp_resolved(
    resolution: impl std::future::Future<Output = io::Result<Vec<SocketAddr>>>,
) -> io::Result<tokio::net::TcpStream> {
    let addresses = resolution
        .await
        .map_err(|e| ConnectFailure::wrap(RejectionCode::TcpResolutionFailed, e))?;
    if addresses.is_empty() {
        return Err(ConnectFailure::wrap(
            RejectionCode::TcpResolutionFailed,
            io::Error::new(io::ErrorKind::NotFound, "no target addresses"),
        ));
    }
    tokio::net::TcpStream::connect(&addresses[..])
        .await
        .map_err(|e| ConnectFailure::wrap(tcp_error_code(e.kind()), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn resolution_failure_and_refusal_are_distinct() {
        for resolution in [
            Ok(vec![]),
            Err(io::Error::other("resolver failure")),
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "DNS server refused",
            )),
        ] {
            let error = connect_tcp_resolved(async { resolution })
                .await
                .unwrap_err();
            assert_eq!(
                ConnectFailure::from_io(&error).unwrap().code,
                RejectionCode::TcpResolutionFailed
            );
        }
        let reserved = tokio::net::TcpSocket::new_v4().unwrap();
        reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let error = connect_tcp(&reserved.local_addr().unwrap().to_string())
            .await
            .unwrap_err();
        assert_eq!(
            ConnectFailure::from_io(&error).unwrap().code,
            RejectionCode::TcpConnectionRefused
        );
        assert_eq!(
            tcp_error_code(io::ErrorKind::TimedOut),
            RejectionCode::TcpConnectTimedOut
        );
        assert_eq!(
            tcp_error_code(io::ErrorKind::HostUnreachable),
            RejectionCode::TcpDestinationUnreachable
        );
        assert_eq!(
            tcp_error_code(io::ErrorKind::Other),
            RejectionCode::TcpConnectFailed
        );
    }
}
