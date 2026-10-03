//! Outbound SOCKS5 CONNECT client.
//!
//! Supports no-auth CONNECT requests to IPv4, IPv6, and domain destinations.
//! Each protocol stage has an explicit timeout, and the whole operation is
//! cancelable by dropping the future.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// SOCKS5 reply code names for diagnostics.
fn reply_name(code: u8) -> &'static str {
    match code {
        0x00 => "success",
        0x01 => "general_server_failure",
        0x02 => "connection_not_allowed",
        0x03 => "network_unreachable",
        0x04 => "host_unreachable",
        0x05 => "connection_refused",
        0x06 => "ttl_expired",
        0x07 => "command_not_supported",
        0x08 => "address_type_not_supported",
        _ => "unknown",
    }
}

/// Destination address type for a SOCKS5 CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksDestination {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(String),
}

impl SocksDestination {
    fn write_request(&self, port: u16, out: &mut Vec<u8>) {
        match self {
            SocksDestination::Ipv4(addr) => {
                out.push(0x01);
                out.extend_from_slice(&addr.octets());
            }
            SocksDestination::Domain(domain) => {
                out.push(0x03);
                let bytes = domain.as_bytes();
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
            }
            SocksDestination::Ipv6(addr) => {
                out.push(0x04);
                out.extend_from_slice(&addr.octets());
            }
        }
        out.extend_from_slice(&port.to_be_bytes());
    }
}

impl std::fmt::Display for SocksDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksDestination::Ipv4(addr) => write!(f, "{addr}"),
            SocksDestination::Ipv6(addr) => write!(f, "[{addr}]"),
            SocksDestination::Domain(domain) => write!(f, "{domain}"),
        }
    }
}

/// Errors returned by the outbound SOCKS5 client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocksClientError {
    /// The proxy rejected the handshake or request with a SOCKS reply code.
    Rejected { code: u8, stage: &'static str },
    /// The server returned an unsupported address type in its reply.
    UnsupportedReplyAddressType(u8),
    /// A protocol stage timed out.
    TimedOut(&'static str),
    /// The server returned an unexpected version or method selection.
    Protocol(&'static str),
    /// The target address could not be parsed.
    InvalidTarget(&'static str),
    /// An I/O error occurred on the proxy connection.
    Io(String),
}

impl std::fmt::Display for SocksClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksClientError::Rejected { code, stage } => {
                write!(
                    f,
                    "SOCKS proxy rejected {stage}: 0x{code:02x} {}",
                    reply_name(*code)
                )
            }
            SocksClientError::UnsupportedReplyAddressType(atyp) => {
                write!(f, "unsupported SOCKS reply address type: 0x{atyp:02x}")
            }
            SocksClientError::TimedOut(stage) => write!(f, "SOCKS stage timed out: {stage}"),
            SocksClientError::Protocol(msg) => write!(f, "SOCKS protocol error: {msg}"),
            SocksClientError::InvalidTarget(msg) => write!(f, "invalid SOCKS target: {msg}"),
            SocksClientError::Io(msg) => write!(f, "SOCKS I/O error: {msg}"),
        }
    }
}

impl std::error::Error for SocksClientError {}

impl From<io::Error> for SocksClientError {
    fn from(error: io::Error) -> Self {
        SocksClientError::Io(error.to_string())
    }
}

/// Parse a target string of the form `host:port` into a SOCKS destination.
///
/// Supports:
///   - `127.0.0.1:80` (IPv4)
///   - `[::1]:80`     (IPv6)
///   - `example.com:80` (domain)
pub fn parse_target(target: &str) -> Result<(SocksDestination, u16), SocksClientError> {
    if target.is_empty() {
        return Err(SocksClientError::InvalidTarget("empty target"));
    }

    // IPv6 bracket form.
    if target.starts_with('[') {
        let Some((host, port_str)) = target.rsplit_once(':') else {
            return Err(SocksClientError::InvalidTarget("missing port"));
        };
        if !host.starts_with('[') || !host.ends_with(']') {
            return Err(SocksClientError::InvalidTarget("malformed IPv6 brackets"));
        }
        let inner = &host[1..host.len() - 1];
        let addr = inner
            .parse::<Ipv6Addr>()
            .map_err(|_| SocksClientError::InvalidTarget("invalid IPv6 address"))?;
        let port = port_str
            .parse::<u16>()
            .map_err(|_| SocksClientError::InvalidTarget("invalid port"))?;
        if port == 0 {
            return Err(SocksClientError::InvalidTarget("zero port"));
        }
        return Ok((SocksDestination::Ipv6(addr), port));
    }

    // IPv4 or domain: find the last colon to avoid IPv6 literals without brackets.
    let Some((host, port_str)) = target.rsplit_once(':') else {
        return Err(SocksClientError::InvalidTarget("missing port"));
    };
    if host.is_empty() {
        return Err(SocksClientError::InvalidTarget("empty host"));
    }
    if host.contains(':') {
        return Err(SocksClientError::InvalidTarget(
            "IPv6 literals must be bracketed",
        ));
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| SocksClientError::InvalidTarget("invalid port"))?;
    if port == 0 {
        return Err(SocksClientError::InvalidTarget("zero port"));
    }
    if host.len() > 255
        || !host.is_ascii()
        || host
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(SocksClientError::InvalidTarget(
            "invalid domain length or encoding",
        ));
    }

    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        Ok((SocksDestination::Ipv4(addr), port))
    } else {
        Ok((SocksDestination::Domain(host.to_owned()), port))
    }
}

/// Established SOCKS5 connection result.
#[derive(Debug)]
pub struct SocksConnection {
    /// The TCP stream to the proxy, ready for application data.
    pub stream: TcpStream,
    /// The address the proxy reports it bound for the upstream connection.
    pub bind_addr: SocksDestination,
    /// The port the proxy reports it bound for the upstream connection.
    pub bind_port: u16,
}

/// Connect through a SOCKS5 proxy.
///
/// `proxy` is the SOCKS5 listener address. `target` is the desired destination
/// as `host:port`. The operation can be canceled by dropping the returned
/// future; each stage is bounded by `stage_timeout`.
async fn with_timeout<T>(
    name: &'static str,
    limit: Duration,
    fut: impl std::future::Future<Output = Result<T, SocksClientError>> + Send,
) -> Result<T, SocksClientError> {
    timeout(limit, fut)
        .await
        .map_err(|_| SocksClientError::TimedOut(name))?
}

/// Connect through a SOCKS5 proxy.
///
/// `proxy` is the SOCKS5 listener address. `target` is the desired destination
/// as `host:port`. The operation can be canceled by dropping the returned
/// future; each stage is bounded by `stage_timeout`.
pub async fn connect(
    proxy: SocketAddr,
    target: &str,
    stage_timeout: Duration,
) -> Result<SocksConnection, SocksClientError> {
    let (destination, port) = parse_target(target)?;

    let mut stream = with_timeout("tcp_connect", stage_timeout, async {
        Ok::<_, SocksClientError>(TcpStream::connect(proxy).await?)
    })
    .await?;

    // Greeting: VER=5, NMETHODS=1, METHODS=[NO_AUTH]
    with_timeout("greeting_send", stage_timeout, async {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        Ok::<_, SocksClientError>(())
    })
    .await?;

    with_timeout("greeting_reply", stage_timeout, async {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x05 {
            return Err(SocksClientError::Protocol("unexpected greeting version"));
        }
        if header[1] == 0xFF {
            return Err(SocksClientError::Rejected {
                code: header[1],
                stage: "method negotiation",
            });
        }
        if header[1] != 0x00 {
            return Err(SocksClientError::Protocol(
                "unexpected selected auth method",
            ));
        }
        Ok::<_, SocksClientError>(())
    })
    .await?;

    // Request: VER=5, CMD=CONNECT, RSV=0, ATYP, DST.ADDR, DST.PORT
    let mut request = vec![0x05, 0x01, 0x00];
    destination.write_request(port, &mut request);
    with_timeout("request_send", stage_timeout, async {
        stream.write_all(&request).await?;
        Ok::<_, SocksClientError>(())
    })
    .await?;

    with_timeout("request_reply", stage_timeout, async {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x05 {
            return Err(SocksClientError::Protocol("unexpected reply version"));
        }
        if header[1] != 0x00 {
            return Err(SocksClientError::Rejected {
                code: header[1],
                stage: "connect request",
            });
        }
        let atyp = header[3];
        let bind_addr = match atyp {
            0x01 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                SocksDestination::Ipv4(Ipv4Addr::from(octets))
            }
            0x03 => {
                let len = stream.read_u8().await? as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await?;
                let domain = String::from_utf8(domain)
                    .map_err(|_| SocksClientError::Protocol("invalid domain name in reply"))?;
                SocksDestination::Domain(domain)
            }
            0x04 => {
                let mut octets = [0u8; 16];
                stream.read_exact(&mut octets).await?;
                SocksDestination::Ipv6(Ipv6Addr::from(octets))
            }
            _ => return Err(SocksClientError::UnsupportedReplyAddressType(atyp)),
        };
        let mut port_bytes = [0u8; 2];
        stream.read_exact(&mut port_bytes).await?;
        let bind_port = u16::from_be_bytes(port_bytes);
        Ok::<_, SocksClientError>(SocksConnection {
            stream,
            bind_addr,
            bind_port,
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve_socks(
        listener: TcpListener,
        reply_code: u8,
        reply_atyp: u8,
        reply_addr: Vec<u8>,
        reply_port: u16,
    ) -> io::Result<()> {
        let (mut stream, _) = listener.accept().await?;

        // Greeting.
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(greeting[0], 0x05);
        let nmethods = greeting[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;
        assert!(methods.contains(&0x00));
        stream.write_all(&[0x05, 0x00]).await?;

        // Request.
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        assert_eq!(header[0], 0x05);
        assert_eq!(header[1], 0x01); // CONNECT
        assert_eq!(header[2], 0x00);
        let atyp = header[3];
        match atyp {
            0x01 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
            }
            0x03 => {
                let len = stream.read_u8().await? as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await?;
            }
            0x04 => {
                let mut buf = [0u8; 16];
                stream.read_exact(&mut buf).await?;
            }
            _ => panic!("unexpected atyp {atyp}"),
        }
        let mut port_bytes = [0u8; 2];
        stream.read_exact(&mut port_bytes).await?;

        // Reply. For ATYP 0x03 prepend the domain length byte.
        let mut reply = vec![0x05, reply_code, 0x00, reply_atyp];
        if reply_atyp == 0x03 {
            reply.push(reply_addr.len().min(255) as u8);
        }
        reply.extend_from_slice(&reply_addr);
        reply.extend_from_slice(&reply_port.to_be_bytes());
        stream.write_all(&reply).await?;
        Ok(())
    }

    #[tokio::test]
    async fn request_encoding_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_socks(
            listener,
            0x00,
            0x01,
            Ipv4Addr::LOCALHOST.octets().to_vec(),
            12345,
        ));
        let conn = connect(proxy_addr, "127.0.0.1:8080", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(conn.bind_addr, SocksDestination::Ipv4(Ipv4Addr::LOCALHOST));
        assert_eq!(conn.bind_port, 12345);
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn request_encoding_ipv6() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_socks(
            listener,
            0x00,
            0x04,
            Ipv6Addr::LOCALHOST.octets().to_vec(),
            80,
        ));
        let conn = connect(proxy_addr, "[::1]:443", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(conn.bind_addr, SocksDestination::Ipv6(Ipv6Addr::LOCALHOST));
        assert_eq!(conn.bind_port, 80);
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn request_encoding_domain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_socks(
            listener,
            0x00,
            0x03,
            b"bound.example.com".to_vec(),
            443,
        ));
        let conn = connect(proxy_addr, "example.com:443", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            conn.bind_addr,
            SocksDestination::Domain("bound.example.com".into())
        );
        assert_eq!(conn.bind_port, 443);
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn fragmented_reply_is_reassembled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            let nmethods = greeting[1] as usize;
            let mut methods = vec![0u8; nmethods];
            stream.read_exact(&mut methods).await.unwrap();
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).await.unwrap();
            let atyp = header[3];
            match atyp {
                0x01 => {
                    let _ = stream.read_exact(&mut [0u8; 4]).await;
                }
                0x03 => {
                    let len = stream.read_u8().await.unwrap() as usize;
                    let _ = stream.read_exact(&mut vec![0u8; len]).await;
                }
                0x04 => {
                    let _ = stream.read_exact(&mut [0u8; 16]).await;
                }
                _ => panic!(),
            }
            stream.read_exact(&mut [0u8; 2]).await.unwrap();

            // Send reply one byte at a time.
            let reply = [0x05u8, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34];
            for byte in reply {
                stream.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let conn = connect(proxy_addr, "127.0.0.1:1", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(conn.bind_port, 0x1234);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn all_valid_reply_atypes() {
        for (atyp, addr, port) in [
            (0x01u8, b"\x7f\x00\x00\x01".as_slice(), 80u16),
            (0x03u8, b"host".as_slice(), 443u16),
            (0x04u8, &[0u8; 16], 8080u16),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = listener.local_addr().unwrap();
            let server = tokio::spawn(serve_socks(listener, 0x00, atyp, addr.to_vec(), port));
            let conn = connect(proxy_addr, "127.0.0.1:1", Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(conn.bind_port, port);
            server.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn malformed_greeting_version_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(&[0x04, 0x00]).await.unwrap();
        });
        let err = connect(proxy_addr, "127.0.0.1:1", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SocksClientError::Protocol("unexpected greeting version")
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn timeout_on_stalled_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        let err = connect(proxy_addr, "127.0.0.1:1", Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(err, SocksClientError::TimedOut(_)));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn cancellation_by_drop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let (ready, received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            ready.send(()).unwrap();
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
        });
        {
            let fut = connect(proxy_addr, "127.0.0.1:1", Duration::from_secs(60));
            tokio::pin!(fut);
            tokio::select! { _ = received => {}, _ = &mut fut => panic!("handshake should be pending") }
        }
        timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn rejected_request_returns_code() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_socks(
            listener,
            0x05,
            0x01,
            Ipv4Addr::LOCALHOST.octets().to_vec(),
            0,
        ));
        let err = connect(proxy_addr, "127.0.0.1:1", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            SocksClientError::Rejected {
                code: 0x05,
                stage: "connect request",
            }
        );
        server.await.unwrap().unwrap();
    }

    #[test]
    fn parse_target_variants() {
        assert_eq!(
            parse_target("127.0.0.1:80").unwrap(),
            (SocksDestination::Ipv4(Ipv4Addr::LOCALHOST), 80)
        );
        assert_eq!(
            parse_target("[::1]:443").unwrap(),
            (SocksDestination::Ipv6(Ipv6Addr::LOCALHOST), 443)
        );
        assert_eq!(
            parse_target("example.com:8080").unwrap(),
            (SocksDestination::Domain("example.com".into()), 8080)
        );
        assert!(parse_target("example.com").is_err());
        assert!(parse_target(":80").is_err());
        assert!(parse_target("::1:80").is_err());
        assert!(parse_target(&format!("{}:80", "x".repeat(256))).is_err());
        assert!(parse_target("localhost:0").is_err());
    }

    #[test]
    fn exact_destination_wire_bytes() {
        for (target, expected) in [
            ("192.0.2.1:8080", vec![1, 192, 0, 2, 1, 0x1f, 0x90]),
            (
                "example.com:443",
                [vec![3, 11], b"example.com".to_vec(), vec![1, 187]].concat(),
            ),
            (
                "[::1]:80",
                [vec![4], Ipv6Addr::LOCALHOST.octets().to_vec(), vec![0, 80]].concat(),
            ),
        ] {
            let (destination, port) = parse_target(target).unwrap();
            let mut actual = Vec::new();
            destination.write_request(port, &mut actual);
            assert_eq!(actual, expected);
        }
    }
}
