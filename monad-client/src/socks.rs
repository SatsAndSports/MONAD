//! Minimal SOCKS5 server implementation.
//!
//! Accepts local connections, parses SOCKS5 CONNECT requests, and returns the
//! destination address. The caller is responsible for actually proxying the data.
//!
//! Supports:
//!   - SOCKS5 with no authentication
//!   - CONNECT command only
//!   - IPv4, IPv6, and domain name address types

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::warn;

fn socks_method_name(method: u8) -> &'static str {
    match method {
        0x00 => "NO_AUTH",
        0x01 => "GSSAPI",
        0x02 => "USERNAME_PASSWORD",
        0x03..=0x7f => "IANA_ASSIGNED",
        0x80..=0xfe => "PRIVATE",
        0xff => "NO_ACCEPTABLE_METHODS",
    }
}

fn socks_command_name(cmd: u8) -> &'static str {
    match cmd {
        0x01 => "CONNECT",
        0x02 => "BIND",
        0x03 => "UDP_ASSOCIATE",
        _ => "UNKNOWN",
    }
}

fn socks_atyp_name(atyp: u8) -> &'static str {
    match atyp {
        0x01 => "IPV4",
        0x03 => "DOMAINNAME",
        0x04 => "IPV6",
        _ => "UNKNOWN",
    }
}

/// The destination extracted from a SOCKS5 CONNECT request.
#[derive(Debug, Clone)]
pub struct SocksTarget {
    /// The destination as "host:port" for use in H2 CONNECT authority.
    pub authority: String,
}

/// Perform the SOCKS5 handshake on an incoming local connection.
///
/// After this returns, the `stream` is ready for bidirectional data transfer.
/// The caller should proxy the stream to the target.
pub async fn socks5_handshake(stream: &mut TcpStream) -> io::Result<SocksTarget> {
    // --- Greeting phase ---
    // Client sends: VER (1) | NMETHODS (1) | METHODS (1-255)
    let ver = stream.read_u8().await?;
    if ver != 0x05 {
        warn!("SOCKS5 greeting rejected: unsupported_version=0x{ver:02x}");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported SOCKS version: {ver}"),
        ));
    }

    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    // We only support NO AUTH (0x00)
    if !methods.contains(&0x00) {
        // Send back "no acceptable methods"
        stream.write_all(&[0x05, 0xFF]).await?;
        let offered_methods = methods
            .iter()
            .map(|method| format!("0x{method:02x}({})", socks_method_name(*method)))
            .collect::<Vec<_>>()
            .join(",");
        warn!(
            "SOCKS5 auth negotiation rejected: offered_methods=[{offered_methods}], required_method=0x00(NO_AUTH)"
        );
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client does not support no-auth",
        ));
    }

    // Send back: VER (0x05) | METHOD (0x00 = no auth)
    stream.write_all(&[0x05, 0x00]).await?;

    // --- Request phase ---
    // Client sends: VER (1) | CMD (1) | RSV (1) | ATYP (1) | DST.ADDR (variable) | DST.PORT (2)
    let ver = stream.read_u8().await?;
    if ver != 0x05 {
        warn!("SOCKS5 request rejected: unexpected_request_version=0x{ver:02x}");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected version in request",
        ));
    }

    let cmd = stream.read_u8().await?;
    if cmd != 0x01 {
        // Only CONNECT (0x01) is supported
        // Send error reply: command not supported
        send_reply(stream, 0x07, "0.0.0.0", 0).await?;
        warn!(
            "SOCKS5 request rejected: unsupported_command=0x{cmd:02x}({}), supported_command=0x01(CONNECT)",
            socks_command_name(cmd)
        );
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported SOCKS5 command: {cmd}"),
        ));
    }

    let _rsv = stream.read_u8().await?; // reserved byte

    let atyp = stream.read_u8().await?;
    let host = match atyp {
        0x01 => {
            // IPv4: 4 bytes
            let mut addr = [0u8; 4];
            stream.read_exact(&mut addr).await?;
            Ipv4Addr::from(addr).to_string()
        }
        0x03 => {
            // Domain name: 1 byte length + domain
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|_| {
                warn!("SOCKS5 request rejected: invalid_domain_encoding");
                io::Error::new(io::ErrorKind::InvalidData, "invalid domain name encoding")
            })?
        }
        0x04 => {
            // IPv6: 16 bytes
            let mut addr = [0u8; 16];
            stream.read_exact(&mut addr).await?;
            format!("[{}]", Ipv6Addr::from(addr))
        }
        _ => {
            send_reply(stream, 0x08, "0.0.0.0", 0).await?;
            warn!(
                "SOCKS5 request rejected: unsupported_atyp=0x{atyp:02x}({}), supported_atyp=[0x01(IPV4),0x03(DOMAINNAME),0x04(IPV6)]",
                socks_atyp_name(atyp)
            );
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported address type: {atyp}"),
            ));
        }
    };

    let port = stream.read_u16().await?;
    let authority = format!("{host}:{port}");

    // We don't send the reply yet — the caller will send it after the tunnel
    // is established (or an error occurs).

    Ok(SocksTarget { authority })
}

/// Send a SOCKS5 reply to the client.
///
/// Reply format: VER (1) | REP (1) | RSV (1) | ATYP (1) | BND.ADDR (4) | BND.PORT (2)
pub async fn send_reply(
    stream: &mut TcpStream,
    reply_code: u8,
    bind_addr: &str,
    bind_port: u16,
) -> io::Result<()> {
    let mut reply = vec![
        0x05, // VER
        reply_code, 0x00, // RSV
        0x01, // ATYP: IPv4
        0, 0, 0, 0, // BND.ADDR (0.0.0.0)
    ];

    // Parse bind_addr as IPv4 if possible, otherwise use 0.0.0.0
    if let Ok(addr) = bind_addr.parse::<Ipv4Addr>() {
        reply[4..8].copy_from_slice(&addr.octets());
    }

    reply.extend_from_slice(&bind_port.to_be_bytes());
    stream.write_all(&reply).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_socks5_handshake_ipv6_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let target = socks5_handshake(&mut stream).await.unwrap();
            assert_eq!(target.authority, "[::1]:7777");
        });

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();

            // Greeting: VER=5, NMETHODS=1, METHODS=[NO AUTH]
            stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

            let mut method_select = [0u8; 2];
            stream.read_exact(&mut method_select).await.unwrap();
            assert_eq!(method_select, [0x05, 0x00]);

            // Request: VER=5, CMD=CONNECT, RSV=0, ATYP=IPv6, DST.ADDR=::1, DST.PORT=7777
            let mut request = vec![0x05, 0x01, 0x00, 0x04];
            request.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
            request.extend_from_slice(&7777u16.to_be_bytes());
            stream.write_all(&request).await.unwrap();
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_handshake_rejects_unsupported_auth_methods() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let err = socks5_handshake(&mut stream).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("client does not support no-auth"));
        });

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();

            // Greeting: VER=5, NMETHODS=1, METHODS=[USERNAME/PASSWORD]
            stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();

            let mut reply = [0u8; 2];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [0x05, 0xFF]);
        });

        server.await.unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_handshake_rejects_unsupported_command() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let err = socks5_handshake(&mut stream).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Unsupported);
            assert!(err.to_string().contains("unsupported SOCKS5 command: 3"));
        });

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();

            // Greeting: VER=5, NMETHODS=1, METHODS=[NO AUTH]
            stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

            let mut method_select = [0u8; 2];
            stream.read_exact(&mut method_select).await.unwrap();
            assert_eq!(method_select, [0x05, 0x00]);

            // Request: VER=5, CMD=UDP_ASSOCIATE, RSV=0, ATYP=IPv4, DST.ADDR=127.0.0.1, DST.PORT=7777
            let mut request = vec![0x05, 0x03, 0x00, 0x01];
            request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
            request.extend_from_slice(&7777u16.to_be_bytes());
            stream.write_all(&request).await.unwrap();

            let mut reply = [0u8; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(reply[1], 0x07);
        });

        server.await.unwrap();
        client.await.unwrap();
    }
}
