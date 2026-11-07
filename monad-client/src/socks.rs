//! Minimal SOCKS5 server implementation.
//!
//! Accepts local connections, parses SOCKS5 CONNECT requests, and returns the
//! destination address. The caller is responsible for actually proxying the data.
//!
//! Supports:
//!   - SOCKS5 with no authentication
//!   - Opt-in MONAD diagnostics on the mode-aware handshake entry point
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
        0x80 => "MONAD_DIAGNOSTICS",
        0x81..=0xfe => "PRIVATE",
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
    pub reply_mode: crate::socks_diagnostics::SocksReplyMode,
}

/// Perform the SOCKS5 handshake on an incoming local connection.
///
/// This standard-only entry point returns the requested target. The caller must
/// establish its tunnel and send a success reply before proxying application data.
pub async fn socks5_handshake(stream: &mut TcpStream) -> io::Result<SocksTarget> {
    handshake(stream, false).await
}

/// Accept standard SOCKS or explicitly offered MONAD diagnostics. Callers must
/// carry the returned reply mode through every CONNECT failure response.
pub async fn socks5_handshake_with_diagnostics(stream: &mut TcpStream) -> io::Result<SocksTarget> {
    handshake(stream, true).await
}

async fn handshake(stream: &mut TcpStream, allow_diagnostics: bool) -> io::Result<SocksTarget> {
    use crate::socks_diagnostics::{SocksReplyMode, ACK, DIAGNOSTIC_TIMEOUT, HELLO, METHOD};
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

    let diagnostics = allow_diagnostics && methods.contains(&METHOD);
    if !diagnostics && !methods.contains(&0x00) {
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
    let reply_mode = if diagnostics {
        tokio::time::timeout(DIAGNOSTIC_TIMEOUT, async {
            stream.write_all(&[0x05, METHOD]).await?;
            let mut hello = [0u8; 6];
            stream.read_exact(&mut hello).await?;
            if &hello != HELLO {
                stream.write_all(&[1, 1]).await?;
                stream.shutdown().await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported MONAD SOCKS diagnostic protocol",
                ));
            }
            stream.write_all(&ACK).await
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "SOCKS diagnostics negotiation timed out",
            )
        })??;
        SocksReplyMode::DiagnosticsV1
    } else {
        stream.write_all(&[0x05, 0x00]).await?;
        SocksReplyMode::Standard
    };

    if diagnostics {
        tokio::time::timeout(DIAGNOSTIC_TIMEOUT, read_connect_request(stream, reply_mode))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "SOCKS diagnostics request timed out",
                )
            })?
    } else {
        read_connect_request(stream, reply_mode).await
    }
}

async fn read_connect_request(
    stream: &mut TcpStream,
    reply_mode: crate::socks_diagnostics::SocksReplyMode,
) -> io::Result<SocksTarget> {
    use crate::socks_diagnostics::SocksDiagnostic;

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
        send_failure(
            stream,
            reply_mode,
            0x07,
            &SocksDiagnostic::simple("request", "Only SOCKS CONNECT is supported."),
        )
        .await?;
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
            send_failure(
                stream,
                reply_mode,
                0x08,
                &SocksDiagnostic::simple("request", "Unsupported SOCKS address type."),
            )
            .await?;
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

    Ok(SocksTarget {
        authority,
        reply_mode,
    })
}

/// Send one failure reply, optional negotiated diagnostics, then close the write
/// side. Serialization and all output are bounded; no raw upstream body is sent.
pub async fn send_failure(
    stream: &mut TcpStream,
    mode: crate::socks_diagnostics::SocksReplyMode,
    code: u8,
    diagnostic: &crate::socks_diagnostics::SocksDiagnostic,
) -> io::Result<()> {
    use crate::socks_diagnostics::{SocksReplyMode, DIAGNOSTIC_TIMEOUT, MAX_DIAGNOSTIC_BYTES};
    if code == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "failure reply cannot indicate success",
        ));
    }
    let payload = if mode == SocksReplyMode::DiagnosticsV1 {
        diagnostic.validate()?;
        let bytes = serde_json::to_vec(diagnostic).map_err(io::Error::other)?;
        if bytes.len() > MAX_DIAGNOSTIC_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS diagnostic too large",
            ));
        }
        Some(bytes)
    } else {
        None
    };
    tokio::time::timeout(DIAGNOSTIC_TIMEOUT, async {
        send_reply(stream, code, "0.0.0.0", 0).await?;
        if let Some(payload) = payload {
            stream.write_u32(payload.len() as u32).await?;
            stream.write_all(&payload).await?;
        }
        stream.shutdown().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS failure reply timed out"))?
}

/// Reject a SOCKS5 CONNECT request because the proxy is temporarily
/// unavailable (e.g. the upstream route is reconnecting).
pub async fn reject_socks5_connect_unavailable(stream: &mut TcpStream) -> io::Result<()> {
    socks5_handshake(stream).await?;
    // 0x05 = connection refused.
    send_reply(stream, 0x05, "0.0.0.0", 0).await
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
    async fn test_reconnect_rejection_uses_connect_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            reject_socks5_connect_unavailable(&mut stream)
                .await
                .unwrap();
        });

        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

            let mut method_select = [0u8; 2];
            stream.read_exact(&mut method_select).await.unwrap();
            assert_eq!(method_select, [0x05, 0x00]);

            let mut request = vec![0x05, 0x01, 0x00, 0x01];
            request.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
            request.extend_from_slice(&7777u16.to_be_bytes());
            stream.write_all(&request).await.unwrap();

            let mut reply = [0u8; 10];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[0], 0x05);
            assert_eq!(reply[1], 0x05);
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
