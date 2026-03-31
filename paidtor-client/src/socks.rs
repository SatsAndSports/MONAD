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
        reply_code,
        0x00, // RSV
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
