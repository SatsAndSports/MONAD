use anyhow::{anyhow, Context, Result};
use monad_common::secp_identity::{
    transport_auth_digest, verify_transport_auth_digest, Secp256k1Pubkey, SecpTransportKeypair,
};
use std::io;
use tokio::io::AsyncWriteExt;

pub const AUTH_STREAM_KIND: u8 = 0x01;
pub const STREAM_ERROR_UNKNOWN_KIND: u64 = 0x21;
pub const STREAM_ERROR_AUTH_REQUIRED: u64 = 0x22;
pub const STREAM_ERROR_BAD_AUTH: u64 = 0x23;
pub const EXPORTER_LABEL: &[u8] = b"monad-quic-secp256k1-auth-v1";
pub const EXPORTER_LEN: usize = 32;

pub fn stream_error_code(code: u64) -> quinn::VarInt {
    quinn::VarInt::from_u64(code).expect("valid QUIC application error code")
}

pub fn reject_stream(send: &mut quinn::SendStream, recv: &mut quinn::RecvStream, code: u64) {
    let code = stream_error_code(code);
    let _ = recv.stop(code);
    let _ = send.reset(code);
}

pub fn export_binding(conn: &quinn::Connection) -> Result<[u8; EXPORTER_LEN]> {
    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow!("failed to export QUIC keying material: {e:?}"))?;
    Ok(exporter)
}

pub async fn request_attestation_signature(
    conn: &quinn::Connection,
    challenge: [u8; 32],
) -> Result<[u8; 64]> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open auth stream")?;
    send.write_all(&[AUTH_STREAM_KIND]).await?;
    send.write_all(&challenge).await?;
    send.flush().await?;

    let mut signature = [0u8; 64];
    recv.read_exact(&mut signature)
        .await
        .context("failed to read attestation signature")?;
    Ok(signature)
}

pub async fn authenticate_connection(
    conn: &quinn::Connection,
    expected_pubkey: &Secp256k1Pubkey,
) -> Result<()> {
    let challenge = rand::random::<[u8; 32]>();
    let signature = request_attestation_signature(conn, challenge).await?;
    let exporter = export_binding(conn)?;
    let digest = transport_auth_digest(EXPORTER_LABEL, &challenge, &exporter);
    verify_transport_auth_digest(expected_pubkey, &digest, &signature)
        .map_err(|e| anyhow!("secp256k1 attestation verification failed: {e}"))
}

pub async fn serve_attestation_stream(
    conn: &quinn::Connection,
    transport_key: &SecpTransportKeypair,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
) -> io::Result<()> {
    let mut challenge = [0u8; 32];
    recv.read_exact(&mut challenge)
        .await
        .map_err(|e| io::Error::other(format!("failed to read QUIC auth challenge: {e}")))?;

    let exporter = export_binding(conn)
        .map_err(|e| io::Error::other(format!("failed to export QUIC binding: {e}")))?;
    let digest = transport_auth_digest(EXPORTER_LABEL, &challenge, &exporter);
    let signature = transport_key.sign_digest(&digest);

    send.write_all(&signature)
        .await
        .map_err(|e| io::Error::other(format!("failed to write QUIC auth signature: {e}")))?;
    send.finish()
        .map_err(|e| io::Error::other(format!("failed to finish QUIC auth stream: {e}")))?;
    Ok(())
}
