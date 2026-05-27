//! TCP and QUIC listener that accepts connections and performs the Noise NK handshake.

use crate::quic_pool::QuicPool;
use crate::session::{relay_session_from_noise_stream, relay_session_from_transport_stream};
use cashu::nuts::SecretKey;
use cdk_spilman::configurable_networking::{build_keyset_info_json, fetch_all_keysets_from_mint};
use monad_common::identity::ServerIdentity;
use monad_common::noise;
use monad_common::noise::NoiseStream;
use monad_common::noise_secp256k1;
use monad_common::protocol::MintUnitKeysets;
use monad_common::secp_identity::SecpTransportKeypair;
use monad_quic::auth::{
    reject_stream, serve_attestation_stream, AUTH_STREAM_KIND, STREAM_ERROR_AUTH_REQUIRED,
    STREAM_ERROR_UNKNOWN_KIND,
};
use monad_quic::stream::{QuicStream, STREAM_KIND_PLAIN_NOISE, STREAM_KIND_SECP_NOISE};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{error, info};

/// Hardcoded trusted mint policy for now: mint URL -> allowed units.
pub type TrustedMintUnits = BTreeMap<String, BTreeSet<String>>;

/// Server-side cached view of trusted mints.
#[derive(Debug, Clone, Default)]
pub struct SpilmanMintCache {
    /// Mint URL -> unit -> advertised keyset IDs.
    pub advertised: MintUnitKeysets,
    /// Mint URL -> keyset ID -> keyset info JSON.
    pub keyset_info_json_by_mint: BTreeMap<String, BTreeMap<String, String>>,
}

/// Server configuration.
pub struct ServerConfig {
    /// The server's unified identity (Ed25519 seed + derived keys).
    pub identity: ServerIdentity,
    /// Optional shared secp256k1 transport identity for secp-authenticated transports.
    pub transport_key: Option<SecpTransportKeypair>,
    /// Receiver secp256k1 secret used for Spilman channel validation.
    pub payment_receiver_secret: SecretKey,
    /// Hardcoded trusted mint policy.
    pub trusted_mint_units: TrustedMintUnits,
}

/// Discover all keyset IDs (active and inactive) and cache their keyset info JSON.
pub async fn discover_spilman_mint_cache(
    trusted_mint_units: &TrustedMintUnits,
) -> io::Result<SpilmanMintCache> {
    let mut cache = SpilmanMintCache::default();

    for (mint_url, trusted_units) in trusted_mint_units {
        let keysets = fetch_all_keysets_from_mint(mint_url)
            .await
            .map_err(|e| io::Error::other(format!("discover keysets from {mint_url}: {e}")))?;

        let mut by_unit = BTreeMap::<String, Vec<String>>::new();
        let mut by_id = BTreeMap::<String, String>::new();
        for keyset in keysets {
            let unit = keyset.unit.to_string();
            if !trusted_units.contains(&unit) {
                continue;
            }

            let id = keyset.id.to_string();
            by_unit.entry(unit.clone()).or_default().push(id.clone());
            by_id.insert(
                id,
                build_keyset_info_json(
                    &keyset.id,
                    &keyset.unit,
                    &keyset.keys,
                    keyset.input_fee_ppk,
                ),
            );
        }

        for ids in by_unit.values_mut() {
            ids.sort();
            ids.dedup();
        }

        info!(mint = %mint_url, units = ?by_unit.keys().collect::<Vec<_>>(), "discovered trusted mint keysets");
        cache.advertised.insert(mint_url.clone(), by_unit);
        cache
            .keyset_info_json_by_mint
            .insert(mint_url.clone(), by_id);
    }

    Ok(cache)
}

/// Run the server: listen for TCP and optionally QUIC connections, perform Noise
/// handshake, handle H2 sessions.
///
/// Both TCP and QUIC connections are fed into the same Noise+H2 session handler.
/// The server treats them identically after the transport is established.
///
/// Handles Ctrl+C gracefully: stops accepting new connections, waits for active
/// sessions to finish (up to a timeout), then exits. This ensures NoiseStream
/// Drop impls run and wire byte counters are logged.
pub async fn run(
    listener: TcpListener,
    quic_endpoint: Option<quinn::Endpoint>,
    config: Arc<ServerConfig>,
) -> io::Result<()> {
    let transport_key = config.transport_key.clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "server transport_key is required for secp-authenticated transport",
        )
    })?;
    let local_addr = listener.local_addr()?;
    info!("listening on {local_addr}");

    let mut sessions = JoinSet::new();

    // Create the QUIC connection pool for outbound CONNECT quic: forwarding.
    // This is separate from the QUIC endpoint (which handles inbound connections).
    let quic_pool = QuicPool::new().ok();
    let discovered_spilman_mint_cache =
        Arc::new(discover_spilman_mint_cache(&config.trusted_mint_units).await?);

    // Accept loop — runs until Ctrl+C
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut tcp_stream, peer_addr) = result?;
                info!("accepted TCP connection from {peer_addr}");

                let config = config.clone();
                let transport_key = transport_key.clone();
                let quic_pool = quic_pool.clone();
                let discovered_spilman_mint_cache = discovered_spilman_mint_cache.clone();

                sessions.spawn(async move {
                    let (send_cipher, recv_cipher, session_id) =
                        match noise_secp256k1::handshake_responder(&mut tcp_stream, &transport_key)
                            .await
                        {
                            Ok(v) => {
                                info!("secp noise handshake complete with {peer_addr} (TCP)");
                                v
                            }
                            Err(e) => {
                                error!("secp noise handshake failed with {peer_addr}: {e}");
                                return;
                            }
                        };

                    let label = format!("{local_addr} <-> {peer_addr} (TCP)");
                    let secp_stream = noise_secp256k1::SecpNoiseStream::new(
                        tcp_stream,
                        send_cipher,
                        recv_cipher,
                        session_id,
                        label,
                    );

                    // Run the H2 session
                    match relay_session_from_transport_stream(
                        secp_stream,
                        session_id,
                        quic_pool,
                        config.payment_receiver_secret.clone(),
                        discovered_spilman_mint_cache.as_ref().clone(),
                    )
                    .await {
                        Ok(session) => {
                            if let Err(e) = session.run().await {
                                error!("session error with {peer_addr}: {e}");
                            }
                        }
                        Err(e) => {
                            error!("H2 handshake failed with {peer_addr}: {e}");
                        }
                    }

                    info!("connection with {peer_addr} closed (TCP)");
                });

                // Reap any finished sessions (non-blocking)
                while let Some(result) = sessions.try_join_next() {
                    if let Err(e) = result {
                        error!("session task panicked: {e}");
                    }
                }
            }
            Some(incoming) = async {
                match &quic_endpoint {
                    Some(ep) => ep.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                let config = config.clone();
                let transport_key = transport_key.clone();
                let quic_pool = quic_pool.clone();
                let discovered_spilman_mint_cache = discovered_spilman_mint_cache.clone();

                sessions.spawn(async move {
                    // Complete the QUIC connection handshake
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            error!("QUIC connection handshake failed: {e}");
                            return;
                        }
                    };
                    let remote = conn.remote_address();
                    info!("accepted QUIC connection from {remote}");
                    let authenticated = Arc::new(AtomicBool::new(false));

                    // Accept bidirectional streams from this QUIC connection.
                    // Each stream is an independent Noise+H2 session.
                    loop {
                        match conn.accept_bi().await {
                            Ok((send, recv)) => {
                                let stream_id = send.id();
                                info!(%remote, ?stream_id, "accepted QUIC stream");

                                let config = config.clone();
                                let transport_key = transport_key.clone();
                                let quic_pool = quic_pool.clone();
                                let discovered_spilman_mint_cache = discovered_spilman_mint_cache.clone();
                                let authenticated = authenticated.clone();
                                let conn = conn.clone();
                                tokio::spawn(async move {
                                    let mut send = send;
                                    let mut recv = recv;
                                    let mut kind = [0u8; 1];
                                    if recv.read_exact(&mut kind).await.is_err() {
                                        return;
                                    }

                                    if kind[0] == AUTH_STREAM_KIND {
                                        if let Err(e) = serve_attestation_stream(
                                            &conn,
                                            &transport_key,
                                            &mut send,
                                            &mut recv,
                                        )
                                        .await
                                        {
                                            error!("QUIC secp256k1 auth failed with {remote} ({stream_id:?}): {e}");
                                        } else {
                                            authenticated.store(true, Ordering::Release);
                                        }
                                        return;
                                    }

                                    if kind[0] != STREAM_KIND_PLAIN_NOISE && kind[0] != STREAM_KIND_SECP_NOISE {
                                        reject_stream(&mut send, &mut recv, STREAM_ERROR_UNKNOWN_KIND);
                                        return;
                                    }

                                    match kind[0] {
                                        STREAM_KIND_PLAIN_NOISE => {
                                            let mut quic_stream = QuicStream::new(send, recv);

                                            let (transport, session_id) = match noise::handshake_responder(
                                                &mut quic_stream,
                                                config.identity.x25519_private(),
                                            )
                                            .await
                                            {
                                                Ok(t) => {
                                                    info!("noise handshake complete with {remote} (QUIC {stream_id:?})");
                                                    t
                                                }
                                                Err(e) => {
                                                    error!("noise handshake failed with {remote} (QUIC {stream_id:?}): {e}");
                                                    return;
                                                }
                                            };

                                            let label = format!("{} <-> {remote} (QUIC {stream_id:?})", "quic");
                                            let noise_stream = NoiseStream::new(
                                                quic_stream,
                                                transport,
                                                session_id,
                                                label,
                                            );

                                            match relay_session_from_noise_stream(
                                                noise_stream,
                                                quic_pool,
                                                config.payment_receiver_secret.clone(),
                                                discovered_spilman_mint_cache.as_ref().clone(),
                                            )
                                            .await {
                                                Ok(session) => {
                                                    if let Err(e) = session.run().await {
                                                        error!("session error with {remote} (QUIC {stream_id:?}): {e}");
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("H2 handshake failed with {remote} (QUIC {stream_id:?}): {e}");
                                                }
                                            }
                                        }
                                        STREAM_KIND_SECP_NOISE => {
                                            if !authenticated.load(Ordering::Acquire) {
                                                reject_stream(&mut send, &mut recv, STREAM_ERROR_AUTH_REQUIRED);
                                                return;
                                            }
                                            let mut quic_stream = QuicStream::new(send, recv);
                                            let (send_cipher, recv_cipher, session_id) =
                                                match noise_secp256k1::handshake_responder(
                                                    &mut quic_stream,
                                                    &transport_key,
                                                )
                                                .await
                                                {
                                                    Ok(v) => {
                                                        info!("secp noise handshake complete with {remote} (QUIC {stream_id:?})");
                                                        v
                                                    }
                                                    Err(e) => {
                                                        error!("secp noise handshake failed with {remote} (QUIC {stream_id:?}): {e}");
                                                        return;
                                                    }
                                                };
                                            let secp_stream = noise_secp256k1::SecpNoiseStream::new(
                                                quic_stream,
                                                send_cipher,
                                                recv_cipher,
                                                session_id,
                                                format!(
                                                    "{} <-> {remote} (QUIC {stream_id:?} secp)",
                                                    "quic"
                                                ),
                                            );

                                            match relay_session_from_transport_stream(
                                                secp_stream,
                                                session_id,
                                                quic_pool,
                                                config.payment_receiver_secret.clone(),
                                                discovered_spilman_mint_cache.as_ref().clone(),
                                            )
                                            .await {
                                                Ok(session) => {
                                                    if let Err(e) = session.run().await {
                                                        error!("session error with {remote} (QUIC {stream_id:?}): {e}");
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("H2 handshake failed with {remote} (QUIC {stream_id:?}): {e}");
                                                }
                                            }
                                        }
                                        _ => unreachable!(),
                                    }

                                    info!("QUIC stream {stream_id:?} from {remote} closed");
                                });
                            }
                            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                                info!(%remote, "QUIC connection closed by peer");
                                break;
                            }
                            Err(e) => {
                                error!(%remote, error = %e, "QUIC accept_bi failed");
                                break;
                            }
                        }
                    }
                });

                while let Some(result) = sessions.try_join_next() {
                    if let Err(e) = result {
                        error!("session task panicked: {e}");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down (Ctrl+C)...");
                break;
            }
        }
    }

    // Graceful shutdown: wait for active sessions to finish.
    let active = sessions.len();
    if active > 0 {
        info!("waiting for {active} active session(s) to finish...");

        let timeout = tokio::time::sleep(std::time::Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                result = sessions.join_next() => {
                    match result {
                        Some(Ok(())) => {}
                        Some(Err(e)) => error!("session task panicked: {e}"),
                        None => {
                            info!("all sessions finished");
                            break;
                        }
                    }
                }
                _ = &mut timeout => {
                    let remaining = sessions.len();
                    info!("shutdown timeout, aborting {remaining} remaining session(s)");
                    sessions.abort_all();
                    break;
                }
            }
        }
    }

    if let Some(ep) = quic_endpoint {
        ep.close(0u32.into(), b"shutdown");
    }

    info!("server shut down");
    Ok(())
}
