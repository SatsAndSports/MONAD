use bytes::Bytes;
use cashu::nuts::nut02::{Id, KeySetVersion};
use cdk_spilman::parse_keyset_info_from_json;
use monad_common::h2stream::wait_for_send_capacity;
use monad_common::protocol::{ClientMessage, MintUnitKeysets, ServerMessage};
use monad_common::session::{RelayConnection, SessionPricing, SessionSpilmanInfo};
use std::io;
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, warn};

const CLIENT_VERSION: u8 = 0;

fn encode_client_message(message: &ClientMessage) -> io::Result<Bytes> {
    let bytes = serde_json::to_vec(message)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("json error: {e}")))?;
    let mut frame = Vec::with_capacity(bytes.len() + 1);
    frame.extend_from_slice(&bytes);
    frame.push(b'\n');
    Ok(Bytes::from(frame))
}

async fn send_control_message(
    h2_send: &mut h2::SendStream<Bytes>,
    message: &ClientMessage,
) -> io::Result<()> {
    let frame = encode_client_message(message)?;
    h2_send.reserve_capacity(frame.len());
    wait_for_send_capacity(h2_send).await?;
    h2_send
        .send_data(frame, false)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 send error: {e}")))
}

fn io_other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn pick_advertised_keyset(mints_units_keysets: &MintUnitKeysets) -> Option<(String, String, String)> {
    for (mint_url, unit_map) in mints_units_keysets {
        if let Some(keysets) = unit_map.get("sat") {
            if let Some(keyset_id) = keysets.first() {
                return Some((mint_url.clone(), "sat".to_string(), keyset_id.clone()));
            }
        }
    }

    for (mint_url, unit_map) in mints_units_keysets {
        if let Some((unit, keysets)) = unit_map.iter().next() {
            if let Some(keyset_id) = keysets.first() {
                return Some((mint_url.clone(), unit.clone(), keyset_id.clone()));
            }
        }
    }

    None
}

fn build_keyset_info_from_responses(
    keysets_json: &str,
    keys_json: &str,
    keyset_id: &str,
) -> io::Result<String> {
    let keysets_resp: serde_json::Value = serde_json::from_str(keysets_json)
        .map_err(|e| io_other(format!("parse /v1/keysets response: {e}")))?;
    let keys_resp: serde_json::Value = serde_json::from_str(keys_json)
        .map_err(|e| io_other(format!("parse /v1/keys response: {e}")))?;

    let keysets = keysets_resp
        .get("keysets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| io_other("invalid /v1/keysets response: missing keysets array"))?;
    let keyset_entry = keysets
        .iter()
        .find(|entry| entry.get("id").and_then(|v| v.as_str()) == Some(keyset_id))
        .ok_or_else(|| io_other(format!("keyset {keyset_id} not found in /v1/keysets response")))?;

    let unit = keyset_entry
        .get("unit")
        .and_then(|v| v.as_str())
        .ok_or_else(|| io_other("invalid /v1/keysets response: missing unit"))?;
    let input_fee_ppk = keyset_entry
        .get("input_fee_ppk")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let final_expiry = keyset_entry.get("final_expiry").and_then(|v| v.as_u64());

    let keys = keys_resp
        .get("keysets")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|entry| entry.get("keys"))
        .cloned()
        .ok_or_else(|| io_other("invalid /v1/keys response: missing keys"))?;

    let keyset_info_json = serde_json::json!({
        "keysetId": keyset_id,
        "unit": unit,
        "keys": keys,
        "inputFeePpk": input_fee_ppk,
        "finalExpiry": final_expiry,
    })
    .to_string();

    let keyset_info = parse_keyset_info_from_json(&keyset_info_json)
        .map_err(|e| io_other(format!("parse assembled keyset info: {e}")))?;
    let computed_id = match keyset_info.keyset_id.get_version() {
        KeySetVersion::Version00 => Id::v1_from_keys(&keyset_info.active_keys),
        KeySetVersion::Version01 => Id::v2_from_data(
            &keyset_info.active_keys,
            &keyset_info.unit,
            keyset_info.input_fee_ppk,
            keyset_info.final_expiry,
        ),
    };
    if keyset_info.keyset_id != computed_id {
        return Err(io_other(format!(
            "keyset ID mismatch: claimed {} but keys derive {}",
            keyset_info.keyset_id, computed_id
        )));
    }

    Ok(keyset_info_json)
}

async fn fetch_session_spilman_info(
    receiver_pubkey: String,
    mints_units_keysets: MintUnitKeysets,
) -> io::Result<Option<SessionSpilmanInfo>> {
    let Some((mint_url, unit, keyset_id)) = pick_advertised_keyset(&mints_units_keysets) else {
        return Ok(None);
    };

    let client = reqwest::Client::new();
    let keysets_json = client
        .get(format!("{mint_url}/v1/keysets"))
        .send()
        .await
        .map_err(|e| io_other(format!("fetch {mint_url}/v1/keysets: {e}")))?
        .error_for_status()
        .map_err(|e| io_other(format!("fetch {mint_url}/v1/keysets: {e}")))?
        .text()
        .await
        .map_err(|e| io_other(format!("read {mint_url}/v1/keysets: {e}")))?;
    let keys_json = client
        .get(format!("{mint_url}/v1/keys/{keyset_id}"))
        .send()
        .await
        .map_err(|e| io_other(format!("fetch {mint_url}/v1/keys/{keyset_id}: {e}")))?
        .error_for_status()
        .map_err(|e| io_other(format!("fetch {mint_url}/v1/keys/{keyset_id}: {e}")))?
        .text()
        .await
        .map_err(|e| io_other(format!("read {mint_url}/v1/keys/{keyset_id}: {e}")))?;

    let keyset_info_json = build_keyset_info_from_responses(&keysets_json, &keys_json, &keyset_id)?;

    Ok(Some(SessionSpilmanInfo {
        receiver_pubkey,
        mint_url,
        unit,
        keyset_id,
        keyset_info_json,
    }))
}

async fn run_control_task(
    mut h2_send: h2::SendStream<Bytes>,
    mut h2_recv: h2::RecvStream,
    fake_payment_millisats: u64,
    ready_tx: oneshot::Sender<()>,
    pricing_handle: Arc<RwLock<Option<SessionPricing>>>,
    spilman_info_handle: Arc<RwLock<Option<SessionSpilmanInfo>>>,
) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut ready_tx = Some(ready_tx);

    // Send Hello as the first message on the control stream.
    send_control_message(&mut h2_send, &ClientMessage::Hello { version: CLIENT_VERSION }).await?;

    while let Some(chunk) = h2_recv.data().await {
        let data = chunk
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 recv error: {e}")))?;
        let len = data.len();
        let _ = h2_recv.flow_control().release_capacity(len);
        buf.extend_from_slice(&data);

        while let Some(newline_pos) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=newline_pos).collect();
            let line = line.trim_ascii();
            if line.is_empty() {
                continue;
            }

            let message: ServerMessage = serde_json::from_slice(line)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("json error: {e}")))?;
            match message {
                ServerMessage::SessionParams {
                    version,
                    in_bytes_per_millisat,
                    out_bytes_per_millisat,
                    receiver_pubkey,
                    mints_units_keysets,
                } => {
                    let pricing = SessionPricing::new(
                        version,
                        in_bytes_per_millisat,
                        out_bytes_per_millisat,
                    );
                    info!(
                        "session params: version={} in_bytes_per_millisat={} out_bytes_per_millisat={} lcm={}",
                        pricing.version,
                        pricing.in_bytes_per_millisat,
                        pricing.out_bytes_per_millisat,
                        pricing.pricing_lcm,
                    );
                    *pricing_handle.write().await = Some(pricing);

                    match fetch_session_spilman_info(receiver_pubkey, mints_units_keysets).await {
                        Ok(Some(spilman_info)) => {
                            info!(
                                mint = %spilman_info.mint_url,
                                unit = %spilman_info.unit,
                                keyset_id = %spilman_info.keyset_id,
                                "fetched session Spilman keyset info"
                            );
                            *spilman_info_handle.write().await = Some(spilman_info);
                        }
                        Ok(None) => {
                            info!("server advertised no usable Spilman keysets");
                        }
                        Err(e) => {
                            warn!("failed to fetch session Spilman keyset info: {e}");
                        }
                    }
                }
                ServerMessage::Error { message } => {
                    warn!("control error: {message}");
                }
                ServerMessage::SessionStatus {
                    session_total_in,
                    session_total_out,
                    total_paid_millisats,
                    remaining_milli_sats,
                    paused,
                } => {
                    info!(
                        "session status: paused={} balance={} paid={} in={} out={}",
                        paused,
                        remaining_milli_sats,
                        total_paid_millisats,
                        session_total_in,
                        session_total_out
                    );

                    if paused && remaining_milli_sats <= 0 {
                        info!(
                            "session paused; sending fake payment of {} millisats",
                            fake_payment_millisats
                        );
                        send_control_message(
                            &mut h2_send,
                            &ClientMessage::FakePayment {
                                milli_sats: fake_payment_millisats,
                            },
                        )
                        .await?;
                    } else if !paused {
                        if let Some(tx) = ready_tx.take() {
                            let _ = tx.send(());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn start_fake_payment_controller(
    conn: &RelayConnection,
    fake_payment_millisats: u64,
) -> io::Result<(JoinHandle<()>, oneshot::Receiver<()>)> {
    let (control_send, control_recv) = conn.open_control().await?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let pricing_handle = conn.session_pricing_handle();
    let spilman_info_handle = conn.session_spilman_info_handle();

    let handle = tokio::spawn(async move {
        if let Err(e) = run_control_task(
            control_send,
            control_recv,
            fake_payment_millisats,
            ready_tx,
            pricing_handle,
            spilman_info_handle,
        )
        .await
        {
            warn!("control task ended with error: {e}");
        }
    });

    Ok((handle, ready_rx))
}
