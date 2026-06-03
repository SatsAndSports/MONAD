use anyhow::{anyhow, Result};
use clap::Parser;
use monad_test_client::{
    run_fd_logger, run_socks_listener, start_local_relays, Circuit, CircuitConfig,
    RebuildAfterFailureOutcome,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::time::{self, Duration};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "monad-test-client",
    about = "MONAD localhost SOCKS5 client focused on circuit reliability"
)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:1080")]
    socks: String,

    #[arg(long, default_value_t = 5)]
    relays: usize,

    #[arg(long, default_value_t = 3)]
    hops: usize,

    #[arg(long, default_value_t = 5)]
    status_interval_secs: u64,
}

fn rebuild_backoff(attempt: usize) -> Duration {
    match attempt {
        0 => Duration::from_secs(0),
        1 => Duration::from_secs(1),
        2 => Duration::from_secs(2),
        3 => Duration::from_secs(5),
        _ => Duration::from_secs(10),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    if cli.relays == 0 {
        return Err(anyhow!("--relays must be at least 1"));
    }
    if cli.hops == 0 {
        return Err(anyhow!("--hops must be at least 1"));
    }
    if cli.hops > cli.relays {
        return Err(anyhow!("--hops cannot exceed --relays"));
    }

    let mut relays = start_local_relays(cli.relays).await?;
    for (relay_idx, relay) in relays.iter().enumerate() {
        info!(
            "started local relay {relay_idx}: {} ({})",
            relay.spec.addr, relay.spec.pubkey
        );
    }

    let specs = relays[..cli.hops]
        .iter()
        .map(|relay| relay.spec.clone())
        .collect::<Vec<_>>();
    info!(
        "building persistent {}-hop QUIC circuit: {}",
        specs.len(),
        specs
            .iter()
            .map(|relay| relay.addr.as_str())
            .collect::<Vec<_>>()
            .join(" -> ")
    );

    let status_interval = if cli.status_interval_secs == 0 {
        None
    } else {
        Some(Duration::from_secs(cli.status_interval_secs))
    };
    let (mut circuit, mut failure_rx) = Circuit::new(
        specs,
        CircuitConfig {
            status_interval,
            status_timeout: status_interval
                .map(|interval| interval.saturating_mul(3))
                .unwrap_or(Duration::from_secs(15))
                .max(Duration::from_secs(15)),
            ..CircuitConfig::default()
        },
    )?;
    circuit.build_full().await?;
    let active_final_conn = circuit.active_final_conn_handle();
    let circuit = Arc::new(Mutex::new(circuit));

    let rebuild_circuit = circuit.clone();
    let rebuild_task = tokio::spawn(async move {
        while let Some(failure) = failure_rx.recv().await {
            let mut attempt = 0usize;
            loop {
                let delay = rebuild_backoff(attempt);
                if !delay.is_zero() {
                    time::sleep(delay).await;
                }

                let mut circuit = rebuild_circuit.lock().await;
                warn!(
                    "reported unhealthy hop {}/{} (epoch {}): {}",
                    failure.hop_idx + 1,
                    circuit.hop_count(),
                    failure.epoch,
                    failure.reason,
                );
                match circuit.rebuild_after_failure(failure.clone()).await {
                    Ok(RebuildAfterFailureOutcome::Rebuilt) => {
                        info!(
                            "rebuilt circuit suffix from hop {}/{}",
                            failure.hop_idx + 1,
                            circuit.hop_count()
                        );
                        break;
                    }
                    Ok(RebuildAfterFailureOutcome::Stale) => {
                        info!(
                            "ignoring stale failure for hop {}/{} at epoch {}",
                            failure.hop_idx + 1,
                            circuit.hop_count(),
                            failure.epoch
                        );
                        break;
                    }
                    Ok(RebuildAfterFailureOutcome::InvalidHop) => {
                        warn!(
                            "ignoring invalid failure for hop {}/{} at epoch {}",
                            failure.hop_idx + 1,
                            circuit.hop_count(),
                            failure.epoch
                        );
                        break;
                    }
                    Err(err) => {
                        warn!(
                            "failed to rebuild circuit suffix from hop {}/{}: {err}",
                            failure.hop_idx + 1,
                            circuit.hop_count()
                        );
                    }
                }
                drop(circuit);
                attempt += 1;
            }
        }
    });

    let listener = TcpListener::bind(&cli.socks).await?;
    info!(
        "persistent circuit established; binding SOCKS5 listener on {}",
        cli.socks
    );
    let fd_logger = tokio::spawn(run_fd_logger(status_interval));
    let mut socks_task = tokio::spawn(run_socks_listener(listener, active_final_conn));

    tokio::select! {
        result = &mut socks_task => {
            fd_logger.abort();
            rebuild_task.abort();
            for relay in &mut relays {
                relay.stop().await;
            }
            match result {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err.into()),
                Err(err) => return Err(anyhow!("SOCKS listener task failed: {err}")),
            }
        }
        result = tokio::signal::ctrl_c() => {
            if let Err(err) = result {
                return Err(err.into());
            }
            info!("shutting down test client (Ctrl+C)...");
            socks_task.abort();
            fd_logger.abort();
            rebuild_task.abort();
            for relay in &mut relays {
                relay.stop().await;
            }
        }
    }

    Ok(())
}
