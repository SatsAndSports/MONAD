use clap::Parser;
use std::{collections::BTreeMap, net::SocketAddr};

#[derive(Parser)]
#[command(about = "Local MONAD monitoring and management HTTP/SSE aggregator")]
struct Args {
    #[arg(long)]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let config = monad_common::config::MonadConfig::load(args.config)?;
    let settings = config
        .management
        .ok_or("management configuration is required")?;
    if settings.auth_token.is_some() {
        return Err("auth_token is not implemented; this service is loopback-only".into());
    }
    let addr: SocketAddr = settings.listen.parse()?;
    if !addr.ip().is_loopback() {
        return Err("management.listen must be a loopback address".into());
    }
    let mut processes: BTreeMap<String, String> = settings.processes;
    if processes.is_empty() {
        if let Some(path) = settings.relay_socket {
            processes.insert("relays".into(), path);
        }
        if let Some(path) = settings.client_socket {
            processes.insert("clients".into(), path);
        }
        if let Some(path) = settings.test_mint_socket {
            processes.insert("test-mints".into(), path);
        }
    }
    if processes.is_empty() {
        return Err("configure at least one management process socket".into());
    }
    let state = monad_management::aggregate::Aggregator::new(processes)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!(
        "management HTTP/SSE listening on {}",
        listener.local_addr()?
    );
    monad_management::aggregate::serve(listener, state, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}
