use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Persistent MONAD demo mints using fake Lightning; no real value")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(long)]
        config: String,
        #[arg(long)]
        mint: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Args::parse().command {
        Command::Run { config, mint } => {
            let config = monad_common::config::MonadConfig::load(config)?;
            monad_test_mint::run(config, mint.as_deref(), async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await
        }
    }
}
