//! Wallet-admin CLI for `monad-relay`.
//!
//! Supports listing relay identities, showing per-relay summaries, listing
//! channels, and closing channels.  Output is human-readable by default and
//! JSON with `--json`.

use crate::config::MonadConfig;
use crate::wallet_manager::{ChannelSummary, RelayWalletManager};
use clap::{Parser, Subcommand};
use std::io::Write;

#[derive(Parser)]
pub struct WalletArgs {
    /// Path to the shared SQLite relay-wallet database.
    #[arg(long)]
    pub wallet_db_path: Option<String>,

    /// Path to a relay YAML config file.  The wallet DB path is taken from the
    /// selected relay entry.
    #[arg(long)]
    pub config: Option<String>,

    /// Relay name to select from the config file.
    #[arg(long)]
    pub relay: Option<String>,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    pub json: bool,

    #[command(subcommand)]
    pub command: WalletCommand,
}

#[derive(Subcommand)]
pub enum WalletCommand {
    /// List all relay identities registered in the wallet DB.
    List,

    /// Show a single relay identity and channel count.
    Show {
        /// Relay identity name.  Required when using `--wallet-db-path`.
        #[arg(long)]
        wallet_name: Option<String>,
    },

    /// List channels for a relay identity.
    Channels {
        /// Relay identity name.  Required when using `--wallet-db-path`.
        #[arg(long)]
        wallet_name: Option<String>,
    },

    /// Close a channel.  The owning relay identity is discovered from the
    /// channel metadata table.
    Close {
        /// Channel ID to close.
        #[arg(long)]
        channel_id: String,
    },
}

pub async fn run_wallet_command(args: WalletArgs) -> anyhow::Result<()> {
    let wallet_db_path = resolve_wallet_db_path(&args)?;
    let manager = RelayWalletManager::open(&wallet_db_path)?;

    match args.command {
        WalletCommand::List => {
            let identities = manager.list_identities();
            if args.json {
                print_json(&identities)?;
            } else {
                println!("Identities in {wallet_db_path}:");
                for id in identities {
                    println!("  {}  receiver={}", id.name, id.receiver_pubkey_hex);
                }
            }
        }
        WalletCommand::Show {
            wallet_name: ref name_opt,
        } => {
            let name = resolve_wallet_name(&args, name_opt.clone())?;
            let identities = manager.list_identities();
            let identity = identities
                .into_iter()
                .find(|i| i.name == name)
                .ok_or_else(|| anyhow::anyhow!("unknown relay identity '{name}'"))?;
            let channel_count = manager.list_channels(Some(&name))?.len();
            if args.json {
                print_json(&serde_json::json!({
                    "name": identity.name,
                    "receiver_pubkey_hex": identity.receiver_pubkey_hex,
                    "channel_count": channel_count,
                }))?;
            } else {
                println!("relay: {}", identity.name);
                println!("receiver: {}", identity.receiver_pubkey_hex);
                println!("channels: {channel_count}");
            }
        }
        WalletCommand::Channels {
            wallet_name: ref name_opt,
        } => {
            let name = resolve_wallet_name(&args, name_opt.clone())?;
            let channels = manager.list_channels(Some(&name))?;
            if args.json {
                print_json(&channels)?;
            } else {
                print_channels(&channels);
            }
        }
        WalletCommand::Close { channel_id } => {
            let net = manager
                .reqwest_networking_for_channel(&channel_id)
                .map_err(|e| anyhow::anyhow!(e))?;
            let result = manager.close_channel(&channel_id, &net).await?;
            if args.json {
                print_json(&result)?;
            } else {
                if result.already_closed {
                    println!("channel {} is already closed", result.channel_id);
                } else {
                    println!("closed channel {}", result.channel_id);
                }
                println!("  total_value: {}", result.total_value);
                println!("  receiver_sum: {}", result.receiver_sum);
                println!("  sender_sum: {}", result.sender_sum);
            }
        }
    }

    Ok(())
}

fn resolve_wallet_db_path(args: &WalletArgs) -> anyhow::Result<String> {
    match (&args.wallet_db_path, &args.config) {
        (Some(path), _) => Ok(path.clone()),
        (None, Some(config_path)) => {
            let config = MonadConfig::load(config_path)?;
            let relay = config.select_relay(args.relay.as_deref())?;
            Ok(relay.wallet_db_path.clone())
        }
        (None, None) => Err(anyhow::anyhow!(
            "either --wallet-db-path or --config is required"
        )),
    }
}

fn resolve_wallet_name(args: &WalletArgs, explicit: Option<String>) -> anyhow::Result<String> {
    if let Some(name) = explicit {
        return Ok(name);
    }
    if args.config.is_some() {
        return args
            .relay
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--relay is required when using --config"));
    }
    Err(anyhow::anyhow!(
        "--wallet-name is required when using --wallet-db-path"
    ))
}

fn print_channels(channels: &[ChannelSummary]) {
    if channels.is_empty() {
        println!("No channels.");
        return;
    }
    println!(
        "{:<44} {:<8} {:<32} {:<6} {:>10} {:>10}",
        "CHANNEL ID", "STATE", "MINT", "UNIT", "CAPACITY", "BALANCE"
    );
    for c in channels {
        let state = format!("{:?}", c.state);
        println!(
            "{:<44} {:<8} {:<32} {:<6} {:>10} {:>10}",
            c.channel_id,
            state,
            truncate(&c.mint_url, 32),
            c.unit,
            c.capacity_raw,
            c.balance_raw
        );
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, value)?;
    writeln!(handle)?;
    Ok(())
}
