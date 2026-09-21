//! Wallet-admin CLI for `monad-relay`.
//!
//! Supports listing relay identities, showing per-relay summaries, listing
//! channels, and closing channels.  Output is human-readable by default and
//! JSON with `--json`.

use crate::payments::CloseOutcome;
use crate::wallet_manager::{
    ChannelSummary, CloseExpiringChannelsResult, DrainSummary, DrainSwapResult,
    ExpiringChannelSummary, RelayWalletInspection, RelayWalletManager,
};
use clap::{Parser, Subcommand};
use monad_common::config::{MonadConfig, RelayChannelPolicyConfig};
use monad_common::wallet_lock::{WalletLockMode, WalletLocks};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

    /// List Open / Closing channels that are close to expiry.
    ExpiringChannels {
        /// Relay identity name.  Omit to scan all relay identities.
        #[arg(long)]
        wallet_name: Option<String>,
    },

    /// Close Open / Closing channels that are close to expiry.
    CloseExpiringChannels {
        /// Relay identity name.  Omit to scan all relay identities.
        #[arg(long)]
        wallet_name: Option<String>,

        /// Show channels that would be closed without closing them.
        #[arg(long)]
        dry_run: bool,
    },

    /// Close a channel.  The owning relay identity is discovered from the
    /// channel metadata table.
    Close {
        /// Channel ID to close.
        #[arg(long)]
        channel_id: String,
    },

    /// List relay drain attempts.
    Drains,

    /// Drain closed relay-owned channel receiver proofs through a mint swap.
    Drain {
        /// Relay identity name. Required when using `--wallet-db-path`.
        #[arg(long)]
        wallet_name: Option<String>,

        /// Mint URL to drain closed channels from.
        #[arg(long)]
        mint_url: String,

        /// Cashu unit to drain.
        #[arg(long)]
        unit: String,

        /// Maximum number of closed channels to include.
        #[arg(long)]
        limit: Option<usize>,
    },

    /// Recover a previously submitted drain attempt.
    RecoverDrain {
        /// Drain ID to recover.
        #[arg(long)]
        drain_id: String,
    },
}

pub async fn run_wallet_command(args: WalletArgs) -> anyhow::Result<()> {
    let wallet_db_path = resolve_wallet_db_path(&args)?;
    let read_only = wallet_command_is_read_only(&args.command);
    let _locks = WalletLocks::acquire(
        [Path::new(&wallet_db_path)],
        if read_only {
            WalletLockMode::ReadOnly
        } else {
            WalletLockMode::Maintenance
        },
        "relay",
    )?;

    if read_only {
        let inspection = RelayWalletInspection::open(&wallet_db_path)?;
        return run_read_only_wallet_command(&args, &wallet_db_path, &inspection);
    }

    let manager = RelayWalletManager::open_with_locks(&wallet_db_path, _locks)?;
    match args.command {
        WalletCommand::CloseExpiringChannels {
            wallet_name: ref name_opt,
            dry_run,
        } => {
            debug_assert!(!dry_run);
            let (channels, close_before_expiry_secs) =
                find_expiring_channels_for_command(&args, &manager, name_opt.clone())?;
            if !args.json {
                print_close_expiring_header(channels.len(), close_before_expiry_secs);
            }
            let result = manager
                .close_expiring_channel_candidates(channels, close_before_expiry_secs)
                .await;
            if args.json {
                print_json(&result)?;
            } else {
                print_close_expiring_results(&result);
                print_close_expiring_summary(&result);
            }
            if !result.failures.is_empty() || !result.unresolved.is_empty() {
                return Err(anyhow::anyhow!(
                    "failed to close {} expiring channel(s)",
                    result.failures.len() + result.unresolved.len()
                ));
            }
        }
        WalletCommand::Close { channel_id } => {
            let net = manager
                .mint_client_for_channel(&channel_id)
                .map_err(|e| anyhow::anyhow!(e))?;
            let result = manager.close_channel(&channel_id, &net).await?;
            if args.json {
                print_json(&result)?;
            } else {
                print_close_outcome(&result);
            }
            if matches!(result, CloseOutcome::UnknownSpent { .. }) {
                anyhow::bail!(
                    "funding spent; close versus refund unresolved; journal retained for retry"
                );
            }
        }
        WalletCommand::Drain {
            wallet_name: ref name_opt,
            ref mint_url,
            ref unit,
            limit,
        } => {
            let name = resolve_wallet_name(&args, name_opt.clone())?;
            let net = manager
                .mint_client_for_relay(&name, mint_url, unit)
                .map_err(|e| anyhow::anyhow!(e))?;
            let result = manager
                .drain_closed_channels_to_swap(&name, mint_url, unit, &net, limit)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            if args.json {
                print_json(&result)?;
            } else {
                print_drain_result(&result);
            }
        }
        WalletCommand::RecoverDrain { drain_id } => {
            let drain = manager
                .list_drains()
                .map_err(|e| anyhow::anyhow!(e))?
                .into_iter()
                .find(|drain| drain.drain_id == drain_id)
                .ok_or_else(|| anyhow::anyhow!("unknown drain '{drain_id}'"))?;
            let net = manager
                .mint_client_for_relay(&drain.relay_name, &drain.mint_url, &drain.unit)
                .map_err(|e| anyhow::anyhow!(e))?;
            let result = manager
                .recover_submitted_drain(&drain_id, &net)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            if args.json {
                print_json(&result)?;
            } else {
                print_drain_result(&result);
            }
        }
        WalletCommand::List
        | WalletCommand::Show { .. }
        | WalletCommand::Channels { .. }
        | WalletCommand::ExpiringChannels { .. }
        | WalletCommand::Drains => {
            unreachable!("read-only command classified before opening the manager")
        }
    }

    Ok(())
}

fn wallet_command_is_read_only(command: &WalletCommand) -> bool {
    matches!(
        command,
        WalletCommand::List
            | WalletCommand::Show { .. }
            | WalletCommand::Channels { .. }
            | WalletCommand::ExpiringChannels { .. }
            | WalletCommand::Drains
            | WalletCommand::CloseExpiringChannels { dry_run: true, .. }
    )
}

fn run_read_only_wallet_command(
    args: &WalletArgs,
    wallet_db_path: &str,
    inspection: &RelayWalletInspection,
) -> anyhow::Result<()> {
    match &args.command {
        WalletCommand::List => {
            let identities = inspection.list_identities()?;
            if args.json {
                print_json(&identities)
            } else {
                println!("Identities in {wallet_db_path}:");
                for id in identities {
                    println!("  {}  receiver={}", id.name, id.receiver_pubkey_hex);
                }
                Ok(())
            }
        }
        WalletCommand::Show { wallet_name } => {
            let name = resolve_wallet_name(args, wallet_name.clone())?;
            let identity = inspection
                .list_identities()?
                .into_iter()
                .find(|identity| identity.name == name)
                .ok_or_else(|| anyhow::anyhow!("unknown relay identity '{name}'"))?;
            let channel_count = inspection.list_channels(Some(&name))?.len();
            if args.json {
                print_json(&serde_json::json!({
                    "name": identity.name,
                    "receiver_pubkey_hex": identity.receiver_pubkey_hex,
                    "channel_count": channel_count,
                }))
            } else {
                println!("relay: {}", identity.name);
                println!("receiver: {}", identity.receiver_pubkey_hex);
                println!("channels: {channel_count}");
                Ok(())
            }
        }
        WalletCommand::Channels { wallet_name } => {
            let name = resolve_wallet_name(args, wallet_name.clone())?;
            let channels = inspection.list_channels(Some(&name))?;
            if args.json {
                print_json(&channels)
            } else {
                print_channels(&channels);
                Ok(())
            }
        }
        WalletCommand::ExpiringChannels { wallet_name } => {
            let (channels, close_before_expiry_secs) =
                find_expiring_channels_for_inspection(args, inspection, wallet_name.clone())?;
            if args.json {
                print_json(&channels)
            } else {
                print_expiring_channels(&channels, close_before_expiry_secs);
                Ok(())
            }
        }
        WalletCommand::CloseExpiringChannels {
            wallet_name,
            dry_run: true,
        } => {
            let (channels, close_before_expiry_secs) =
                find_expiring_channels_for_inspection(args, inspection, wallet_name.clone())?;
            if args.json {
                print_json(&CloseExpiringChannelsResult::dry_run(
                    close_before_expiry_secs,
                    channels,
                ))
            } else {
                println!("Dry run: no channels will be closed.");
                print_expiring_channels(&channels, close_before_expiry_secs);
                Ok(())
            }
        }
        WalletCommand::Drains => {
            let drains = inspection.list_drains()?;
            if args.json {
                print_json(&drains)
            } else {
                print_drains(&drains);
                Ok(())
            }
        }
        _ => unreachable!("mutating command classified as read-only"),
    }
}

fn resolve_wallet_db_path(args: &WalletArgs) -> anyhow::Result<String> {
    match (&args.wallet_db_path, &args.config) {
        (Some(path), _) => Ok(path.clone()),
        (None, Some(config_path)) => {
            let config = MonadConfig::load(config_path)?;
            if args.relay.is_some() {
                let _ = config.select_relay(args.relay.as_deref())?;
            }
            Ok(config
                .relay_wallet
                .ok_or_else(|| anyhow::anyhow!("relay_wallet is required when using --config"))?
                .db_path)
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

fn find_expiring_channels_for_command(
    args: &WalletArgs,
    manager: &RelayWalletManager,
    explicit: Option<String>,
) -> anyhow::Result<(Vec<ExpiringChannelSummary>, u64)> {
    let now = now_seconds();
    if let Some(name) = explicit.or_else(|| args.relay.clone()) {
        let close_before_expiry_secs = close_before_expiry_secs_for_relay(args, Some(&name))?;
        let channels =
            manager.find_expiring_channels(Some(&name), now, close_before_expiry_secs)?;
        return Ok((channels, close_before_expiry_secs));
    }

    if let Some(config_path) = &args.config {
        let config = MonadConfig::load(config_path)?;
        let mut channels = Vec::new();
        let mut max_close_before_expiry_secs = 0u64;
        for relay in &config.relays {
            max_close_before_expiry_secs = max_close_before_expiry_secs.max(
                relay
                    .channel_policy
                    .expiring_channels
                    .close_before_expiry_secs,
            );
            channels.extend(
                manager.find_expiring_channels(
                    Some(&relay.name),
                    now,
                    relay
                        .channel_policy
                        .expiring_channels
                        .close_before_expiry_secs,
                )?,
            );
        }
        channels.sort_by_key(|channel| channel.seconds_until_expiry);
        return Ok((channels, max_close_before_expiry_secs));
    }

    let close_before_expiry_secs = RelayChannelPolicyConfig::default()
        .expiring_channels
        .close_before_expiry_secs;
    let channels = manager.find_expiring_channels(None, now, close_before_expiry_secs)?;
    Ok((channels, close_before_expiry_secs))
}

fn find_expiring_channels_for_inspection(
    args: &WalletArgs,
    inspection: &RelayWalletInspection,
    explicit: Option<String>,
) -> anyhow::Result<(Vec<ExpiringChannelSummary>, u64)> {
    let now = now_seconds();
    if let Some(name) = explicit.or_else(|| args.relay.clone()) {
        let close_before_expiry_secs = close_before_expiry_secs_for_relay(args, Some(&name))?;
        let channels =
            inspection.find_expiring_channels(Some(&name), now, close_before_expiry_secs)?;
        return Ok((channels, close_before_expiry_secs));
    }

    if let Some(config_path) = &args.config {
        let config = MonadConfig::load(config_path)?;
        let mut channels = Vec::new();
        let mut max_close_before_expiry_secs = 0u64;
        for relay in &config.relays {
            let threshold = relay
                .channel_policy
                .expiring_channels
                .close_before_expiry_secs;
            max_close_before_expiry_secs = max_close_before_expiry_secs.max(threshold);
            channels.extend(inspection.find_expiring_channels(
                Some(&relay.name),
                now,
                threshold,
            )?);
        }
        channels.sort_by_key(|channel| channel.seconds_until_expiry);
        return Ok((channels, max_close_before_expiry_secs));
    }

    let close_before_expiry_secs = RelayChannelPolicyConfig::default()
        .expiring_channels
        .close_before_expiry_secs;
    let channels = inspection.find_expiring_channels(None, now, close_before_expiry_secs)?;
    Ok((channels, close_before_expiry_secs))
}

fn close_before_expiry_secs_for_relay(
    args: &WalletArgs,
    relay_name: Option<&str>,
) -> anyhow::Result<u64> {
    if let Some(config_path) = &args.config {
        let config = MonadConfig::load(config_path)?;
        let relay = config.select_relay(relay_name)?;
        Ok(relay
            .channel_policy
            .expiring_channels
            .close_before_expiry_secs)
    } else {
        Ok(RelayChannelPolicyConfig::default()
            .expiring_channels
            .close_before_expiry_secs)
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
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

fn print_expiring_channels(channels: &[ExpiringChannelSummary], close_before_expiry_secs: u64) {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    write_expiring_channels(&mut handle, channels, close_before_expiry_secs)
        .expect("stdout write failed");
}

fn print_close_expiring_header(candidate_count: usize, close_before_expiry_secs: u64) {
    if candidate_count == 0 {
        println!("No channels expiring within {close_before_expiry_secs}s.");
    } else {
        println!(
            "Closing {candidate_count} channel(s) expiring within {close_before_expiry_secs}s:"
        );
    }
}

fn print_close_expiring_results(result: &CloseExpiringChannelsResult) {
    for success in &result.resolved {
        print_close_expiring_success(&success.channel, &success.close);
    }
    for failure in &result.failures {
        print_close_expiring_failure(&failure.channel, &failure.error);
    }
    for channel in &result.unresolved {
        println!(
            "  unresolved {} relay={}; retry recovery later",
            channel.channel_id, channel.relay_name
        );
    }
}

fn print_close_expiring_success(channel: &ExpiringChannelSummary, close: &CloseOutcome) {
    println!(
        "  relay={} expires_in={}",
        channel.relay_name,
        format_duration(channel.seconds_until_expiry)
    );
    print_close_outcome(close);
}

fn print_close_outcome(result: &CloseOutcome) {
    match result {
        CloseOutcome::Closed(close) => println!("Closed channel={} already_closed={} total_value={} receiver_sum={} sender_sum={}", close.channel_id, close.already_closed, close.total_value, close.receiver_sum, close.sender_sum),
        CloseOutcome::SenderRefundedAfterExpiry { channel_id } => println!("SenderRefundedAfterExpiry channel={channel_id}; sender spent full funding minus mint fees; no receiver close payout"),
        CloseOutcome::UnknownSpent { channel_id } => println!("UnknownSpent channel={channel_id}; close versus refund unresolved; retry recovery later"),
    }
}

fn print_close_expiring_failure(channel: &ExpiringChannelSummary, error: &str) {
    println!(
        "  fail  {} relay={} expires_in={} mint={} error={}",
        channel.channel_id,
        channel.relay_name,
        format_duration(channel.seconds_until_expiry),
        channel.mint_url,
        error
    );
}

fn print_close_expiring_summary(result: &CloseExpiringChannelsResult) {
    if result.candidate_count == 0 {
        return;
    }
    println!(
        "Summary: candidates={} resolved={} failed={} unresolved={}",
        result.candidate_count,
        result.resolved.len(),
        result.failures.len(),
        result.unresolved.len()
    );
    if !result.failures.is_empty() {
        println!(
            "WARNING: {} of {} expiring channel(s) failed to close.",
            result.failures.len(),
            result.candidate_count
        );
    }
}

fn write_expiring_channels<W: Write>(
    mut out: W,
    channels: &[ExpiringChannelSummary],
    close_before_expiry_secs: u64,
) -> anyhow::Result<()> {
    if channels.is_empty() {
        writeln!(
            out,
            "No channels expiring within {close_before_expiry_secs}s."
        )?;
        return Ok(());
    }
    writeln!(out, "Channels expiring within {close_before_expiry_secs}s:")?;
    writeln!(
        out,
        "{:<44} {:<16} {:<8} {:<32} {:<6} {:>10} {:>10} {:>12} {:>12}",
        "CHANNEL ID",
        "RELAY",
        "STATE",
        "MINT",
        "UNIT",
        "CAPACITY",
        "BALANCE",
        "EXPIRES_AT",
        "EXPIRES_IN"
    )?;
    for c in channels {
        let state = format!("{:?}", c.state);
        writeln!(
            out,
            "{:<44} {:<16} {:<8} {:<32} {:<6} {:>10} {:>10} {:>12} {:>12}",
            c.channel_id,
            truncate(&c.relay_name, 16),
            state,
            truncate(&c.mint_url, 32),
            c.unit,
            c.capacity_raw,
            c.balance_raw,
            c.expiry_timestamp,
            format_duration(c.seconds_until_expiry)
        )?;
    }
    Ok(())
}

fn print_drains(drains: &[DrainSummary]) {
    if drains.is_empty() {
        println!("No drains.");
        return;
    }
    println!(
        "{:<44} {:<10} {:<16} {:<32} {:<6} {:>10} {:>10}",
        "DRAIN ID", "STATE", "RELAY", "MINT", "UNIT", "INPUT", "OUTPUT"
    );
    for d in drains {
        println!(
            "{:<44} {:<10} {:<16} {:<32} {:<6} {:>10} {:>10}",
            d.drain_id,
            d.state,
            truncate(&d.relay_name, 16),
            truncate(&d.mint_url, 32),
            d.unit,
            d.input_amount_raw,
            d.output_amount_raw
        );
    }
}

fn print_drain_result(result: &DrainSwapResult) {
    if result.recovered {
        println!("recovered drain {}", result.drain_id);
    } else {
        println!("completed drain {}", result.drain_id);
    }
    println!("  relay: {}", result.relay_name);
    println!("  mint: {}", result.mint_url);
    println!("  unit: {}", result.unit);
    println!("  input_amount_raw: {}", result.input_amount_raw);
    println!("  output_amount_raw: {}", result.output_amount_raw);
    println!("  channels: {}", result.channel_ids.join(","));
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn format_duration(seconds: i64) -> String {
    let sign = if seconds < 0 { "-" } else { "" };
    let abs = seconds.unsigned_abs();
    if abs < 60 {
        return format!("{sign}{abs}s");
    }
    let minutes = abs / 60;
    let secs = abs % 60;
    if minutes < 60 {
        return format!("{sign}{minutes}m{secs:02}s");
    }
    let hours = minutes / 60;
    let mins = minutes % 60;
    format!("{sign}{hours}h{mins:02}m")
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, value)?;
    writeln!(handle)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cdk_spilman::ChannelState;

    #[test]
    fn write_expiring_channels_includes_close_window_and_channel_fields() {
        let channels = vec![ExpiringChannelSummary {
            channel_id: "channel-1".to_string(),
            relay_name: "relay-a".to_string(),
            receiver_pubkey_hex: "receiver".to_string(),
            state: ChannelState::Open,
            mint_url: "https://example.com/very/long/mint/url".to_string(),
            unit: "sat".to_string(),
            expiry_timestamp: 1234,
            seconds_until_expiry: 55,
            capacity_raw: 100,
            balance_raw: 42,
        }];
        let mut out = Vec::new();

        write_expiring_channels(&mut out, &channels, 60).unwrap();

        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Channels expiring within 60s"));
        assert!(out.contains("channel-1"));
        assert!(out.contains("RELAY"));
        assert!(out.contains("relay-a"));
        assert!(out.contains("Open"));
        assert!(out.contains("sat"));
        assert!(out.contains("1234"));
        assert!(out.contains("EXPIRES_IN"));
        assert!(out.contains("55s"));
    }

    #[test]
    fn write_expiring_channels_reports_empty_set() {
        let mut out = Vec::new();

        write_expiring_channels(&mut out, &[], 3600).unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            "No channels expiring within 3600s.\n"
        );
    }

    #[test]
    fn format_duration_is_human_readable() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(125), "2m05s");
        assert_eq!(format_duration(7_260), "2h01m");
        assert_eq!(format_duration(-30), "-30s");
    }

    #[test]
    fn wallet_commands_classify_inspection_and_mutation_before_opening_database() {
        assert!(wallet_command_is_read_only(&WalletCommand::List));
        assert!(wallet_command_is_read_only(&WalletCommand::Channels {
            wallet_name: None,
        }));
        assert!(wallet_command_is_read_only(
            &WalletCommand::CloseExpiringChannels {
                wallet_name: None,
                dry_run: true,
            }
        ));
        assert!(!wallet_command_is_read_only(&WalletCommand::Close {
            channel_id: "channel".to_string(),
        }));
        assert!(!wallet_command_is_read_only(
            &WalletCommand::CloseExpiringChannels {
                wallet_name: None,
                dry_run: false,
            }
        ));
        assert!(!wallet_command_is_read_only(&WalletCommand::Drain {
            wallet_name: None,
            mint_url: "https://mint.invalid".to_string(),
            unit: "sat".to_string(),
            limit: None,
        }));
        assert!(!wallet_command_is_read_only(&WalletCommand::RecoverDrain {
            drain_id: "drain".to_string(),
        }));
    }
}
