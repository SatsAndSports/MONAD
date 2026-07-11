use async_trait::async_trait;
use cashu::nuts::{
    CheckStateRequest, CheckStateResponse, CurrencyUnit, KeysetResponse, Proof, PublicKey,
    RestoreRequest, RestoreResponse, SwapRequest, SwapResponse, Token,
};
use cdk_spilman::MintConnection;
use clap::{Parser, Subcommand};
use monad_client::loose_proof_wallet::{LooseProofSummary, LooseProofWallet, NewLooseProof};
use monad_client::runtime::run_configured_client_until_shutdown;
use monad_client::sqlite_client_wallet::{ChannelFundRecoveryResult, SqliteClientWallet};
use monad_client::wallet::{MonadWallet, WalletChannel, WalletChannelState};
use monad_common::config::MonadConfig;
use std::fs;
use std::io::Write;

#[derive(Parser)]
#[command(name = "monad-client", about = "MONAD tunnel client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a configured SOCKS client from shared MONAD YAML.
    Run(RunArgs),

    /// Local client wallet administration and recovery commands.
    Wallet(WalletArgs),
}

#[derive(Parser)]
struct RunArgs {
    /// Shared MONAD YAML config path.
    #[arg(long)]
    config: String,

    /// Client name to run. If omitted, the only configured client is selected.
    #[arg(long)]
    client: Option<String>,
}

#[derive(Parser)]
struct WalletArgs {
    /// SQLite database containing loose bearer proofs.
    #[arg(long)]
    loose_db: String,

    /// SQLite database containing MONAD/upstream channel metadata.
    #[arg(long)]
    channel_db: String,

    /// Sender secret hex used for channel refund/payment signing.
    #[arg(long)]
    sender_secret_hex: String,

    /// Logical loose-proof wallet name inside the loose proof database.
    #[arg(long, default_value = "default")]
    wallet_name: String,

    /// Emit JSON instead of human-readable output.
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: WalletCommand,
}

#[derive(Subcommand)]
enum WalletCommand {
    /// List local client channels.
    Channels,

    /// List available loose proofs grouped by mint, unit, and keyset.
    Proofs,

    /// Import a Cashu token into the loose-proof wallet.
    ImportToken {
        /// Cashu token string to import.
        #[arg(
            long,
            conflicts_with = "token_file",
            required_unless_present = "token_file"
        )]
        token: Option<String>,

        /// Path to a file containing a Cashu token string.
        #[arg(long, conflicts_with = "token", required_unless_present = "token")]
        token_file: Option<String>,
    },

    /// Recover funds for one channel.
    RecoverChannel {
        /// Channel ID to recover.
        #[arg(long)]
        channel_id: String,
    },

    /// Recover ambiguous channel-open attempts.
    RecoverOpenings,
}

struct HttpMintConnection {
    mint_url: String,
    client: reqwest::Client,
}

#[async_trait]
impl MintConnection for HttpMintConnection {
    async fn process_swap(&self, request: SwapRequest) -> anyhow::Result<SwapResponse> {
        self.client
            .post(format!("{}/v1/swap", self.mint_url))
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    async fn post_restore(&self, request: RestoreRequest) -> anyhow::Result<RestoreResponse> {
        self.client
            .post(format!("{}/v1/restore", self.mint_url))
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    async fn check_state(&self, ys: Vec<PublicKey>) -> anyhow::Result<CheckStateResponse> {
        self.client
            .post(format!("{}/v1/checkstate", self.mint_url))
            .json(&CheckStateRequest { ys })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => run_configured_client(args).await,
        Command::Wallet(args) => run_wallet_command(args).await,
    }
}

async fn run_configured_client(args: RunArgs) -> anyhow::Result<()> {
    let config = MonadConfig::load(&args.config)?;
    run_configured_client_until_shutdown(config, args.client.as_deref(), async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!("failed to listen for Ctrl+C: {err}");
        }
    })
    .await
}

async fn run_wallet_command(args: WalletArgs) -> anyhow::Result<()> {
    let loose_wallet = LooseProofWallet::open(&args.loose_db, &args.wallet_name)?;
    let wallet = SqliteClientWallet::open(loose_wallet, &args.channel_db, &args.sender_secret_hex)?;

    match args.command {
        WalletCommand::Channels => {
            let channels = wallet.list_channels()?;
            if args.json {
                print_json(&channels_json(&channels))?;
            } else {
                print_channels(&channels);
            }
        }
        WalletCommand::Proofs => {
            let summaries = wallet.loose_wallet().list_available_proof_summaries()?;
            if args.json {
                print_json(&proof_summaries_json(&summaries))?;
            } else {
                print_proof_summaries(&summaries);
            }
        }
        WalletCommand::ImportToken { token, token_file } => {
            let token_string = read_token_arg(token, token_file)?;
            let imported = import_token(wallet.loose_wallet(), &token_string).await?;
            if args.json {
                print_json(&serde_json::json!({
                    "mint_url": imported.mint_url,
                    "unit": imported.unit,
                    "proof_count": imported.proof_count,
                    "amount_raw": imported.amount_raw,
                }))?;
            } else {
                println!("imported token proofs");
                println!("  mint: {}", imported.mint_url);
                println!("  unit: {}", imported.unit);
                println!("  proof_count: {}", imported.proof_count);
                println!("  amount_raw: {}", imported.amount_raw);
            }
        }
        WalletCommand::RecoverChannel { channel_id } => {
            let channel = wallet.get_channel(&channel_id)?;
            let mint = HttpMintConnection {
                mint_url: channel.mint_url.clone(),
                client: reqwest::Client::new(),
            };
            let result = wallet.recover_channel_funds(&channel_id, &mint).await?;
            if args.json {
                print_json(&recovery_result_json(&result))?;
            } else {
                print_recovery_result(&result);
            }
        }
        WalletCommand::RecoverOpenings => {
            let recovered = wallet.recover_pending_openings()?;
            if args.json {
                print_json(&serde_json::json!({ "recovered_channel_ids": recovered }))?;
            } else if recovered.is_empty() {
                println!("No pending openings recovered.");
            } else {
                println!("Recovered pending openings:");
                for channel_id in recovered {
                    println!("  {channel_id}");
                }
            }
        }
    }
    Ok(())
}

struct ImportedTokenSummary {
    mint_url: String,
    unit: String,
    proof_count: usize,
    amount_raw: u64,
}

async fn import_token(
    loose_wallet: &LooseProofWallet,
    token_string: &str,
) -> anyhow::Result<ImportedTokenSummary> {
    let token: Token = token_string
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("parse Cashu token: {e}"))?;
    let mint_url = token
        .mint_url()
        .map_err(|e| anyhow::anyhow!("read token mint URL: {e}"))?
        .to_string();
    let unit = token.unit().unwrap_or(CurrencyUnit::Sat);
    let keysets = fetch_mint_keysets(&mint_url).await?;
    let proofs = token
        .proofs(&keysets.keysets)
        .map_err(|e| anyhow::anyhow!("extract token proofs: {e}"))?;
    let amount_raw = proofs.iter().try_fold(0u64, |total, proof| {
        total
            .checked_add(u64::from(proof.amount))
            .ok_or_else(|| anyhow::anyhow!("token amount overflow"))
    })?;
    let proof_count = proofs.len();
    let loose_proofs = proofs
        .iter()
        .map(|proof| token_proof_to_loose_proof(proof, &mint_url, &unit))
        .collect::<anyhow::Result<Vec<_>>>()?;
    loose_wallet.import_proofs(&loose_proofs)?;

    Ok(ImportedTokenSummary {
        mint_url,
        unit: unit.to_string(),
        proof_count,
        amount_raw,
    })
}

async fn fetch_mint_keysets(mint_url: &str) -> anyhow::Result<KeysetResponse> {
    reqwest::Client::new()
        .get(format!("{mint_url}/v1/keysets"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .map_err(Into::into)
}

fn token_proof_to_loose_proof(
    proof: &Proof,
    mint_url: &str,
    unit: &CurrencyUnit,
) -> anyhow::Result<NewLooseProof> {
    let proof_id = proof
        .y()
        .map_err(|e| anyhow::anyhow!("compute proof id: {e}"))?
        .to_hex();
    let proof_json = serde_json::to_string(proof)?;
    Ok(NewLooseProof {
        proof_id,
        mint_url: mint_url.to_string(),
        unit: unit.to_string(),
        keyset_id: proof.keyset_id.to_string(),
        amount_raw: u64::from(proof.amount),
        proof_json,
        source_quote_id: None,
        source_batch_id: None,
    })
}

fn read_token_arg(token: Option<String>, token_file: Option<String>) -> anyhow::Result<String> {
    match (token, token_file) {
        (Some(token), None) => Ok(token),
        (None, Some(path)) => Ok(fs::read_to_string(path)?.trim().to_string()),
        (Some(_), Some(_)) => anyhow::bail!("use either --token or --token-file, not both"),
        (None, None) => anyhow::bail!("either --token or --token-file is required"),
    }
}

fn channels_json(channels: &[WalletChannel]) -> serde_json::Value {
    serde_json::Value::Array(channels.iter().map(channel_json).collect())
}

fn channel_json(channel: &WalletChannel) -> serde_json::Value {
    serde_json::json!({
        "channel_id": channel.channel_id,
        "state": wallet_channel_state_str(channel.state),
        "receiver_pubkey": channel.receiver_pubkey,
        "mint_url": channel.mint_url,
        "unit": channel.unit,
        "keyset_id": channel.keyset_id,
        "capacity_msats": channel.capacity_msats,
        "current_signed_balance_msats": channel.current_signed_balance_msats,
        "expiry_timestamp": channel.expiry_timestamp,
        "attached_session_id": channel.attached_session_id.map(hex::encode),
    })
}

fn proof_summaries_json(summaries: &[LooseProofSummary]) -> serde_json::Value {
    serde_json::Value::Array(
        summaries
            .iter()
            .map(|summary| {
                serde_json::json!({
                    "mint_url": summary.mint_url,
                    "unit": summary.unit,
                    "keyset_id": summary.keyset_id,
                    "proof_count": summary.proof_count,
                    "amount_raw": summary.amount_raw,
                })
            })
            .collect(),
    )
}

fn recovery_result_json(result: &ChannelFundRecoveryResult) -> serde_json::Value {
    match result {
        ChannelFundRecoveryResult::AlreadyRecovered {
            channel_id,
            kind,
            recovered_amount_raw,
            recovered_proof_count,
        } => serde_json::json!({
            "result": "already_recovered",
            "channel_id": channel_id,
            "kind": kind,
            "recovered_amount_raw": recovered_amount_raw,
            "recovered_proof_count": recovered_proof_count,
        }),
        ChannelFundRecoveryResult::NotExpiredOrSpentYet {
            expiry_timestamp,
            now,
        } => serde_json::json!({
            "result": "not_expired_or_spent_yet",
            "expiry_timestamp": expiry_timestamp,
            "now": now,
        }),
        ChannelFundRecoveryResult::FundingPending => serde_json::json!({
            "result": "funding_pending",
        }),
        ChannelFundRecoveryResult::PostExpiryRefundRecovered {
            channel_id,
            recovered_amount_raw,
            recovered_proof_count,
        } => serde_json::json!({
            "result": "post_expiry_refund_recovered",
            "channel_id": channel_id,
            "recovered_amount_raw": recovered_amount_raw,
            "recovered_proof_count": recovered_proof_count,
        }),
        ChannelFundRecoveryResult::RelayCloseRecovered {
            channel_id,
            recovered_amount_raw,
            recovered_proof_count,
        } => serde_json::json!({
            "result": "relay_close_recovered",
            "channel_id": channel_id,
            "recovered_amount_raw": recovered_amount_raw,
            "recovered_proof_count": recovered_proof_count,
        }),
        ChannelFundRecoveryResult::RecoveryRetryLater { channel_id, reason } => {
            serde_json::json!({
                "result": "recovery_retry_later",
                "channel_id": channel_id,
                "reason": reason,
            })
        }
        ChannelFundRecoveryResult::UnknownSpent => serde_json::json!({
            "result": "unknown_spent",
        }),
    }
}

fn print_channels(channels: &[WalletChannel]) {
    if channels.is_empty() {
        println!("No channels.");
        return;
    }
    println!(
        "{:<44} {:<8} {:<32} {:<6} {:>12} {:>12} {:>12}",
        "CHANNEL ID", "STATE", "MINT", "UNIT", "CAPACITY_MS", "BALANCE_MS", "EXPIRY"
    );
    for channel in channels {
        println!(
            "{:<44} {:<8} {:<32} {:<6} {:>12} {:>12} {:>12}",
            channel.channel_id,
            wallet_channel_state_str(channel.state),
            truncate(&channel.mint_url, 32),
            channel.unit,
            channel.capacity_msats,
            channel.current_signed_balance_msats,
            channel.expiry_timestamp
        );
    }
}

fn print_proof_summaries(summaries: &[LooseProofSummary]) {
    if summaries.is_empty() {
        println!("No available proofs.");
        return;
    }
    println!(
        "{:<32} {:<6} {:<18} {:>10} {:>10}",
        "MINT", "UNIT", "KEYSET", "PROOFS", "AMOUNT"
    );
    for summary in summaries {
        println!(
            "{:<32} {:<6} {:<18} {:>10} {:>10}",
            truncate(&summary.mint_url, 32),
            summary.unit,
            truncate(&summary.keyset_id, 18),
            summary.proof_count,
            summary.amount_raw
        );
    }
}

fn print_recovery_result(result: &ChannelFundRecoveryResult) {
    match result {
        ChannelFundRecoveryResult::AlreadyRecovered {
            channel_id,
            kind,
            recovered_amount_raw,
            recovered_proof_count,
        } => {
            println!("channel {channel_id} already recovered via {kind}");
            println!("  recovered_amount_raw: {recovered_amount_raw}");
            println!("  recovered_proof_count: {recovered_proof_count}");
        }
        ChannelFundRecoveryResult::NotExpiredOrSpentYet {
            expiry_timestamp,
            now,
        } => {
            println!("channel is not recoverable yet");
            println!("  now: {now}");
            println!("  expiry_timestamp: {expiry_timestamp}");
        }
        ChannelFundRecoveryResult::FundingPending => println!("channel funding is still pending"),
        ChannelFundRecoveryResult::PostExpiryRefundRecovered {
            channel_id,
            recovered_amount_raw,
            recovered_proof_count,
        } => {
            println!("recovered channel {channel_id} by post-expiry refund");
            println!("  recovered_amount_raw: {recovered_amount_raw}");
            println!("  recovered_proof_count: {recovered_proof_count}");
        }
        ChannelFundRecoveryResult::RelayCloseRecovered {
            channel_id,
            recovered_amount_raw,
            recovered_proof_count,
        } => {
            println!("recovered channel {channel_id} from relay close");
            println!("  recovered_amount_raw: {recovered_amount_raw}");
            println!("  recovered_proof_count: {recovered_proof_count}");
        }
        ChannelFundRecoveryResult::RecoveryRetryLater { channel_id, reason } => {
            println!("channel {channel_id} recovery should be retried later");
            println!("  reason: {reason}");
        }
        ChannelFundRecoveryResult::UnknownSpent => {
            println!("channel funding is spent but recovery path is unknown")
        }
    }
}

fn wallet_channel_state_str(state: WalletChannelState) -> &'static str {
    match state {
        WalletChannelState::Open => "Open",
        WalletChannelState::Closing => "Closing",
        WalletChannelState::Closed => "Closed",
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

fn print_json(value: &serde_json::Value) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    serde_json::to_writer_pretty(&mut handle, value)?;
    writeln!(handle)?;
    Ok(())
}
