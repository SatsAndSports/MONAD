//! Shared YAML configuration for MONAD runtimes.
//!
//! A single config file describes shared wallets, multiple relays, multiple
//! clients, and the optional management API. Environment variables can be
//! interpolated with `${VAR}` or `${VAR:-default}` syntax, and a `.env` file in
//! the same directory as the config is loaded automatically before substitution.

use serde::{de, Deserialize, Deserializer};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use crate::secp_identity::Secp256k1Pubkey;

/// Top-level MONAD configuration file.
#[derive(Debug, Clone, Deserialize)]
pub struct MonadConfig {
    pub wallets: WalletsConfig,

    #[serde(default)]
    pub management: Option<ManagementConfig>,

    pub relays: Vec<RelayConfig>,

    #[serde(default)]
    pub clients: Vec<ClientConfig>,
}

impl MonadConfig {
    /// Load a config file from disk, apply `.env` / environment substitution,
    /// and validate it.
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            let _ = dotenvy::from_path(parent.join(".env"));
        }

        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config file {}: {e}", path.display()))?;
        let substituted = substitute_env_vars(&raw)?;

        let mut config: MonadConfig = serde_yaml::from_str(&substituted)
            .map_err(|e| anyhow::anyhow!("failed to parse config file {}: {e}", path.display()))?;
        for relay in &mut config.relays {
            relay.receiver_secret_hex = relay
                .receiver_secret_hex
                .take()
                .filter(|s| !s.trim().is_empty());
        }

        config.validate()?;
        Ok(config)
    }

    /// Select a relay by name, or return the only relay if `name` is `None`.
    pub fn select_relay(&self, name: Option<&str>) -> anyhow::Result<&RelayConfig> {
        match name {
            Some(name) => self
                .relays
                .iter()
                .find(|r| r.name == name)
                .ok_or_else(|| anyhow::anyhow!("no relay named '{name}' in config")),
            None => {
                if self.relays.len() == 1 {
                    Ok(&self.relays[0])
                } else {
                    let names: Vec<_> = self.relays.iter().map(|r| r.name.as_str()).collect();
                    Err(anyhow::anyhow!(
                        "config contains multiple relays; use --relay <name> to select one of: {}",
                        names.join(", ")
                    ))
                }
            }
        }
    }

    /// Select a client by name, or return the only client if `name` is `None`.
    pub fn select_client(&self, name: Option<&str>) -> anyhow::Result<&ClientConfig> {
        match name {
            Some(name) => self
                .clients
                .iter()
                .find(|c| c.name == name)
                .ok_or_else(|| anyhow::anyhow!("no client named '{name}' in config")),
            None => {
                if self.clients.len() == 1 {
                    Ok(&self.clients[0])
                } else {
                    let names: Vec<_> = self.clients.iter().map(|c| c.name.as_str()).collect();
                    Err(anyhow::anyhow!(
                        "config contains {} clients; use --client <name> to select one of: {}",
                        self.clients.len(),
                        names.join(", ")
                    ))
                }
            }
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.wallets.relay.db_path.trim().is_empty() {
            anyhow::bail!("wallets.relay.db_path must not be empty");
        }

        if !self.clients.is_empty() && self.wallets.client.is_none() {
            anyhow::bail!("wallets.client is required when clients are configured");
        }
        if let Some(client_wallet) = &self.wallets.client {
            if client_wallet.loose_db_path.trim().is_empty() {
                anyhow::bail!("wallets.client.loose_db_path must not be empty");
            }
            if client_wallet.channel_db_path.trim().is_empty() {
                anyhow::bail!("wallets.client.channel_db_path must not be empty");
            }
            if client_wallet.wallet_name.trim().is_empty() {
                anyhow::bail!("wallets.client.wallet_name must not be empty");
            }
            validate_hex_secret(
                "wallets.client.sender_secret_hex",
                &client_wallet.sender_secret_hex,
            )?;
            if client_wallet.channel_input_budget_msats == 0 {
                anyhow::bail!(
                    "wallets.client.channel_input_budget_msats must be greater than zero"
                );
            }
        }

        if self.relays.is_empty() {
            anyhow::bail!("config must contain at least one relay");
        }

        let mut relay_names = HashSet::new();
        let mut client_names = HashSet::new();
        let mut listens = HashSet::new();
        let mut socks_listens = HashSet::new();
        let mut receiver_secrets = HashSet::new();

        for relay in &self.relays {
            if !relay_names.insert(relay.name.clone()) {
                anyhow::bail!("duplicate relay name '{}'", relay.name);
            }
            if !listens.insert(relay.listen.clone()) {
                anyhow::bail!(
                    "relay '{}' reuses listen address {}",
                    relay.name,
                    relay.listen
                );
            }
            if let Some(secret) = &relay.receiver_secret_hex {
                let normalized = secret.trim().to_lowercase();
                if !receiver_secrets.insert(normalized.clone()) {
                    anyhow::bail!(
                        "relay '{}' uses the same receiver secret as another relay",
                        relay.name
                    );
                }
                validate_hex_secret(
                    &format!("relay '{}' receiver_secret_hex", relay.name),
                    &normalized,
                )?;
            }
            validate_hex_secret(
                &format!("relay '{}' quic_cert_seed", relay.name),
                &relay.quic_cert_seed,
            )?;
            validate_hex_secret(
                &format!("relay '{}' transport_key", relay.name),
                &relay.transport_key,
            )?;
            if relay.trusted_mints.is_empty() {
                anyhow::bail!("relay '{}' must have at least one trusted mint", relay.name);
            }
            if relay.pricing.in_bytes_per_millisat == 0 {
                anyhow::bail!(
                    "relay '{}' pricing.in_bytes_per_millisat must be greater than zero",
                    relay.name
                );
            }
            if relay.pricing.out_bytes_per_millisat == 0 {
                anyhow::bail!(
                    "relay '{}' pricing.out_bytes_per_millisat must be greater than zero",
                    relay.name
                );
            }
            if relay.channel_policy.min_expiry_secs == 0 {
                anyhow::bail!(
                    "relay '{}' channel_policy.min_expiry must be greater than zero",
                    relay.name
                );
            }
            if relay.channel_policy.close_before_expiry_secs == 0 {
                anyhow::bail!(
                    "relay '{}' channel_policy.close_before_expiry must be greater than zero",
                    relay.name
                );
            }
            if relay.channel_policy.close_before_expiry_secs < relay.channel_policy.min_expiry_secs
            {
                anyhow::bail!(
                    "relay '{}' channel_policy.close_before_expiry must be greater than or equal to channel_policy.min_expiry",
                    relay.name
                );
            }
            if relay.channel_policy.min_capacity_msats == 0 {
                anyhow::bail!(
                    "relay '{}' channel_policy.min_capacity must be greater than zero",
                    relay.name
                );
            }
            if relay.channel_policy.max_amount_per_output_msats == Some(0) {
                anyhow::bail!(
                    "relay '{}' channel_policy.max_amount_per_output must be greater than zero when set",
                    relay.name
                );
            }
        }

        for client in &self.clients {
            if !client_names.insert(client.name.clone()) {
                anyhow::bail!("duplicate client name '{}'", client.name);
            }
            if !socks_listens.insert(client.socks.clone()) {
                anyhow::bail!(
                    "client '{}' reuses socks address {}",
                    client.name,
                    client.socks
                );
            }
            if client.route.is_empty() {
                anyhow::bail!("client '{}' route must not be empty", client.name);
            }
            for (hop_idx, hop) in client.route.iter().enumerate() {
                if hop.addr.trim().is_empty() {
                    anyhow::bail!(
                        "client '{}' route hop {} addr must not be empty",
                        client.name,
                        hop_idx + 1
                    );
                }
                Secp256k1Pubkey::parse_config_pubkey(&hop.pubkey).map_err(|e| {
                    anyhow::anyhow!(
                        "client '{}' route hop {} pubkey is invalid: {e}",
                        client.name,
                        hop_idx + 1
                    )
                })?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct WalletsConfig {
    pub relay: RelayWalletConfig,

    #[serde(default)]
    pub client: Option<ClientWalletConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayWalletConfig {
    pub db_path: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientWalletConfig {
    pub loose_db_path: String,
    pub channel_db_path: String,
    #[serde(default = "default_wallet_name")]
    pub wallet_name: String,
    pub sender_secret_hex: String,
    #[serde(default = "default_channel_input_budget_msats")]
    pub channel_input_budget_msats: u64,
    #[serde(default = "default_target_topup_buffer_msats")]
    pub target_topup_buffer_msats: u64,
    #[serde(default = "default_minimum_topup_msats")]
    pub minimum_topup_msats: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManagementConfig {
    pub listen: String,
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    pub name: String,
    pub receiver_secret_hex: Option<String>,
    pub quic_cert_seed: String,
    pub transport_key: String,
    pub listen: String,
    pub trusted_mints: Vec<TrustedMintConfig>,
    pub pricing: PricingConfig,
    #[serde(default)]
    pub channel_policy: RelayChannelPolicyConfig,
}

impl RelayConfig {
    /// Convert the configured mint list into the internal trusted-mint map used
    /// for keyset discovery.
    pub fn trusted_mint_units(&self) -> BTreeMap<String, BTreeSet<String>> {
        let mut map = BTreeMap::new();
        for mint in &self.trusted_mints {
            map.insert(
                mint.url.clone(),
                mint.units.iter().cloned().collect::<BTreeSet<_>>(),
            );
        }
        map
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PricingConfig {
    pub in_bytes_per_millisat: u64,
    pub out_bytes_per_millisat: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustedMintConfig {
    pub url: String,
    pub units: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RelayChannelPolicyConfig {
    #[serde(
        default = "default_min_channel_expiry_secs",
        rename = "min_expiry",
        deserialize_with = "deserialize_duration_secs"
    )]
    pub min_expiry_secs: u64,
    #[serde(
        default = "default_min_channel_capacity_msats",
        rename = "min_capacity",
        deserialize_with = "deserialize_amount_msats"
    )]
    pub min_capacity_msats: u64,
    #[serde(
        default,
        rename = "max_amount_per_output",
        deserialize_with = "deserialize_optional_amount_msats"
    )]
    pub max_amount_per_output_msats: Option<u64>,
    #[serde(
        default = "default_close_channel_before_expiry_secs",
        rename = "close_before_expiry",
        deserialize_with = "deserialize_duration_secs"
    )]
    pub close_before_expiry_secs: u64,
}

impl Default for RelayChannelPolicyConfig {
    fn default() -> Self {
        Self {
            min_expiry_secs: default_min_channel_expiry_secs(),
            min_capacity_msats: default_min_channel_capacity_msats(),
            max_amount_per_output_msats: None,
            close_before_expiry_secs: default_close_channel_before_expiry_secs(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub name: String,
    pub socks: String,
    pub route: Vec<ClientRouteHopConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientRouteHopConfig {
    pub addr: String,
    pub pubkey: String,
}

fn default_wallet_name() -> String {
    "default".to_string()
}

fn default_channel_input_budget_msats() -> u64 {
    1_000_000
}

fn default_target_topup_buffer_msats() -> u64 {
    10_000_000
}

fn default_minimum_topup_msats() -> u64 {
    0
}

fn default_min_channel_expiry_secs() -> u64 {
    3_600
}

fn default_min_channel_capacity_msats() -> u64 {
    1
}

fn default_close_channel_before_expiry_secs() -> u64 {
    86_400
}

fn deserialize_duration_secs<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct DurationVisitor;

    impl de::Visitor<'_> for DurationVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a duration in seconds or a string like 3600s, 60m, 2h, or 1d")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u64::try_from(value).map_err(|_| E::custom("duration must not be negative"))
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_duration_secs(value).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(DurationVisitor)
}

fn deserialize_amount_msats<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct AmountVisitor;

    impl de::Visitor<'_> for AmountVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a millisat amount string like 1500msat or 2sat")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            parse_amount_msats(value).map_err(E::custom)
        }
    }

    deserializer.deserialize_str(AmountVisitor)
}

fn deserialize_optional_amount_msats<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|value| parse_amount_msats(&value).map_err(de::Error::custom))
        .transpose()
}

fn parse_duration_secs(value: &str) -> Result<u64, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err("duration must not be empty".to_string());
    }
    let split = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let (digits, unit) = value.split_at(split);
    if digits.is_empty() {
        return Err(format!("duration '{value}' is missing a number"));
    }
    let amount = digits
        .parse::<u64>()
        .map_err(|e| format!("invalid duration number '{digits}': {e}"))?;
    let multiplier = match unit.trim() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600,
        "d" | "day" | "days" => 86_400,
        other => return Err(format!("unsupported duration unit '{other}'")),
    };
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration '{value}' overflows seconds"))
}

fn parse_amount_msats(value: &str) -> Result<u64, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err("amount must not be empty".to_string());
    }
    let split = value
        .find(|ch: char| !ch.is_ascii_digit())
        .ok_or_else(|| "amount must include a unit suffix, such as msat or sat".to_string())?;
    let (digits, unit) = value.split_at(split);
    if digits.is_empty() {
        return Err(format!("amount '{value}' is missing a number"));
    }
    let amount = digits
        .parse::<u64>()
        .map_err(|e| format!("invalid amount number '{digits}': {e}"))?;
    match unit.trim() {
        "msat" | "msats" | "millisat" | "millisats" => Ok(amount),
        "sat" | "sats" | "satoshi" | "satoshis" => amount
            .checked_mul(1_000)
            .ok_or_else(|| format!("amount '{value}' overflows millisats")),
        other => Err(format!("unsupported amount unit '{other}'")),
    }
}

fn validate_hex_secret(label: &str, value: &str) -> anyhow::Result<()> {
    let normalized = value.trim().to_lowercase();
    if hex::decode(&normalized)
        .map(|bytes| bytes.len() != 32)
        .unwrap_or(true)
    {
        anyhow::bail!("{label} is not a 32-byte hex string");
    }
    Ok(())
}

/// Replace `${VAR}` and `${VAR:-default}` placeholders with values from the
/// process environment. A missing variable without a default is an error.
pub fn substitute_env_vars(input: &str) -> anyhow::Result<String> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut name = String::new();
            let mut default: Option<String> = None;

            while let Some(&ch) = chars.peek() {
                if ch == '}' {
                    chars.next();
                    break;
                }
                if ch == ':' {
                    let mut lookahead = chars.clone();
                    lookahead.next();
                    if lookahead.next() == Some('-') {
                        chars.next();
                        chars.next();
                        let mut def = String::new();
                        while let Some(&dch) = chars.peek() {
                            if dch == '}' {
                                chars.next();
                                break;
                            }
                            def.push(dch);
                            chars.next();
                        }
                        default = Some(def);
                        break;
                    }
                }
                name.push(ch);
                chars.next();
            }

            let value = match default {
                Some(def) => std::env::var(&name).unwrap_or(def),
                None => std::env::var(&name)
                    .map_err(|_| anyhow::anyhow!("environment variable '{name}' not set"))?,
            };
            output.push_str(&value);
        } else {
            output.push(c);
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn sample_pubkey_hex(seed: u8) -> String {
        crate::secp_identity::SecpTransportKeypair::from_secret_bytes(&[seed; 32])
            .unwrap()
            .pubkey()
            .to_hex()
    }

    fn minimal_config_yaml() -> String {
        let pubkey = sample_pubkey_hex(7);
        format!(
            r#"
wallets:
  relay:
    db_path: /tmp/relay.db
  client:
    loose_db_path: /tmp/client-loose.db
    channel_db_path: /tmp/client-channel.db
    wallet_name: default
    sender_secret_hex: "{ZERO_SECRET}"
management:
  listen: 127.0.0.1:9080
relays:
  - name: r1
    quic_cert_seed: "{ZERO_SECRET}"
    transport_key: "{ZERO_SECRET}"
    listen: 0.0.0.0:9050
    pricing:
      in_bytes_per_millisat: 10
      out_bytes_per_millisat: 20
    trusted_mints:
      - url: https://mint.example
        units: [sat]
clients:
  - name: c1
    socks: 127.0.0.1:1080
    route:
      - addr: 127.10.0.11:9050
        pubkey: "{pubkey}"
"#
        )
    }

    #[test]
    fn substitute_plain_var() {
        std::env::set_var("MONAD_TEST_MINT", "https://mint.example");
        let out = substitute_env_vars("mint: ${MONAD_TEST_MINT}").unwrap();
        assert_eq!(out, "mint: https://mint.example");
    }

    #[test]
    fn substitute_default_when_set() {
        std::env::set_var("MONAD_TEST_SET", "yes");
        let out = substitute_env_vars("${MONAD_TEST_SET:-no}").unwrap();
        assert_eq!(out, "yes");
    }

    #[test]
    fn substitute_default_when_unset() {
        let var = "MONAD_TEST_UNSET_42";
        std::env::remove_var(var);
        let out = substitute_env_vars(&format!("${{{var}:-fallback}}")).unwrap();
        assert_eq!(out, "fallback");
    }

    #[test]
    fn substitute_missing_is_error() {
        std::env::remove_var("MONAD_TEST_MISSING");
        assert!(substitute_env_vars("${MONAD_TEST_MISSING}").is_err());
    }

    #[test]
    fn parse_and_validate_minimal_config() {
        let config: MonadConfig = serde_yaml::from_str(&minimal_config_yaml()).unwrap();
        config.validate().unwrap();
        assert_eq!(config.wallets.relay.db_path, "/tmp/relay.db");
        assert_eq!(
            config
                .wallets
                .client
                .as_ref()
                .unwrap()
                .channel_input_budget_msats,
            1_000_000
        );
        assert_eq!(
            config
                .wallets
                .client
                .as_ref()
                .unwrap()
                .target_topup_buffer_msats,
            10_000_000
        );
        assert_eq!(
            config.wallets.client.as_ref().unwrap().minimum_topup_msats,
            0
        );
        assert_eq!(config.relays[0].pricing.in_bytes_per_millisat, 10);
        assert_eq!(config.relays[0].channel_policy.min_expiry_secs, 3_600);
        assert_eq!(config.relays[0].channel_policy.min_capacity_msats, 1);
        assert_eq!(
            config.relays[0].channel_policy.max_amount_per_output_msats,
            None
        );
        assert_eq!(
            config.relays[0].channel_policy.close_before_expiry_secs,
            86_400
        );
        assert_eq!(config.clients[0].route[0].addr, "127.10.0.11:9050");
    }

    #[test]
    fn parse_relay_channel_policy() {
        let yaml = minimal_config_yaml().replace(
            "    trusted_mints:",
            "    channel_policy:\n      min_expiry: 3600s\n      min_capacity: 1500msat\n      max_amount_per_output: 2sat\n      close_before_expiry: 2h\n    trusted_mints:",
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        config.validate().unwrap();
        let policy = &config.relays[0].channel_policy;
        assert_eq!(policy.min_expiry_secs, 3_600);
        assert_eq!(policy.min_capacity_msats, 1_500);
        assert_eq!(policy.max_amount_per_output_msats, Some(2_000));
        assert_eq!(policy.close_before_expiry_secs, 7_200);
    }

    #[test]
    fn parse_relay_channel_policy_duration_aliases() {
        let yaml = minimal_config_yaml().replace(
            "    trusted_mints:",
            "    channel_policy:\n      min_expiry: 60m\n      min_capacity: 1sat\n      close_before_expiry: 1d\n    trusted_mints:",
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        config.validate().unwrap();
        let policy = &config.relays[0].channel_policy;
        assert_eq!(policy.min_expiry_secs, 3_600);
        assert_eq!(policy.min_capacity_msats, 1_000);
        assert_eq!(policy.close_before_expiry_secs, 86_400);
    }

    #[test]
    fn parse_relay_channel_policy_numeric_duration_seconds() {
        let yaml = minimal_config_yaml().replace(
            "    trusted_mints:",
            "    channel_policy:\n      min_expiry: 3600\n      min_capacity: 1sat\n      close_before_expiry: \"7200\"\n    trusted_mints:",
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        config.validate().unwrap();
        let policy = &config.relays[0].channel_policy;
        assert_eq!(policy.min_expiry_secs, 3_600);
        assert_eq!(policy.close_before_expiry_secs, 7_200);
    }

    #[test]
    fn relay_channel_policy_rejects_bare_amounts() {
        let yaml = minimal_config_yaml().replace(
            "    trusted_mints:",
            "    channel_policy:\n      min_capacity: 1\n    trusted_mints:",
        );
        assert!(serde_yaml::from_str::<MonadConfig>(&yaml).is_err());
    }

    #[test]
    fn relay_channel_policy_rejects_invalid_units() {
        let yaml = minimal_config_yaml().replace(
            "    trusted_mints:",
            "    channel_policy:\n      min_expiry: 1fortnight\n      min_capacity: 1btc\n    trusted_mints:",
        );
        assert!(serde_yaml::from_str::<MonadConfig>(&yaml).is_err());
    }

    #[test]
    fn relay_channel_policy_rejects_close_window_below_min_expiry() {
        let yaml = minimal_config_yaml().replace(
            "    trusted_mints:",
            "    channel_policy:\n      min_expiry: 2h\n      min_capacity: 1sat\n      close_before_expiry: 1h\n    trusted_mints:",
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("close_before_expiry"));
    }

    #[test]
    fn relay_channel_policy_rejects_zero_amounts() {
        let yaml = minimal_config_yaml().replace(
            "    trusted_mints:",
            "    channel_policy:\n      min_capacity: 0msat\n    trusted_mints:",
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("min_capacity"));
    }

    #[test]
    fn relay_channel_policy_rejects_zero_max_amount() {
        let yaml = minimal_config_yaml().replace(
            "    trusted_mints:",
            "    channel_policy:\n      max_amount_per_output: 0sat\n    trusted_mints:",
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("max_amount_per_output"));
    }

    #[test]
    fn zero_client_channel_input_budget_is_rejected() {
        let yaml = minimal_config_yaml().replace(
            &format!("sender_secret_hex: \"{ZERO_SECRET}\""),
            &format!("sender_secret_hex: \"{ZERO_SECRET}\"\n    channel_input_budget_msats: 0"),
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("channel_input_budget_msats"));
    }

    #[test]
    fn parse_non_default_client_payment_policy() {
        let yaml = minimal_config_yaml().replace(
            &format!("sender_secret_hex: \"{ZERO_SECRET}\""),
            &format!(
                "sender_secret_hex: \"{ZERO_SECRET}\"\n    target_topup_buffer_msats: 500000\n    minimum_topup_msats: 250000"
            ),
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        config.validate().unwrap();
        let client_wallet = config.wallets.client.as_ref().unwrap();
        assert_eq!(client_wallet.target_topup_buffer_msats, 500_000);
        assert_eq!(client_wallet.minimum_topup_msats, 250_000);
    }

    #[test]
    fn duplicate_relay_name_is_rejected() {
        let yaml = format!(
            r#"
wallets:
  relay:
    db_path: /tmp/relay.db
relays:
  - name: r1
    quic_cert_seed: "{ZERO_SECRET}"
    transport_key: "{ZERO_SECRET}"
    listen: 0.0.0.0:9050
    pricing: {{ in_bytes_per_millisat: 10, out_bytes_per_millisat: 20 }}
    trusted_mints: [{{ url: https://mint.example, units: [sat] }}]
  - name: r1
    quic_cert_seed: "0000000000000000000000000000000000000000000000000000000000000001"
    transport_key: "0000000000000000000000000000000000000000000000000000000000000002"
    listen: 0.0.0.0:9051
    pricing: {{ in_bytes_per_millisat: 10, out_bytes_per_millisat: 20 }}
    trusted_mints: [{{ url: https://mint.example, units: [sat] }}]
"#
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn duplicate_listen_is_rejected() {
        let yaml = format!(
            r#"
wallets:
  relay:
    db_path: /tmp/relay.db
relays:
  - name: r1
    quic_cert_seed: "{ZERO_SECRET}"
    transport_key: "{ZERO_SECRET}"
    listen: 0.0.0.0:9050
    pricing: {{ in_bytes_per_millisat: 10, out_bytes_per_millisat: 20 }}
    trusted_mints: [{{ url: https://mint.example, units: [sat] }}]
  - name: r2
    quic_cert_seed: "0000000000000000000000000000000000000000000000000000000000000001"
    transport_key: "0000000000000000000000000000000000000000000000000000000000000002"
    listen: 0.0.0.0:9050
    pricing: {{ in_bytes_per_millisat: 10, out_bytes_per_millisat: 20 }}
    trusted_mints: [{{ url: https://mint.example, units: [sat] }}]
"#
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn duplicate_receiver_secret_is_rejected() {
        let yaml = format!(
            r#"
wallets:
  relay:
    db_path: /tmp/relay.db
relays:
  - name: r1
    receiver_secret_hex: "{ZERO_SECRET}"
    quic_cert_seed: "0000000000000000000000000000000000000000000000000000000000000001"
    transport_key: "0000000000000000000000000000000000000000000000000000000000000002"
    listen: 0.0.0.0:9051
    pricing: {{ in_bytes_per_millisat: 10, out_bytes_per_millisat: 20 }}
    trusted_mints: [{{ url: https://mint.example, units: [sat] }}]
  - name: r2
    receiver_secret_hex: "{ZERO_SECRET}"
    quic_cert_seed: "0000000000000000000000000000000000000000000000000000000000000002"
    transport_key: "0000000000000000000000000000000000000000000000000000000000000003"
    listen: 0.0.0.0:9052
    pricing: {{ in_bytes_per_millisat: 10, out_bytes_per_millisat: 20 }}
    trusted_mints: [{{ url: https://mint.example, units: [sat] }}]
"#
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_route_pubkey_is_rejected() {
        let yaml = minimal_config_yaml().replace(
            &format!("pubkey: \"{}\"", sample_pubkey_hex(7)),
            "pubkey: \"not-a-pubkey\"",
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("route hop 1 pubkey is invalid"));
    }

    #[test]
    fn route_does_not_need_matching_relay_name() {
        let mut config: MonadConfig = serde_yaml::from_str(&minimal_config_yaml()).unwrap();
        config.relays[0].name = "different-local-relay".to_string();
        config.validate().unwrap();
    }

    #[test]
    fn client_wallet_required_when_clients_exist() {
        let yaml = minimal_config_yaml().replace(
            &format!(
                r#"  client:
    loose_db_path: /tmp/client-loose.db
    channel_db_path: /tmp/client-channel.db
    wallet_name: default
    sender_secret_hex: "{ZERO_SECRET}"
"#
            ),
            "",
        );
        let config: MonadConfig = serde_yaml::from_str(&yaml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("wallets.client is required"));
    }

    #[test]
    fn load_config_from_file_with_env_and_dotenv() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("monad.yaml");
        let relay_db = dir.path().join("relay.db");

        let mut env_file = std::fs::File::create(dir.path().join(".env")).unwrap();
        writeln!(env_file, "MONAD_CFG_TEST_QUIC={}", "0".repeat(63) + "1").unwrap();
        writeln!(
            env_file,
            "MONAD_CFG_TEST_TRANSPORT={}",
            "0".repeat(63) + "2"
        )
        .unwrap();
        std::env::set_var("MONAD_CFG_TEST_MINT", "https://env.mint.example");
        std::env::remove_var("MONAD_CFG_TEST_SECRET");

        let yaml = format!(
            r#"
wallets:
  relay:
    db_path: {}
relays:
  - name: file-relay
    receiver_secret_hex: "${{MONAD_CFG_TEST_SECRET:-0000000000000000000000000000000000000000000000000000000000000003}}"
    quic_cert_seed: "${{MONAD_CFG_TEST_QUIC}}"
    transport_key: "${{MONAD_CFG_TEST_TRANSPORT}}"
    listen: 127.0.0.1:9050
    pricing:
      in_bytes_per_millisat: 10
      out_bytes_per_millisat: 20
    trusted_mints:
      - url: ${{MONAD_CFG_TEST_MINT}}
        units: [sat, msat]
"#,
            relay_db.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let config = MonadConfig::load(&config_path).unwrap();
        let relay = &config.relays[0];
        assert_eq!(config.wallets.relay.db_path, relay_db.display().to_string());
        assert_eq!(relay.name, "file-relay");
        assert_eq!(relay.quic_cert_seed, "0".repeat(63) + "1");
        assert_eq!(relay.transport_key, "0".repeat(63) + "2");
        assert_eq!(relay.receiver_secret_hex, Some("0".repeat(63) + "3"));
        assert_eq!(relay.trusted_mints[0].url, "https://env.mint.example");
        assert_eq!(relay.trusted_mints[0].units, vec!["sat", "msat"]);
    }
}
