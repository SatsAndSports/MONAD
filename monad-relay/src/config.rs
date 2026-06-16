//! YAML configuration for `monad-relay`.
//!
//! A single config file can describe multiple relays (and, in the future,
//! clients).  Environment variables can be interpolated with `${VAR}` or
//! `${VAR:-default}` syntax, and a `.env` file in the same directory as the
//! config is loaded automatically before substitution.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

const DEFAULT_IN_BYTES_PER_MILLISAT: u64 = 1;
const DEFAULT_OUT_BYTES_PER_MILLISAT: u64 = 1;

/// Top-level MONAD configuration file.
#[derive(Debug, Clone, Deserialize)]
pub struct MonadConfig {
    pub relays: Vec<RelayConfig>,
}

impl MonadConfig {
    /// Load a config file from disk, apply `.env` / environment substitution,
    /// and validate it.
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();

        // Load .env from the config file's directory, if present.
        if let Some(parent) = path.parent() {
            let _ = dotenvy::from_path(parent.join(".env"));
        }

        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config file {}: {e}", path.display()))?;
        let substituted = substitute_env_vars(&raw)?;

        let mut config: MonadConfig = serde_yaml::from_str(&substituted)
            .map_err(|e| anyhow::anyhow!("failed to parse config file {}: {e}", path.display()))?;

        // Normalize optional fields that may have resolved to an empty string.
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

    fn validate(&self) -> anyhow::Result<()> {
        if self.relays.is_empty() {
            anyhow::bail!("config must contain at least one relay");
        }

        let mut names = HashSet::new();
        let mut listens = HashSet::new();
        let mut receiver_secrets = HashSet::new();

        for relay in &self.relays {
            if !names.insert(relay.name.clone()) {
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
                // Basic sanity check that it looks like a hex secret.
                if hex::decode(&normalized)
                    .map(|v| v.len() != 32)
                    .unwrap_or(true)
                {
                    anyhow::bail!(
                        "relay '{}' receiver secret is not a 32-byte hex string",
                        relay.name
                    );
                }
            }

            if relay.wallet_db_path.trim().is_empty() {
                anyhow::bail!("relay '{}' wallet_db_path must not be empty", relay.name);
            }

            if relay.trusted_mints.is_empty() {
                anyhow::bail!("relay '{}' must have at least one trusted mint", relay.name);
            }
        }

        Ok(())
    }
}

/// Configuration for a single relay instance.
#[derive(Debug, Clone, Deserialize)]
pub struct RelayConfig {
    /// Human-readable relay name, used to key the wallet identity.
    pub name: String,

    /// Path to the shared SQLite wallet database.
    pub wallet_db_path: String,

    /// Optional receiver secret. Required on first run to register the relay
    /// identity; on subsequent runs the secret is loaded from the database.
    pub receiver_secret_hex: Option<String>,

    /// Ed25519 seed for QUIC certificate generation.
    pub quic_cert_seed: String,

    /// secp256k1 transport private key for TCP/QUIC transport authentication.
    pub transport_key: String,

    /// Listen address, e.g. `0.0.0.0:9050`.
    pub listen: String,

    /// Enable the QUIC listener on the same port.
    #[serde(default)]
    pub quic: bool,

    /// Mints this relay trusts and the units it will accept from each.
    pub trusted_mints: Vec<TrustedMintConfig>,

    /// Default inbound bytes per millisat for sessions on this relay.
    #[serde(default = "default_in_bytes_per_millisat")]
    pub default_in_bytes_per_millisat: u64,

    /// Default outbound bytes per millisat for sessions on this relay.
    #[serde(default = "default_out_bytes_per_millisat")]
    pub default_out_bytes_per_millisat: u64,
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

/// A trusted mint and the units this relay will accept from it.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustedMintConfig {
    pub url: String,
    pub units: Vec<String>,
}

fn default_in_bytes_per_millisat() -> u64 {
    DEFAULT_IN_BYTES_PER_MILLISAT
}

fn default_out_bytes_per_millisat() -> u64 {
    DEFAULT_OUT_BYTES_PER_MILLISAT
}

/// Replace `${VAR}` and `${VAR:-default}` placeholders with values from the
/// process environment.  A missing variable without a default is an error.
fn substitute_env_vars(input: &str) -> anyhow::Result<String> {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut name = String::new();
            let mut default: Option<String> = None;

            while let Some(&ch) = chars.peek() {
                if ch == '}' {
                    chars.next();
                    break;
                }

                // Look for ${VAR:-default}
                if ch == ':' {
                    let mut lookahead = chars.clone();
                    lookahead.next(); // ':'
                    if lookahead.next() == Some('-') {
                        chars.next(); // ':'
                        chars.next(); // '-'
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
    fn parse_minimal_relay_config() {
        let yaml = r#"
relays:
  - name: r1
    wallet_db_path: /tmp/r.db
    quic_cert_seed: "0000000000000000000000000000000000000000000000000000000000000000"
    transport_key: "0000000000000000000000000000000000000000000000000000000000000000"
    listen: 0.0.0.0:9050
    trusted_mints:
      - url: https://mint.example
        units: [sat]
"#;
        let config: MonadConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.relays.len(), 1);
        assert!(!config.relays[0].quic);
    }

    #[test]
    fn duplicate_relay_name_is_rejected() {
        let yaml = r#"
relays:
  - name: r1
    wallet_db_path: /tmp/a.db
    quic_cert_seed: "0000000000000000000000000000000000000000000000000000000000000000"
    transport_key: "0000000000000000000000000000000000000000000000000000000000000000"
    listen: 0.0.0.0:9050
    trusted_mints:
      - url: https://mint.example
        units: [sat]
  - name: r1
    wallet_db_path: /tmp/b.db
    quic_cert_seed: "0000000000000000000000000000000000000000000000000000000000000001"
    transport_key: "0000000000000000000000000000000000000000000000000000000000000001"
    listen: 0.0.0.0:9051
    trusted_mints:
      - url: https://mint.example
        units: [sat]
"#;
        let config: MonadConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn duplicate_receiver_secret_is_rejected() {
        let yaml = r#"
relays:
  - name: r1
    wallet_db_path: /tmp/a.db
    receiver_secret_hex: "0000000000000000000000000000000000000000000000000000000000000001"
    quic_cert_seed: "0000000000000000000000000000000000000000000000000000000000000000"
    transport_key: "0000000000000000000000000000000000000000000000000000000000000000"
    listen: 0.0.0.0:9050
    trusted_mints:
      - url: https://mint.example
        units: [sat]
  - name: r2
    wallet_db_path: /tmp/b.db
    receiver_secret_hex: "0000000000000000000000000000000000000000000000000000000000000001"
    quic_cert_seed: "0000000000000000000000000000000000000000000000000000000000000002"
    transport_key: "0000000000000000000000000000000000000000000000000000000000000002"
    listen: 0.0.0.0:9051
    trusted_mints:
      - url: https://mint.example
        units: [sat]
"#;
        let config: MonadConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn load_config_from_file_with_env_and_dotenv() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("relay.yaml");
        let db_path = dir.path().join("relay.db");

        let mut env_file = std::fs::File::create(dir.path().join(".env")).unwrap();
        writeln!(
            env_file,
            "MONAD_CFG_TEST_QUIC=0000000000000000000000000000000000000000000000000000000000000001"
        )
        .unwrap();
        writeln!(
            env_file,
            "MONAD_CFG_TEST_TRANSPORT=0000000000000000000000000000000000000000000000000000000000000002"
        )
        .unwrap();

        std::env::set_var("MONAD_CFG_TEST_MINT", "https://env.mint.example");
        std::env::remove_var("MONAD_CFG_TEST_SECRET");

        let yaml = format!(
            r#"
relays:
  - name: file-relay
    wallet_db_path: {}
    receiver_secret_hex: "${{MONAD_CFG_TEST_SECRET:-0000000000000000000000000000000000000000000000000000000000000003}}"
    quic_cert_seed: "${{MONAD_CFG_TEST_QUIC}}"
    transport_key: "${{MONAD_CFG_TEST_TRANSPORT}}"
    listen: 127.0.0.1:9050
    trusted_mints:
      - url: ${{MONAD_CFG_TEST_MINT}}
        units: [sat, msat]
"#,
            db_path.display()
        );
        std::fs::write(&config_path, yaml).unwrap();

        let config = MonadConfig::load(&config_path).unwrap();
        assert_eq!(config.relays.len(), 1);
        let relay = &config.relays[0];
        assert_eq!(relay.name, "file-relay");
        assert_eq!(relay.wallet_db_path, db_path.display().to_string());
        assert_eq!(relay.quic_cert_seed, "0".repeat(63) + "1");
        assert_eq!(relay.transport_key, "0".repeat(63) + "2");
        assert_eq!(relay.receiver_secret_hex, Some("0".repeat(63) + "3"));
        assert_eq!(relay.trusted_mints[0].url, "https://env.mint.example");
        assert_eq!(relay.trusted_mints[0].units, vec!["sat", "msat"]);
    }
}
