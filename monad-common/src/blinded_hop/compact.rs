use super::{BlindedHopDescriptor, BlindedHopMessage, CleartextHop, PathNode};
use crate::secp_identity::Secp256k1Pubkey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, net::Ipv6Addr, str::FromStr};

// 32-byte tweak + parity + nonempty address + 16-byte AEAD tag.
const MIN_CIPHERTEXT: usize = 50;
// Bounds configuration decoding and keeps the hex CONNECT headers small.
const MAX_CIPHERTEXT: usize = 1024;
const HEADER_LEN: usize = 1 + 33 + 2;
const MAX_ENCODED: usize = ((HEADER_LEN + MAX_CIPHERTEXT) * 4).div_ceil(3);

impl FromStr for PathNode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > 64 + 3 + MAX_ENCODED || value.chars().any(char::is_whitespace) {
            return Err("route hop is oversized or contains whitespace".into());
        }
        let (key, rest) = value
            .split_once(':')
            .ok_or("route hop requires <key>::<address> or <key>:B:<data>")?;
        let pubkey = Secp256k1Pubkey::parse_config_pubkey(key)
            .map_err(|_| "route hop key must be a valid npub or 64-hex x-only secp256k1 key")?;
        if let Some(address) = rest.strip_prefix(':') {
            let (host, port, ipv6) = if let Some(bracketed) = address.strip_prefix('[') {
                let (host, suffix) = bracketed
                    .split_once(']')
                    .ok_or("route hop IPv6 address is missing ]")?;
                host.parse::<Ipv6Addr>()
                    .map_err(|_| "route hop has invalid bracketed IPv6 address")?;
                let port = if suffix.is_empty() {
                    "9050"
                } else {
                    suffix
                        .strip_prefix(':')
                        .ok_or("route hop has invalid IPv6 port suffix")?
                };
                (host, port, true)
            } else if address.parse::<Ipv6Addr>().is_ok() {
                (address, "9050", true)
            } else {
                let (host, port) = address.split_once(':').unwrap_or((address, "9050"));
                if host.contains('.')
                    && host.bytes().all(|c| c.is_ascii_digit() || c == b'.')
                    && host.parse::<std::net::Ipv4Addr>().is_err()
                {
                    return Err("route hop has invalid IPv4 address".into());
                }
                let name = host.strip_suffix('.').unwrap_or(host);
                if name.is_empty()
                    || name.len() > 253
                    || !name.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && label.as_bytes()[0].is_ascii_alphanumeric()
                            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                            && label
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                    })
                {
                    return Err("route hop requires an IP address or DNS hostname".into());
                }
                (host, port, false)
            };
            let port = port.parse::<u16>().ok().filter(|p| *p != 0)
                .filter(|_| !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()))
                .ok_or("route hop port must be between 1 and 65535; bracket IPv6 when specifying a port")?;
            let addr = if ipv6 {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            return Ok(Self::Cleartext(CleartextHop { addr, pubkey }));
        }
        let encoded = rest
            .strip_prefix("B:")
            .ok_or("route hop discriminator must be empty (clear) or B (blinded)")?;
        if encoded.len() > MAX_ENCODED {
            return Err("blinded route data exceeds the version 0 size limit".into());
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "blinded route data must be canonical unpadded base64url")?;
        match bytes.first() {
            Some(0) => {}
            Some(_) => {
                return Err("unsupported blinded route data version (only 0 is supported)".into())
            }
            None => return Err("blinded route data is missing its version".into()),
        }
        if bytes.len() < HEADER_LEN {
            return Err("truncated blinded route data header".into());
        }
        let len = u16::from_be_bytes([bytes[34], bytes[35]]) as usize;
        if !(MIN_CIPHERTEXT..=MAX_CIPHERTEXT).contains(&len) || bytes.len() != HEADER_LEN + len {
            return Err("blinded route ciphertext must be 50..=1024 bytes with exact declared length (no trailing bytes)".into());
        }
        let mut ephemeral_pubkey = [0; 33];
        ephemeral_pubkey.copy_from_slice(&bytes[1..34]);
        // Ephemeral ECDH points preserve either parity, unlike x-only identities.
        k256::PublicKey::from_sec1_bytes(&ephemeral_pubkey)
            .map_err(|_| "blinded route data contains an invalid compressed ephemeral key")?;
        Ok(Self::Blinded(BlindedHopDescriptor {
            tweaked_pubkey: pubkey,
            message: BlindedHopMessage {
                ephemeral_pubkey,
                ciphertext: bytes[HEADER_LEN..].to_vec(),
            },
        }))
    }
}

impl PathNode {
    /// Encode a configuration hop, validating public low-level descriptor fields.
    /// Unlike parsed hops, hand-built nodes may not fit the compact envelope.
    pub fn to_compact_string(&self) -> Result<String, String> {
        let value = match self {
            Self::Cleartext(hop) => format!("{}::{}", hop.pubkey, hop.addr),
            Self::Blinded(hop) => {
                if !(MIN_CIPHERTEXT..=MAX_CIPHERTEXT).contains(&hop.message.ciphertext.len()) {
                    return Err("blinded route ciphertext must be 50..=1024 bytes".into());
                }
                let len = hop.message.ciphertext.len() as u16;
                let mut bytes = Vec::with_capacity(HEADER_LEN + usize::from(len));
                bytes.push(0);
                bytes.extend_from_slice(&hop.message.ephemeral_pubkey);
                bytes.extend_from_slice(&len.to_be_bytes());
                bytes.extend_from_slice(&hop.message.ciphertext);
                format!("{}:B:{}", hop.tweaked_pubkey, URL_SAFE_NO_PAD.encode(bytes))
            }
        };
        match value.parse::<Self>()? {
            Self::Cleartext(hop) => Ok(format!("{}::{}", hop.pubkey, hop.addr)),
            Self::Blinded(_) => Ok(value),
        }
    }
}

impl Serialize for PathNode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = self
            .to_compact_string()
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&value)
    }
}

impl<'de> Deserialize<'de> for PathNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HopVisitor;
        impl serde::de::Visitor<'_> for HopVisitor {
            type Value = PathNode;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a compact route hop string")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<PathNode, E> {
                value.parse().map_err(E::custom)
            }
        }
        deserializer.deserialize_str(HopVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blinded_hop::{build_blinded_hop_descriptor, resolve_blinded_hop_for_intro};
    use crate::secp_identity::SecpTransportKeypair;

    fn key(seed: u8) -> SecpTransportKeypair {
        SecpTransportKeypair::from_secret_bytes(&[seed; 32]).unwrap()
    }

    #[test]
    fn clear_keys_addresses_and_yaml_roundtrip() {
        let pubkey = key(7).pubkey();
        let fqdn = format!(
            "{}.{}.{}.{}.",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert!(format!("{pubkey}::{fqdn}").parse::<PathNode>().is_ok());
        let npub = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("npub").unwrap(),
            pubkey.as_bytes(),
        )
        .unwrap();
        for encoding in [pubkey.to_hex(), pubkey.to_hex().to_uppercase(), npub] {
            for (input, expected) in [
                ("127.0.0.1", "127.0.0.1:9050"),
                ("127.0.0.1:443", "127.0.0.1:443"),
                ("relay.example", "relay.example:9050"),
                ("relay.example.:65535", "relay.example.:65535"),
                ("localhost:1", "localhost:1"),
                ("::1", "[::1]:9050"),
                ("[::1]", "[::1]:9050"),
                ("[2001:db8::1]:443", "[2001:db8::1]:443"),
                ("2001:db8::1:443", "[2001:db8::1:443]:9050"),
            ] {
                let hop: PathNode = format!("{encoding}::{input}").parse().unwrap();
                assert_eq!(
                    hop,
                    PathNode::Cleartext(CleartextHop {
                        addr: expected.into(),
                        pubkey
                    })
                );
                assert_eq!(
                    hop.to_compact_string().unwrap(),
                    format!("{pubkey}::{expected}")
                );
                let yaml = serde_yaml::to_string(&hop).unwrap();
                assert_eq!(serde_yaml::from_str::<PathNode>(&yaml).unwrap(), hop);
            }
        }
    }

    #[test]
    fn malformed_clear_hops_are_rejected() {
        let pubkey = key(7).pubkey();
        for address in [
            "",
            ":1",
            "host:",
            "host:0",
            "host:65536",
            "host:-1",
            "host:+1",
            "host:1:2",
            "host/path",
            "user@host",
            "host?x",
            "[::1",
            "[::1]oops",
            "[::1]:",
            "[127.0.0.1]:1",
            "[::gg]:1",
            "bad..name",
            "-bad",
            "bad_",
            "999.0.0.1",
            "host\n",
            "host\0",
        ] {
            assert!(
                format!("{pubkey}::{address}").parse::<PathNode>().is_err(),
                "{address:?}"
            );
        }
        for suffix in ["", ":host", ":b:AA", ":X:AA", ":B:", ":B:AA=="] {
            assert!(format!("{pubkey}{suffix}").parse::<PathNode>().is_err());
        }
        for invalid_key in [
            "".into(),
            "mpub1abcdef".into(),
            "npub1invalid".into(),
            "00".repeat(32),
            "ff".repeat(32),
            hex::encode(pubkey.to_compressed_bytes()),
            "ab".repeat(31),
            "ab".repeat(33),
        ] {
            assert!(format!("{invalid_key}::localhost")
                .parse::<PathNode>()
                .is_err());
        }
        assert!(
            serde_yaml::from_str::<PathNode>(&format!("addr: localhost\npubkey: {pubkey}\n"))
                .is_err()
        );
        assert!(format!("{pubkey}::{}", "a".repeat(254))
            .parse::<PathNode>()
            .is_err());
    }

    #[test]
    fn blinded_crypto_and_both_ephemeral_parities_roundtrip() {
        let intro = key(7);
        let hidden = key(8);
        let descriptor = build_blinded_hop_descriptor(
            intro.pubkey().to_compressed_bytes(),
            "[::1]:9050",
            hidden.pubkey(),
        )
        .unwrap();
        let hop = PathNode::Blinded(descriptor.clone());
        let encoded = hop.to_compact_string().unwrap();
        let decoded: PathNode = encoded.parse().unwrap();
        assert_eq!(decoded, hop);
        let PathNode::Blinded(parsed) = decoded else {
            unreachable!()
        };
        let resolved = resolve_blinded_hop_for_intro(&intro, &parsed).unwrap();
        assert_eq!(resolved.next_hop_real_pubkey, hidden.pubkey());
        assert_eq!(resolved.next_hop_addr, "[::1]:9050");
        let npub = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("npub").unwrap(),
            descriptor.tweaked_pubkey.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            format!("{npub}:B:{}", encoded.split(":B:").nth(1).unwrap())
                .parse::<PathNode>()
                .unwrap(),
            hop
        );
        for parity in [2, 3] {
            let mut changed = descriptor.clone();
            changed.message.ephemeral_pubkey[0] = parity;
            let node = PathNode::Blinded(changed);
            assert_eq!(
                node.to_compact_string()
                    .unwrap()
                    .parse::<PathNode>()
                    .unwrap(),
                node
            );
            assert_eq!(
                serde_yaml::from_str::<PathNode>(&serde_yaml::to_string(&node).unwrap()).unwrap(),
                node
            );
        }
    }

    #[test]
    fn hand_built_nodes_serialize_without_panicking_on_invalid_fields() {
        let descriptor = build_blinded_hop_descriptor(
            key(7).pubkey().to_compressed_bytes(),
            "localhost:9050",
            key(8).pubkey(),
        )
        .unwrap();
        for len in [0, 49, 1025, 65536] {
            let mut invalid = descriptor.clone();
            invalid.message.ciphertext.resize(len, 0);
            let node = PathNode::Blinded(invalid);
            assert!(node.to_compact_string().is_err());
            assert!(serde_yaml::to_string(&node).is_err());
        }
        let mut invalid = descriptor;
        invalid.message.ephemeral_pubkey = [0; 33];
        assert!(serde_yaml::to_string(&PathNode::Blinded(invalid)).is_err());
        let clear = PathNode::Cleartext(CleartextHop {
            addr: "localhost".into(),
            pubkey: key(7).pubkey(),
        });
        assert!(clear
            .to_compact_string()
            .unwrap()
            .ends_with("::localhost:9050"));
        let invalid = PathNode::Cleartext(CleartextHop {
            addr: "bad:address".into(),
            pubkey: key(7).pubkey(),
        });
        assert!(serde_yaml::to_string(&invalid).is_err());
    }

    #[test]
    fn blinded_envelope_bounds_versions_and_canonical_encoding() {
        let descriptor = build_blinded_hop_descriptor(
            key(7).pubkey().to_compressed_bytes(),
            "localhost:9050",
            key(8).pubkey(),
        )
        .unwrap();
        let text = PathNode::Blinded(descriptor.clone())
            .to_compact_string()
            .unwrap();
        let (_, encoded) = text.split_once(":B:").unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let parse = |b: &[u8]| {
            format!(
                "{}:B:{}",
                descriptor.tweaked_pubkey,
                URL_SAFE_NO_PAD.encode(b)
            )
            .parse::<PathNode>()
        };
        for end in 0..bytes.len() {
            assert!(parse(&bytes[..end]).is_err());
        }
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(parse(&changed).is_err());
        for version in 1..=255 {
            changed = bytes.clone();
            changed[0] = version;
            assert!(parse(&changed).unwrap_err().contains("unsupported"));
        }
        for prefix in [0, 1, 4, 255] {
            changed = bytes.clone();
            changed[1] = prefix;
            assert!(parse(&changed).is_err());
        }
        changed = bytes.clone();
        changed[2..34].fill(255);
        assert!(parse(&changed).is_err());
        for len in [0usize, 49, 50, 1024, 1025, 65535] {
            changed = bytes[..HEADER_LEN].to_vec();
            changed[34..36].copy_from_slice(&(len as u16).to_be_bytes());
            changed.resize(HEADER_LEN + len, 0);
            assert_eq!(parse(&changed).is_ok(), (50..=1024).contains(&len));
        }
        for bad in [
            format!("{encoded}="),
            "A+/_".into(),
            "AB".into(),
            "_".repeat(MAX_ENCODED + 1),
        ] {
            assert!(format!("{}:B:{bad}", descriptor.tweaked_pubkey)
                .parse::<PathNode>()
                .is_err());
        }
        // Mutate only unused base64 bits of an otherwise valid envelope.
        changed = bytes[..HEADER_LEN].to_vec();
        changed[34..36].copy_from_slice(&52u16.to_be_bytes());
        changed.resize(HEADER_LEN + 52, 0);
        let mut noncanonical = URL_SAFE_NO_PAD.encode(&changed);
        assert!(noncanonical.ends_with('A'));
        noncanonical.pop();
        noncanonical.push('B');
        assert!(format!("{}:B:{noncanonical}", descriptor.tweaked_pubkey)
            .parse::<PathNode>()
            .is_err());
    }
}
