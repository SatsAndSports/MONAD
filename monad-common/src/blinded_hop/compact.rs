use super::types::{validate_route_address, MAX_BLINDED_CIPHERTEXT_BYTES};
use super::{BlindedHopDescriptor, BlindedHopMessage, CleartextHop, PathNode};
use crate::secp_identity::Secp256k1Pubkey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

// 32-byte tweak + parity + nonempty address + 16-byte AEAD tag.
const MIN_CIPHERTEXT: usize = 50;
// Bounds configuration decoding and keeps the hex CONNECT headers small.
const MAX_CIPHERTEXT: usize = MAX_BLINDED_CIPHERTEXT_BYTES;
const HEADER_LEN: usize = 1 + 33 + 2;
const MAX_ENCODED: usize = ((HEADER_LEN + MAX_CIPHERTEXT) * 4).div_ceil(3);

impl FromStr for PathNode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (key, rest) = value
            .split_once(':')
            .ok_or("route hop requires <key>::<address> or <key>:B:<data>")?;
        let pubkey = Secp256k1Pubkey::parse_config_pubkey(key)
            .map_err(|_| "route hop key must be a valid npub or 64-hex x-only secp256k1 key")?;
        if let Some(address) = rest.strip_prefix(':') {
            validate_route_address(address).map_err(|error| error.to_string())?;
            return Ok(Self::Cleartext(CleartextHop {
                addr: address.to_owned(),
                pubkey,
            }));
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
    fn clear_keys_and_opaque_addresses_roundtrip_losslessly() {
        let pubkey = key(7).pubkey();
        let npub = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("npub").unwrap(),
            pubkey.as_bytes(),
        )
        .unwrap();
        for encoding in [pubkey.to_hex(), pubkey.to_hex().to_uppercase(), npub] {
            for input in [
                "127.0.0.1",
                "relay.example:00080",
                "::1",
                "[::1]",
                "[2001:db8::1]:443",
                "opaque:scheme:value",
                "  relay path\t\n雪  ",
            ] {
                let hop: PathNode = format!("{encoding}::{input}").parse().unwrap();
                assert_eq!(
                    hop,
                    PathNode::Cleartext(CleartextHop {
                        addr: input.into(),
                        pubkey
                    })
                );
                assert_eq!(
                    hop.to_compact_string().unwrap(),
                    format!("{pubkey}::{input}")
                );
                let yaml = serde_yaml::to_string(&hop).unwrap();
                assert_eq!(serde_yaml::from_str::<PathNode>(&yaml).unwrap(), hop);
            }
        }
    }

    #[test]
    fn clear_hops_only_enforce_basic_representation_constraints() {
        let pubkey = key(7).pubkey();
        for address in ["", "host\0"] {
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
        assert!(format!(
            "{pubkey}::{}",
            "a".repeat(super::super::types::MAX_ROUTE_ADDRESS_BYTES + 1)
        )
        .parse::<PathNode>()
        .is_err());
    }

    #[test]
    fn blinded_crypto_and_both_ephemeral_parities_roundtrip() {
        let intro = key(7);
        let hidden = key(8);
        let descriptor = build_blinded_hop_descriptor(
            intro.pubkey().to_compressed_bytes(),
            "opaque:下一跳 [::1] no-port",
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
        assert_eq!(resolved.next_hop_addr, "opaque:下一跳 [::1] no-port");
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
    fn hand_built_nodes_serialize_without_rewriting_opaque_addresses() {
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
        assert!(clear.to_compact_string().unwrap().ends_with("::localhost"));
        let opaque = PathNode::Cleartext(CleartextHop {
            addr: "bad:address".into(),
            pubkey: key(7).pubkey(),
        });
        assert_eq!(
            serde_yaml::from_str::<PathNode>(&serde_yaml::to_string(&opaque).unwrap()).unwrap(),
            opaque
        );
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
