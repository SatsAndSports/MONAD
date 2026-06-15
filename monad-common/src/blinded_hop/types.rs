use crate::secp_identity::Secp256k1Pubkey;
use crate::secp_identity::SecpTransportKeypair;

#[derive(Debug, thiserror::Error)]
pub enum BlindedHopError {
    #[error("invalid blinded path: {0}")]
    InvalidPath(&'static str),
    #[error("invalid tweak bytes")]
    InvalidTweak,
    #[error("invalid secp256k1 public key bytes")]
    InvalidPublicKey,
    #[error("failed to generate randomness")]
    Randomness,
    #[error("invalid blinded hop payload: {0}")]
    InvalidPayload(&'static str),
    #[error("invalid blinded hop address utf-8: {0}")]
    InvalidUtf8(std::str::Utf8Error),
    #[error("failed to derive symmetric key")]
    KeyDerivation,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
}

/// A tweak scalar for one blinded hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HopTweak([u8; 32]);

impl HopTweak {
    // Raw random tweak generation stays private so callers go through
    // identity-aware helpers that enforce an even tweaked pubkey.
    pub(super) fn generate() -> Result<Self, BlindedHopError> {
        Ok(Self(
            SecpTransportKeypair::generate().normalized_secret_bytes(),
        ))
    }

    #[allow(dead_code)]
    pub(super) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(super) fn raw_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// The secret payload revealed to the current relay after decrypting a blinded hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlindedHopPlaintext {
    pub next_hop_addr: String,
    pub next_hop_tweak: HopTweak,
}

/// A one-shot sealed blinded-hop message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedHopMessage {
    pub ephemeral_pubkey: [u8; 33],
    pub ciphertext: Vec<u8>,
}

/// Minimal client-facing data needed to reach one blinded hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedHopDescriptor {
    pub tweaked_pubkey: Secp256k1Pubkey,
    pub message: BlindedHopMessage,
}

/// Relay-facing result of decrypting a blinded-hop descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBlindedHop {
    pub next_hop_addr: String,
    pub next_hop_real_pubkey: Secp256k1Pubkey,
    pub tweak: [u8; 32],
}

/// A cleartext hop whose real address and published secp256k1 pubkey are known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextHop {
    pub addr: String,
    pub pubkey: Secp256k1Pubkey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathNode {
    Cleartext(CleartextHop),
    Blinded(BlindedHopDescriptor),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub hops: Vec<PathNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathHopMode {
    Cleartext,
    Blinded,
}

#[derive(Clone, Copy)]
pub struct PathHop<'a> {
    pub addr: &'a str,
    pub identity: &'a SecpTransportKeypair,
    pub mode: PathHopMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct TweakedHopPublic {
    pub tweaked_pubkey: Secp256k1Pubkey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TweakedHopIdentity {
    pub tweak: HopTweak,
    pub tweaked_pubkey: Secp256k1Pubkey,
    pub responder_secret_key: [u8; 32],
}
