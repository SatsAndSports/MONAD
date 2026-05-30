//! Ed25519 QUIC certificate identity helpers for MONAD relays.
//!
//! MONAD still uses an Ed25519 keypair internally for QUIC/TLS certificate
//! generation. From this keypair, we derive:
//!
//! - **QUIC/TLS certificate**: self-signed cert from the Ed25519 key
//! - **QUIC pinned public key** (SPKI DER): fixed ASN.1 header + raw Ed25519 public key

use ring::signature::KeyPair as _;
use std::io;

// ---------------------------------------------------------------------------
// Ed25519Pubkey — validated 32-byte public key newtype
// ---------------------------------------------------------------------------

/// A validated 32-byte Ed25519 public key.
///
/// This is the published Ed25519 public key for a MONAD relay's QUIC
/// certificate plumbing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Pubkey([u8; 32]);

impl Ed25519Pubkey {
    /// Wrap a raw 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Validate and wrap a byte slice (must be exactly 32 bytes).
    pub fn from_slice(bytes: &[u8]) -> io::Result<Self> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Ed25519 public key must be 32 bytes, got {}", bytes.len()),
            )
        })?;
        Ok(Self(arr))
    }

    /// Decode a hex string into an `Ed25519Pubkey`.
    pub fn from_hex(hex: &str) -> io::Result<Self> {
        let bytes = hex::decode(hex)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid hex: {e}")))?;
        Self::from_slice(&bytes)
    }

    /// The raw 32-byte key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the SPKI DER blob for QUIC pinned-key verification.
    pub fn to_spki_der(&self) -> Vec<u8> {
        ed25519_pubkey_to_spki_der(&self.0)
    }
}

impl std::fmt::Display for Ed25519Pubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ---------------------------------------------------------------------------
// QuicCertIdentity — Ed25519 QUIC certificate identity derived from a seed
// ---------------------------------------------------------------------------

/// A relay's Ed25519 identity, derived from a single Ed25519 seed.
pub struct QuicCertIdentity {
    seed: [u8; 32],
    ed25519_pubkey: Ed25519Pubkey,
}

impl QuicCertIdentity {
    /// Generate a new random relay identity.
    pub fn generate() -> io::Result<Self> {
        let (seed, pubkey) = generate_identity()?;
        Ok(Self {
            seed,
            ed25519_pubkey: pubkey,
        })
    }

    /// Derive a relay identity from a known Ed25519 seed.
    pub fn from_seed(seed: [u8; 32]) -> io::Result<Self> {
        let pubkey = Ed25519Pubkey(ed25519_seed_to_pubkey(&seed)?);
        Ok(Self {
            seed,
            ed25519_pubkey: pubkey,
        })
    }

    /// Decode a hex-encoded Ed25519 seed into a `QuicCertIdentity`.
    pub fn from_hex(hex: &str) -> io::Result<Self> {
        let bytes = hex::decode(hex)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("invalid hex: {e}")))?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("seed must be 32 bytes, got {}", bytes.len()),
            )
        })?;
        Self::from_seed(seed)
    }

    /// The raw 32-byte Ed25519 seed (private key material).
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// The relay's Ed25519 public key (its published identity).
    pub fn ed25519_pubkey(&self) -> &Ed25519Pubkey {
        &self.ed25519_pubkey
    }
}

// ---------------------------------------------------------------------------
// Low-level key derivation functions
// ---------------------------------------------------------------------------

/// The fixed ASN.1 DER header for an Ed25519 SubjectPublicKeyInfo (SPKI).
///
/// SEQUENCE {
///   SEQUENCE { OID 1.3.101.112 }
///   BIT STRING { <32 bytes> }
/// }
///
/// This is 12 bytes, followed by the 32-byte raw Ed25519 public key.
const ED25519_SPKI_HEADER: [u8; 12] = [
    0x30, 0x2a, // SEQUENCE, 42 bytes
    0x30, 0x05, // SEQUENCE, 5 bytes
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x03, 0x21, 0x00, // BIT STRING, 33 bytes (0 unused bits)
];

/// The fixed PKCS#8 DER header for an Ed25519 private key.
///
/// SEQUENCE {
///   INTEGER 0
///   SEQUENCE { OID 1.3.101.112 }
///   OCTET STRING { OCTET STRING { <32 bytes seed> } }
/// }
///
/// This is 16 bytes, followed by the 32-byte Ed25519 seed.
const ED25519_PKCS8_HEADER: [u8; 16] = [
    0x30, 0x2e, // SEQUENCE, 46 bytes
    0x02, 0x01, 0x00, // INTEGER 0
    0x30, 0x05, // SEQUENCE, 5 bytes
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22, // OCTET STRING, 34 bytes
    0x04, 0x20, // OCTET STRING, 32 bytes
];

/// Generate a new Ed25519 identity.
///
/// Returns `(seed, public_key)` where seed is 32 bytes of private key material
/// and public_key is the relay's identity.
pub fn generate_identity() -> io::Result<([u8; 32], Ed25519Pubkey)> {
    let rng = ring::rand::SystemRandom::new();
    let mut seed = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut seed)
        .map_err(|_| io::Error::other("failed to generate random seed"))?;

    let pubkey = Ed25519Pubkey(ed25519_seed_to_pubkey(&seed)?);
    Ok((seed, pubkey))
}

/// Derive the Ed25519 public key from a 32-byte seed.
pub fn ed25519_seed_to_pubkey(seed: &[u8; 32]) -> io::Result<[u8; 32]> {
    let pkcs8 = ed25519_seed_to_pkcs8_der(seed);
    let key_pair =
        ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad Ed25519 seed: {e}"))
        })?;

    let pub_bytes = key_pair.public_key().as_ref();
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(pub_bytes);
    Ok(pubkey)
}

/// Construct the SPKI DER encoding of an Ed25519 public key.
///
/// This is the format used for QUIC pinned key verification:
/// a fixed 12-byte ASN.1 header followed by the 32-byte raw public key.
pub fn ed25519_pubkey_to_spki_der(ed25519_pub: &[u8; 32]) -> Vec<u8> {
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&ED25519_SPKI_HEADER);
    spki.extend_from_slice(ed25519_pub);
    spki
}

/// Construct the PKCS#8 DER encoding of an Ed25519 private key seed.
///
/// This wraps the 32-byte seed in the standard PKCS#8 ASN.1 structure
/// that `ring` and `rcgen` expect when loading Ed25519 private keys.
pub fn ed25519_seed_to_pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&ED25519_PKCS8_HEADER);
    pkcs8.extend_from_slice(seed);
    pkcs8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_roundtrip() {
        // Generate an identity and verify the cached derivations are consistent.
        let (seed, pubkey) = generate_identity().unwrap();

        // Verify we can derive the same pubkey from the seed
        let pubkey2 = ed25519_seed_to_pubkey(&seed).unwrap();
        assert_eq!(pubkey.as_bytes(), &pubkey2);

        // Verify SPKI DER has the right structure
        let spki = pubkey.to_spki_der();
        assert_eq!(spki.len(), 44);
        assert_eq!(&spki[..12], &ED25519_SPKI_HEADER);
        assert_eq!(&spki[12..], pubkey.as_bytes());

        // Verify PKCS#8 DER has the right structure
        let pkcs8 = ed25519_seed_to_pkcs8_der(&seed);
        assert_eq!(pkcs8.len(), 48);
        assert_eq!(&pkcs8[..16], &ED25519_PKCS8_HEADER);
        assert_eq!(&pkcs8[16..], &seed);
    }
}
