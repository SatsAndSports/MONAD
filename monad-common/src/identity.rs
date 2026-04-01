//! Unified Ed25519 identity for MONAD servers.
//!
//! Each server has one Ed25519 keypair that serves as its identity.
//! From this single keypair, we derive:
//!
//! - **X25519 private key** (for Noise NK handshakes): `SHA-512(seed)[0..32]`
//! - **X25519 public key** (for Noise NK client verification): Edwards-to-Montgomery conversion
//! - **QUIC/TLS certificate** (for relay-to-relay transport): self-signed cert from the Ed25519 key
//! - **QUIC pinned public key** (SPKI DER): fixed ASN.1 header + raw Ed25519 public key
//!
//! This means operators generate and publish one key, and clients specify one key per hop.

use ring::signature::KeyPair as _;
use sha2::{Digest, Sha512};
use std::io;

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
/// Returns `(seed, public_key)` where both are 32 bytes.
/// The seed is the private key material; the public key is the server's identity.
pub fn generate_identity() -> io::Result<([u8; 32], [u8; 32])> {
    let rng = ring::rand::SystemRandom::new();
    let mut seed = [0u8; 32];
    ring::rand::SecureRandom::fill(&rng, &mut seed)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to generate random seed"))?;

    let pubkey = ed25519_seed_to_pubkey(&seed)?;
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

/// Convert an Ed25519 seed (32 bytes) to an X25519 private key (32 bytes).
///
/// This follows the standard Ed25519-to-X25519 conversion:
/// `x25519_private = SHA-512(seed)[0..32]`
///
/// Snow's Noise implementation will apply X25519 clamping internally
/// when this key is used.
pub fn ed25519_seed_to_x25519_private(seed: &[u8; 32]) -> [u8; 32] {
    let hash = Sha512::digest(seed);
    let mut x25519_private = [0u8; 32];
    x25519_private.copy_from_slice(&hash[..32]);
    x25519_private
}

/// Convert an Ed25519 public key (32 bytes) to an X25519 public key (32 bytes).
///
/// This performs the Edwards-to-Montgomery point conversion:
/// the Ed25519 compressed Edwards Y coordinate is decompressed to a curve point,
/// then converted to Montgomery form (X25519 u-coordinate).
pub fn ed25519_pubkey_to_x25519_pubkey(ed25519_pub: &[u8; 32]) -> io::Result<[u8; 32]> {
    let compressed = curve25519_dalek::edwards::CompressedEdwardsY(*ed25519_pub);
    let edwards_point = compressed.decompress().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Ed25519 public key: failed to decompress Edwards point",
        )
    })?;

    let montgomery_point = edwards_point.to_montgomery();
    Ok(montgomery_point.to_bytes())
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
        // Generate an identity and verify the conversions are consistent.
        let (seed, pubkey) = generate_identity().unwrap();

        // Verify we can derive the same pubkey from the seed
        let pubkey2 = ed25519_seed_to_pubkey(&seed).unwrap();
        assert_eq!(pubkey, pubkey2);

        // Verify X25519 conversion produces valid-looking keys
        let x25519_priv = ed25519_seed_to_x25519_private(&seed);
        assert_ne!(
            x25519_priv, [0u8; 32],
            "X25519 private key should not be all zeros"
        );

        let x25519_pub = ed25519_pubkey_to_x25519_pubkey(&pubkey).unwrap();
        assert_ne!(
            x25519_pub, [0u8; 32],
            "X25519 public key should not be all zeros"
        );

        // Verify SPKI DER has the right structure
        let spki = ed25519_pubkey_to_spki_der(&pubkey);
        assert_eq!(spki.len(), 44);
        assert_eq!(&spki[..12], &ED25519_SPKI_HEADER);
        assert_eq!(&spki[12..], &pubkey);

        // Verify PKCS#8 DER has the right structure
        let pkcs8 = ed25519_seed_to_pkcs8_der(&seed);
        assert_eq!(pkcs8.len(), 48);
        assert_eq!(&pkcs8[..16], &ED25519_PKCS8_HEADER);
        assert_eq!(&pkcs8[16..], &seed);
    }

    #[test]
    fn test_x25519_conversion_matches_snow() {
        // Verify that our Ed25519→X25519 conversion produces keys that
        // snow can use for a Noise handshake.
        let (seed, pubkey) = generate_identity().unwrap();

        let x25519_priv = ed25519_seed_to_x25519_private(&seed);
        let x25519_pub = ed25519_pubkey_to_x25519_pubkey(&pubkey).unwrap();

        // Build a Noise responder with the derived X25519 private key
        let builder = snow::Builder::new("Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let _responder = builder
            .local_private_key(&x25519_priv)
            .build_responder()
            .expect("snow should accept our derived X25519 private key");

        // Build a Noise initiator with the derived X25519 public key
        let builder = snow::Builder::new("Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let _initiator = builder
            .remote_public_key(&x25519_pub)
            .build_initiator()
            .expect("snow should accept our derived X25519 public key");
    }

    #[test]
    fn test_x25519_keypair_consistency() {
        // Verify that the X25519 public key we derive from the Ed25519 public key
        // matches the X25519 public key that snow would derive from the X25519
        // private key. This confirms the Ed25519→X25519 conversion is correct.
        let (seed, pubkey) = generate_identity().unwrap();

        let x25519_priv = ed25519_seed_to_x25519_private(&seed);
        let x25519_pub_from_ed = ed25519_pubkey_to_x25519_pubkey(&pubkey).unwrap();

        // Ask snow to derive the X25519 public key from the private key
        let builder = snow::Builder::new("Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let snow_keypair = builder.generate_keypair().unwrap();
        // We can't easily get snow to derive from our key, but we can verify
        // via a Noise handshake that both sides agree.

        // Build responder with our derived X25519 private key
        let builder = snow::Builder::new("Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let mut responder = builder
            .local_private_key(&x25519_priv)
            .build_responder()
            .unwrap();

        // Build initiator with our derived X25519 public key
        let builder = snow::Builder::new("Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let mut initiator = builder
            .remote_public_key(&x25519_pub_from_ed)
            .build_initiator()
            .unwrap();

        // Perform the Noise handshake (NK: 2 messages)
        let mut buf = [0u8; 256];
        let len = initiator.write_message(&[], &mut buf).unwrap();
        let mut buf2 = [0u8; 256];
        responder.read_message(&buf[..len], &mut buf2).unwrap();

        let len = responder.write_message(&[], &mut buf).unwrap();
        initiator.read_message(&buf[..len], &mut buf2).unwrap();

        // Both sides should transition to transport mode
        let mut initiator_transport = initiator.into_transport_mode().unwrap();
        let mut responder_transport = responder.into_transport_mode().unwrap();

        // Verify data can flow
        let msg = b"unified key test";
        let len = initiator_transport.write_message(msg, &mut buf).unwrap();
        let len = responder_transport
            .read_message(&buf[..len], &mut buf2)
            .unwrap();
        assert_eq!(&buf2[..len], msg);

        // Suppress unused variable warning
        let _ = snow_keypair;
    }
}
