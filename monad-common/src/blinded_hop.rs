//! Low-level blinded-hop helpers.
//!
//! This module is intentionally standalone. It does not wire blinded routing
//! into the rest of MONAD yet; it only provides the first crypto/data-format
//! building blocks needed for one blinded hop.
//!
//! A blinded hop message is a one-shot sealed message of the form:
//!
//! ```text
//! (E, ciphertext)
//! ```
//!
//! where `E` is a fresh ephemeral X25519 public key and `ciphertext` is an
//! AEAD-encrypted payload. There is deliberately no nonce field in the wire
//! format. Instead, encryption uses a fixed all-zero nonce, which is safe only
//! because the sender must generate a fresh ephemeral secret `e` (and thus a
//! fresh `E = e*G`) for every different plaintext.
//!
//! Reusing `e` / `E` for more than one plaintext breaks this security model.

use crate::identity::{Ed25519Pubkey, ServerIdentity};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ring::aead;
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

const BLINDED_HOP_HKDF_LABEL: &[u8] = b"monad-blinded-hop-v1";
const BLINDED_HOP_AAD: &[u8] = b"monad-blinded-hop-v1";
const BLINDED_HOP_ZERO_NONCE: [u8; 12] = [0u8; 12];
const ED25519_BASEPOINT_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Debug, thiserror::Error)]
pub enum BlindedHopError {
    #[error("invalid blinded path: {0}")]
    InvalidPath(&'static str),
    #[error("invalid ed25519 public key")]
    InvalidEd25519Pubkey,
    #[error("failed to generate randomness")]
    Randomness,
    #[error("failed to derive recipient x25519 public key: {0}")]
    X25519Derivation(std::io::Error),
    #[error("failed to serialize blinded hop payload: {0}")]
    Serialize(serde_json::Error),
    #[error("failed to deserialize blinded hop payload: {0}")]
    Deserialize(serde_json::Error),
    #[error("failed to derive symmetric key")]
    KeyDerivation,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
}

/// A tweak value for one blinded hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopTweak([u8; 32]);

impl HopTweak {
    /// Generate a fresh random tweak.
    pub fn generate() -> Result<Self, BlindedHopError> {
        let rng = SystemRandom::new();
        loop {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes)
                .map_err(|_| BlindedHopError::Randomness)?;

            // Avoid the identity-preserving zero tweak even under scalar reduction.
            if Scalar::from_bytes_mod_order(bytes) != Scalar::ZERO {
                return Ok(Self(bytes));
            }
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    fn is_zero_mod_eight(&self) -> bool {
        (self.0[0] & 0b0000_0111) == 0
    }

    fn as_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.0)
    }
}

/// The secret payload revealed to the current relay after decrypting a blinded hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedHopPlaintext {
    pub next_hop_addr: String,
    pub next_hop_tweak: HopTweak,
}

/// A one-shot sealed blinded-hop message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedHopMessage {
    pub ephemeral_pubkey: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// The minimal client-facing data needed to reach one blinded hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedHopDescriptor {
    pub tweaked_ed25519_pubkey: Ed25519Pubkey,
    pub message: BlindedHopMessage,
}

/// A cleartext hop whose real address and published identity are known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleartextHop {
    pub addr: String,
    pub pubkey: Ed25519Pubkey,
}

/// One hop in a mixed path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathNode {
    Cleartext(CleartextHop),
    Blinded(BlindedHopDescriptor),
}

/// A client-facing path whose first hop is cleartext and later hops may be blinded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    pub hops: Vec<PathNode>,
}

/// Service-side real hop input used to build a client-facing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathHopMode {
    Cleartext,
    Blinded,
}

#[derive(Clone, Copy)]
pub struct PathHop<'a> {
    pub addr: &'a str,
    pub identity: &'a ServerIdentity,
    pub mode: PathHopMode,
}

/// The client-facing tweaked identity for a blinded hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TweakedHopPublic {
    pub tweaked_ed25519_pubkey: Ed25519Pubkey,
    pub tweaked_x25519_pubkey: [u8; 32],
}

/// A tweaked hop identity that is fully compatible with MONAD's current
/// Noise/X25519 responder requirements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibleTweakedHop {
    pub tweak: HopTweak,
    pub tweaked_ed25519_pubkey: Ed25519Pubkey,
    pub tweaked_x25519_pubkey: [u8; 32],
    pub responder_x25519_private: [u8; 32],
    pub representative_k: u8,
    pub attempts_used: usize,
}

struct AeadKeyLen;

impl hkdf::KeyType for AeadKeyLen {
    fn len(&self) -> usize {
        32
    }
}

/// Additively tweak an Ed25519 public key in Edwards form.
pub fn tweak_ed25519_pubkey(
    pubkey: &Ed25519Pubkey,
    tweak: &HopTweak,
) -> Result<Ed25519Pubkey, BlindedHopError> {
    let compressed = CompressedEdwardsY(*pubkey.as_bytes());
    let point = compressed
        .decompress()
        .ok_or(BlindedHopError::InvalidEd25519Pubkey)?;
    let tweak_point = EdwardsPoint::mul_base(&tweak.as_scalar());
    let tweaked = point + tweak_point;
    Ok(Ed25519Pubkey::from_bytes(tweaked.compress().to_bytes()))
}

/// Reverse an additive tweak on an Ed25519 public key in Edwards form.
pub fn untweak_ed25519_pubkey(
    tweaked_pubkey: &Ed25519Pubkey,
    tweak: &HopTweak,
) -> Result<Ed25519Pubkey, BlindedHopError> {
    let compressed = CompressedEdwardsY(*tweaked_pubkey.as_bytes());
    let point = compressed
        .decompress()
        .ok_or(BlindedHopError::InvalidEd25519Pubkey)?;
    let tweak_point = EdwardsPoint::mul_base(&tweak.as_scalar());
    let original = point - tweak_point;
    Ok(Ed25519Pubkey::from_bytes(original.compress().to_bytes()))
}

/// Derive the tweaked X25519 public key from a tweaked Ed25519 public key.
pub fn tweaked_x25519_pubkey_from_ed25519(
    tweaked_pubkey: &Ed25519Pubkey,
) -> Result<[u8; 32], BlindedHopError> {
    tweaked_pubkey
        .to_x25519()
        .map_err(BlindedHopError::X25519Derivation)
}

/// Convenience helper returning both client-facing forms of a tweaked hop key.
pub fn derive_tweaked_hop_public(
    real_pubkey: &Ed25519Pubkey,
    tweak: &HopTweak,
) -> Result<TweakedHopPublic, BlindedHopError> {
    let tweaked_ed25519_pubkey = tweak_ed25519_pubkey(real_pubkey, tweak)?;
    let tweaked_x25519_pubkey = tweaked_x25519_pubkey_from_ed25519(&tweaked_ed25519_pubkey)?;
    Ok(TweakedHopPublic {
        tweaked_ed25519_pubkey,
        tweaked_x25519_pubkey,
    })
}

/// Derive the Ed25519 secret scalar bytes from an Ed25519 seed.
fn ed25519_seed_to_secret_scalar_bytes(seed: &[u8; 32]) -> [u8; 32] {
    let hash = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    scalar[0] &= 248;
    scalar[31] &= 63;
    scalar[31] |= 64;
    scalar
}

fn tweak_ed25519_secret_scalar(seed: &[u8; 32], tweak: &HopTweak) -> Scalar {
    let base = Scalar::from_bytes_mod_order(ed25519_seed_to_secret_scalar_bytes(seed));
    base + tweak.as_scalar()
}

fn add_le_bytes(a: [u8; 32], b: [u8; 32]) -> ([u8; 32], bool) {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    (out, carry != 0)
}

fn is_clamped_x25519_private_bytes(bytes: &[u8; 32]) -> bool {
    (bytes[0] & 0b0000_0111) == 0
        && (bytes[31] & 0b1000_0000) == 0
        && (bytes[31] & 0b0100_0000) == 0b0100_0000
}

fn find_clamped_x25519_representative_for_tweaked_scalar(
    tweaked_scalar: Scalar,
) -> Option<([u8; 32], u8)> {
    let mut candidate = tweaked_scalar.to_bytes();

    for k in 0u8..16 {
        if is_clamped_x25519_private_bytes(&candidate) {
            return Some((candidate, k));
        }
        let (next, overflow) = add_le_bytes(candidate, ED25519_BASEPOINT_ORDER_LE);
        if overflow {
            break;
        }
        candidate = next;
    }

    None
}

fn candidate_public_from_private_bytes(candidate_private: [u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(candidate_private).to_bytes()
}

fn derive_compatible_tweaked_hop_with_tweak_source<F>(
    identity: &ServerIdentity,
    mut next_tweak: F,
) -> Result<CompatibleTweakedHop, BlindedHopError>
where
    F: FnMut() -> Result<HopTweak, BlindedHopError>,
{
    let mut attempt = 1usize;
    loop {
        let tweak = next_tweak()?;
        let tweaked_scalar = tweak_ed25519_secret_scalar(identity.seed(), &tweak);
        let Some((responder_x25519_private, representative_k)) =
            find_clamped_x25519_representative_for_tweaked_scalar(tweaked_scalar)
        else {
            attempt += 1;
            continue;
        };

        let tweaked = derive_tweaked_hop_public(identity.ed25519_pubkey(), &tweak)?;
        let responder_public = candidate_public_from_private_bytes(responder_x25519_private);
        if responder_public != tweaked.tweaked_x25519_pubkey {
            attempt += 1;
            continue;
        }

        return Ok(CompatibleTweakedHop {
            tweak,
            tweaked_ed25519_pubkey: tweaked.tweaked_ed25519_pubkey,
            tweaked_x25519_pubkey: tweaked.tweaked_x25519_pubkey,
            responder_x25519_private,
            representative_k,
            attempts_used: attempt,
        });
    }
}

/// Rejection-sample tweaks until a fully Noise-compatible blinded hop identity
/// is found for the given server identity.
pub fn derive_compatible_tweaked_hop(
    identity: &ServerIdentity,
) -> Result<CompatibleTweakedHop, BlindedHopError> {
    derive_compatible_tweaked_hop_with_tweak_source(identity, HopTweak::generate)
}

/// Build the minimal client-facing descriptor for one blinded hop.
pub fn build_blinded_hop_descriptor(
    intro_pubkey: &Ed25519Pubkey,
    next_hop_addr: &str,
    hidden_hop_identity: &ServerIdentity,
) -> Result<BlindedHopDescriptor, BlindedHopError> {
    let compatible = derive_compatible_tweaked_hop(hidden_hop_identity)?;
    let message = encrypt_blinded_hop_for_intro(
        intro_pubkey,
        &BlindedHopPlaintext {
            next_hop_addr: next_hop_addr.to_owned(),
            next_hop_tweak: compatible.tweak,
        },
    )?;

    Ok(BlindedHopDescriptor {
        tweaked_ed25519_pubkey: compatible.tweaked_ed25519_pubkey,
        message,
    })
}

/// Build a mixed client-facing path from a real hop sequence.
pub fn build_path(hops: &[PathHop<'_>]) -> Result<Path, BlindedHopError> {
    if hops.is_empty() {
        return Err(BlindedHopError::InvalidPath(
            "path requires at least one real hop",
        ));
    }
    if hops[0].mode != PathHopMode::Cleartext {
        return Err(BlindedHopError::InvalidPath(
            "first path hop must be cleartext",
        ));
    }

    let mut path = Vec::with_capacity(hops.len());

    for (i, hop) in hops.iter().enumerate() {
        match hop.mode {
            PathHopMode::Cleartext => {
                path.push(PathNode::Cleartext(CleartextHop {
                    addr: hop.addr.to_owned(),
                    pubkey: hop.identity.ed25519_pubkey().clone(),
                }));
            }
            PathHopMode::Blinded => {
                let predecessor = &hops[i - 1];
                path.push(PathNode::Blinded(build_blinded_hop_descriptor(
                    predecessor.identity.ed25519_pubkey(),
                    hop.addr,
                    hop.identity,
                )?));
            }
        }
    }

    Ok(Path { hops: path })
}

/// Encrypt a blinded-hop plaintext for a relay using the relay's real public key.
pub fn encrypt_blinded_hop_for_intro(
    recipient_pubkey: &Ed25519Pubkey,
    plaintext: &BlindedHopPlaintext,
) -> Result<BlindedHopMessage, BlindedHopError> {
    let recipient_x25519 = recipient_pubkey
        .to_x25519()
        .map_err(BlindedHopError::X25519Derivation)?;

    let rng = SystemRandom::new();
    let mut ephemeral_secret = [0u8; 32];
    rng.fill(&mut ephemeral_secret)
        .map_err(|_| BlindedHopError::Randomness)?;

    let ephemeral_pubkey = MontgomeryPoint::mul_base_clamped(ephemeral_secret).to_bytes();
    let recipient_point = MontgomeryPoint(recipient_x25519);
    let shared_secret = recipient_point.mul_clamped(ephemeral_secret).to_bytes();
    let symmetric_key = derive_aead_key(&shared_secret)?;

    let mut in_out = serde_json::to_vec(plaintext).map_err(BlindedHopError::Serialize)?;
    let nonce = aead::Nonce::assume_unique_for_key(BLINDED_HOP_ZERO_NONCE);
    symmetric_key
        .seal_in_place_append_tag(nonce, aead::Aad::from(BLINDED_HOP_AAD), &mut in_out)
        .map_err(|_| BlindedHopError::Encrypt)?;

    Ok(BlindedHopMessage {
        ephemeral_pubkey,
        ciphertext: in_out,
    })
}

/// Decrypt a blinded-hop message with the relay's real identity.
pub fn decrypt_blinded_hop_for_intro(
    recipient: &ServerIdentity,
    message: &BlindedHopMessage,
) -> Result<BlindedHopPlaintext, BlindedHopError> {
    let sender_point = MontgomeryPoint(message.ephemeral_pubkey);
    let shared_secret = sender_point
        .mul_clamped(*recipient.x25519_private())
        .to_bytes();
    let symmetric_key = derive_aead_key(&shared_secret)?;

    let nonce = aead::Nonce::assume_unique_for_key(BLINDED_HOP_ZERO_NONCE);
    let mut in_out = message.ciphertext.clone();
    let plaintext = symmetric_key
        .open_in_place(nonce, aead::Aad::from(BLINDED_HOP_AAD), &mut in_out)
        .map_err(|_| BlindedHopError::Decrypt)?;

    serde_json::from_slice(plaintext).map_err(BlindedHopError::Deserialize)
}

fn derive_aead_key(shared_secret: &[u8; 32]) -> Result<aead::LessSafeKey, BlindedHopError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, BLINDED_HOP_HKDF_LABEL);
    let prk = salt.extract(shared_secret);
    let okm = prk
        .expand(&[BLINDED_HOP_HKDF_LABEL], AeadKeyLen)
        .map_err(|_| BlindedHopError::KeyDerivation)?;
    let mut key_bytes = [0u8; 32];
    okm.fill(&mut key_bytes)
        .map_err(|_| BlindedHopError::KeyDerivation)?;

    let key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
        .map_err(|_| BlindedHopError::KeyDerivation)?;
    Ok(aead::LessSafeKey::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ed25519_seed_to_pubkey;
    use snow::Builder;
    use std::collections::HashSet;

    const COMPATIBILITY_SAMPLES: usize = 64;
    const COMPATIBLE_HELPER_SAMPLES: usize = 256;
    const ZERO_MOD_EIGHT_SAMPLES: usize = 1024;
    const COMPATIBILITY_RATE_SAMPLES: usize = 4096;
    const COMPATIBILITY_RATE_STRESS_SAMPLES: usize = 65_536;

    fn sample_seed(i: u32) -> [u8; 32] {
        let mut hasher = Sha512::new();
        hasher.update(b"monad-blinded-hop-seed");
        hasher.update(i.to_le_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        out
    }

    fn sample_tweak(i: u32) -> HopTweak {
        let mut hasher = Sha512::new();
        hasher.update(b"monad-blinded-hop-tweak");
        hasher.update(i.to_le_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest[..32]);
        HopTweak::from_bytes(out)
    }

    fn sample_zero_mod_eight_tweak(i: u32) -> HopTweak {
        let mut attempt = i;
        loop {
            let mut k_bytes = *sample_tweak(attempt).as_bytes();
            // Of the 256 bits of deterministic randomness, clear the top 7 so k < 2^249.
            k_bytes[31] &= 0b0000_0001;
            if k_bytes != [0u8; 32] {
                return HopTweak::from_bytes(mul_le_bytes_by_eight(k_bytes));
            }
            attempt = attempt.wrapping_add(1);
        }
    }

    fn mul_le_bytes_by_eight(bytes: [u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u8;

        for (src, dst) in bytes.into_iter().zip(out.iter_mut()) {
            *dst = (src << 3) | carry;
            carry = src >> 5;
        }

        debug_assert_eq!(carry, 0);
        out
    }

    fn deterministic_zero_mod_eight_compatibility_sample(
        i: u32,
    ) -> Option<([u8; 32], TweakedHopPublic)> {
        let seed = sample_seed(i);
        let identity = ServerIdentity::from_seed(seed).unwrap();
        let tweak = sample_zero_mod_eight_tweak(i);
        assert!(tweak.is_zero_mod_eight(), "sample {i}");

        let tweaked = derive_tweaked_hop_public(identity.ed25519_pubkey(), &tweak).unwrap();
        let tweaked_scalar = tweak_ed25519_secret_scalar(&seed, &tweak);
        let (candidate, _k) =
            find_clamped_x25519_representative_for_tweaked_scalar(tweaked_scalar)?;

        assert!(is_clamped_x25519_private_bytes(&candidate), "sample {i}");
        Some((candidate, tweaked))
    }

    fn assert_descriptor_matches_hidden_hop(
        descriptor: &BlindedHopDescriptor,
        intro_identity: &ServerIdentity,
        hidden_identity: &ServerIdentity,
        expected_next_hop_addr: &str,
    ) {
        let plaintext = decrypt_blinded_hop_for_intro(intro_identity, &descriptor.message).unwrap();
        assert_eq!(plaintext.next_hop_addr, expected_next_hop_addr);

        let tweaked =
            derive_tweaked_hop_public(hidden_identity.ed25519_pubkey(), &plaintext.next_hop_tweak)
                .unwrap();
        assert_eq!(
            descriptor.tweaked_ed25519_pubkey,
            tweaked.tweaked_ed25519_pubkey
        );
        let recovered = untweak_ed25519_pubkey(
            &descriptor.tweaked_ed25519_pubkey,
            &plaintext.next_hop_tweak,
        )
        .unwrap();
        assert_eq!(recovered, *hidden_identity.ed25519_pubkey());
        assert_eq!(
            recovered.to_spki_der(),
            hidden_identity.ed25519_pubkey().to_spki_der()
        );

        let tweaked_scalar =
            tweak_ed25519_secret_scalar(hidden_identity.seed(), &plaintext.next_hop_tweak);
        let (candidate, _k) =
            find_clamped_x25519_representative_for_tweaked_scalar(tweaked_scalar).unwrap();
        let candidate_public = candidate_public_from_private_bytes(candidate);

        assert_eq!(candidate_public, tweaked.tweaked_x25519_pubkey);
        assert!(noise_handshake_succeeds(
            candidate,
            tweaked.tweaked_x25519_pubkey
        ));
    }

    fn noise_handshake_succeeds(responder_private: [u8; 32], remote_public: [u8; 32]) -> bool {
        let builder = Builder::new("Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let mut responder = match builder
            .local_private_key(&responder_private)
            .build_responder()
        {
            Ok(r) => r,
            Err(_) => return false,
        };

        let builder = Builder::new("Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap());
        let mut initiator = match builder.remote_public_key(&remote_public).build_initiator() {
            Ok(i) => i,
            Err(_) => return false,
        };

        let mut buf = [0u8; 256];
        let len = match initiator.write_message(&[], &mut buf) {
            Ok(len) => len,
            Err(_) => return false,
        };

        let mut scratch = [0u8; 256];
        if responder.read_message(&buf[..len], &mut scratch).is_err() {
            return false;
        }

        let len = match responder.write_message(&[], &mut buf) {
            Ok(len) => len,
            Err(_) => return false,
        };

        initiator.read_message(&buf[..len], &mut scratch).is_ok()
    }

    #[test]
    fn test_blinded_hop_encrypt_decrypt_roundtrip() {
        let recipient = ServerIdentity::generate().unwrap();
        let tweak = HopTweak::generate().unwrap();
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: "10.1.2.3:9050".to_string(),
            next_hop_tweak: tweak,
        };

        let message =
            encrypt_blinded_hop_for_intro(recipient.ed25519_pubkey(), &plaintext).unwrap();
        let decrypted = decrypt_blinded_hop_for_intro(&recipient, &message).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_blinded_hop_wrong_recipient_fails() {
        let recipient_a = ServerIdentity::generate().unwrap();
        let recipient_b = ServerIdentity::generate().unwrap();
        let tweak = HopTweak::generate().unwrap();
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: "10.1.2.3:9050".to_string(),
            next_hop_tweak: tweak,
        };

        let message =
            encrypt_blinded_hop_for_intro(recipient_a.ed25519_pubkey(), &plaintext).unwrap();
        let result = decrypt_blinded_hop_for_intro(&recipient_b, &message);
        assert!(matches!(
            result,
            Err(BlindedHopError::Decrypt) | Err(BlindedHopError::Deserialize(_))
        ));
    }

    #[test]
    fn test_blinded_hop_uses_fresh_ephemeral_key() {
        let recipient = ServerIdentity::generate().unwrap();
        let tweak = HopTweak::generate().unwrap();
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: "10.1.2.3:9050".to_string(),
            next_hop_tweak: tweak,
        };

        let msg1 = encrypt_blinded_hop_for_intro(recipient.ed25519_pubkey(), &plaintext).unwrap();
        let msg2 = encrypt_blinded_hop_for_intro(recipient.ed25519_pubkey(), &plaintext).unwrap();

        assert_ne!(msg1.ephemeral_pubkey, msg2.ephemeral_pubkey);
        assert_ne!(msg1.ciphertext, msg2.ciphertext);
    }

    #[test]
    fn test_build_blinded_hop_descriptor_roundtrip_and_compatibility() {
        let intro_identity = ServerIdentity::generate().unwrap();
        let hidden_identity = ServerIdentity::generate().unwrap();
        let descriptor = build_blinded_hop_descriptor(
            intro_identity.ed25519_pubkey(),
            "127.0.0.1:9002",
            &hidden_identity,
        )
        .unwrap();

        assert_descriptor_matches_hidden_hop(
            &descriptor,
            &intro_identity,
            &hidden_identity,
            "127.0.0.1:9002",
        );
    }

    #[test]
    fn test_build_path_builds_cleartext_then_blinded_hops() {
        let hop_a = ServerIdentity::generate().unwrap();
        let hop_b = ServerIdentity::generate().unwrap();
        let hop_c = ServerIdentity::generate().unwrap();
        let path = build_path(&[
            PathHop {
                addr: "127.0.0.1:9101",
                identity: &hop_a,
                mode: PathHopMode::Cleartext,
            },
            PathHop {
                addr: "127.0.0.1:9102",
                identity: &hop_b,
                mode: PathHopMode::Blinded,
            },
            PathHop {
                addr: "127.0.0.1:9103",
                identity: &hop_c,
                mode: PathHopMode::Blinded,
            },
        ])
        .unwrap();

        assert_eq!(path.hops.len(), 3);
        assert!(matches!(
            &path.hops[0],
            PathNode::Cleartext(CleartextHop { addr, pubkey })
                if addr == "127.0.0.1:9101" && *pubkey == *hop_a.ed25519_pubkey()
        ));

        let PathNode::Blinded(descriptor_b) = &path.hops[1] else {
            panic!("expected blinded hop at index 1");
        };
        let PathNode::Blinded(descriptor_c) = &path.hops[2] else {
            panic!("expected blinded hop at index 2");
        };

        assert_descriptor_matches_hidden_hop(descriptor_b, &hop_a, &hop_b, "127.0.0.1:9102");
        assert_descriptor_matches_hidden_hop(descriptor_c, &hop_b, &hop_c, "127.0.0.1:9103");
    }

    #[test]
    fn test_build_path_with_one_real_hop_is_cleartext_only() {
        let hop = ServerIdentity::generate().unwrap();
        let path = build_path(&[PathHop {
            addr: "127.0.0.1:9201",
            identity: &hop,
            mode: PathHopMode::Cleartext,
        }])
        .unwrap();

        assert_eq!(path.hops.len(), 1);
        assert!(matches!(
            &path.hops[0],
            PathNode::Cleartext(CleartextHop { addr, pubkey })
                if addr == "127.0.0.1:9201" && *pubkey == *hop.ed25519_pubkey()
        ));
    }

    #[test]
    fn test_build_path_rejects_empty_input() {
        let result = build_path(&[]);

        assert!(matches!(
            result,
            Err(BlindedHopError::InvalidPath(
                "path requires at least one real hop"
            ))
        ));
    }

    #[test]
    fn test_build_path_rejects_blinded_first_hop() {
        let hop_a = ServerIdentity::generate().unwrap();
        let hop_b = ServerIdentity::generate().unwrap();
        let result = build_path(&[
            PathHop {
                addr: "127.0.0.1:9251",
                identity: &hop_a,
                mode: PathHopMode::Blinded,
            },
            PathHop {
                addr: "127.0.0.1:9252",
                identity: &hop_b,
                mode: PathHopMode::Cleartext,
            },
        ]);

        assert!(matches!(
            result,
            Err(BlindedHopError::InvalidPath(
                "first path hop must be cleartext"
            ))
        ));
    }

    #[test]
    fn test_build_path_supports_cleartext_hop_in_the_middle() {
        let hop_a = ServerIdentity::generate().unwrap();
        let hop_b = ServerIdentity::generate().unwrap();
        let hop_c = ServerIdentity::generate().unwrap();
        let hop_d = ServerIdentity::generate().unwrap();
        let path = build_path(&[
            PathHop {
                addr: "127.0.0.1:9261",
                identity: &hop_a,
                mode: PathHopMode::Cleartext,
            },
            PathHop {
                addr: "127.0.0.1:9262",
                identity: &hop_b,
                mode: PathHopMode::Blinded,
            },
            PathHop {
                addr: "127.0.0.1:9263",
                identity: &hop_c,
                mode: PathHopMode::Cleartext,
            },
            PathHop {
                addr: "127.0.0.1:9264",
                identity: &hop_d,
                mode: PathHopMode::Blinded,
            },
        ])
        .unwrap();

        assert_eq!(path.hops.len(), 4);
        assert!(matches!(&path.hops[0], PathNode::Cleartext(_)));
        assert!(matches!(&path.hops[1], PathNode::Blinded(_)));
        assert!(matches!(&path.hops[2], PathNode::Cleartext(_)));
        assert!(matches!(&path.hops[3], PathNode::Blinded(_)));

        let PathNode::Blinded(descriptor_b) = &path.hops[1] else {
            panic!("expected blinded hop for B");
        };
        let PathNode::Cleartext(cleartext_c) = &path.hops[2] else {
            panic!("expected cleartext hop for C");
        };
        let PathNode::Blinded(descriptor_d) = &path.hops[3] else {
            panic!("expected blinded hop for D");
        };

        assert_descriptor_matches_hidden_hop(descriptor_b, &hop_a, &hop_b, "127.0.0.1:9262");
        assert_eq!(cleartext_c.addr, "127.0.0.1:9263");
        assert_eq!(cleartext_c.pubkey, *hop_c.ed25519_pubkey());
        assert_descriptor_matches_hidden_hop(descriptor_d, &hop_c, &hop_d, "127.0.0.1:9264");
    }

    #[test]
    fn test_build_path_multiple_blinded_hops_predecessors_recover_real_addr_and_pubkey() {
        let hop_a = ServerIdentity::generate().unwrap();
        let hop_b = ServerIdentity::generate().unwrap();
        let hop_c = ServerIdentity::generate().unwrap();
        let hop_d = ServerIdentity::generate().unwrap();
        let path = build_path(&[
            PathHop {
                addr: "127.0.0.1:9301",
                identity: &hop_a,
                mode: PathHopMode::Cleartext,
            },
            PathHop {
                addr: "127.0.0.1:9302",
                identity: &hop_b,
                mode: PathHopMode::Blinded,
            },
            PathHop {
                addr: "127.0.0.1:9303",
                identity: &hop_c,
                mode: PathHopMode::Blinded,
            },
            PathHop {
                addr: "127.0.0.1:9304",
                identity: &hop_d,
                mode: PathHopMode::Blinded,
            },
        ])
        .unwrap();

        assert_eq!(path.hops.len(), 4);
        assert!(matches!(&path.hops[0], PathNode::Cleartext(_)));
        assert!(matches!(&path.hops[1], PathNode::Blinded(_)));
        assert!(matches!(&path.hops[2], PathNode::Blinded(_)));
        assert!(matches!(&path.hops[3], PathNode::Blinded(_)));

        let PathNode::Blinded(descriptor_b) = &path.hops[1] else {
            panic!("expected blinded hop for B");
        };
        let PathNode::Blinded(descriptor_c) = &path.hops[2] else {
            panic!("expected blinded hop for C");
        };
        let PathNode::Blinded(descriptor_d) = &path.hops[3] else {
            panic!("expected blinded hop for D");
        };

        assert_descriptor_matches_hidden_hop(descriptor_b, &hop_a, &hop_b, "127.0.0.1:9302");
        assert_descriptor_matches_hidden_hop(descriptor_c, &hop_b, &hop_c, "127.0.0.1:9303");
        assert_descriptor_matches_hidden_hop(descriptor_d, &hop_c, &hop_d, "127.0.0.1:9304");
    }

    #[test]
    fn test_tweaked_ed25519_pubkey_differs_from_original() {
        let identity = ServerIdentity::generate().unwrap();
        let tweak = HopTweak::generate().unwrap();

        let tweaked = tweak_ed25519_pubkey(identity.ed25519_pubkey(), &tweak).unwrap();
        assert_ne!(tweaked, *identity.ed25519_pubkey());
    }

    #[test]
    fn test_tweaked_ed25519_pubkey_converts_to_x25519() {
        let identity = ServerIdentity::generate().unwrap();
        let tweak = HopTweak::generate().unwrap();

        let tweaked = tweak_ed25519_pubkey(identity.ed25519_pubkey(), &tweak).unwrap();
        let x25519 = tweaked_x25519_pubkey_from_ed25519(&tweaked).unwrap();
        assert_ne!(x25519, [0u8; 32]);
    }

    #[test]
    fn test_untweak_ed25519_pubkey_roundtrip_over_many_samples() {
        for i in 0..COMPATIBILITY_SAMPLES as u32 {
            let seed = sample_seed(i);
            let identity = ServerIdentity::from_seed(seed).unwrap();
            let tweak = sample_tweak(i);
            let tweaked = tweak_ed25519_pubkey(identity.ed25519_pubkey(), &tweak).unwrap();
            let recovered = untweak_ed25519_pubkey(&tweaked, &tweak).unwrap();

            assert_eq!(recovered, *identity.ed25519_pubkey(), "sample {i}");
        }
    }

    #[test]
    fn test_untweak_recovered_pubkey_matches_original_x25519_and_spki_over_many_samples() {
        for i in 0..COMPATIBILITY_SAMPLES as u32 {
            let seed = sample_seed(i);
            let identity = ServerIdentity::from_seed(seed).unwrap();
            let tweak = sample_tweak(i);
            let tweaked = tweak_ed25519_pubkey(identity.ed25519_pubkey(), &tweak).unwrap();
            let recovered = untweak_ed25519_pubkey(&tweaked, &tweak).unwrap();

            assert_eq!(
                recovered.to_x25519().unwrap(),
                identity.ed25519_pubkey().to_x25519().unwrap(),
                "sample {i}"
            );
            assert_eq!(
                recovered.to_spki_der(),
                identity.ed25519_pubkey().to_spki_der(),
                "sample {i}"
            );
        }
    }

    #[test]
    fn test_derive_tweaked_hop_public_returns_both_forms() {
        let identity = ServerIdentity::generate().unwrap();
        let tweak = HopTweak::generate().unwrap();

        let tweaked = derive_tweaked_hop_public(identity.ed25519_pubkey(), &tweak).unwrap();
        assert_ne!(tweaked.tweaked_ed25519_pubkey, *identity.ed25519_pubkey());
        assert_ne!(tweaked.tweaked_x25519_pubkey, [0u8; 32]);
    }

    #[test]
    fn test_ed25519_secret_scalar_reproduces_real_public_key_over_many_samples() {
        for i in 0..COMPATIBILITY_SAMPLES as u32 {
            let seed = sample_seed(i);
            let scalar_bytes = ed25519_seed_to_secret_scalar_bytes(&seed);
            let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
            let derived_pubkey = EdwardsPoint::mul_base(&scalar).compress().to_bytes();
            let real_pubkey = ed25519_seed_to_pubkey(&seed).unwrap();

            assert_eq!(derived_pubkey, real_pubkey, "sample {i}");
        }
    }

    #[test]
    fn test_tweaked_ed25519_secret_scalar_reproduces_tweaked_public_key_over_many_samples() {
        for i in 0..COMPATIBILITY_SAMPLES as u32 {
            let seed = sample_seed(i);
            let identity = ServerIdentity::from_seed(seed).unwrap();
            let tweak = sample_tweak(i);
            let tweaked_scalar = tweak_ed25519_secret_scalar(&seed, &tweak);
            let tweaked_from_scalar = EdwardsPoint::mul_base(&tweaked_scalar)
                .compress()
                .to_bytes();
            let tweaked_from_helper = tweak_ed25519_pubkey(identity.ed25519_pubkey(), &tweak)
                .unwrap()
                .as_bytes()
                .to_owned();

            assert_eq!(tweaked_from_scalar, tweaked_from_helper, "sample {i}");
        }
    }

    #[test]
    fn test_clamped_x25519_representative_exists_only_for_subset_over_many_samples() {
        let mut found = 0usize;
        let mut missing = 0usize;
        let mut sign_zero_found = 0usize;
        let mut sign_one_found = 0usize;
        let mut max_k = 0u8;

        for i in 0..COMPATIBILITY_SAMPLES as u32 {
            let seed = sample_seed(i);
            let identity = ServerIdentity::from_seed(seed).unwrap();
            let tweak = sample_tweak(i);
            let tweaked_scalar = tweak_ed25519_secret_scalar(&seed, &tweak);

            match find_clamped_x25519_representative_for_tweaked_scalar(tweaked_scalar) {
                Some((candidate, k)) => {
                    assert!(is_clamped_x25519_private_bytes(&candidate), "sample {i}");
                    found += 1;
                    max_k = max_k.max(k);
                    let sign = identity.ed25519_pubkey().as_bytes()[31] >> 7;
                    if sign == 0 {
                        sign_zero_found += 1;
                    } else {
                        sign_one_found += 1;
                    }
                }
                None => {
                    missing += 1;
                }
            }
        }

        // A clamped X25519 private-byte space has size about 2^251, while the
        // Edwards scalar field has order about 2^252. So we expect some, but
        // not all, tweaked Edwards scalar classes to admit a clamped X25519
        // representative.
        assert!(found > 0, "expected at least one compatible sample");
        assert!(missing > 0, "expected at least one incompatible sample");
        assert!(sign_zero_found > 0 && sign_one_found > 0);
        assert!(max_k < 16);
    }

    #[test]
    fn test_random_tweak_compatibility_rate_stays_near_half_over_large_sample() {
        let mut found = 0usize;
        let mut missing = 0usize;

        for i in 0..COMPATIBILITY_RATE_SAMPLES as u32 {
            let seed = sample_seed(i);
            let tweak = sample_tweak(i.wrapping_mul(17).wrapping_add(5));
            let tweaked_scalar = tweak_ed25519_secret_scalar(&seed, &tweak);

            if find_clamped_x25519_representative_for_tweaked_scalar(tweaked_scalar).is_some() {
                found += 1;
            } else {
                missing += 1;
            }
        }

        let rate = found as f64 / COMPATIBILITY_RATE_SAMPLES as f64;
        eprintln!(
            "compatibility rate summary: samples={} found={} missing={} rate={rate:.6}",
            COMPATIBILITY_RATE_SAMPLES, found, missing,
        );

        assert!(found > 0 && missing > 0);
        assert!(
            (0.40..=0.60).contains(&rate),
            "compatibility rate unexpectedly far from half: {rate:.6}"
        );
    }

    #[test]
    fn test_representative_public_matches_tweaked_x25519_public_when_representative_exists() {
        let mut checked = 0usize;
        for i in 0..COMPATIBILITY_SAMPLES as u32 {
            let seed = sample_seed(i);
            let identity = ServerIdentity::from_seed(seed).unwrap();
            let tweak = sample_tweak(i);
            let tweaked = derive_tweaked_hop_public(identity.ed25519_pubkey(), &tweak).unwrap();
            let tweaked_scalar = tweak_ed25519_secret_scalar(&seed, &tweak);

            let Some((candidate, _k)) =
                find_clamped_x25519_representative_for_tweaked_scalar(tweaked_scalar)
            else {
                continue;
            };
            let candidate_public = candidate_public_from_private_bytes(candidate);

            checked += 1;
            assert_eq!(
                candidate_public, tweaked.tweaked_x25519_pubkey,
                "sample {i}"
            );
        }
        assert!(checked > 0, "expected at least one checked sample");
    }

    #[test]
    fn test_representative_private_serves_noise_handshake_when_representative_exists() {
        let mut checked = 0usize;
        for i in 0..COMPATIBILITY_SAMPLES as u32 {
            let seed = sample_seed(i);
            let identity = ServerIdentity::from_seed(seed).unwrap();
            let tweak = sample_tweak(i);
            let tweaked = derive_tweaked_hop_public(identity.ed25519_pubkey(), &tweak).unwrap();
            let tweaked_scalar = tweak_ed25519_secret_scalar(&seed, &tweak);

            let Some((candidate, _k)) =
                find_clamped_x25519_representative_for_tweaked_scalar(tweaked_scalar)
            else {
                continue;
            };

            checked += 1;
            assert!(
                noise_handshake_succeeds(candidate, tweaked.tweaked_x25519_pubkey),
                "sample {i}"
            );
        }
        assert!(checked > 0, "expected at least one checked sample");
    }

    #[test]
    fn test_derive_compatible_tweaked_hop_always_returns_noise_compatible_result_over_many_samples()
    {
        let mut attempt_counts = Vec::with_capacity(COMPATIBLE_HELPER_SAMPLES);
        let mut max_attempts_used = 0usize;
        let mut total_attempts_used = 0usize;

        for i in 0..COMPATIBLE_HELPER_SAMPLES as u32 {
            let seed = sample_seed(i);
            let identity = ServerIdentity::from_seed(seed).unwrap();
            let mut next_attempt = 0u32;
            let result = derive_compatible_tweaked_hop_with_tweak_source(&identity, || {
                let tweak = sample_tweak(i.wrapping_mul(1000).wrapping_add(next_attempt));
                next_attempt = next_attempt.wrapping_add(1);
                Ok(tweak)
            })
            .unwrap();

            let responder_public =
                candidate_public_from_private_bytes(result.responder_x25519_private);
            let derived_x25519 = result.tweaked_ed25519_pubkey.to_x25519().unwrap();

            assert!(
                is_clamped_x25519_private_bytes(&result.responder_x25519_private),
                "sample {i}"
            );
            assert_eq!(responder_public, result.tweaked_x25519_pubkey, "sample {i}");
            assert_eq!(derived_x25519, result.tweaked_x25519_pubkey, "sample {i}");
            assert!(
                noise_handshake_succeeds(
                    result.responder_x25519_private,
                    result.tweaked_x25519_pubkey
                ),
                "sample {i}"
            );

            attempt_counts.push(result.attempts_used);
            max_attempts_used = max_attempts_used.max(result.attempts_used);
            total_attempts_used += result.attempts_used;
            eprintln!(
                "compatible tweak sample {i}: attempts={} k={}",
                result.attempts_used, result.representative_k
            );
        }

        let average_attempts = total_attempts_used as f64 / COMPATIBLE_HELPER_SAMPLES as f64;
        eprintln!(
            "compatible tweak summary: samples={} avg_attempts={average_attempts:.3} max_attempts={} attempts={:?}",
            COMPATIBLE_HELPER_SAMPLES,
            max_attempts_used,
            attempt_counts,
        );

        assert!(
            average_attempts < 4.0,
            "average attempts unexpectedly high: {average_attempts}"
        );
    }

    #[test]
    fn test_generated_tweaks_are_nonzero_and_not_constant() {
        let mut seen = HashSet::with_capacity(COMPATIBILITY_SAMPLES);

        for _ in 0..COMPATIBILITY_SAMPLES {
            let tweak = HopTweak::generate().unwrap();
            assert_ne!(tweak.as_scalar(), Scalar::ZERO);
            seen.insert(*tweak.as_bytes());
        }

        assert!(
            seen.len() > 1,
            "generated tweak stream unexpectedly constant"
        );
    }

    #[test]
    fn test_canonical_zero_mod_eight_tweaks_do_not_always_admit_clamped_representatives() {
        let mut found = 0usize;
        let mut missing = 0usize;

        for i in 0..ZERO_MOD_EIGHT_SAMPLES as u32 {
            if deterministic_zero_mod_eight_compatibility_sample(i).is_some() {
                found += 1;
            } else {
                missing += 1;
            }
        }

        assert!(found > 0, "expected at least one compatible 0 mod 8 sample");
        assert!(
            missing > 0,
            "expected at least one incompatible 0 mod 8 sample"
        );
    }

    #[test]
    fn test_canonical_zero_mod_eight_representative_matches_public_when_it_exists() {
        let mut checked = 0usize;

        for i in 0..ZERO_MOD_EIGHT_SAMPLES as u32 {
            let Some((candidate, tweaked)) = deterministic_zero_mod_eight_compatibility_sample(i)
            else {
                continue;
            };
            let candidate_public = candidate_public_from_private_bytes(candidate);

            checked += 1;
            assert_eq!(
                candidate_public, tweaked.tweaked_x25519_pubkey,
                "sample {i}"
            );
        }

        assert!(checked > 0, "expected at least one checked 0 mod 8 sample");
    }

    #[test]
    fn test_canonical_zero_mod_eight_representative_serves_noise_when_it_exists() {
        let mut checked = 0usize;

        for i in 0..ZERO_MOD_EIGHT_SAMPLES as u32 {
            let Some((candidate, tweaked)) = deterministic_zero_mod_eight_compatibility_sample(i)
            else {
                continue;
            };

            checked += 1;
            assert!(
                noise_handshake_succeeds(candidate, tweaked.tweaked_x25519_pubkey),
                "sample {i}"
            );
        }

        assert!(checked > 0, "expected at least one checked 0 mod 8 sample");
    }

    #[test]
    fn test_zero_mod_eight_tweak_source_still_needs_rejection_sampling() {
        let mut saw_retry = false;

        for i in 0..COMPATIBLE_HELPER_SAMPLES as u32 {
            let seed = sample_seed(i);
            let identity = ServerIdentity::from_seed(seed).unwrap();
            let mut next_attempt = 0u32;
            let result = derive_compatible_tweaked_hop_with_tweak_source(&identity, || {
                let tweak =
                    sample_zero_mod_eight_tweak(i.wrapping_mul(1000).wrapping_add(next_attempt));
                next_attempt = next_attempt.wrapping_add(1);
                Ok(tweak)
            })
            .unwrap();
            let responder_public =
                candidate_public_from_private_bytes(result.responder_x25519_private);
            let derived_x25519 = result.tweaked_ed25519_pubkey.to_x25519().unwrap();

            assert!(result.tweak.is_zero_mod_eight(), "sample {i}");
            assert!(result.attempts_used >= 1, "sample {i}");
            assert!(
                is_clamped_x25519_private_bytes(&result.responder_x25519_private),
                "sample {i}"
            );
            assert_eq!(responder_public, result.tweaked_x25519_pubkey, "sample {i}");
            assert_eq!(derived_x25519, result.tweaked_x25519_pubkey, "sample {i}");
            assert!(
                noise_handshake_succeeds(
                    result.responder_x25519_private,
                    result.tweaked_x25519_pubkey
                ),
                "sample {i}"
            );

            if result.attempts_used > 1 {
                saw_retry = true;
            }
        }

        assert!(
            saw_retry,
            "expected at least one 0 mod 8 sequence to need a retry"
        );
    }

    #[test]
    #[ignore = "stress coverage for compatibility rate stability"]
    fn test_random_tweak_compatibility_rate_stress() {
        let mut found = 0usize;
        let mut missing = 0usize;

        for i in 0..COMPATIBILITY_RATE_STRESS_SAMPLES as u32 {
            let seed = sample_seed(i);
            let tweak = sample_tweak(i.wrapping_mul(29).wrapping_add(11));
            let tweaked_scalar = tweak_ed25519_secret_scalar(&seed, &tweak);

            if find_clamped_x25519_representative_for_tweaked_scalar(tweaked_scalar).is_some() {
                found += 1;
            } else {
                missing += 1;
            }
        }

        let rate = found as f64 / COMPATIBILITY_RATE_STRESS_SAMPLES as f64;
        eprintln!(
            "compatibility rate stress summary: samples={} found={} missing={} rate={rate:.6}",
            COMPATIBILITY_RATE_STRESS_SAMPLES, found, missing,
        );

        assert!(found > 0 && missing > 0);
        assert!(
            (0.45..=0.55).contains(&rate),
            "stress compatibility rate unexpectedly far from half: {rate:.6}"
        );
    }

    #[test]
    fn test_multiplying_by_eight_mod_order_does_not_force_zero_mod_eight_encoding() {
        let eight = Scalar::from(8u64);
        let mut saw_zero_mod_eight = false;
        let mut saw_non_zero_mod_eight = false;

        for i in 0..COMPATIBILITY_SAMPLES as u32 {
            let bytes = (sample_tweak(i).as_scalar() * eight).to_bytes();
            if (bytes[0] & 0b0000_0111) == 0 {
                saw_zero_mod_eight = true;
            } else {
                saw_non_zero_mod_eight = true;
            }
        }

        assert!(saw_zero_mod_eight);
        assert!(
            saw_non_zero_mod_eight,
            "multiplication by 8 mod l should not constrain integer encodings to 0 mod 8"
        );
    }
}
