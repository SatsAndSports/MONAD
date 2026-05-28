//! Low-level blinded-hop helpers.
//!
//! This module targets MONAD's secp256k1 transport identity model. Blinding is
//! applied directly in secp256k1 scalar/group space, so there is no longer any
//! need for the old Ed25519/X25519 compatibility bridge or its rejection
//! sampling.

use crate::secp_identity::Secp256k1Pubkey;
use crate::secp_identity::SecpTransportKeypair;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey;
use k256::{ecdh, ProjectivePoint, PublicKey, Scalar, SecretKey};
use rand_core::OsRng;
use ring::aead;
use ring::hkdf;

const BLINDED_HOP_HKDF_LABEL: &[u8] = b"monad-blinded-hop-v2-secp256k1";
const BLINDED_HOP_AAD: &[u8] = b"monad-blinded-hop-v2-secp256k1";
const BLINDED_HOP_ZERO_NONCE: [u8; 12] = [0u8; 12];

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
pub struct HopTweak([u8; 32]);

impl HopTweak {
    pub fn generate() -> Result<Self, BlindedHopError> {
        Ok(Self(
            SecpTransportKeypair::generate().normalized_secret_bytes(),
        ))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn scalar(&self) -> Result<Scalar, BlindedHopError> {
        let signing_key =
            SigningKey::from_bytes(&self.0).map_err(|_| BlindedHopError::InvalidTweak)?;
        Ok(*signing_key.as_nonzero_scalar().as_ref())
    }
}

/// The secret payload revealed to the current relay after decrypting a blinded hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedHopPlaintext {
    pub next_hop_addr: String,
    pub next_hop_tweak: HopTweak,
}

fn encode_blinded_hop_plaintext(
    plaintext: &BlindedHopPlaintext,
) -> Result<Vec<u8>, BlindedHopError> {
    if plaintext.next_hop_addr.is_empty() {
        return Err(BlindedHopError::InvalidPayload(
            "next hop address must not be empty",
        ));
    }
    if plaintext.next_hop_addr.as_bytes().contains(&0) {
        return Err(BlindedHopError::InvalidPayload(
            "blinded hop address contains interior null",
        ));
    }

    let mut out = Vec::with_capacity(32 + plaintext.next_hop_addr.len());
    out.extend_from_slice(plaintext.next_hop_tweak.as_bytes());
    out.extend_from_slice(plaintext.next_hop_addr.as_bytes());
    Ok(out)
}

fn decode_blinded_hop_plaintext(bytes: &[u8]) -> Result<BlindedHopPlaintext, BlindedHopError> {
    if bytes.len() <= 32 {
        return Err(BlindedHopError::InvalidPayload(
            "blinded hop payload too short",
        ));
    }

    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&bytes[..32]);
    let addr_bytes = &bytes[32..];
    if addr_bytes.is_empty() {
        return Err(BlindedHopError::InvalidPayload(
            "next hop address must not be empty",
        ));
    }
    if addr_bytes.contains(&0) {
        return Err(BlindedHopError::InvalidPayload(
            "blinded hop address contains interior null",
        ));
    }

    let next_hop_addr = std::str::from_utf8(addr_bytes)
        .map_err(BlindedHopError::InvalidUtf8)?
        .to_owned();
    Ok(BlindedHopPlaintext {
        next_hop_addr,
        next_hop_tweak: HopTweak::from_bytes(tweak),
    })
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

/// A cleartext hop whose real address and published compressed secp256k1 pubkey are known.
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
pub struct TweakedHopPublic {
    pub tweaked_pubkey: Secp256k1Pubkey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TweakedHopIdentity {
    pub tweak: HopTweak,
    pub tweaked_pubkey: Secp256k1Pubkey,
    pub responder_secret_key: [u8; 32],
}

struct AeadKeyLen;

impl hkdf::KeyType for AeadKeyLen {
    fn len(&self) -> usize {
        32
    }
}

fn public_key_from_bytes(pubkey: &[u8; 33]) -> Result<PublicKey, BlindedHopError> {
    PublicKey::from_sec1_bytes(pubkey).map_err(|_| BlindedHopError::InvalidPublicKey)
}

fn public_key_from_point(point: ProjectivePoint) -> Result<PublicKey, BlindedHopError> {
    PublicKey::from_affine(point.to_affine()).map_err(|_| BlindedHopError::InvalidTweak)
}

fn compressed_bytes(public_key: &PublicKey) -> [u8; 33] {
    let encoded = public_key.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

#[cfg(test)]
fn pubkey_from_secret_bytes(secret_bytes: &[u8; 32]) -> Result<Secp256k1Pubkey, BlindedHopError> {
    let secret_key =
        SecretKey::from_slice(secret_bytes).map_err(|_| BlindedHopError::InvalidTweak)?;
    let public_key = secret_key.public_key();
    let compressed = compressed_bytes(&public_key);
    Secp256k1Pubkey::from_compressed_bytes(compressed)
        .map_err(|_| BlindedHopError::InvalidPublicKey)
}

fn is_even_point(public_key: &PublicKey) -> bool {
    compressed_bytes(public_key)[0] == 0x02
}

fn derive_even_tweaked_secret_key(
    identity: &SecpTransportKeypair,
) -> Result<(HopTweak, [u8; 32], Secp256k1Pubkey), BlindedHopError> {
    let base_key = SigningKey::from_bytes(&identity.normalized_secret_bytes())
        .map_err(|_| BlindedHopError::InvalidTweak)?;

    loop {
        let tweak = HopTweak::generate()?;
        let tweaked_scalar = *base_key.as_nonzero_scalar().as_ref() + tweak.scalar()?;
        let responder_secret_key: [u8; 32] = tweaked_scalar.to_bytes().into();
        let secret_key = SecretKey::from_slice(&responder_secret_key)
            .map_err(|_| BlindedHopError::InvalidTweak)?;
        let tweaked_public = secret_key.public_key();
        if is_even_point(&tweaked_public) {
            let tweaked_pubkey =
                Secp256k1Pubkey::from_compressed_bytes(compressed_bytes(&tweaked_public))
                    .map_err(|_| BlindedHopError::InvalidPublicKey)?;
            return Ok((tweak, responder_secret_key, tweaked_pubkey));
        }
    }
}

#[cfg(test)]
fn pubkey_from_secret_bytes_for_test(
    secret_bytes: &[u8; 32],
) -> Result<Secp256k1Pubkey, BlindedHopError> {
    pubkey_from_secret_bytes(secret_bytes)
}

pub fn tweak_pubkey(
    pubkey: Secp256k1Pubkey,
    tweak: &HopTweak,
) -> Result<Secp256k1Pubkey, BlindedHopError> {
    let public = pubkey
        .to_public_key()
        .map_err(|_| BlindedHopError::InvalidPublicKey)?;
    let tweaked_point =
        ProjectivePoint::from(public) + ProjectivePoint::GENERATOR * tweak.scalar()?;
    let tweaked_public = public_key_from_point(tweaked_point)?;
    let tweaked_compressed = compressed_bytes(&tweaked_public);
    Secp256k1Pubkey::from_compressed_bytes(tweaked_compressed)
        .map_err(|_| BlindedHopError::InvalidPublicKey)
}

pub fn untweak_pubkey(
    tweaked_pubkey: Secp256k1Pubkey,
    tweak: &HopTweak,
) -> Result<Secp256k1Pubkey, BlindedHopError> {
    let public = tweaked_pubkey
        .to_public_key()
        .map_err(|_| BlindedHopError::InvalidPublicKey)?;
    let original_point =
        ProjectivePoint::from(public) - ProjectivePoint::GENERATOR * tweak.scalar()?;
    let original_public = public_key_from_point(original_point)?;
    let original_compressed = compressed_bytes(&original_public);
    Secp256k1Pubkey::from_compressed_bytes(original_compressed)
        .map_err(|_| BlindedHopError::InvalidPublicKey)
}

pub fn derive_tweaked_hop_public(
    real_pubkey: Secp256k1Pubkey,
    tweak: &HopTweak,
) -> Result<TweakedHopPublic, BlindedHopError> {
    Ok(TweakedHopPublic {
        tweaked_pubkey: tweak_pubkey(real_pubkey, tweak)?,
    })
}

pub fn derive_tweaked_hop_identity(
    identity: &SecpTransportKeypair,
) -> Result<TweakedHopIdentity, BlindedHopError> {
    let (tweak, responder_secret_key, tweaked_pubkey) = derive_even_tweaked_secret_key(identity)?;
    Ok(TweakedHopIdentity {
        tweak,
        tweaked_pubkey,
        responder_secret_key,
    })
}

pub fn build_blinded_hop_descriptor(
    intro_pubkey: [u8; 33],
    next_hop_addr: &str,
    hidden_hop_identity: &SecpTransportKeypair,
) -> Result<BlindedHopDescriptor, BlindedHopError> {
    let tweaked = derive_tweaked_hop_identity(hidden_hop_identity)?;
    let message = encrypt_blinded_hop_for_intro(
        intro_pubkey,
        &BlindedHopPlaintext {
            next_hop_addr: next_hop_addr.to_owned(),
            next_hop_tweak: tweaked.tweak,
        },
    )?;

    Ok(BlindedHopDescriptor {
        tweaked_pubkey: tweaked.tweaked_pubkey,
        message,
    })
}

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
            PathHopMode::Cleartext => path.push(PathNode::Cleartext(CleartextHop {
                addr: hop.addr.to_owned(),
                pubkey: hop.identity.pubkey(),
            })),
            PathHopMode::Blinded => {
                let predecessor = &hops[i - 1];
                path.push(PathNode::Blinded(build_blinded_hop_descriptor(
                    predecessor.identity.pubkey().to_compressed_bytes(),
                    hop.addr,
                    hop.identity,
                )?));
            }
        }
    }

    Ok(Path { hops: path })
}

pub fn encrypt_blinded_hop_for_intro(
    recipient_pubkey: [u8; 33],
    plaintext: &BlindedHopPlaintext,
) -> Result<BlindedHopMessage, BlindedHopError> {
    let recipient_public = public_key_from_bytes(&recipient_pubkey)?;
    let ephemeral_secret = ecdh::EphemeralSecret::random(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    let symmetric_key = derive_aead_key(shared_secret.raw_secret_bytes())?;

    let mut in_out = encode_blinded_hop_plaintext(plaintext)?;
    let nonce = aead::Nonce::assume_unique_for_key(BLINDED_HOP_ZERO_NONCE);
    symmetric_key
        .seal_in_place_append_tag(nonce, aead::Aad::from(BLINDED_HOP_AAD), &mut in_out)
        .map_err(|_| BlindedHopError::Encrypt)?;

    Ok(BlindedHopMessage {
        ephemeral_pubkey: compressed_bytes(&ephemeral_public),
        ciphertext: in_out,
    })
}

pub fn decrypt_blinded_hop_for_intro(
    recipient: &SecpTransportKeypair,
    message: &BlindedHopMessage,
) -> Result<BlindedHopPlaintext, BlindedHopError> {
    let secret_key = SecretKey::from_slice(&recipient.normalized_secret_bytes())
        .map_err(|_| BlindedHopError::InvalidTweak)?;
    let sender_public = PublicKey::from_sec1_bytes(&message.ephemeral_pubkey)
        .map_err(|_| BlindedHopError::Decrypt)?;
    let shared_secret =
        ecdh::diffie_hellman(secret_key.to_nonzero_scalar(), sender_public.as_affine());
    let symmetric_key = derive_aead_key(shared_secret.raw_secret_bytes())?;

    let nonce = aead::Nonce::assume_unique_for_key(BLINDED_HOP_ZERO_NONCE);
    let mut in_out = message.ciphertext.clone();
    let plaintext = symmetric_key
        .open_in_place(nonce, aead::Aad::from(BLINDED_HOP_AAD), &mut in_out)
        .map_err(|_| BlindedHopError::Decrypt)?;
    decode_blinded_hop_plaintext(plaintext)
}

fn derive_aead_key(shared_secret: &[u8]) -> Result<aead::LessSafeKey, BlindedHopError> {
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
    use crate::noise_secp256k1;
    use sha2::{Digest, Sha512};

    const SAMPLE_COUNT: usize = 64;

    fn sample_secret_bytes(label: &[u8], i: u32) -> [u8; 32] {
        let mut attempt = 0u32;
        loop {
            let mut hasher = Sha512::new();
            hasher.update(label);
            hasher.update(i.to_le_bytes());
            hasher.update(attempt.to_le_bytes());
            let digest = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&digest[..32]);
            if SecpTransportKeypair::from_secret_bytes(&out).is_ok() {
                return out;
            }
            attempt = attempt.wrapping_add(1);
        }
    }

    fn sample_identity(i: u32) -> SecpTransportKeypair {
        SecpTransportKeypair::from_secret_bytes(&sample_secret_bytes(b"monad-secp-hop-key", i))
            .unwrap()
    }

    fn assert_descriptor_matches_hidden_hop(
        descriptor: &BlindedHopDescriptor,
        intro_identity: &SecpTransportKeypair,
        hidden_identity: &SecpTransportKeypair,
        expected_next_hop_addr: &str,
    ) {
        let plaintext = decrypt_blinded_hop_for_intro(intro_identity, &descriptor.message).unwrap();
        assert_eq!(plaintext.next_hop_addr, expected_next_hop_addr);

        let recovered_hidden =
            untweak_pubkey(descriptor.tweaked_pubkey, &plaintext.next_hop_tweak).unwrap();
        assert_eq!(recovered_hidden, hidden_identity.pubkey());

        let tweaked =
            derive_tweaked_hop_public(hidden_identity.pubkey(), &plaintext.next_hop_tweak).unwrap();
        assert_eq!(descriptor.tweaked_pubkey, tweaked.tweaked_pubkey);
    }

    #[test]
    fn test_tweak_pubkey_differs_from_original() {
        let identity = sample_identity(0);
        let tweak = derive_even_tweaked_secret_key(&identity).unwrap().0;
        let tweaked = tweak_pubkey(identity.pubkey(), &tweak).unwrap();

        assert_ne!(tweaked, identity.pubkey());
    }

    #[test]
    fn test_tweak_secret_matches_tweaked_pubkey_over_many_samples() {
        for i in 0..SAMPLE_COUNT as u32 {
            let identity = sample_identity(i);
            let (tweak, tweaked_secret, tweaked_pubkey) =
                derive_even_tweaked_secret_key(&identity).unwrap();

            assert_eq!(
                pubkey_from_secret_bytes_for_test(&tweaked_secret).unwrap(),
                tweaked_pubkey,
                "sample {i}"
            );
            assert_eq!(
                tweak_pubkey(identity.pubkey(), &tweak).unwrap(),
                tweaked_pubkey,
                "sample {i}"
            );
        }
    }

    #[test]
    fn test_tweak_and_untweak_roundtrip_over_many_samples() {
        for i in 0..SAMPLE_COUNT as u32 {
            let identity = sample_identity(i);
            let tweak = derive_even_tweaked_secret_key(&identity).unwrap().0;
            let original = identity.pubkey();
            let tweaked = tweak_pubkey(original, &tweak).unwrap();
            let untweaked = untweak_pubkey(tweaked, &tweak).unwrap();

            assert_eq!(untweaked, original, "sample {i}");
        }
    }

    #[test]
    fn test_blinded_hop_encrypt_decrypt_roundtrip() {
        let recipient = sample_identity(0);
        let tweak = HopTweak::generate().unwrap();
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: "10.1.2.3:9050".to_string(),
            next_hop_tweak: tweak,
        };

        let message =
            encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
                .unwrap();
        let decrypted = decrypt_blinded_hop_for_intro(&recipient, &message).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_blinded_hop_plaintext_binary_roundtrip() {
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: "example.com:9050".to_string(),
            next_hop_tweak: HopTweak::from_bytes(sample_secret_bytes(b"monad-plaintext-tweak", 0)),
        };

        let encoded = encode_blinded_hop_plaintext(&plaintext).unwrap();
        assert_eq!(&encoded[..32], plaintext.next_hop_tweak.as_bytes());
        assert_eq!(&encoded[32..], plaintext.next_hop_addr.as_bytes());
        assert_eq!(decode_blinded_hop_plaintext(&encoded).unwrap(), plaintext);
    }

    #[test]
    fn test_blinded_hop_plaintext_rejects_empty_address() {
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: String::new(),
            next_hop_tweak: HopTweak::from_bytes(sample_secret_bytes(b"monad-plaintext-tweak", 1)),
        };

        assert!(matches!(
            encode_blinded_hop_plaintext(&plaintext),
            Err(BlindedHopError::InvalidPayload(
                "next hop address must not be empty"
            ))
        ));

        let encoded = vec![0u8; 32];
        assert!(matches!(
            decode_blinded_hop_plaintext(&encoded),
            Err(BlindedHopError::InvalidPayload(
                "blinded hop payload too short"
            ))
        ));
    }

    #[test]
    fn test_blinded_hop_plaintext_rejects_too_short_payload() {
        let encoded = vec![0u8; 31];
        assert!(matches!(
            decode_blinded_hop_plaintext(&encoded),
            Err(BlindedHopError::InvalidPayload(
                "blinded hop payload too short"
            ))
        ));
    }

    #[test]
    fn test_blinded_hop_plaintext_rejects_interior_null() {
        let mut encoded = vec![0u8; 32];
        encoded.extend_from_slice(b"example");
        encoded.push(0);
        encoded.extend_from_slice(b"com:9050");
        assert!(matches!(
            decode_blinded_hop_plaintext(&encoded),
            Err(BlindedHopError::InvalidPayload(
                "blinded hop address contains interior null"
            ))
        ));
    }

    #[test]
    fn test_blinded_hop_plaintext_rejects_invalid_utf8() {
        let mut encoded = vec![0u8; 32];
        encoded.extend_from_slice(&[0xff, 0xfe]);
        assert!(matches!(
            decode_blinded_hop_plaintext(&encoded),
            Err(BlindedHopError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn test_blinded_hop_wrong_recipient_fails() {
        let recipient_a = sample_identity(0);
        let recipient_b = sample_identity(1);
        let tweak = HopTweak::generate().unwrap();
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: "10.1.2.3:9050".to_string(),
            next_hop_tweak: tweak,
        };

        let message =
            encrypt_blinded_hop_for_intro(recipient_a.pubkey().to_compressed_bytes(), &plaintext)
                .unwrap();
        let result = decrypt_blinded_hop_for_intro(&recipient_b, &message);
        assert!(matches!(
            result,
            Err(BlindedHopError::Decrypt)
                | Err(BlindedHopError::InvalidPayload(_))
                | Err(BlindedHopError::InvalidUtf8(_))
        ));
    }

    #[test]
    fn test_blinded_hop_uses_fresh_ephemeral_key() {
        let recipient = sample_identity(0);
        let tweak = HopTweak::generate().unwrap();
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: "10.1.2.3:9050".to_string(),
            next_hop_tweak: tweak,
        };

        let msg1 =
            encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
                .unwrap();
        let msg2 =
            encrypt_blinded_hop_for_intro(recipient.pubkey().to_compressed_bytes(), &plaintext)
                .unwrap();
        assert_ne!(msg1.ephemeral_pubkey, msg2.ephemeral_pubkey);
        assert_ne!(msg1.ciphertext, msg2.ciphertext);
    }

    #[test]
    fn test_build_blinded_hop_descriptor_roundtrip_and_recovery() {
        let intro_identity = sample_identity(0);
        let hidden_identity = sample_identity(1);
        let descriptor = build_blinded_hop_descriptor(
            intro_identity.pubkey().to_compressed_bytes(),
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
    fn test_build_path_rejects_empty_input() {
        assert!(matches!(
            build_path(&[]),
            Err(BlindedHopError::InvalidPath(
                "path requires at least one real hop"
            ))
        ));
    }

    #[test]
    fn test_build_path_rejects_blinded_first_hop() {
        let hop_a = sample_identity(0);
        let hop_b = sample_identity(1);
        assert!(matches!(
            build_path(&[
                PathHop {
                    addr: "127.0.0.1:9251",
                    identity: &hop_a,
                    mode: PathHopMode::Blinded
                },
                PathHop {
                    addr: "127.0.0.1:9252",
                    identity: &hop_b,
                    mode: PathHopMode::Cleartext
                },
            ]),
            Err(BlindedHopError::InvalidPath(
                "first path hop must be cleartext"
            ))
        ));
    }

    #[test]
    fn test_build_path_supports_mixed_cleartext_and_blinded_hops() {
        let hop_a = sample_identity(0);
        let hop_b = sample_identity(1);
        let hop_c = sample_identity(2);
        let hop_d = sample_identity(3);
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
        let PathNode::Blinded(descriptor_b) = &path.hops[1] else {
            panic!("expected blinded hop")
        };
        let PathNode::Cleartext(clear_c) = &path.hops[2] else {
            panic!("expected cleartext hop")
        };
        let PathNode::Blinded(descriptor_d) = &path.hops[3] else {
            panic!("expected blinded hop")
        };

        assert_descriptor_matches_hidden_hop(descriptor_b, &hop_a, &hop_b, "127.0.0.1:9262");
        assert_eq!(clear_c.addr, "127.0.0.1:9263");
        assert_eq!(clear_c.pubkey, hop_c.pubkey());
        assert_descriptor_matches_hidden_hop(descriptor_d, &hop_c, &hop_d, "127.0.0.1:9264");
    }

    #[tokio::test]
    async fn test_tweaked_identity_serves_secp_noise_handshake() {
        let identity = sample_identity(10);
        let tweaked = derive_tweaked_hop_identity(&identity).unwrap();
        let responder = tweaked.responder_secret_key;
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let tweaked_pubkey = tweaked.tweaked_pubkey;

        let initiator_task = tokio::spawn(async move {
            noise_secp256k1::handshake_initiator_with_pubkey(
                &mut a,
                tweaked_pubkey.to_compressed_bytes(),
            )
            .await
            .expect("initiator handshake should succeed")
        });
        let responder_task = tokio::spawn(async move {
            noise_secp256k1::handshake_responder_with_secret_key_bytes(&mut b, responder)
                .await
                .expect("responder handshake should succeed")
        });

        let (_, _, initiator_session_id) = initiator_task.await.unwrap();
        let (_, _, responder_session_id) = responder_task.await.unwrap();
        assert_eq!(initiator_session_id, responder_session_id);
    }
}
