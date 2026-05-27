//! Low-level blinded-hop helpers.
//!
//! This module targets MONAD's secp256k1 transport identity model. Blinding is
//! applied directly in secp256k1 scalar/group space, so there is no longer any
//! need for the old Ed25519/X25519 compatibility bridge or its rejection
//! sampling.

use crate::secp_identity::{Secp256k1Pubkey, SecpTransportKeypair, SignedSecp256k1Pubkey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::SigningKey;
use k256::{ecdh, ProjectivePoint, PublicKey, Scalar, SecretKey};
use rand_core::OsRng;
use ring::aead;
use ring::hkdf;
use serde::{Deserialize, Serialize};

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

/// A tweak scalar for one blinded hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindedHopPlaintext {
    pub next_hop_addr: String,
    pub next_hop_pubkey_hex: String,
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
    pub tweaked_pubkey: SignedSecp256k1Pubkey,
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
    pub tweaked_pubkey: SignedSecp256k1Pubkey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TweakedHopIdentity {
    pub tweak: HopTweak,
    pub tweaked_pubkey: SignedSecp256k1Pubkey,
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

fn signed_public_key_from_identity(identity: &SecpTransportKeypair) -> SignedSecp256k1Pubkey {
    SignedSecp256k1Pubkey::from_compressed_bytes(identity.pubkey().to_compressed_bytes())
        .expect("normalized identity yields valid even signed pubkey")
}

fn signed_public_key(pubkey: Secp256k1Pubkey) -> SignedSecp256k1Pubkey {
    SignedSecp256k1Pubkey::from_compressed_bytes(pubkey.to_compressed_bytes())
        .expect("x-only identity yields valid even signed pubkey")
}

#[cfg(test)]
fn signed_public_key_from_secret_bytes(
    secret_bytes: &[u8; 32],
) -> Result<SignedSecp256k1Pubkey, BlindedHopError> {
    let signing_key =
        SigningKey::from_bytes(secret_bytes).map_err(|_| BlindedHopError::InvalidTweak)?;
    let public_key = PublicKey::from(*signing_key.verifying_key());
    Ok(SignedSecp256k1Pubkey::from_public_key(&public_key))
}

fn tweak_secret_key_with_tweak(
    identity: &SecpTransportKeypair,
    tweak: &HopTweak,
) -> Result<[u8; 32], BlindedHopError> {
    let base_key = SigningKey::from_bytes(&identity.normalized_secret_bytes())
        .map_err(|_| BlindedHopError::InvalidTweak)?;
    let tweaked_scalar = *base_key.as_nonzero_scalar().as_ref() + tweak.scalar()?;
    Ok(tweaked_scalar.to_bytes().into())
}

pub fn tweak_pubkey(
    pubkey: SignedSecp256k1Pubkey,
    tweak: &HopTweak,
) -> Result<SignedSecp256k1Pubkey, BlindedHopError> {
    let public = public_key_from_bytes(&pubkey.to_compressed_bytes())?;
    let tweaked_point =
        ProjectivePoint::from(public) + ProjectivePoint::GENERATOR * tweak.scalar()?;
    let tweaked_public = public_key_from_point(tweaked_point)?;
    Ok(SignedSecp256k1Pubkey::from_public_key(&tweaked_public))
}

pub fn untweak_pubkey(
    tweaked_pubkey: SignedSecp256k1Pubkey,
    tweak: &HopTweak,
) -> Result<SignedSecp256k1Pubkey, BlindedHopError> {
    let public = public_key_from_bytes(&tweaked_pubkey.to_compressed_bytes())?;
    let original_point =
        ProjectivePoint::from(public) - ProjectivePoint::GENERATOR * tweak.scalar()?;
    let original_public = public_key_from_point(original_point)?;
    Ok(SignedSecp256k1Pubkey::from_public_key(&original_public))
}

pub fn derive_tweaked_hop_public(
    real_pubkey: Secp256k1Pubkey,
    tweak: &HopTweak,
) -> Result<TweakedHopPublic, BlindedHopError> {
    Ok(TweakedHopPublic {
        tweaked_pubkey: tweak_pubkey(signed_public_key(real_pubkey), tweak)?,
    })
}

pub fn derive_tweaked_hop_identity(
    identity: &SecpTransportKeypair,
) -> Result<TweakedHopIdentity, BlindedHopError> {
    let tweak = HopTweak::generate()?;
    let responder_secret_key = tweak_secret_key_with_tweak(identity, &tweak)?;
    let tweaked_pubkey = tweak_pubkey(signed_public_key_from_identity(identity), &tweak)?;
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
            next_hop_pubkey_hex: hidden_hop_identity.pubkey().to_hex(),
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
                    signed_public_key_from_identity(predecessor.identity).to_compressed_bytes(),
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

    let mut in_out = serde_json::to_vec(plaintext).map_err(BlindedHopError::Serialize)?;
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
    serde_json::from_slice(plaintext).map_err(BlindedHopError::Deserialize)
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

    fn sample_tweak(i: u32) -> HopTweak {
        HopTweak::from_bytes(sample_secret_bytes(b"monad-secp-hop-tweak", i))
    }

    fn assert_descriptor_matches_hidden_hop(
        descriptor: &BlindedHopDescriptor,
        intro_identity: &SecpTransportKeypair,
        hidden_identity: &SecpTransportKeypair,
        expected_next_hop_addr: &str,
    ) {
        let plaintext = decrypt_blinded_hop_for_intro(intro_identity, &descriptor.message).unwrap();
        assert_eq!(plaintext.next_hop_addr, expected_next_hop_addr);
        assert_eq!(
            plaintext.next_hop_pubkey_hex,
            hidden_identity.pubkey().to_hex()
        );

        let tweaked =
            derive_tweaked_hop_public(hidden_identity.pubkey(), &plaintext.next_hop_tweak).unwrap();
        assert_eq!(descriptor.tweaked_pubkey, tweaked.tweaked_pubkey);
    }

    fn same_x_coordinate(a: SignedSecp256k1Pubkey, b: SignedSecp256k1Pubkey) -> bool {
        a.x_only_bytes() == b.x_only_bytes()
    }

    #[test]
    fn test_tweak_pubkey_differs_from_original() {
        let identity = sample_identity(0);
        let tweak = HopTweak::generate().unwrap();
        let tweaked = tweak_pubkey(signed_public_key_from_identity(&identity), &tweak).unwrap();

        assert_ne!(tweaked, signed_public_key_from_identity(&identity));
    }

    #[test]
    fn test_tweak_secret_matches_tweaked_pubkey_x_coordinate_over_many_samples() {
        for i in 0..SAMPLE_COUNT as u32 {
            let identity = sample_identity(i);
            let tweak = sample_tweak(i);
            let tweaked_secret = tweak_secret_key_with_tweak(&identity, &tweak).unwrap();
            let tweaked_pubkey =
                tweak_pubkey(signed_public_key_from_identity(&identity), &tweak).unwrap();

            assert!(
                same_x_coordinate(
                    signed_public_key_from_secret_bytes(&tweaked_secret).unwrap(),
                    tweaked_pubkey
                ),
                "sample {i}"
            );
        }
    }

    #[test]
    fn test_tweak_and_untweak_roundtrip_over_many_samples() {
        for i in 0..SAMPLE_COUNT as u32 {
            let identity = sample_identity(i);
            let tweak = sample_tweak(i);
            let original = signed_public_key_from_identity(&identity);
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
            next_hop_pubkey_hex: recipient.pubkey().to_hex(),
            next_hop_tweak: tweak,
        };

        let message = encrypt_blinded_hop_for_intro(
            signed_public_key_from_identity(&recipient).to_compressed_bytes(),
            &plaintext,
        )
        .unwrap();
        let decrypted = decrypt_blinded_hop_for_intro(&recipient, &message).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_blinded_hop_wrong_recipient_fails() {
        let recipient_a = sample_identity(0);
        let recipient_b = sample_identity(1);
        let tweak = HopTweak::generate().unwrap();
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: "10.1.2.3:9050".to_string(),
            next_hop_pubkey_hex: recipient_a.pubkey().to_hex(),
            next_hop_tweak: tweak,
        };

        let message = encrypt_blinded_hop_for_intro(
            signed_public_key_from_identity(&recipient_a).to_compressed_bytes(),
            &plaintext,
        )
        .unwrap();
        let result = decrypt_blinded_hop_for_intro(&recipient_b, &message);
        assert!(matches!(
            result,
            Err(BlindedHopError::Decrypt) | Err(BlindedHopError::Deserialize(_))
        ));
    }

    #[test]
    fn test_blinded_hop_uses_fresh_ephemeral_key() {
        let recipient = sample_identity(0);
        let tweak = HopTweak::generate().unwrap();
        let plaintext = BlindedHopPlaintext {
            next_hop_addr: "10.1.2.3:9050".to_string(),
            next_hop_pubkey_hex: recipient.pubkey().to_hex(),
            next_hop_tweak: tweak,
        };

        let msg1 = encrypt_blinded_hop_for_intro(
            signed_public_key_from_identity(&recipient).to_compressed_bytes(),
            &plaintext,
        )
        .unwrap();
        let msg2 = encrypt_blinded_hop_for_intro(
            signed_public_key_from_identity(&recipient).to_compressed_bytes(),
            &plaintext,
        )
        .unwrap();
        assert_ne!(msg1.ephemeral_pubkey, msg2.ephemeral_pubkey);
        assert_ne!(msg1.ciphertext, msg2.ciphertext);
    }

    #[test]
    fn test_build_blinded_hop_descriptor_roundtrip_and_recovery() {
        let intro_identity = sample_identity(0);
        let hidden_identity = sample_identity(1);
        let descriptor = build_blinded_hop_descriptor(
            signed_public_key_from_identity(&intro_identity).to_compressed_bytes(),
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
