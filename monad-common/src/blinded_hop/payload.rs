use super::math::{compressed_bytes, public_key_from_bytes};
use super::types::{BlindedHopError, BlindedHopMessage, BlindedHopPlaintext, HopTweak};
use crate::secp_identity::SecpTransportKeypair;
use k256::{ecdh, SecretKey};
use rand_core::OsRng;
use ring::aead;
use ring::hkdf;

const BLINDED_HOP_HKDF_LABEL: &[u8] = b"monad-blinded-hop-v2-secp256k1";
const BLINDED_HOP_AAD: &[u8] = b"monad-blinded-hop-v2-secp256k1";
const BLINDED_HOP_ZERO_NONCE: [u8; 12] = [0u8; 12];

struct AeadKeyLen;

impl hkdf::KeyType for AeadKeyLen {
    fn len(&self) -> usize {
        32
    }
}

pub(super) fn encode_blinded_hop_plaintext(
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

#[allow(dead_code)]
pub(super) fn decode_blinded_hop_plaintext(
    bytes: &[u8],
) -> Result<BlindedHopPlaintext, BlindedHopError> {
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

pub(crate) fn encrypt_blinded_hop_for_intro(
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

#[allow(dead_code)]
pub(crate) fn decrypt_blinded_hop_for_intro(
    recipient: &SecpTransportKeypair,
    message: &BlindedHopMessage,
) -> Result<BlindedHopPlaintext, BlindedHopError> {
    let secret_key = SecretKey::from_slice(&recipient.normalized_secret_bytes())
        .map_err(|_| BlindedHopError::InvalidTweak)?;
    let sender_public =
        public_key_from_bytes(&message.ephemeral_pubkey).map_err(|_| BlindedHopError::Decrypt)?;
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
