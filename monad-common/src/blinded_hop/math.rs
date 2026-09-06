use super::types::{BlindedHopError, HopTweak};
use crate::secp_identity::Secp256k1Pubkey;
use crate::secp_identity::SecpTransportKeypair;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
#[cfg(test)]
use k256::SecretKey;
use k256::{ProjectivePoint, PublicKey, Scalar};

pub(super) fn public_key_from_bytes(pubkey: &[u8; 33]) -> Result<PublicKey, BlindedHopError> {
    PublicKey::from_sec1_bytes(pubkey).map_err(|_| BlindedHopError::InvalidPublicKey)
}

pub(super) fn public_key_from_point(point: ProjectivePoint) -> Result<PublicKey, BlindedHopError> {
    PublicKey::from_affine(point.to_affine()).map_err(|_| BlindedHopError::InvalidTweak)
}

pub(super) fn compressed_bytes(public_key: &PublicKey) -> [u8; 33] {
    let encoded = public_key.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

fn is_even_point(public_key: &PublicKey) -> bool {
    compressed_bytes(public_key)[0] == 0x02
}

impl HopTweak {
    pub(super) fn scalar(&self) -> Result<Scalar, BlindedHopError> {
        nonzero_scalar_from_bytes(self.raw_bytes())
    }
}

fn nonzero_scalar_from_bytes(bytes: [u8; 32]) -> Result<Scalar, BlindedHopError> {
    let scalar = Option::<Scalar>::from(Scalar::from_repr(bytes.into()))
        .ok_or(BlindedHopError::InvalidTweak)?;
    if bool::from(scalar.is_zero()) {
        return Err(BlindedHopError::InvalidTweak);
    }
    Ok(scalar)
}

pub(super) fn tweak_pubkey_with_parity(
    pubkey: Secp256k1Pubkey,
    tweak: &HopTweak,
) -> Result<(Secp256k1Pubkey, bool), BlindedHopError> {
    let public = pubkey
        .to_public_key()
        .map_err(|_| BlindedHopError::InvalidPublicKey)?;
    let mut tweaked_point =
        ProjectivePoint::from(public) + ProjectivePoint::GENERATOR * tweak.scalar()?;
    let tweaked_public = public_key_from_point(tweaked_point)?;
    let l_prime_y_is_odd = !is_even_point(&tweaked_public);
    if l_prime_y_is_odd {
        tweaked_point = -tweaked_point;
    }
    let tweaked_public = public_key_from_point(tweaked_point)?;
    let tweaked_compressed = compressed_bytes(&tweaked_public);
    Ok((
        Secp256k1Pubkey::from_compressed_bytes(tweaked_compressed)
            .map_err(|_| BlindedHopError::InvalidPublicKey)?,
        l_prime_y_is_odd,
    ))
}

pub(super) fn untweak_pubkey(
    tweaked_pubkey: Secp256k1Pubkey,
    tweak: &HopTweak,
    l_prime_y_is_odd: bool,
) -> Result<Secp256k1Pubkey, BlindedHopError> {
    let public = tweaked_pubkey
        .to_public_key()
        .map_err(|_| BlindedHopError::InvalidPublicKey)?;
    let l_prime = if l_prime_y_is_odd {
        -ProjectivePoint::from(public)
    } else {
        ProjectivePoint::from(public)
    };
    let original_point = l_prime - ProjectivePoint::GENERATOR * tweak.scalar()?;
    let original_public = public_key_from_point(original_point)?;
    let original_compressed = compressed_bytes(&original_public);
    Secp256k1Pubkey::from_compressed_bytes(original_compressed)
        .map_err(|_| BlindedHopError::InvalidPublicKey)
}

pub(super) fn derive_tweaked_responder_secret_key(
    identity: &SecpTransportKeypair,
    tweak_bytes: [u8; 32],
) -> Result<[u8; 32], BlindedHopError> {
    let base_scalar = nonzero_scalar_from_bytes(identity.normalized_secret_bytes())?;
    let tweak = HopTweak::from_bytes(tweak_bytes);
    let tweaked_scalar = base_scalar + tweak.scalar()?;
    let tweaked_secret: [u8; 32] = tweaked_scalar.to_bytes().into();
    SecpTransportKeypair::from_secret_bytes(&tweaked_secret)
        .map(|keypair| keypair.normalized_secret_bytes())
        .map_err(|_| BlindedHopError::InvalidTweak)
}

#[cfg(test)]
pub(super) fn pubkey_from_secret_bytes(
    secret_bytes: &[u8; 32],
) -> Result<Secp256k1Pubkey, BlindedHopError> {
    let secret_key =
        SecretKey::from_slice(secret_bytes).map_err(|_| BlindedHopError::InvalidTweak)?;
    let public_key = secret_key.public_key();
    let compressed = compressed_bytes(&public_key);
    Secp256k1Pubkey::from_compressed_bytes(compressed)
        .map_err(|_| BlindedHopError::InvalidPublicKey)
}
