use super::types::{BlindedHopError, HopTweak, TweakedHopIdentity, TweakedHopPublic};
use crate::secp_identity::Secp256k1Pubkey;
use crate::secp_identity::SecpTransportKeypair;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, Scalar, SecretKey};

pub(super) fn public_key_from_bytes(pubkey: &[u8; 33]) -> Result<PublicKey, BlindedHopError> {
    PublicKey::from_sec1_bytes(pubkey).map_err(|_| BlindedHopError::InvalidPublicKey)
}

#[cfg_attr(not(test), allow(dead_code))]
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

// Sample one tweak scalar, then if P + tG lands on an odd-Y point, negate the
// tweaked secret and adjust the transmitted tweak so the published tweaked hop
// identity still uses the even-Y representative of the same x-only pubkey.
pub(super) fn derive_even_tweaked_secret_key(
    identity: &SecpTransportKeypair,
) -> Result<(HopTweak, [u8; 32], Secp256k1Pubkey), BlindedHopError> {
    let base_scalar = nonzero_scalar_from_bytes(identity.normalized_secret_bytes())?;

    loop {
        let candidate_tweak = HopTweak::generate()?;
        let candidate_scalar = base_scalar + candidate_tweak.scalar()?;
        let candidate_secret_key = match SecretKey::from_slice(&candidate_scalar.to_bytes()) {
            Ok(secret_key) => secret_key,
            Err(_) => continue,
        };
        let candidate_public = candidate_secret_key.public_key();

        let (tweaked_scalar, tweak_bytes) = if is_even_point(&candidate_public) {
            (candidate_scalar, candidate_tweak.raw_bytes())
        } else {
            let adjusted_scalar = -candidate_scalar;
            let adjusted_tweak_scalar = adjusted_scalar - base_scalar;
            let adjusted_tweak_bytes: [u8; 32] = adjusted_tweak_scalar.to_bytes().into();
            if nonzero_scalar_from_bytes(adjusted_tweak_bytes).is_err() {
                continue;
            }
            (adjusted_scalar, adjusted_tweak_bytes)
        };

        let responder_secret_key: [u8; 32] = tweaked_scalar.to_bytes().into();
        let secret_key = match SecretKey::from_slice(&responder_secret_key) {
            Ok(secret_key) => secret_key,
            Err(_) => continue,
        };
        let tweaked_public = secret_key.public_key();
        let tweaked_pubkey =
            Secp256k1Pubkey::from_compressed_bytes(compressed_bytes(&tweaked_public))
                .map_err(|_| BlindedHopError::InvalidPublicKey)?;
        return Ok((
            HopTweak::from_bytes(tweak_bytes),
            responder_secret_key,
            tweaked_pubkey,
        ));
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn tweak_pubkey(
    pubkey: Secp256k1Pubkey,
    tweak: &HopTweak,
) -> Result<Secp256k1Pubkey, BlindedHopError> {
    let public = pubkey
        .to_public_key()
        .map_err(|_| BlindedHopError::InvalidPublicKey)?;
    let mut tweaked_point =
        ProjectivePoint::from(public) + ProjectivePoint::GENERATOR * tweak.scalar()?;
    let tweaked_public = public_key_from_point(tweaked_point)?;
    if !is_even_point(&tweaked_public) {
        tweaked_point = -tweaked_point;
    }
    let tweaked_public = public_key_from_point(tweaked_point)?;
    let tweaked_compressed = compressed_bytes(&tweaked_public);
    Secp256k1Pubkey::from_compressed_bytes(tweaked_compressed)
        .map_err(|_| BlindedHopError::InvalidPublicKey)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn untweak_pubkey(
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

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn derive_tweaked_hop_public(
    real_pubkey: Secp256k1Pubkey,
    tweak: &HopTweak,
) -> Result<TweakedHopPublic, BlindedHopError> {
    Ok(TweakedHopPublic {
        tweaked_pubkey: tweak_pubkey(real_pubkey, tweak)?,
    })
}

pub(super) fn derive_tweaked_hop_identity(
    identity: &SecpTransportKeypair,
) -> Result<TweakedHopIdentity, BlindedHopError> {
    let (tweak, responder_secret_key, tweaked_pubkey) = derive_even_tweaked_secret_key(identity)?;
    Ok(TweakedHopIdentity {
        tweak,
        tweaked_pubkey,
        responder_secret_key,
    })
}

pub(super) fn derive_tweaked_responder_secret_key(
    identity: &SecpTransportKeypair,
    tweak_bytes: [u8; 32],
) -> Result<[u8; 32], BlindedHopError> {
    let base_scalar = nonzero_scalar_from_bytes(identity.normalized_secret_bytes())?;
    let tweak = HopTweak::from_bytes(tweak_bytes);
    let tweaked_scalar = base_scalar + tweak.scalar()?;
    Ok(tweaked_scalar.to_bytes().into())
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
