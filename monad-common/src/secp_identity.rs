use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use k256::PublicKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum SecpIdentityError {
    #[error("invalid secp256k1 compressed public key hex: {0}")]
    Hex(hex::FromHexError),
    #[error("invalid secp256k1 compressed public key bytes")]
    InvalidPublicKey,
    #[error("invalid secp256k1 secret key bytes")]
    InvalidSecretKey,
    #[error("invalid schnorr signature bytes")]
    InvalidSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Secp256k1Pubkey([u8; 33]);

impl Secp256k1Pubkey {
    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, SecpIdentityError> {
        PublicKey::from_sec1_bytes(&bytes).map_err(|_| SecpIdentityError::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn from_hex(pubkey_hex: &str) -> Result<Self, SecpIdentityError> {
        let bytes = hex::decode(pubkey_hex).map_err(SecpIdentityError::Hex)?;
        let arr: [u8; 33] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecpIdentityError::InvalidPublicKey)?;
        Self::from_bytes(arr)
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_public_key(&self) -> Result<PublicKey, SecpIdentityError> {
        PublicKey::from_sec1_bytes(&self.0).map_err(|_| SecpIdentityError::InvalidPublicKey)
    }
}

impl fmt::Display for Secp256k1Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[derive(Clone)]
pub struct SecpTransportKeypair {
    signing_key: SigningKey,
}

impl SecpTransportKeypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::random(&mut OsRng),
        }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, SecpIdentityError> {
        let signing_key =
            SigningKey::from_bytes(bytes).map_err(|_| SecpIdentityError::InvalidSecretKey)?;
        Ok(Self { signing_key })
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    pub fn pubkey(&self) -> Secp256k1Pubkey {
        let public_key = PublicKey::from(*self.signing_key.verifying_key());
        let encoded = public_key.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(encoded.as_bytes());
        Secp256k1Pubkey(out)
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.signing_key
            .sign_raw(digest, &[0u8; 32])
            .expect("valid digest")
            .to_bytes()
    }
}

pub fn transport_auth_digest(label: &[u8], challenge: &[u8; 32], exporter: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(challenge);
    hasher.update(exporter);
    hasher.finalize().into()
}

pub fn verify_transport_auth_digest(
    pubkey: &Secp256k1Pubkey,
    digest: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> Result<(), SecpIdentityError> {
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| SecpIdentityError::InvalidSignature)?;
    let verifying_key = VerifyingKey::try_from(pubkey.to_public_key()?)
        .map_err(|_| SecpIdentityError::InvalidPublicKey)?;
    verifying_key
        .verify_raw(digest, &signature)
        .map_err(|_| SecpIdentityError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pubkey_roundtrip() {
        let keypair = SecpTransportKeypair::generate();
        let hex = keypair.pubkey().to_hex();
        let decoded = Secp256k1Pubkey::from_hex(&hex).unwrap();

        assert_eq!(decoded, keypair.pubkey());
    }

    #[test]
    fn test_transport_auth_sign_and_verify() {
        let keypair = SecpTransportKeypair::generate();
        let challenge = [1u8; 32];
        let exporter = [2u8; 32];
        let digest = transport_auth_digest(b"monad-test-v1", &challenge, &exporter);
        let signature = keypair.sign_digest(&digest);

        verify_transport_auth_digest(&keypair.pubkey(), &digest, &signature).unwrap();
        let wrong_digest = transport_auth_digest(b"monad-test-v1", &[3u8; 32], &exporter);
        assert!(
            verify_transport_auth_digest(&keypair.pubkey(), &wrong_digest, &signature).is_err()
        );
    }
}
