use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use k256::PublicKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum SecpIdentityError {
    #[error("invalid secp256k1 public key hex: {0}")]
    Hex(hex::FromHexError),
    #[error("invalid secp256k1 x-only public key bytes")]
    InvalidPublicKey,
    #[error("invalid secp256k1 signed public key bytes")]
    InvalidSignedPublicKey,
    #[error("invalid secp256k1 secret key bytes")]
    InvalidSecretKey,
    #[error("invalid schnorr signature bytes")]
    InvalidSignature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Secp256k1Pubkey([u8; 32]);

impl Secp256k1Pubkey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SecpIdentityError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| SecpIdentityError::InvalidPublicKey)?;
        Ok(Self(bytes))
    }

    pub fn from_hex(pubkey_hex: &str) -> Result<Self, SecpIdentityError> {
        let bytes = hex::decode(pubkey_hex).map_err(SecpIdentityError::Hex)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| SecpIdentityError::InvalidPublicKey)?;
        Self::from_bytes(arr)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_verifying_key(&self) -> Result<VerifyingKey, SecpIdentityError> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| SecpIdentityError::InvalidPublicKey)
    }

    pub fn to_public_key(&self) -> Result<PublicKey, SecpIdentityError> {
        Ok(PublicKey::from(self.to_verifying_key()?))
    }

    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        let public_key = self
            .to_public_key()
            .expect("valid x-only secp256k1 public key");
        let encoded = public_key.to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    pub fn from_compressed_bytes(bytes: [u8; 33]) -> Result<Self, SecpIdentityError> {
        let signed = SignedSecp256k1Pubkey::from_compressed_bytes(bytes)?;
        if signed.is_odd() {
            return Err(SecpIdentityError::InvalidPublicKey);
        }
        Self::from_bytes(signed.x_only_bytes())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignedSecp256k1Pubkey {
    x_only: [u8; 32],
    odd: bool,
}

impl SignedSecp256k1Pubkey {
    pub fn from_compressed_bytes(bytes: [u8; 33]) -> Result<Self, SecpIdentityError> {
        let prefix = bytes[0];
        if prefix != 0x02 && prefix != 0x03 {
            return Err(SecpIdentityError::InvalidSignedPublicKey);
        }
        PublicKey::from_sec1_bytes(&bytes)
            .map_err(|_| SecpIdentityError::InvalidSignedPublicKey)?;
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&bytes[1..]);
        Ok(Self {
            x_only,
            odd: prefix == 0x03,
        })
    }

    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let encoded = public_key.to_encoded_point(true);
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(encoded.as_bytes());
        Self::from_compressed_bytes(bytes).expect("valid compressed secp256k1 public key")
    }

    pub fn x_only_bytes(&self) -> [u8; 32] {
        self.x_only
    }

    pub fn is_odd(&self) -> bool {
        self.odd
    }

    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = if self.odd { 0x03 } else { 0x02 };
        out[1..].copy_from_slice(&self.x_only);
        out
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_compressed_bytes())
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
        Self::normalize_signing_key(SigningKey::random(&mut OsRng))
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, SecpIdentityError> {
        let signing_key =
            SigningKey::from_bytes(bytes).map_err(|_| SecpIdentityError::InvalidSecretKey)?;
        Ok(Self::normalize_signing_key(signing_key))
    }

    pub fn normalized_secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    pub fn pubkey(&self) -> Secp256k1Pubkey {
        Secp256k1Pubkey::from_bytes(self.signing_key.verifying_key().to_bytes().into())
            .expect("normalized signing key has valid x-only pubkey")
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.signing_key
            .sign_raw(digest, &[0u8; 32])
            .expect("valid digest")
            .to_bytes()
    }

    fn normalize_signing_key(signing_key: SigningKey) -> Self {
        let public_key = PublicKey::from(*signing_key.verifying_key());
        let encoded = public_key.to_encoded_point(true);
        if encoded.as_bytes()[0] == 0x02 {
            return Self { signing_key };
        }

        let normalized_bytes = (-*signing_key.as_nonzero_scalar().as_ref()).to_bytes();
        let signing_key =
            SigningKey::from_bytes(&normalized_bytes).expect("negated secp256k1 secret key");
        Self { signing_key }
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
    let verifying_key = pubkey.to_verifying_key()?;
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

    #[test]
    fn test_generated_pubkey_is_even_y_form() {
        for _ in 0..32 {
            let keypair = SecpTransportKeypair::generate();
            assert_eq!(keypair.pubkey().to_compressed_bytes()[0], 0x02);
        }
    }

    #[test]
    fn test_from_secret_bytes_normalizes_negated_scalar() {
        let keypair = SecpTransportKeypair::generate();
        let negated_bytes: [u8; 32] =
            (-*SigningKey::from_bytes(&keypair.normalized_secret_bytes())
                .unwrap()
                .as_nonzero_scalar()
                .as_ref())
            .to_bytes()
            .into();

        let normalized =
            SecpTransportKeypair::from_secret_bytes(&keypair.normalized_secret_bytes()).unwrap();
        let from_negated = SecpTransportKeypair::from_secret_bytes(&negated_bytes).unwrap();

        assert_eq!(
            normalized.normalized_secret_bytes(),
            from_negated.normalized_secret_bytes()
        );
        assert_eq!(normalized.pubkey(), from_negated.pubkey());
        assert_eq!(normalized.pubkey().to_compressed_bytes()[0], 0x02);
    }

    #[test]
    fn test_signed_pubkey_roundtrip_preserves_parity() {
        let keypair = SecpTransportKeypair::generate();
        let even =
            SignedSecp256k1Pubkey::from_compressed_bytes(keypair.pubkey().to_compressed_bytes())
                .unwrap();
        let negated_bytes: [u8; 32] =
            (-*SigningKey::from_bytes(&keypair.normalized_secret_bytes())
                .unwrap()
                .as_nonzero_scalar()
                .as_ref())
            .to_bytes()
            .into();
        let odd = SignedSecp256k1Pubkey::from_compressed_bytes(
            SecpTransportKeypair::from_secret_bytes(&negated_bytes)
                .unwrap()
                .pubkey()
                .to_compressed_bytes(),
        )
        .unwrap();

        assert!(!even.is_odd());
        assert_eq!(even.to_compressed_bytes()[0], 0x02);
        assert_eq!(odd.to_compressed_bytes()[0], 0x02);
    }
}
