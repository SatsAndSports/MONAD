use bech32::{Bech32, Hrp};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use k256::PublicKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

const NPUB_HRP: &str = "npub";

#[derive(Debug, thiserror::Error)]
pub enum SecpIdentityError {
    #[error("bech32 decode error: {0}")]
    Bech32Decode(bech32::DecodeError),
    #[error("bech32 encode error: {0}")]
    Bech32Encode(bech32::EncodeError),
    #[error("invalid npub human-readable prefix: expected 'npub', got '{0}'")]
    InvalidHrp(String),
    #[error("invalid x-only public key bytes")]
    InvalidVerifyingKey,
    #[error("invalid secp256k1 secret key bytes")]
    InvalidSigningKey,
    #[error("invalid schnorr signature bytes")]
    InvalidSignature,
}

#[derive(Clone)]
pub struct TransportKeypair {
    signing_key: SigningKey,
}

impl TransportKeypair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::random(&mut OsRng),
        }
    }

    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, SecpIdentityError> {
        let signing_key =
            SigningKey::from_bytes(bytes).map_err(|_| SecpIdentityError::InvalidSigningKey)?;
        Ok(Self { signing_key })
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    pub fn npub(&self) -> String {
        npub_from_verifying_key(&self.verifying_key()).expect("npub encoding should succeed")
    }

    pub fn compressed_public_key_bytes(&self) -> [u8; 33] {
        compressed_public_key_bytes(&self.verifying_key())
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.signing_key
            .sign_raw(digest, &[0u8; 32])
            .expect("valid digest")
            .to_bytes()
    }
}

pub fn npub_from_verifying_key(verifying_key: &VerifyingKey) -> Result<String, SecpIdentityError> {
    let hrp = Hrp::parse(NPUB_HRP).expect("hardcoded npub HRP is valid");
    bech32::encode::<Bech32>(hrp, &verifying_key.to_bytes())
        .map_err(SecpIdentityError::Bech32Encode)
}

pub fn verifying_key_from_npub(npub: &str) -> Result<VerifyingKey, SecpIdentityError> {
    let (hrp, data) = bech32::decode(npub).map_err(SecpIdentityError::Bech32Decode)?;
    if hrp != Hrp::parse(NPUB_HRP).expect("hardcoded npub HRP is valid") {
        return Err(SecpIdentityError::InvalidHrp(hrp.to_string()));
    }
    VerifyingKey::from_bytes(&data).map_err(|_| SecpIdentityError::InvalidVerifyingKey)
}

pub fn compressed_public_key_bytes(verifying_key: &VerifyingKey) -> [u8; 33] {
    let public_key = PublicKey::from(*verifying_key);
    let encoded = public_key.to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(encoded.as_bytes());
    out
}

pub fn compressed_public_key_bytes_from_npub(npub: &str) -> Result<[u8; 33], SecpIdentityError> {
    let verifying_key = verifying_key_from_npub(npub)?;
    Ok(compressed_public_key_bytes(&verifying_key))
}

pub fn transport_auth_digest(label: &[u8], challenge: &[u8; 32], exporter: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(challenge);
    hasher.update(exporter);
    hasher.finalize().into()
}

pub fn verify_digest(
    verifying_key: &VerifyingKey,
    digest: &[u8; 32],
    signature_bytes: &[u8; 64],
) -> Result<(), SecpIdentityError> {
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| SecpIdentityError::InvalidSignature)?;
    verifying_key
        .verify_raw(digest, &signature)
        .map_err(|_| SecpIdentityError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_npub_roundtrip() {
        let keypair = TransportKeypair::generate();
        let npub = keypair.npub();
        let recovered = verifying_key_from_npub(&npub).unwrap();

        assert_eq!(recovered, keypair.verifying_key());
    }

    #[test]
    fn test_compressed_public_key_is_even_y_form() {
        let keypair = TransportKeypair::generate();
        let compressed = keypair.compressed_public_key_bytes();

        assert_eq!(compressed[0], 0x02);
    }

    #[test]
    fn test_digest_sign_and_verify() {
        let keypair = TransportKeypair::generate();
        let challenge = [7u8; 32];
        let exporter = [9u8; 32];
        let digest = transport_auth_digest(b"monad-test-v1", &challenge, &exporter);
        let signature = keypair.sign_digest(&digest);

        verify_digest(&keypair.verifying_key(), &digest, &signature).unwrap();

        let wrong_digest = transport_auth_digest(b"monad-test-v1", &[8u8; 32], &exporter);
        assert!(verify_digest(&keypair.verifying_key(), &wrong_digest, &signature).is_err());
    }
}
