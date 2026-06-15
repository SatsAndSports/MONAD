use crate::blinded_hop::{BlindedHopDescriptor, BlindedHopMessage};
use crate::secp_identity::Secp256k1Pubkey;
use http::HeaderMap;

pub const BLINDED_HOP_CONNECT_URI: &str = "http://monad/blinded_hop_v1";
pub const BLINDED_HOP_CONNECT_PATH: &str = "/blinded_hop_v1";
pub const BLINDED_TWEAKED_PUBKEY_HEADER: &str = "monad-blinded-tweaked-pubkey";
pub const BLINDED_EPHEMERAL_PUBKEY_HEADER: &str = "monad-blinded-ephemeral-pubkey";
pub const BLINDED_CIPHERTEXT_HEADER: &str = "monad-blinded-ciphertext";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindedConnectRequest {
    pub tweaked_pubkey: Secp256k1Pubkey,
    pub ephemeral_pubkey: [u8; 33],
    pub ciphertext: Vec<u8>,
}

impl BlindedConnectRequest {
    pub fn from_descriptor(descriptor: &BlindedHopDescriptor) -> Self {
        Self {
            tweaked_pubkey: descriptor.tweaked_pubkey,
            ephemeral_pubkey: descriptor.message.ephemeral_pubkey,
            ciphertext: descriptor.message.ciphertext.clone(),
        }
    }

    pub fn into_descriptor(self) -> BlindedHopDescriptor {
        BlindedHopDescriptor {
            tweaked_pubkey: self.tweaked_pubkey,
            message: BlindedHopMessage {
                ephemeral_pubkey: self.ephemeral_pubkey,
                ciphertext: self.ciphertext,
            },
        }
    }

    pub fn header_pairs(&self) -> [(&'static str, String); 3] {
        [
            (BLINDED_TWEAKED_PUBKEY_HEADER, self.tweaked_pubkey.to_hex()),
            (
                BLINDED_EPHEMERAL_PUBKEY_HEADER,
                hex::encode(self.ephemeral_pubkey),
            ),
            (BLINDED_CIPHERTEXT_HEADER, hex::encode(&self.ciphertext)),
        ]
    }

    pub fn from_headers(headers: &HeaderMap) -> Result<Self, BlindedConnectRequestError> {
        let tweaked_pubkey_hex = required_header(headers, BLINDED_TWEAKED_PUBKEY_HEADER)?;
        let tweaked_pubkey = Secp256k1Pubkey::from_hex(tweaked_pubkey_hex)
            .map_err(|_| BlindedConnectRequestError::InvalidTweakedPubkey)?;

        let ephemeral_pubkey = decode_fixed_hex::<33>(headers, BLINDED_EPHEMERAL_PUBKEY_HEADER)?;

        let ciphertext = decode_hex(headers, BLINDED_CIPHERTEXT_HEADER)?;
        if ciphertext.is_empty() {
            return Err(BlindedConnectRequestError::EmptyCiphertext);
        }

        Ok(Self {
            tweaked_pubkey,
            ephemeral_pubkey,
            ciphertext,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlindedConnectRequestError {
    #[error("missing required blinded CONNECT header: {0}")]
    MissingHeader(&'static str),
    #[error("invalid blinded CONNECT header value: {0}")]
    InvalidHeaderValue(&'static str),
    #[error("invalid hex in blinded CONNECT header: {0}")]
    InvalidHex(&'static str),
    #[error(
        "invalid byte length in blinded CONNECT header {header}: expected {expected}, got {actual}"
    )]
    InvalidLength {
        header: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid tweaked secp256k1 public key in blinded CONNECT headers")]
    InvalidTweakedPubkey,
    #[error("blinded CONNECT ciphertext must not be empty")]
    EmptyCiphertext,
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, BlindedConnectRequestError> {
    headers
        .get(name)
        .ok_or(BlindedConnectRequestError::MissingHeader(name))?
        .to_str()
        .map_err(|_| BlindedConnectRequestError::InvalidHeaderValue(name))
}

fn decode_hex(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Vec<u8>, BlindedConnectRequestError> {
    let value = required_header(headers, name)?;
    hex::decode(value).map_err(|_| BlindedConnectRequestError::InvalidHex(name))
}

fn decode_fixed_hex<const N: usize>(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<[u8; N], BlindedConnectRequestError> {
    let bytes = decode_hex(headers, name)?;
    let actual = bytes.len();
    bytes
        .try_into()
        .map_err(|_| BlindedConnectRequestError::InvalidLength {
            header: name,
            expected: N,
            actual,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secp_identity::SecpTransportKeypair;
    use http::HeaderValue;

    fn sample_request() -> BlindedConnectRequest {
        let tweaked_pubkey = SecpTransportKeypair::from_secret_bytes(&[7u8; 32])
            .unwrap()
            .pubkey();
        let ephemeral_pubkey = SecpTransportKeypair::from_secret_bytes(&[11u8; 32])
            .unwrap()
            .pubkey()
            .to_compressed_bytes();
        BlindedConnectRequest {
            tweaked_pubkey,
            ephemeral_pubkey,
            ciphertext: vec![1, 2, 3, 4, 5, 6],
        }
    }

    fn header_map(request: &BlindedConnectRequest) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in request.header_pairs() {
            headers.insert(name, HeaderValue::from_str(&value).unwrap());
        }
        headers
    }

    #[test]
    fn blinded_connect_request_roundtrips_through_headers() {
        let request = sample_request();
        let headers = header_map(&request);
        let parsed = BlindedConnectRequest::from_headers(&headers).unwrap();
        assert_eq!(parsed, request);
    }

    #[test]
    fn blinded_connect_request_missing_header_is_rejected() {
        let request = sample_request();
        let mut headers = header_map(&request);
        headers.remove(BLINDED_CIPHERTEXT_HEADER);

        let err = BlindedConnectRequest::from_headers(&headers).unwrap_err();
        assert!(matches!(
            err,
            BlindedConnectRequestError::MissingHeader(BLINDED_CIPHERTEXT_HEADER)
        ));
    }

    #[test]
    fn blinded_connect_request_invalid_hex_is_rejected() {
        let request = sample_request();
        let mut headers = header_map(&request);
        headers.insert(
            BLINDED_EPHEMERAL_PUBKEY_HEADER,
            HeaderValue::from_static("zz"),
        );

        let err = BlindedConnectRequest::from_headers(&headers).unwrap_err();
        assert!(matches!(
            err,
            BlindedConnectRequestError::InvalidHex(BLINDED_EPHEMERAL_PUBKEY_HEADER)
        ));
    }

    #[test]
    fn blinded_connect_request_invalid_ephemeral_length_is_rejected() {
        let request = sample_request();
        let mut headers = header_map(&request);
        headers.insert(
            BLINDED_EPHEMERAL_PUBKEY_HEADER,
            HeaderValue::from_static("0203"),
        );

        let err = BlindedConnectRequest::from_headers(&headers).unwrap_err();
        assert!(matches!(
            err,
            BlindedConnectRequestError::InvalidLength {
                header: BLINDED_EPHEMERAL_PUBKEY_HEADER,
                expected: 33,
                actual: 2,
            }
        ));
    }

    #[test]
    fn blinded_connect_request_empty_ciphertext_is_rejected() {
        let request = sample_request();
        let mut headers = header_map(&request);
        headers.insert(BLINDED_CIPHERTEXT_HEADER, HeaderValue::from_static(""));

        let err = BlindedConnectRequest::from_headers(&headers).unwrap_err();
        assert!(matches!(err, BlindedConnectRequestError::EmptyCiphertext));
    }

    #[test]
    fn blinded_connect_request_invalid_tweaked_pubkey_is_rejected() {
        let request = sample_request();
        let mut headers = header_map(&request);
        headers.insert(
            BLINDED_TWEAKED_PUBKEY_HEADER,
            HeaderValue::from_static("00"),
        );

        let err = BlindedConnectRequest::from_headers(&headers).unwrap_err();
        assert!(matches!(
            err,
            BlindedConnectRequestError::InvalidTweakedPubkey
        ));
    }
}
