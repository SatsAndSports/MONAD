use monad_common::blinded_hop::BlindedHopDescriptor;
use monad_common::secp_identity::Secp256k1Pubkey;
use std::io;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteHop {
    Cleartext {
        addr: String,
        pubkey: Secp256k1Pubkey,
        use_quic: bool,
    },
    Blinded {
        descriptor: BlindedHopDescriptor,
    },
}

impl RouteHop {
    pub fn handshake_pubkey(&self) -> Secp256k1Pubkey {
        match self {
            Self::Cleartext { pubkey, .. } => *pubkey,
            Self::Blinded { descriptor } => descriptor.tweaked_pubkey,
        }
    }

    pub fn requires_quic(&self) -> bool {
        match self {
            Self::Cleartext { use_quic, .. } => *use_quic,
            Self::Blinded { .. } => true,
        }
    }

    pub fn cleartext_addr(&self) -> Option<&str> {
        match self {
            Self::Cleartext { addr, .. } => Some(addr),
            Self::Blinded { .. } => None,
        }
    }

    pub fn blinded_descriptor(&self) -> Option<&BlindedHopDescriptor> {
        match self {
            Self::Cleartext { .. } => None,
            Self::Blinded { descriptor } => Some(descriptor),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    hops: Vec<RouteHop>,
}

impl Route {
    pub fn new(hops: Vec<RouteHop>) -> io::Result<Self> {
        Self::validate(&hops)?;
        Ok(Self { hops })
    }

    pub fn hops(&self) -> &[RouteHop] {
        &self.hops
    }

    pub fn validate(hops: &[RouteHop]) -> io::Result<()> {
        if hops.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at least one hop is required",
            ));
        }

        if matches!(hops.first(), Some(RouteHop::Blinded { .. })) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the first hop must be cleartext",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monad_common::blinded_hop::BlindedHopMessage;
    use monad_common::secp_identity::SecpTransportKeypair;

    fn sample_pubkey(seed: u8) -> Secp256k1Pubkey {
        SecpTransportKeypair::from_secret_bytes(&[seed; 32])
            .unwrap()
            .pubkey()
    }

    fn sample_blinded_descriptor() -> BlindedHopDescriptor {
        BlindedHopDescriptor {
            tweaked_pubkey: sample_pubkey(9),
            message: BlindedHopMessage {
                ephemeral_pubkey: sample_pubkey(10).to_compressed_bytes(),
                ciphertext: vec![1, 2, 3],
            },
        }
    }

    #[test]
    fn route_rejects_empty_hop_list() {
        let err = Route::new(Vec::new()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("at least one hop is required"));
    }

    #[test]
    fn route_rejects_blinded_first_hop() {
        let err = Route::new(vec![RouteHop::Blinded {
            descriptor: sample_blinded_descriptor(),
        }])
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("first hop must be cleartext"));
    }

    #[test]
    fn route_accepts_cleartext_then_blinded_suffix() {
        let route = Route::new(vec![
            RouteHop::Cleartext {
                addr: "127.0.0.1:9000".to_string(),
                pubkey: sample_pubkey(7),
                use_quic: false,
            },
            RouteHop::Blinded {
                descriptor: sample_blinded_descriptor(),
            },
        ])
        .unwrap();

        assert_eq!(route.hops().len(), 2);
    }

    #[test]
    fn route_hop_helpers_return_expected_values() {
        let cleartext = RouteHop::Cleartext {
            addr: "127.0.0.1:9000".to_string(),
            pubkey: sample_pubkey(7),
            use_quic: false,
        };
        assert_eq!(cleartext.handshake_pubkey(), sample_pubkey(7));
        assert!(!cleartext.requires_quic());
        assert_eq!(cleartext.cleartext_addr(), Some("127.0.0.1:9000"));
        assert!(cleartext.blinded_descriptor().is_none());

        let descriptor = sample_blinded_descriptor();
        let blinded = RouteHop::Blinded {
            descriptor: descriptor.clone(),
        };
        assert_eq!(blinded.handshake_pubkey(), descriptor.tweaked_pubkey);
        assert!(blinded.requires_quic());
        assert_eq!(blinded.cleartext_addr(), None);
        assert_eq!(blinded.blinded_descriptor(), Some(&descriptor));
    }
}
