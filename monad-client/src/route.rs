use monad_common::blinded_hop::BlindedHopDescriptor;
use monad_common::bootstrap::BootstrapCapabilities;
use monad_common::secp_identity::Secp256k1Pubkey;
use std::io;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteHopCapabilityRequirements {
    pub direct_tcp_exit: bool,
    pub nested_monad_over_tcp: bool,
    pub nested_monad_over_quic: bool,
    pub blinded_connect_v1: bool,
    pub tweaked_noise_v1: bool,
}

impl RouteHopCapabilityRequirements {
    pub fn is_satisfied_by(&self, capabilities: &BootstrapCapabilities) -> bool {
        (!self.direct_tcp_exit || capabilities.direct_tcp_exit)
            && (!self.nested_monad_over_tcp || capabilities.nested_monad_over_tcp)
            && (!self.nested_monad_over_quic || capabilities.nested_monad_over_quic)
            && (!self.blinded_connect_v1 || capabilities.blinded_connect_v1)
            && (!self.tweaked_noise_v1 || capabilities.tweaked_noise_v1)
    }
}

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

    pub fn previous_hop_capability_requirements(&self) -> RouteHopCapabilityRequirements {
        match self {
            Self::Cleartext { use_quic, .. } => RouteHopCapabilityRequirements {
                nested_monad_over_quic: *use_quic,
                nested_monad_over_tcp: !use_quic,
                ..RouteHopCapabilityRequirements::default()
            },
            Self::Blinded { .. } => RouteHopCapabilityRequirements {
                blinded_connect_v1: true,
                ..RouteHopCapabilityRequirements::default()
            },
        }
    }

    pub fn target_hop_capability_requirements(&self) -> RouteHopCapabilityRequirements {
        match self {
            Self::Cleartext { .. } => RouteHopCapabilityRequirements::default(),
            Self::Blinded { .. } => RouteHopCapabilityRequirements {
                tweaked_noise_v1: true,
                ..RouteHopCapabilityRequirements::default()
            },
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
    use monad_common::bootstrap::initial_server_capabilities;
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

    #[test]
    fn cleartext_hop_capability_requirements_match_transport() {
        let cleartext_tcp = RouteHop::Cleartext {
            addr: "127.0.0.1:9000".to_string(),
            pubkey: sample_pubkey(7),
            use_quic: false,
        };
        assert_eq!(
            cleartext_tcp.previous_hop_capability_requirements(),
            RouteHopCapabilityRequirements {
                nested_monad_over_tcp: true,
                ..RouteHopCapabilityRequirements::default()
            }
        );

        let cleartext_quic = RouteHop::Cleartext {
            addr: "127.0.0.1:9001".to_string(),
            pubkey: sample_pubkey(8),
            use_quic: true,
        };
        assert_eq!(
            cleartext_quic.previous_hop_capability_requirements(),
            RouteHopCapabilityRequirements {
                nested_monad_over_quic: true,
                ..RouteHopCapabilityRequirements::default()
            }
        );
        assert_eq!(
            cleartext_quic.target_hop_capability_requirements(),
            RouteHopCapabilityRequirements::default()
        );
    }

    #[test]
    fn blinded_hop_capability_requirements_split_intro_and_target_roles() {
        let blinded = RouteHop::Blinded {
            descriptor: sample_blinded_descriptor(),
        };
        assert_eq!(
            blinded.previous_hop_capability_requirements(),
            RouteHopCapabilityRequirements {
                blinded_connect_v1: true,
                ..RouteHopCapabilityRequirements::default()
            }
        );
        assert_eq!(
            blinded.target_hop_capability_requirements(),
            RouteHopCapabilityRequirements {
                tweaked_noise_v1: true,
                ..RouteHopCapabilityRequirements::default()
            }
        );
    }

    #[test]
    fn capability_requirement_checks_use_bootstrap_flags() {
        let mut capabilities = initial_server_capabilities();
        let requirements = RouteHopCapabilityRequirements {
            blinded_connect_v1: true,
            tweaked_noise_v1: true,
            ..RouteHopCapabilityRequirements::default()
        };

        assert!(!requirements.is_satisfied_by(&capabilities));

        capabilities.blinded_connect_v1 = true;
        capabilities.tweaked_noise_v1 = true;
        assert!(requirements.is_satisfied_by(&capabilities));
    }
}
