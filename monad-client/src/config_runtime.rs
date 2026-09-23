use crate::route::{Route, RouteHop};
use monad_common::config::{ClientConfig, ClientRouteHopConfig};
use std::io;

pub fn route_from_client_config(client: &ClientConfig) -> io::Result<Route> {
    let hops = client
        .route
        .iter()
        .map(|hop| match hop {
            ClientRouteHopConfig::Cleartext(hop) => RouteHop::Cleartext {
                addr: hop.addr.clone(),
                pubkey: hop.pubkey,
                use_quic: true,
            },
            ClientRouteHopConfig::Blinded(descriptor) => RouteHop::Blinded {
                descriptor: descriptor.clone(),
            },
        })
        .collect();

    Route::new(hops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use monad_common::secp_identity::SecpTransportKeypair;

    #[test]
    fn config_route_uses_quic_for_all_hops() {
        let pubkey = SecpTransportKeypair::from_secret_bytes(&[7u8; 32])
            .unwrap()
            .pubkey()
            .to_hex();
        let client = ClientConfig {
            name: "local".to_string(),
            socks: "127.10.0.1:1080".to_string(),
            route: vec![format!("{pubkey}::127.10.0.11").parse().unwrap()],
        };

        let route = route_from_client_config(&client).unwrap();
        assert_eq!(route.hops().len(), 1);
        let RouteHop::Cleartext { addr, use_quic, .. } = &route.hops()[0] else {
            panic!("expected cleartext hop");
        };
        assert_eq!(addr, "127.10.0.11:9050");
        assert!(*use_quic);
    }

    #[test]
    fn config_rejects_empty_and_blinded_first_routes() {
        let mut client: ClientConfig =
            serde_yaml::from_str("name: local\nsocks: localhost:1080\nroute: []").unwrap();
        assert!(route_from_client_config(&client).is_err());
        let key = SecpTransportKeypair::from_secret_bytes(&[7; 32])
            .unwrap()
            .pubkey();
        let descriptor = monad_common::blinded_hop::build_blinded_hop_descriptor(
            key.to_compressed_bytes(),
            "localhost:9050",
            key,
        )
        .unwrap();
        client.route.push(ClientRouteHopConfig::Blinded(descriptor));
        let err = route_from_client_config(&client).unwrap_err();
        assert!(err.to_string().contains("first hop must be cleartext"));
    }
}
