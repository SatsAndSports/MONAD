use crate::route::{Route, RouteHop};
use monad_common::config::ClientConfig;
use monad_common::secp_identity::Secp256k1Pubkey;
use std::io;

pub fn route_from_client_config(client: &ClientConfig) -> io::Result<Route> {
    let hops = client
        .route
        .iter()
        .map(|hop| {
            let pubkey = Secp256k1Pubkey::parse_config_pubkey(&hop.pubkey).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid pubkey for route hop {}: {e}", hop.addr),
                )
            })?;
            Ok(RouteHop::Cleartext {
                addr: hop.addr.clone(),
                pubkey,
                use_quic: true,
            })
        })
        .collect::<io::Result<Vec<_>>>()?;

    Route::new(hops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use monad_common::config::ClientRouteHopConfig;
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
            route: vec![ClientRouteHopConfig {
                addr: "127.10.0.11:9050".to_string(),
                pubkey,
            }],
        };

        let route = route_from_client_config(&client).unwrap();
        assert_eq!(route.hops().len(), 1);
        let RouteHop::Cleartext { addr, use_quic, .. } = &route.hops()[0] else {
            panic!("expected cleartext hop");
        };
        assert_eq!(addr, "127.10.0.11:9050");
        assert!(*use_quic);
    }
}
