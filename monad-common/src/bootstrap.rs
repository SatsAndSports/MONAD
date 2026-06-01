use serde::{Deserialize, Serialize};
use std::io;

pub const BOOTSTRAP_VERSION: u8 = 1;
pub const SESSION_PROTOCOL_H2: &str = "h2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapCapabilities {
    pub direct_tcp_exit: bool,
    pub nested_monad_over_tcp: bool,
    pub nested_monad_over_quic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapClientHello {
    pub bootstrap_version: u8,
    pub session_protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum BootstrapServerResponse {
    Accept {
        bootstrap_version: u8,
        session_protocol: String,
        capabilities: BootstrapCapabilities,
    },
    Reject {
        bootstrap_version: u8,
        reason: String,
    },
}

pub fn initial_client_hello() -> BootstrapClientHello {
    BootstrapClientHello {
        bootstrap_version: BOOTSTRAP_VERSION,
        session_protocol: SESSION_PROTOCOL_H2.to_string(),
    }
}

pub fn initial_server_capabilities() -> BootstrapCapabilities {
    BootstrapCapabilities {
        direct_tcp_exit: true,
        nested_monad_over_tcp: true,
        nested_monad_over_quic: true,
    }
}

pub fn initial_server_accept() -> BootstrapServerResponse {
    BootstrapServerResponse::Accept {
        bootstrap_version: BOOTSTRAP_VERSION,
        session_protocol: SESSION_PROTOCOL_H2.to_string(),
        capabilities: initial_server_capabilities(),
    }
}

pub fn validate_initial_client_hello(hello: &BootstrapClientHello) -> Result<(), String> {
    if hello.bootstrap_version != BOOTSTRAP_VERSION {
        return Err(format!(
            "unsupported bootstrap version: {}",
            hello.bootstrap_version
        ));
    }
    if hello.session_protocol != SESSION_PROTOCOL_H2 {
        return Err(format!(
            "unsupported session protocol: {}",
            hello.session_protocol
        ));
    }
    Ok(())
}

pub fn encode_client_hello(hello: &BootstrapClientHello) -> io::Result<Vec<u8>> {
    serde_json::to_vec(hello).map_err(|e| io::Error::other(format!("bootstrap json error: {e}")))
}

pub fn decode_client_hello(payload: &[u8]) -> io::Result<BootstrapClientHello> {
    serde_json::from_slice(payload)
        .map_err(|e| io::Error::other(format!("bootstrap json error: {e}")))
}

pub fn encode_server_response(response: &BootstrapServerResponse) -> io::Result<Vec<u8>> {
    serde_json::to_vec(response).map_err(|e| io::Error::other(format!("bootstrap json error: {e}")))
}

pub fn decode_server_response(payload: &[u8]) -> io::Result<BootstrapServerResponse> {
    serde_json::from_slice(payload)
        .map_err(|e| io::Error::other(format!("bootstrap json error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_bootstrap_round_trips() {
        let hello = initial_client_hello();
        let encoded = encode_client_hello(&hello).unwrap();
        let decoded = decode_client_hello(&encoded).unwrap();
        assert_eq!(decoded, hello);

        let response = initial_server_accept();
        let encoded = encode_server_response(&response).unwrap();
        let decoded = decode_server_response(&encoded).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn unexpected_protocol_is_rejected() {
        let hello = BootstrapClientHello {
            bootstrap_version: BOOTSTRAP_VERSION,
            session_protocol: "something-else".to_string(),
        };
        assert_eq!(
            validate_initial_client_hello(&hello),
            Err("unsupported session protocol: something-else".to_string())
        );
    }
}
