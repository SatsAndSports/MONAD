use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
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
pub struct BootstrapV1ClientHello {
    pub session_protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapV1ServerAccept {
    pub session_protocol: String,
    pub capabilities: BootstrapCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct BootstrapClientHello {
    pub versions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum BootstrapServerResponse {
    Accept {
        selected_version: u8,
        response: Value,
    },
    Reject {
        supported_versions: Vec<u8>,
        reason: String,
    },
}

fn version_key(version: u8) -> String {
    version.to_string()
}

pub fn initial_client_hello() -> BootstrapClientHello {
    let mut versions = BTreeMap::new();
    versions.insert(
        version_key(BOOTSTRAP_VERSION),
        serde_json::to_value(BootstrapV1ClientHello {
            session_protocols: vec![SESSION_PROTOCOL_H2.to_string()],
        })
        .expect("initial bootstrap v1 hello is serializable"),
    );
    BootstrapClientHello { versions }
}

pub fn initial_server_capabilities() -> BootstrapCapabilities {
    BootstrapCapabilities {
        direct_tcp_exit: true,
        nested_monad_over_tcp: true,
        nested_monad_over_quic: true,
    }
}

pub fn initial_server_accept_v1() -> BootstrapV1ServerAccept {
    BootstrapV1ServerAccept {
        session_protocol: SESSION_PROTOCOL_H2.to_string(),
        capabilities: initial_server_capabilities(),
    }
}

pub fn initial_server_accept() -> BootstrapServerResponse {
    BootstrapServerResponse::Accept {
        selected_version: BOOTSTRAP_VERSION,
        response: serde_json::to_value(initial_server_accept_v1())
            .expect("initial bootstrap v1 accept is serializable"),
    }
}

pub fn supported_bootstrap_versions() -> Vec<u8> {
    vec![BOOTSTRAP_VERSION]
}

pub fn highest_supported_version(hello: &BootstrapClientHello) -> Option<u8> {
    supported_bootstrap_versions()
        .into_iter()
        .filter(|version| hello.versions.contains_key(&version_key(*version)))
        .max()
}

pub fn decode_v1_client_hello(
    hello: &BootstrapClientHello,
) -> Result<BootstrapV1ClientHello, String> {
    let value = hello
        .versions
        .get(&version_key(BOOTSTRAP_VERSION))
        .ok_or_else(|| format!("missing bootstrap version {}", BOOTSTRAP_VERSION))?
        .clone();
    serde_json::from_value(value).map_err(|e| format!("invalid bootstrap v1 payload: {e}"))
}

pub fn validate_v1_client_hello(hello: &BootstrapV1ClientHello) -> Result<(), String> {
    if hello
        .session_protocols
        .iter()
        .any(|protocol| protocol == SESSION_PROTOCOL_H2)
    {
        return Ok(());
    }
    Err(format!(
        "unsupported session protocols: {:?}",
        hello.session_protocols
    ))
}

pub fn decode_v1_server_accept(response: Value) -> io::Result<BootstrapV1ServerAccept> {
    serde_json::from_value(response)
        .map_err(|e| io::Error::other(format!("bootstrap json error: {e}")))
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
    use serde_json::json;

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
    fn highest_mutual_version_is_selected() {
        let hello = BootstrapClientHello {
            versions: BTreeMap::from([
                ("1".to_string(), json!({"session_protocols": ["h2"]})),
                ("2".to_string(), json!({"future": true})),
            ]),
        };
        assert_eq!(highest_supported_version(&hello), Some(1));
    }

    #[test]
    fn v1_accepts_h2_among_other_protocols() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec!["future".to_string(), "h2".to_string()],
        };
        assert_eq!(validate_v1_client_hello(&hello), Ok(()));
    }

    #[test]
    fn v1_rejects_when_h2_missing() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec!["something-else".to_string()],
        };
        assert_eq!(
            validate_v1_client_hello(&hello),
            Err("unsupported session protocols: [\"something-else\"]".to_string())
        );
    }
}
