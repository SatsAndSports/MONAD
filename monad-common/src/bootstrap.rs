use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;

pub const BOOTSTRAP_VERSION: u8 = 1;
pub const SESSION_PROTOCOL_H2: &str = "h2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapCapabilities {
    #[serde(default)]
    pub direct_tcp_exit: bool,
    #[serde(default)]
    pub nested_monad_over_tcp: bool,
    #[serde(default)]
    pub nested_monad_over_quic: bool,
    #[serde(default)]
    pub blinded_connect_v1: bool,
    #[serde(default)]
    pub tweaked_noise_v1: bool,
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
        blinded_connect_v1: false,
        tweaked_noise_v1: false,
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

pub fn validate_v1_server_accept(accept: &BootstrapV1ServerAccept) -> Result<(), String> {
    if accept.session_protocol != SESSION_PROTOCOL_H2 {
        return Err(format!(
            "unsupported session protocol: {}",
            accept.session_protocol
        ));
    }
    Ok(())
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
    fn old_capability_payload_defaults_new_blinded_flags_to_false() {
        let response = serde_json::json!({
            "session_protocol": "h2",
            "capabilities": {
                "direct_tcp_exit": true,
                "nested_monad_over_tcp": true,
                "nested_monad_over_quic": true
            }
        });

        let decoded: BootstrapV1ServerAccept = serde_json::from_value(response).unwrap();
        assert!(decoded.capabilities.direct_tcp_exit);
        assert!(decoded.capabilities.nested_monad_over_tcp);
        assert!(decoded.capabilities.nested_monad_over_quic);
        assert!(!decoded.capabilities.blinded_connect_v1);
        assert!(!decoded.capabilities.tweaked_noise_v1);
    }

    #[test]
    fn blinded_capability_flags_round_trip() {
        let accept = BootstrapV1ServerAccept {
            session_protocol: SESSION_PROTOCOL_H2.to_string(),
            capabilities: BootstrapCapabilities {
                direct_tcp_exit: true,
                nested_monad_over_tcp: true,
                nested_monad_over_quic: true,
                blinded_connect_v1: true,
                tweaked_noise_v1: true,
            },
        };

        let encoded = serde_json::to_value(&accept).unwrap();
        let decoded: BootstrapV1ServerAccept = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, accept);
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

    #[test]
    fn v1_server_accept_rejects_unknown_session_protocol() {
        let accept = BootstrapV1ServerAccept {
            session_protocol: "future".to_string(),
            capabilities: initial_server_capabilities(),
        };
        assert_eq!(
            validate_v1_server_accept(&accept),
            Err("unsupported session protocol: future".to_string())
        );
    }
}
