use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io;

pub const BOOTSTRAP_VERSION: u8 = 1;
pub const SESSION_PROTOCOL_H2: &str = "h2";
pub const CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29: &str = "2026-08-29";
pub const CASHU_SPILMAN_KEYSET_VERSION_V1: &str = "v1";
pub const CASHU_SPILMAN_KEYSET_VERSION_V2: &str = "v2";
pub const PRICING_POLICY_SESSION_CONSTANT: &str = "session_constant";

pub type CashuSpilmanProtocolKeysetVersions = BTreeMap<String, BTreeSet<String>>;

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
    pub cashu_spilman_protocol_keyset_versions: CashuSpilmanProtocolKeysetVersions,
    pub pricing_policies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapV1ServerAccept {
    pub session_protocol: String,
    pub capabilities: BootstrapCapabilities,
    pub cashu_spilman_protocol_version: Option<String>,
    pub cashu_spilman_keyset_versions: Option<BTreeSet<String>>,
    pub pricing_policy: Option<String>,
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
            cashu_spilman_protocol_keyset_versions:
                supported_cashu_spilman_protocol_keyset_versions(),
            pricing_policies: supported_pricing_policies(),
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
        blinded_connect_v1: true,
        tweaked_noise_v1: true,
    }
}

pub fn server_accept_v1(capabilities: BootstrapCapabilities) -> BootstrapV1ServerAccept {
    BootstrapV1ServerAccept {
        session_protocol: SESSION_PROTOCOL_H2.to_string(),
        capabilities,
        cashu_spilman_protocol_version: Some(CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string()),
        cashu_spilman_keyset_versions: Some(supported_cashu_spilman_keyset_versions()),
        pricing_policy: Some(PRICING_POLICY_SESSION_CONSTANT.to_string()),
    }
}

pub fn initial_server_accept_v1() -> BootstrapV1ServerAccept {
    server_accept_v1(initial_server_capabilities())
}

pub fn server_accept(accept: BootstrapV1ServerAccept) -> BootstrapServerResponse {
    BootstrapServerResponse::Accept {
        selected_version: BOOTSTRAP_VERSION,
        response: serde_json::to_value(accept).expect("bootstrap v1 accept is serializable"),
    }
}

pub fn initial_server_accept() -> BootstrapServerResponse {
    server_accept(initial_server_accept_v1())
}

pub fn supported_bootstrap_versions() -> Vec<u8> {
    vec![BOOTSTRAP_VERSION]
}

pub fn supported_cashu_spilman_keyset_versions() -> BTreeSet<String> {
    BTreeSet::from([
        CASHU_SPILMAN_KEYSET_VERSION_V1.to_string(),
        CASHU_SPILMAN_KEYSET_VERSION_V2.to_string(),
    ])
}

pub fn supported_cashu_spilman_protocol_keyset_versions() -> CashuSpilmanProtocolKeysetVersions {
    BTreeMap::from([(
        CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
        supported_cashu_spilman_keyset_versions(),
    )])
}

pub fn is_supported_cashu_spilman_protocol_version(version: &str) -> bool {
    supported_cashu_spilman_protocol_keyset_versions().contains_key(version)
}

pub fn select_cashu_spilman_protocol_keyset_versions(
    client_versions: &CashuSpilmanProtocolKeysetVersions,
) -> Option<(String, BTreeSet<String>)> {
    select_cashu_spilman_protocol_keyset_versions_from_supported(
        client_versions,
        &supported_cashu_spilman_protocol_keyset_versions(),
    )
}

fn select_cashu_spilman_protocol_keyset_versions_from_supported(
    client_versions: &CashuSpilmanProtocolKeysetVersions,
    server_versions: &CashuSpilmanProtocolKeysetVersions,
) -> Option<(String, BTreeSet<String>)> {
    server_versions
        .iter()
        .find_map(|(protocol, server_keyset_versions)| {
            let client_keyset_versions = client_versions.get(protocol)?;
            let mutual_keyset_versions = client_keyset_versions
                .intersection(server_keyset_versions)
                .cloned()
                .collect::<BTreeSet<_>>();
            (!mutual_keyset_versions.is_empty()).then(|| (protocol.clone(), mutual_keyset_versions))
        })
}

pub fn supported_pricing_policies() -> Vec<String> {
    vec![PRICING_POLICY_SESSION_CONSTANT.to_string()]
}

pub fn is_supported_pricing_policy(policy: &str) -> bool {
    policy == PRICING_POLICY_SESSION_CONSTANT
}

pub fn select_pricing_policy(client_policies: &[String]) -> Option<String> {
    client_policies
        .iter()
        .find(|policy| is_supported_pricing_policy(policy))
        .cloned()
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
        if select_cashu_spilman_protocol_keyset_versions(
            &hello.cashu_spilman_protocol_keyset_versions,
        )
        .is_some()
        {
            if select_pricing_policy(&hello.pricing_policies).is_some() {
                return Ok(());
            }
            return Err(format!(
                "unsupported pricing_policies: {:?}",
                hello.pricing_policies
            ));
        }
        return Err(format!(
            "unsupported cashu_spilman_protocol_keyset_versions: {:?}",
            hello.cashu_spilman_protocol_keyset_versions
        ));
    }
    Err(format!(
        "unsupported session protocols: {:?}",
        hello.session_protocols
    ))
}

pub fn validate_v1_server_accept(
    accept: &BootstrapV1ServerAccept,
    hello: &BootstrapV1ClientHello,
) -> Result<(), String> {
    if accept.session_protocol != SESSION_PROTOCOL_H2
        || !hello.session_protocols.contains(&accept.session_protocol)
    {
        return Err(format!(
            "unsupported session protocol: {}",
            accept.session_protocol
        ));
    }
    let version = accept
        .cashu_spilman_protocol_version
        .as_deref()
        .ok_or_else(|| "missing cashu_spilman_protocol_version".to_string())?;
    if !is_supported_cashu_spilman_protocol_version(version)
        || !hello
            .cashu_spilman_protocol_keyset_versions
            .contains_key(version)
    {
        return Err(format!(
            "unsupported cashu_spilman_protocol_version: {}",
            version
        ));
    }
    let keyset_versions = accept
        .cashu_spilman_keyset_versions
        .as_ref()
        .ok_or_else(|| "missing cashu_spilman_keyset_versions".to_string())?;
    let supported_protocol_keyset_versions = supported_cashu_spilman_protocol_keyset_versions();
    let supported_keyset_versions = supported_protocol_keyset_versions
        .get(version)
        .expect("supported protocol has keyset versions");
    if keyset_versions.is_empty()
        || !keyset_versions.is_subset(supported_keyset_versions)
        || !keyset_versions.is_subset(&hello.cashu_spilman_protocol_keyset_versions[version])
    {
        return Err(format!(
            "unsupported cashu_spilman_keyset_versions for {version}: {keyset_versions:?}"
        ));
    }
    let pricing_policy = accept
        .pricing_policy
        .as_deref()
        .ok_or_else(|| "missing pricing_policy".to_string())?;
    if !is_supported_pricing_policy(pricing_policy)
        || !hello
            .pricing_policies
            .iter()
            .any(|offered| offered == pricing_policy)
    {
        return Err(format!("unsupported pricing_policy: {}", pricing_policy));
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
    fn negotiation_matrix_and_offer_aware_validation() {
        for (offered, expected) in [
            (vec!["v1"], vec!["v1"]),
            (vec!["v2"], vec!["v2"]),
            (vec!["v1", "v2"], vec!["v1", "v2"]),
            (vec!["v2", "future"], vec!["v2"]),
            (vec![], vec![]),
            (vec!["future"], vec![]),
        ] {
            let mut hello = decode_v1_client_hello(&initial_client_hello()).unwrap();
            hello.cashu_spilman_protocol_keyset_versions.insert(
                CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
                offered.into_iter().map(String::from).collect(),
            );
            let selected = select_cashu_spilman_protocol_keyset_versions(
                &hello.cashu_spilman_protocol_keyset_versions,
            );
            assert_eq!(
                validate_v1_client_hello(&hello).is_ok(),
                !expected.is_empty()
            );
            if expected.is_empty() {
                assert!(selected.is_none());
            } else {
                let mut accept = initial_server_accept_v1();
                let expected = expected
                    .into_iter()
                    .map(String::from)
                    .collect::<BTreeSet<_>>();
                assert_eq!(selected.unwrap().1, expected);
                accept.cashu_spilman_keyset_versions = Some(expected);
                assert_eq!(validate_v1_server_accept(&accept, &hello), Ok(()));
            }
        }
        let mut hello = decode_v1_client_hello(&initial_client_hello()).unwrap();
        let mut accept = initial_server_accept_v1();
        hello
            .cashu_spilman_protocol_keyset_versions
            .get_mut(CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29)
            .unwrap()
            .remove("v2");
        assert!(validate_v1_server_accept(&accept, &hello).is_err());
        accept.cashu_spilman_keyset_versions = Some(BTreeSet::from(["v1".to_string()]));
        assert!(validate_v1_server_accept(&accept, &hello).is_ok());
        hello.pricing_policies.clear();
        assert!(validate_v1_server_accept(&accept, &hello).is_err());
        hello = decode_v1_client_hello(&initial_client_hello()).unwrap();
        hello.session_protocols.clear();
        assert!(validate_v1_server_accept(&accept, &hello).is_err());
        hello = decode_v1_client_hello(&initial_client_hello()).unwrap();
        hello.cashu_spilman_protocol_keyset_versions.clear();
        assert!(validate_v1_server_accept(&accept, &hello).is_err());
    }

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
            },
            "cashu_spilman_protocol_version": "2026-08-29",
            "cashu_spilman_keyset_versions": ["v1", "v2"],
            "pricing_policy": "session_constant"
        });

        let decoded: BootstrapV1ServerAccept = serde_json::from_value(response).unwrap();
        assert!(decoded.capabilities.direct_tcp_exit);
        assert!(decoded.capabilities.nested_monad_over_tcp);
        assert!(decoded.capabilities.nested_monad_over_quic);
        assert!(!decoded.capabilities.blinded_connect_v1);
        assert!(!decoded.capabilities.tweaked_noise_v1);
        assert_eq!(
            decoded.cashu_spilman_protocol_version.as_deref(),
            Some(CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29)
        );
        assert_eq!(
            decoded.pricing_policy.as_deref(),
            Some(PRICING_POLICY_SESSION_CONSTANT)
        );
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
            cashu_spilman_protocol_version: Some(
                CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
            ),
            cashu_spilman_keyset_versions: Some(supported_cashu_spilman_keyset_versions()),
            pricing_policy: Some(PRICING_POLICY_SESSION_CONSTANT.to_string()),
        };

        let encoded = serde_json::to_value(&accept).unwrap();
        let decoded: BootstrapV1ServerAccept = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded, accept);
    }

    #[test]
    fn highest_mutual_version_is_selected() {
        let hello = BootstrapClientHello {
            versions: BTreeMap::from([
                (
                    "1".to_string(),
                    json!({
                        "session_protocols": ["h2"],
                        "cashu_spilman_protocol_keyset_versions": {
                            "2026-08-29": ["v1", "v2"]
                        },
                        "pricing_policies": ["session_constant"]
                    }),
                ),
                ("2".to_string(), json!({"future": true})),
            ]),
        };
        assert_eq!(highest_supported_version(&hello), Some(1));
    }

    #[test]
    fn v1_accepts_h2_among_other_protocols() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec!["future".to_string(), "h2".to_string()],
            cashu_spilman_protocol_keyset_versions:
                supported_cashu_spilman_protocol_keyset_versions(),
            pricing_policies: vec![PRICING_POLICY_SESSION_CONSTANT.to_string()],
        };
        assert_eq!(validate_v1_client_hello(&hello), Ok(()));
    }

    #[test]
    fn v1_rejects_when_h2_missing() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec!["something-else".to_string()],
            cashu_spilman_protocol_keyset_versions:
                supported_cashu_spilman_protocol_keyset_versions(),
            pricing_policies: vec![PRICING_POLICY_SESSION_CONSTANT.to_string()],
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
            cashu_spilman_protocol_version: Some(
                CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
            ),
            cashu_spilman_keyset_versions: Some(supported_cashu_spilman_keyset_versions()),
            pricing_policy: Some(PRICING_POLICY_SESSION_CONSTANT.to_string()),
        };
        assert_eq!(
            validate_v1_server_accept(
                &accept,
                &decode_v1_client_hello(&initial_client_hello()).unwrap()
            ),
            Err("unsupported session protocol: future".to_string())
        );
    }

    #[test]
    fn v1_rejects_when_cashu_spilman_version_missing() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec![SESSION_PROTOCOL_H2.to_string()],
            cashu_spilman_protocol_keyset_versions: BTreeMap::new(),
            pricing_policies: vec![PRICING_POLICY_SESSION_CONSTANT.to_string()],
        };
        assert_eq!(
            validate_v1_client_hello(&hello),
            Err("unsupported cashu_spilman_protocol_keyset_versions: {}".to_string())
        );
    }

    #[test]
    fn v1_rejects_when_cashu_spilman_version_unsupported() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec![SESSION_PROTOCOL_H2.to_string()],
            cashu_spilman_protocol_keyset_versions: BTreeMap::from([(
                "future".to_string(),
                supported_cashu_spilman_keyset_versions(),
            )]),
            pricing_policies: vec![PRICING_POLICY_SESSION_CONSTANT.to_string()],
        };
        assert_eq!(
            validate_v1_client_hello(&hello),
            Err(
                "unsupported cashu_spilman_protocol_keyset_versions: {\"future\": {\"v1\", \"v2\"}}"
                    .to_string()
            )
        );
    }

    #[test]
    fn v1_rejects_the_pre_canonical_spilman_protocol_version() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec![SESSION_PROTOCOL_H2.to_string()],
            cashu_spilman_protocol_keyset_versions: BTreeMap::from([(
                "2026-03-20".to_string(),
                supported_cashu_spilman_keyset_versions(),
            )]),
            pricing_policies: vec![PRICING_POLICY_SESSION_CONSTANT.to_string()],
        };
        assert_eq!(
            validate_v1_client_hello(&hello),
            Err(
                "unsupported cashu_spilman_protocol_keyset_versions: {\"2026-03-20\": {\"v1\", \"v2\"}}"
                    .to_string()
            )
        );
    }

    #[test]
    fn selects_full_mutual_keyset_version_set() {
        let client_versions = BTreeMap::from([(
            CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
            BTreeSet::from(["v1".to_string(), "v2".to_string(), "v3".to_string()]),
        )]);
        let server_versions = BTreeMap::from([(
            CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
            BTreeSet::from(["v1".to_string(), "v2".to_string()]),
        )]);
        let selected = select_cashu_spilman_protocol_keyset_versions_from_supported(
            &client_versions,
            &server_versions,
        );
        assert_eq!(
            selected,
            Some((
                CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
                supported_cashu_spilman_keyset_versions(),
            ))
        );
    }

    #[test]
    fn selects_nonempty_intersection() {
        let client_versions = BTreeMap::from([(
            CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
            BTreeSet::from(["v1".to_string(), "v2".to_string(), "v3".to_string()]),
        )]);
        let server_versions = BTreeMap::from([(
            CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
            BTreeSet::from(["v2".to_string(), "v3".to_string()]),
        )]);

        assert_eq!(
            select_cashu_spilman_protocol_keyset_versions_from_supported(
                &client_versions,
                &server_versions,
            ),
            Some((
                CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
                BTreeSet::from(["v2".to_string(), "v3".to_string()])
            ))
        );
    }

    #[test]
    fn v1_accepts_client_with_single_keyset_version() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec![SESSION_PROTOCOL_H2.to_string()],
            cashu_spilman_protocol_keyset_versions: BTreeMap::from([(
                CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
                BTreeSet::from([CASHU_SPILMAN_KEYSET_VERSION_V1.to_string()]),
            )]),
            pricing_policies: vec![PRICING_POLICY_SESSION_CONSTANT.to_string()],
        };

        assert_eq!(validate_v1_client_hello(&hello), Ok(()));
    }

    #[test]
    fn v1_server_accept_rejects_missing_cashu_spilman_protocol_version() {
        let accept = BootstrapV1ServerAccept {
            session_protocol: SESSION_PROTOCOL_H2.to_string(),
            capabilities: initial_server_capabilities(),
            cashu_spilman_protocol_version: None,
            cashu_spilman_keyset_versions: Some(supported_cashu_spilman_keyset_versions()),
            pricing_policy: Some(PRICING_POLICY_SESSION_CONSTANT.to_string()),
        };
        assert_eq!(
            validate_v1_server_accept(
                &accept,
                &decode_v1_client_hello(&initial_client_hello()).unwrap()
            ),
            Err("missing cashu_spilman_protocol_version".to_string())
        );
    }

    #[test]
    fn v1_server_accept_rejects_unknown_cashu_spilman_protocol_version() {
        let accept = BootstrapV1ServerAccept {
            session_protocol: SESSION_PROTOCOL_H2.to_string(),
            capabilities: initial_server_capabilities(),
            cashu_spilman_protocol_version: Some("future".to_string()),
            cashu_spilman_keyset_versions: Some(supported_cashu_spilman_keyset_versions()),
            pricing_policy: Some(PRICING_POLICY_SESSION_CONSTANT.to_string()),
        };
        assert_eq!(
            validate_v1_server_accept(
                &accept,
                &decode_v1_client_hello(&initial_client_hello()).unwrap()
            ),
            Err("unsupported cashu_spilman_protocol_version: future".to_string())
        );
    }

    #[test]
    fn v1_server_accept_rejects_missing_or_empty_keyset_version_set() {
        let mut accept = initial_server_accept_v1();
        accept.cashu_spilman_keyset_versions = None;
        assert_eq!(
            validate_v1_server_accept(
                &accept,
                &decode_v1_client_hello(&initial_client_hello()).unwrap()
            ),
            Err("missing cashu_spilman_keyset_versions".to_string())
        );

        accept.cashu_spilman_keyset_versions = Some(BTreeSet::new());
        assert!(matches!(
            validate_v1_server_accept(&accept, &decode_v1_client_hello(&initial_client_hello()).unwrap()),
            Err(message) if message.contains("unsupported cashu_spilman_keyset_versions")
        ));
    }

    #[test]
    fn v1_rejects_when_pricing_policy_missing() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec![SESSION_PROTOCOL_H2.to_string()],
            cashu_spilman_protocol_keyset_versions:
                supported_cashu_spilman_protocol_keyset_versions(),
            pricing_policies: vec![],
        };
        assert_eq!(
            validate_v1_client_hello(&hello),
            Err("unsupported pricing_policies: []".to_string())
        );
    }

    #[test]
    fn v1_rejects_when_pricing_policy_unsupported() {
        let hello = BootstrapV1ClientHello {
            session_protocols: vec![SESSION_PROTOCOL_H2.to_string()],
            cashu_spilman_protocol_keyset_versions:
                supported_cashu_spilman_protocol_keyset_versions(),
            pricing_policies: vec!["future".to_string()],
        };
        assert_eq!(
            validate_v1_client_hello(&hello),
            Err("unsupported pricing_policies: [\"future\"]".to_string())
        );
    }

    #[test]
    fn select_pricing_policy_prefers_first_mutual_client_entry() {
        let selected = select_pricing_policy(&[
            "future".to_string(),
            PRICING_POLICY_SESSION_CONSTANT.to_string(),
        ]);
        assert_eq!(selected.as_deref(), Some(PRICING_POLICY_SESSION_CONSTANT));
    }

    #[test]
    fn v1_server_accept_rejects_missing_pricing_policy() {
        let accept = BootstrapV1ServerAccept {
            session_protocol: SESSION_PROTOCOL_H2.to_string(),
            capabilities: initial_server_capabilities(),
            cashu_spilman_protocol_version: Some(
                CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
            ),
            cashu_spilman_keyset_versions: Some(supported_cashu_spilman_keyset_versions()),
            pricing_policy: None,
        };
        assert_eq!(
            validate_v1_server_accept(
                &accept,
                &decode_v1_client_hello(&initial_client_hello()).unwrap()
            ),
            Err("missing pricing_policy".to_string())
        );
    }

    #[test]
    fn v1_server_accept_rejects_unknown_pricing_policy() {
        let accept = BootstrapV1ServerAccept {
            session_protocol: SESSION_PROTOCOL_H2.to_string(),
            capabilities: initial_server_capabilities(),
            cashu_spilman_protocol_version: Some(
                CASHU_SPILMAN_PROTOCOL_VERSION_2026_08_29.to_string(),
            ),
            cashu_spilman_keyset_versions: Some(supported_cashu_spilman_keyset_versions()),
            pricing_policy: Some("future".to_string()),
        };
        assert_eq!(
            validate_v1_server_accept(
                &accept,
                &decode_v1_client_hello(&initial_client_hello()).unwrap()
            ),
            Err("unsupported pricing_policy: future".to_string())
        );
    }
}
