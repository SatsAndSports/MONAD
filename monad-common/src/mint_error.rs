use serde::{Deserialize, Serialize};

/// HTTP-origin rejection evidence. Never retains the untrusted response body.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintHttpRejection {
    pub status: u16,
    pub code: Option<u64>,
}

impl MintHttpRejection {
    pub fn from_body(status: u16, body: &str) -> Self {
        Self {
            status,
            code: serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v.get("code").and_then(|c| c.as_u64())),
        }
    }

    pub fn inactive_output_keyset(&self) -> bool {
        (400..500).contains(&self.status) && self.code == Some(12002)
    }
}

impl std::fmt::Display for MintHttpRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "mint HTTP rejection ({}, NUT-00 code {:?})",
            self.status, self.code
        )
    }
}

impl std::fmt::Debug for MintHttpRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for MintHttpRejection {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_authority_requires_numeric_code_and_client_error_status() {
        for (status, body, expected) in [
            (400, r#"{"code":12002,"detail":"secret-sentinel"}"#, true),
            (500, r#"{"code":12002,"detail":"secret-sentinel"}"#, false),
            (400, r#"{"code":"12002"}"#, false),
            (400, r#"{"error":12002}"#, false),
            (400, "invalid secret-sentinel", false),
        ] {
            let error = MintHttpRejection::from_body(status, body);
            assert_eq!(error.inactive_output_keyset(), expected);
            assert!(!format!("{error} {error:?}").contains("secret-sentinel"));
        }
    }
}
