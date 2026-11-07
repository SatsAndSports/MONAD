//! MONAD's opt-in SOCKS5 diagnostics method (private method 0x80).
//!
//! This is not authentication. After selecting 0x80, the client sends `MONAD\x01`
//! and the server replies `[1, 0]` (accepted) or `[1, 1]` (rejected). Successful
//! CONNECT replies/data remain standard SOCKS. Failure replies append a u32-be
//! length and UTF-8 JSON, at most 4096 bytes, before connection closure.

use serde::{Deserialize, Serialize};
use std::{io, time::Duration};

pub const METHOD: u8 = 0x80;
pub const HELLO: &[u8; 6] = b"MONAD\x01";
pub const ACK: [u8; 2] = [1, 0];
pub const MAX_DIAGNOSTIC_BYTES: usize = 4096;
pub const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocksReplyMode {
    #[default]
    Standard,
    DiagnosticsV1,
}

/// Advisory detail only: unknown future codes/stages are preserved, never used
/// to authorize retries. Text is bounded and excludes terminal control characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocksDiagnostic {
    pub stage: String,
    pub code: Option<String>,
    pub message: String,
    pub http_status: Option<u16>,
}

impl SocksDiagnostic {
    pub(crate) fn simple(stage: &str, message: &str) -> Self {
        Self {
            stage: stage.into(),
            code: None,
            message: message.into(),
            http_status: None,
        }
    }

    pub(crate) fn connect_failure(error: &io::Error, http_status: Option<u16>) -> Self {
        let mut diagnostic = Self::simple("connect", "Tunnel setup failed.");
        diagnostic.http_status = http_status;
        if let Some(rejection) = monad_common::rejection::Rejection::from_io(error) {
            diagnostic.code = Some(
                serde_json::to_value(rejection.code)
                    .expect("rejection code serializes")
                    .as_str()
                    .expect("string code")
                    .into(),
            );
            // Use canonical text, not arbitrary remote error strings or bodies.
            diagnostic.message = rejection.code.rejection().message;
        } else if let Some(status) = http_status {
            diagnostic.message = format!("Relay rejected CONNECT (HTTP {status}).");
            if error.kind() == io::ErrorKind::InvalidData {
                diagnostic.message = "Invalid relay CONNECT rejection metadata.".into();
            }
        }
        diagnostic
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        let token = |s: &str, max: usize| {
            !s.is_empty()
                && s.len() <= max
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        };
        if !token(&self.stage, 64)
            || self.code.as_ref().is_some_and(|s| !token(s, 128))
            || self.message.is_empty()
            || self.message.len() > 1024
            || self.message.chars().any(char::is_control)
            || self
                .http_status
                .is_some_and(|status| !(100..=599).contains(&status))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS diagnostic fields",
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_details_preserve_known_codes_and_http_status_without_echoing_raw_errors() {
        use monad_common::rejection::{Rejection, RejectionCode};
        let error = Rejection {
            code: RejectionCode::SessionConnectSetupLimitReached,
            message: "secret sentinel".into(),
        }
        .into_io();
        let diagnostic = SocksDiagnostic::connect_failure(&error, Some(429));
        assert_eq!(
            diagnostic.code.as_deref(),
            Some("SESSION_CONNECT_SETUP_LIMIT_REACHED")
        );
        assert_eq!(diagnostic.http_status, Some(429));
        assert!(!diagnostic.message.contains("sentinel"));
        diagnostic.validate().unwrap();
        let error = io::Error::other("secret sentinel");
        let generic = SocksDiagnostic::connect_failure(&error, Some(502));
        assert_eq!(generic.http_status, Some(502));
        assert_eq!(generic.code, None);
        assert_eq!(generic.message, "Relay rejected CONNECT (HTTP 502).");
        assert_eq!(
            SocksDiagnostic::connect_failure(&error, None).message,
            "Tunnel setup failed."
        );
    }
}
