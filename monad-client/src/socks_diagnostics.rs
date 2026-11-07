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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<FailureContext>,
    /// Historical route-setup context, not necessarily the cause of this request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_route_failure: Option<RouteFailureDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureContext {
    pub origin: String,
    pub operation: String,
    pub reporting_hop: Option<usize>,
    pub target_hop: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteFailureDetail {
    pub context: FailureContext,
    pub code: Option<String>,
    pub message: String,
    pub http_status: Option<u16>,
}

impl RouteFailureDetail {
    pub(crate) fn from_io(error: &io::Error) -> Option<Self> {
        if let Some(refusal) = crate::admission::RouteRefusal::from_io(error) {
            return Some(Self {
                context: FailureContext {
                    origin: "relay".into(),
                    operation: match refusal.operation {
                        "connect" => "relay_connect",
                        "session" => "session_handshake",
                        _ => "route",
                    }
                    .into(),
                    reporting_hop: Some(refusal.refusing_hop),
                    target_hop: Some(refusal.target_hop),
                },
                code: Some(code_name(refusal.rejection.code)),
                message: refusal.rejection.code.rejection().message,
                http_status: if refusal.operation == "connect" {
                    refusal
                        .rejection
                        .code
                        .connect_status()
                        .map(|status| status.as_u16())
                } else {
                    None
                },
            });
        }
        let local = crate::admission::RouteAttemptFailure::from_io(error)?;
        Some(Self {
            context: FailureContext {
                origin: if local.http_status.is_some() {
                    "relay"
                } else {
                    "local"
                }
                .into(),
                operation: local.operation.into(),
                reporting_hop: local
                    .http_status
                    .and_then(|_| local.target_hop.checked_sub(1))
                    .filter(|hop| *hop > 0),
                target_hop: Some(local.target_hop),
            },
            code: local.code.map(code_name),
            message: local
                .code
                .map(|code| code.rejection().message)
                .unwrap_or_else(|| {
                    if let Some(status) = local.http_status {
                        format!("Relay rejected CONNECT (HTTP {status}).")
                    } else if error.kind() == io::ErrorKind::TimedOut {
                        "Route setup attempt timed out.".into()
                    } else {
                        "Route connection attempt failed.".into()
                    }
                }),
            http_status: local.http_status,
        })
    }
}

fn code_name(code: monad_common::rejection::RejectionCode) -> String {
    serde_json::to_value(code)
        .expect("code serializes")
        .as_str()
        .expect("string code")
        .into()
}

pub(crate) fn socks_reply_code(error: &io::Error) -> u8 {
    use monad_common::rejection::{Rejection, RejectionCode as C};
    match Rejection::from_io(error).map(|r| r.code) {
        Some(C::DestinationPolicyDenied) => 0x02,
        Some(C::TcpResolutionFailed | C::TcpDestinationUnreachable) => 0x04,
        Some(
            C::TcpConnectTimedOut
            | C::TcpConnectFailed
            | C::QuicResolutionFailed
            | C::QuicConnectTimedOut
            | C::QuicConnectFailed
            | C::QuicAuthenticationFailed
            | C::QuicAuthenticationUnavailable
            | C::QuicStreamFailed,
        ) => 0x01,
        _ => 0x05,
    }
}

impl SocksDiagnostic {
    pub(crate) fn simple(stage: &str, message: &str) -> Self {
        Self {
            stage: stage.into(),
            code: None,
            message: message.into(),
            http_status: None,
            context: Some(FailureContext {
                origin: "local".into(),
                operation: stage.into(),
                reporting_hop: None,
                target_hop: None,
            }),
            last_route_failure: None,
        }
    }

    pub(crate) fn connect_failure(error: &io::Error, http_status: Option<u16>) -> Self {
        let mut diagnostic = Self::simple("connect", "Tunnel setup failed.");
        diagnostic.http_status = http_status;
        diagnostic.context = Some(FailureContext {
            origin: if http_status.is_some() {
                "relay"
            } else {
                "local"
            }
            .into(),
            operation: "exit_connect".into(),
            reporting_hop: None,
            target_hop: None,
        });
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
        } else if let Some(local) = monad_common::connect_failure::ConnectFailure::from_io(error) {
            diagnostic.code = Some(code_name(local.code));
            diagnostic.message = local.code.rejection().message;
        }
        diagnostic
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        let token = |s: &str, max: usize| {
            !s.is_empty()
                && s.len() <= max
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        };
        let context_valid = |context: &FailureContext| {
            token(&context.origin, 32)
                && token(&context.operation, 64)
                && context
                    .reporting_hop
                    .into_iter()
                    .chain(context.target_hop)
                    .all(|hop| (1..=65535).contains(&hop))
                && !(context.origin == "local" && context.reporting_hop.is_some())
        };
        if self
            .context
            .as_ref()
            .is_some_and(|context| !context_valid(context))
            || self.last_route_failure.as_ref().is_some_and(|failure| {
                !context_valid(&failure.context)
                    || failure.code.as_ref().is_some_and(|code| !token(code, 128))
                    || failure.message.is_empty()
                    || failure.message.len() > 1024
                    || failure.message.chars().any(char::is_control)
                    || failure
                        .http_status
                        .is_some_and(|status| !(100..=599).contains(&status))
            })
            || !token(&self.stage, 64)
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
    #[test]
    fn hop_attribution_separates_remote_report_from_local_observation() {
        use monad_common::rejection::RejectionCode as C;
        let remote = crate::admission::RouteRefusal::annotate(
            C::QuicConnectTimedOut.rejection().into_io(),
            2,
            3,
            "connect",
            "private target".into(),
        );
        let detail = RouteFailureDetail::from_io(&remote).unwrap();
        assert_eq!(detail.context.origin, "relay");
        assert_eq!(detail.context.reporting_hop, Some(2));
        assert_eq!(detail.context.target_hop, Some(3));
        assert_eq!(detail.context.operation, "relay_connect");
        let future_operation = crate::admission::RouteRefusal::annotate(
            C::BootstrapRejected.rejection().into_io(),
            2,
            3,
            "future_operation",
            "private target".into(),
        );
        assert_eq!(
            RouteFailureDetail::from_io(&future_operation)
                .unwrap()
                .context
                .operation,
            "route"
        );
        let local = crate::admission::RouteAttemptFailure::annotate(
            io::Error::new(io::ErrorKind::BrokenPipe, "private target"),
            3,
            "relay_connect",
        );
        let detail = RouteFailureDetail::from_io(&local).unwrap();
        assert_eq!(detail.context.origin, "local");
        assert_eq!(detail.context.reporting_hop, None);
        assert_eq!(detail.context.target_hop, Some(3));
        assert_eq!(detail.code, None);
        assert!(!detail.message.contains("private"));
        let legacy = crate::admission::RouteAttemptFailure::annotate(
            monad_common::rejection::connect_error(
                http::StatusCode::BAD_GATEWAY,
                &http::HeaderMap::new(),
            ),
            3,
            "relay_connect",
        );
        let detail = RouteFailureDetail::from_io(&legacy).unwrap();
        assert_eq!(detail.context.origin, "relay");
        assert_eq!(detail.context.reporting_hop, Some(2));
        assert_eq!(detail.http_status, Some(502));
        assert_eq!(detail.code, None);
        assert_eq!(
            socks_reply_code(&C::TcpConnectTimedOut.rejection().into_io()),
            1
        );
        assert_eq!(
            socks_reply_code(&C::TcpResolutionFailed.rejection().into_io()),
            4
        );
        assert_eq!(
            socks_reply_code(&C::TcpConnectionRefused.rejection().into_io()),
            5
        );
    }
}
