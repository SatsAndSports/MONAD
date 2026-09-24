//! Structured protocol refusal, independent of the envelope carrying it.
use serde::{Deserialize, Serialize};
use std::{fmt, io};

pub const CONNECT_REJECTION_HEADER: &str = "monad-rejection-code";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RejectionCode {
    RelayDisabled,
    SessionAdmissionDisabled,
    TunnelAdmissionDisabled,
    ChannelAdmissionDisabled,
    DestinationPolicyDenied,
    BootstrapRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rejection {
    pub code: RejectionCode,
    pub message: String,
}

impl RejectionCode {
    pub fn rejection(self) -> Rejection {
        let message = match self {
            Self::RelayDisabled => "This relay is disabled.",
            Self::SessionAdmissionDisabled => "This relay is not accepting new sessions.",
            Self::TunnelAdmissionDisabled => "This relay is not accepting new tunnels.",
            Self::ChannelAdmissionDisabled => "This relay is not accepting new channels.",
            Self::DestinationPolicyDenied => "This destination is denied by relay policy.",
            Self::BootstrapRejected => "Bootstrap negotiation was rejected.",
        };
        Rejection {
            code: self,
            message: message.into(),
        }
    }

    pub fn connect_status(self) -> Option<http::StatusCode> {
        match self {
            Self::RelayDisabled | Self::TunnelAdmissionDisabled => {
                Some(http::StatusCode::SERVICE_UNAVAILABLE)
            }
            Self::DestinationPolicyDenied => Some(http::StatusCode::FORBIDDEN),
            _ => None,
        }
    }

    pub fn header_value(self) -> http::HeaderValue {
        let value = serde_json::to_value(self).expect("rejection code serialization");
        http::HeaderValue::from_str(value.as_str().unwrap()).expect("ASCII code")
    }
}

impl Rejection {
    pub fn bootstrap(message: String) -> Self {
        Self {
            code: RejectionCode::BootstrapRejected,
            message,
        }
    }
    pub fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionRefused, self)
    }
    pub fn from_io(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}
impl std::error::Error for Rejection {}

/// Only a valid code/status pair is actionable. Unknown/malformed metadata is
/// never interpreted as authorization to wait indefinitely.
pub fn connect_error(status: http::StatusCode, headers: &http::HeaderMap) -> io::Error {
    let values = headers.get_all(CONNECT_REJECTION_HEADER);
    let mut values = values.iter();
    if let Some(value) = values.next() {
        let code = value.to_str().ok().and_then(|s| {
            serde_json::from_value::<RejectionCode>(serde_json::Value::String(s.into())).ok()
        });
        if values.next().is_none() {
            if let Some(code) = code.filter(|code| code.connect_status() == Some(status)) {
                return code.rejection().into_io();
            }
        }
        return io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid MONAD CONNECT rejection metadata",
        );
    }
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!("CONNECT rejected: {status}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_matching_known_connect_rejections_are_typed() {
        for code in [
            RejectionCode::RelayDisabled,
            RejectionCode::TunnelAdmissionDisabled,
            RejectionCode::DestinationPolicyDenied,
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert(CONNECT_REJECTION_HEADER, code.header_value());
            let error = connect_error(code.connect_status().unwrap(), &headers);
            assert_eq!(Rejection::from_io(&error).unwrap().code, code);
            assert!(
                Rejection::from_io(&connect_error(http::StatusCode::BAD_GATEWAY, &headers))
                    .is_none()
            );
            headers.append(CONNECT_REJECTION_HEADER, code.header_value());
            assert_eq!(
                connect_error(http::StatusCode::SERVICE_UNAVAILABLE, &headers).kind(),
                io::ErrorKind::InvalidData
            );
        }
        for value in [
            "FUTURE_CODE",
            "SESSION_ADMISSION_DISABLED",
            "",
            "not a code",
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert(CONNECT_REJECTION_HEADER, value.parse().unwrap());
            assert!(Rejection::from_io(&connect_error(
                http::StatusCode::SERVICE_UNAVAILABLE,
                &headers
            ))
            .is_none());
        }
        assert!(Rejection::from_io(&connect_error(
            http::StatusCode::SERVICE_UNAVAILABLE,
            &http::HeaderMap::new()
        ))
        .is_none());
    }

    #[test]
    fn bootstrap_rejection_is_minimal_and_structured() {
        let response = crate::bootstrap::BootstrapServerResponse::Reject {
            error: RejectionCode::RelayDisabled.rejection(),
        };
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::json!({"result": "reject", "error": {"code": "RELAY_DISABLED", "message": "This relay is disabled."}})
        );
        assert!(serde_json::from_value::<crate::bootstrap::BootstrapServerResponse>(serde_json::json!({"result":"reject", "error":{"code":"UNKNOWN", "message":"retry"}})).is_err());
    }
}
