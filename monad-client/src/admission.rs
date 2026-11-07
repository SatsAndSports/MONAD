use monad_common::rejection::{Rejection, RejectionCode};
use serde::Serialize;
use std::{fmt, io};

pub const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
pub const ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Hop indices in monitoring are one-based. The issuer of an onward CONNECT
/// refusal is the preceding relay, not the session we were trying to establish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RouteRefusal {
    pub refusing_hop: usize,
    pub target_hop: usize,
    pub operation: &'static str,
    pub destination: String,
    pub rejection: Rejection,
}

impl RouteRefusal {
    pub fn from_io(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
    pub fn is_policy_denial(error: &io::Error) -> bool {
        Self::from_io(error)
            .is_some_and(|r| r.rejection.code == RejectionCode::DestinationPolicyDenied)
    }
    pub(crate) fn is_administrative(&self) -> bool {
        matches!(
            (self.operation, self.rejection.code),
            (
                "session",
                RejectionCode::RelayDisabled | RejectionCode::SessionAdmissionDisabled
            ) | (
                "connect",
                RejectionCode::RelayDisabled | RejectionCode::TunnelAdmissionDisabled
            )
        )
    }
    pub(crate) fn annotate(
        error: io::Error,
        refusing_hop: usize,
        target_hop: usize,
        operation: &'static str,
        destination: String,
    ) -> io::Error {
        match Rejection::from_io(&error) {
            Some(rejection) => io::Error::new(
                error.kind(),
                Self {
                    refusing_hop,
                    target_hop,
                    operation,
                    destination,
                    rejection: rejection.clone(),
                },
            ),
            None => error,
        }
    }
}

impl fmt::Display for RouteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hop {} refused {} for hop {} ({}): {}",
            self.refusing_hop, self.operation, self.target_hop, self.destination, self.rejection
        )
    }
}
impl std::error::Error for RouteRefusal {}

/// An observed failure while establishing a known target session. Legacy HTTP
/// refusals retain their status; local transport collapse never identifies a
/// culprit among the preceding relays.
#[derive(Debug)]
pub struct RouteAttemptFailure {
    pub target_hop: usize,
    pub operation: &'static str,
    pub code: Option<RejectionCode>,
    pub http_status: Option<u16>,
    source: io::Error,
}
impl RouteAttemptFailure {
    pub fn from_io(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref()
    }
    pub(crate) fn annotate(
        error: io::Error,
        target_hop: usize,
        operation: &'static str,
    ) -> io::Error {
        if RouteRefusal::from_io(&error).is_some() || Self::from_io(&error).is_some() {
            return error;
        }
        let code = monad_common::connect_failure::ConnectFailure::from_io(&error).map(|e| e.code);
        let http_status = error
            .get_ref()
            .and_then(|e| e.downcast_ref::<monad_common::rejection::ConnectRejection>())
            .map(|e| e.0.as_u16());
        io::Error::new(
            error.kind(),
            Self {
                target_hop,
                operation,
                code,
                http_status,
                source: error,
            },
        )
    }
}
impl fmt::Display for RouteAttemptFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} attempt for hop {} failed: {}",
            self.operation, self.target_hop, self.source
        )
    }
}
impl std::error::Error for RouteAttemptFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdmissionWait {
    pub refusal: RouteRefusal,
    pub retry_at_unix_ms: u64,
    pub retry_interval_ms: u64,
}
