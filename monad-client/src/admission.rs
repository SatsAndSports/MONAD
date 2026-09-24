use monad_common::rejection::{Rejection, RejectionCode};
use serde::Serialize;
use std::{fmt, io};

pub const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
pub const ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Hop indices in monitoring are one-based. The issuer of an onward CONNECT
/// refusal is the preceding relay, not the session we were trying to establish.
#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct AdmissionWait {
    pub refusal: RouteRefusal,
    pub retry_at_unix_ms: u64,
    pub retry_interval_ms: u64,
}
