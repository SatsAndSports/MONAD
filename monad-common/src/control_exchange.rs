//! Ordered ordinary control requests. Probes/advisories never consume slots.
use crate::protocol::{ServerErrorCode, ServerMessage};
use std::{collections::VecDeque, io};

pub const MAX_PENDING_REQUESTS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingRequest {
    Link {
        channel_id: String,
    },
    Payment {
        channel_id: String,
        balance_raw: u64,
        minimum_increment_msats: u64,
    },
    Unlink {
        channel_id: String,
    },
    Status,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    InitialStatus,
    Response(PendingRequest),
    Notification,
    Unsolicited,
}

#[derive(Debug, Default)]
pub struct ControlExchange {
    initialized: bool,
    pending: VecDeque<PendingRequest>,
    confirmed_paid: u64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn is_fatal_error(code: &ServerErrorCode) -> bool {
    code.is_fatal()
}

impl ControlExchange {
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
    pub fn enqueue(&mut self, request: PendingRequest) -> io::Result<()> {
        if !self.initialized {
            return Err(invalid("ordinary request before initial status"));
        }
        if self.pending.len() == MAX_PENDING_REQUESTS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "five control requests already outstanding",
            ));
        }
        self.pending.push_back(request);
        Ok(())
    }

    /// Validate before consuming the oldest request. Failure never skips ahead.
    /// A payment response uses P from earlier responses plus *its own* increment;
    /// later queued payments and probes are irrelevant to this response's floor.
    pub fn observe(&mut self, message: &ServerMessage) -> io::Result<Attribution> {
        if let ServerMessage::SessionStatus {
            active_in_rate,
            active_out_rate,
            ..
        } = message
        {
            if *active_in_rate == 0 || *active_out_rate == 0 {
                return Err(invalid("status pricing rates must be positive"));
            }
        }
        if let ServerMessage::Error { code, .. } = message {
            if is_fatal_error(code) {
                return Err(invalid("fatal relay control error"));
            }
        }
        if !self.initialized {
            if let ServerMessage::ExtensionNotification(_) = message {
                return Ok(Attribution::Notification);
            }
            let ServerMessage::SessionStatus {
                total_paid_millisats,
                ..
            } = message
            else {
                return Err(invalid("first relay control message must be SessionStatus"));
            };
            self.initialized = true;
            self.confirmed_paid = *total_paid_millisats;
            return Ok(Attribution::InitialStatus);
        }
        match message {
            ServerMessage::SessionStatus {
                total_paid_millisats,
                linked_channel,
                ..
            } => {
                let Some(request) = self.pending.front() else {
                    return Ok(Attribution::Unsolicited);
                };
                let increment = match request {
                    PendingRequest::Link { channel_id } => {
                        if linked_channel
                            .as_ref()
                            .is_none_or(|c| &c.channel_id != channel_id)
                        {
                            return Err(invalid(
                                "link response does not identify requested channel",
                            ));
                        }
                        0
                    }
                    PendingRequest::Payment {
                        channel_id,
                        balance_raw,
                        minimum_increment_msats,
                    } => {
                        if !linked_channel.as_ref().is_some_and(|c| {
                            &c.channel_id == channel_id && c.balance_raw == *balance_raw
                        }) {
                            return Err(invalid(
                                "payment response does not match submitted channel and balance",
                            ));
                        }
                        *minimum_increment_msats
                    }
                    PendingRequest::Unlink { .. } => {
                        if linked_channel.is_some() {
                            return Err(invalid("unlink response still reports a linked channel"));
                        }
                        0
                    }
                    PendingRequest::Status => 0,
                };
                let expected = self
                    .confirmed_paid
                    .checked_add(increment)
                    .ok_or_else(|| invalid("expected session paid total overflow"))?;
                if *total_paid_millisats < expected {
                    return Err(invalid(
                        "relay session paid total is smaller than expected for this response",
                    ));
                }
                self.confirmed_paid = *total_paid_millisats;
                Ok(Attribution::Response(self.pending.pop_front().unwrap()))
            }
            ServerMessage::Error { .. } => Ok(match self.pending.pop_front() {
                Some(request) => Attribution::Response(request),
                None => Attribution::Unsolicited,
            }),
            _ => Ok(Attribution::Notification),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::LinkedChannelStatus;
    fn status(paid: u64, linked: Option<(&str, u64)>) -> ServerMessage {
        ServerMessage::SessionStatus {
            receiver_pubkey: "receiver".into(),
            advertisements: Default::default(),
            linked_channel: linked.map(|(id, balance)| LinkedChannelStatus {
                channel_id: id.into(),
                balance_raw: balance,
                capacity_raw: 10000,
                unit: "msat".into(),
            }),
            active_in_rate: 1,
            active_out_rate: 1,
            session_total_bytes_in: 0,
            session_total_bytes_out: 0,
            total_paid_millisats: paid,
            remaining_milli_sats: paid as i64,
            paused: paid == 0,
            open_connects: 0,
            total_connects: 0,
            failed_connects: 0,
        }
    }
    fn payment(balance: u64, increment: u64) -> PendingRequest {
        PendingRequest::Payment {
            channel_id: "A".into(),
            balance_raw: balance,
            minimum_increment_msats: increment,
        }
    }
    fn initialized(paid: u64) -> ControlExchange {
        let mut exchange = ControlExchange::default();
        assert_eq!(
            exchange.observe(&status(paid, None)).unwrap(),
            Attribution::InitialStatus
        );
        exchange
    }

    fn extension(name: &str) -> ServerMessage {
        ServerMessage::ExtensionNotification(crate::protocol::ExtensionNotification {
            name: name.into(),
            rest: serde_json::Map::from_iter([(
                "arbitrary".into(),
                serde_json::json!({"optional": null}),
            )]),
        })
    }

    #[test]
    fn extensions_are_notifications_before_and_after_initialization() {
        let mut exchange = ControlExchange::default();
        assert_eq!(
            exchange.observe(&extension("before")).unwrap(),
            Attribution::Notification
        );
        assert_eq!(
            exchange.observe(&status(3, None)).unwrap(),
            Attribution::InitialStatus
        );
        exchange.enqueue(PendingRequest::Status).unwrap();
        assert_eq!(
            exchange.observe(&extension("after")).unwrap(),
            Attribution::Notification
        );
        assert_eq!(exchange.pending_len(), 1);
        assert_eq!(
            exchange.observe(&status(3, None)).unwrap(),
            Attribution::Response(PendingRequest::Status)
        );
    }

    #[test]
    fn five_requests_with_probes_and_advisories_keep_exact_order() {
        let mut exchange = initialized(0);
        let requests = [
            PendingRequest::Link {
                channel_id: "A".into(),
            },
            payment(10, 10),
            PendingRequest::Status,
            payment(15, 5),
            PendingRequest::Unlink {
                channel_id: "A".into(),
            },
        ];
        for request in &requests {
            exchange.enqueue(request.clone()).unwrap();
        }
        assert_eq!(
            exchange.enqueue(PendingRequest::Status).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let replies = [
            status(0, Some(("A", 0))),
            status(12, Some(("A", 10))),
            status(12, Some(("A", 10))),
            status(17, Some(("A", 15))),
            status(17, None),
        ];
        for (i, (request, reply)) in requests.into_iter().zip(replies).enumerate() {
            for notification in [
                ServerMessage::Pong {
                    nonce: "opaque".into(),
                },
                ServerMessage::ChannelReleaseRequested {
                    channel_id: "A".into(),
                },
            ] {
                assert_eq!(
                    exchange.observe(&notification).unwrap(),
                    Attribution::Notification
                );
                assert_eq!(exchange.pending_len(), 5 - i);
            }
            assert_eq!(
                exchange.observe(&reply).unwrap(),
                Attribution::Response(request)
            );
        }
        assert!(exchange.is_empty());
        assert_eq!(
            exchange.observe(&status(999, None)).unwrap(),
            Attribution::Unsolicited
        );
        assert_eq!(exchange.confirmed_paid, 17);
    }

    #[test]
    fn earlier_status_excludes_later_payment_but_payment_must_meet_its_floor() {
        let mut exchange = initialized(1000);
        exchange.enqueue(PendingRequest::Status).unwrap();
        exchange.enqueue(payment(1500, 500)).unwrap();
        assert_eq!(
            exchange.observe(&status(1000, Some(("A", 1000)))).unwrap(),
            Attribution::Response(PendingRequest::Status)
        );
        assert!(exchange.observe(&status(1499, Some(("A", 1500)))).is_err());
        assert_eq!(exchange.pending_len(), 1);
        assert_eq!(exchange.confirmed_paid, 1000);
    }

    #[test]
    fn mismatched_response_is_fatal_not_skipped_to_a_later_request() {
        let mut exchange = initialized(0);
        exchange.enqueue(payment(10, 10)).unwrap();
        exchange.enqueue(payment(20, 10)).unwrap();
        for wrong in [status(20, Some(("A", 20))), status(10, Some(("B", 10)))] {
            assert!(exchange.observe(&wrong).is_err());
            assert_eq!(exchange.pending_len(), 2);
        }
        let mut exchange = initialized(0);
        exchange
            .enqueue(PendingRequest::Unlink {
                channel_id: "A".into(),
            })
            .unwrap();
        assert!(exchange.observe(&status(0, Some(("B", 0)))).is_err());
    }

    #[test]
    fn nonfatal_failure_consumes_one_entry_without_cancelling_successors() {
        let mut exchange = initialized(100);
        exchange.enqueue(payment(110, 10)).unwrap();
        exchange.enqueue(payment(120, 10)).unwrap();
        let error = ServerMessage::Error {
            code: ServerErrorCode::PaymentInvalid,
            message: "untrusted text".into(),
        };
        assert_eq!(
            exchange.observe(&error).unwrap(),
            Attribution::Response(payment(110, 10))
        );
        assert_eq!(exchange.confirmed_paid, 100);
        assert_eq!(
            exchange.observe(&status(110, Some(("A", 120)))).unwrap(),
            Attribution::Response(payment(120, 10))
        );
        assert_eq!(exchange.observe(&error).unwrap(), Attribution::Unsolicited);
    }

    #[test]
    fn payment_conflict_is_an_ordered_nonfatal_response() {
        let mut exchange = initialized(100);
        exchange.enqueue(payment(110, 10)).unwrap();
        exchange.enqueue(PendingRequest::Status).unwrap();
        let conflict = ServerMessage::Error {
            code: ServerErrorCode::PaymentConflict,
            message: "conflict".into(),
        };
        assert_eq!(
            exchange.observe(&conflict).unwrap(),
            Attribution::Response(payment(110, 10))
        );
        assert_eq!(
            exchange.observe(&status(100, Some(("A", 100)))).unwrap(),
            Attribution::Response(PendingRequest::Status)
        );
    }

    #[test]
    fn lower_paid_query_or_unlink_response_is_fatal() {
        for request in [
            PendingRequest::Status,
            PendingRequest::Unlink {
                channel_id: "A".into(),
            },
        ] {
            let mut exchange = initialized(100);
            exchange.enqueue(request).unwrap();
            assert!(exchange.observe(&status(99, None)).is_err());
            assert_eq!(exchange.pending_len(), 1);
        }
    }

    #[test]
    fn initial_message_and_fatal_errors_are_checked_independently_of_fifo() {
        for message in [
            ServerMessage::Pong {
                nonce: "early".into(),
            },
            ServerMessage::ChannelEvicted {
                channel_id: "A".into(),
                scope: crate::protocol::ChannelEvictionScope::Session,
            },
            ServerMessage::Error {
                code: ServerErrorCode::PaymentInvalid,
                message: String::new(),
            },
        ] {
            assert!(ControlExchange::default().observe(&message).is_err());
        }
        for queued in [false, true] {
            let mut exchange = initialized(0);
            if queued {
                exchange.enqueue(PendingRequest::Status).unwrap();
            }
            assert!(exchange
                .observe(&ServerMessage::Error {
                    code: ServerErrorCode::ControlInvalidMessage,
                    message: String::new()
                })
                .is_err());
        }
    }
}
