//! Wire-level interoperability and bounded framing for the private SOCKS method.
use monad_client::{
    socks,
    socks_client::{self, SocksClientError},
    socks_diagnostics::{
        SocksDiagnostic, SocksReplyMode, ACK, HELLO, MAX_DIAGNOSTIC_BYTES, METHOD,
    },
};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(2);

fn detail() -> SocksDiagnostic {
    SocksDiagnostic {
        context: None,
        last_route_failure: None,
        stage: "connect".into(),
        code: Some("SESSION_CONNECT_SETUP_LIMIT_REACHED".into()),
        message: "This session has reached its concurrent CONNECT setup limit.".into(),
        http_status: Some(429),
    }
}

async fn listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

async fn accept_private(listener: TcpListener) -> TcpStream {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [5, 1, METHOD]);
    stream.write_all(&[5, METHOD]).await.unwrap();
    let mut hello = [0; 6];
    stream.read_exact(&mut hello).await.unwrap();
    assert_eq!(&hello, HELLO);
    stream.write_all(&ACK).await.unwrap();
    let mut request = [0; 10];
    stream.read_exact(&mut request).await.unwrap();
    assert_eq!(request, [5, 1, 0, 1, 127, 0, 0, 1, 1, 187]);
    stream
}

async fn receive_failure(length: u32, bytes: Vec<u8>, fragmented: bool) -> SocksClientError {
    let listener = listener().await;
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accept_private(listener).await;
        let mut wire = vec![5, 5, 0, 1, 0, 0, 0, 0, 0, 0];
        wire.extend(length.to_be_bytes());
        wire.extend(bytes);
        if fragmented {
            for chunk in wire.chunks(3) {
                stream.write_all(chunk).await.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        } else {
            stream.write_all(&wire).await.unwrap();
        }
        stream.shutdown().await.unwrap();
    });
    let error = socks_client::connect_with_diagnostics(addr, "127.0.0.1:443", LIMIT)
        .await
        .unwrap_err();
    server.await.unwrap();
    error
}

#[tokio::test]
async fn success_in_both_modes_preserves_ipv4_ipv6_domains_and_first_application_bytes() {
    for target in ["127.0.0.1:443", "[::1]:443", "example.com:443"] {
        for extended in [false, true] {
            let listener = listener().await;
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = socks::socks5_handshake_with_diagnostics(&mut stream)
                    .await
                    .unwrap();
                assert_eq!(request.authority, target);
                assert_eq!(
                    request.reply_mode,
                    if extended {
                        SocksReplyMode::DiagnosticsV1
                    } else {
                        SocksReplyMode::Standard
                    }
                );
                socks::send_reply(&mut stream, 0, "0.0.0.0", 0)
                    .await
                    .unwrap();
                // Looks like a length/magic prefix; must remain application data.
                stream.write_all(b"\0\0\0\x06MONAD\x01").await.unwrap();
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).await.unwrap();
                assert_eq!(bytes, b"client data");
            });
            let mut connection = if extended {
                socks_client::connect_with_diagnostics(addr, target, LIMIT).await
            } else {
                socks_client::connect(addr, target, LIMIT).await
            }
            .unwrap();
            let mut first = [0; 10];
            connection.stream.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"\0\0\0\x06MONAD\x01");
            connection.stream.write_all(b"client data").await.unwrap();
            connection.stream.shutdown().await.unwrap();
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn standard_failure_has_no_diagnostic_bytes() {
    let listener = listener().await;
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = socks::socks5_handshake_with_diagnostics(&mut stream)
            .await
            .unwrap();
        assert_eq!(request.reply_mode, SocksReplyMode::Standard);
        socks::send_failure(&mut stream, request.reply_mode, 5, &detail())
            .await
            .unwrap();
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut selection = [0; 2];
    stream.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, 0]);
    stream
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 1, 187])
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(LIMIT, stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
    server.await.unwrap();
}

#[tokio::test]
async fn required_diagnostics_never_falls_back_to_an_old_proxy() {
    let listener = listener().await;
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(socks::socks5_handshake(&mut stream).await.is_err());
    });
    assert_eq!(
        socks_client::connect_with_diagnostics(addr, "127.0.0.1:443", LIMIT)
            .await
            .unwrap_err(),
        SocksClientError::Rejected {
            code: 255,
            stage: "method negotiation"
        }
    );
    server.await.unwrap();
}

#[tokio::test]
async fn private_method_identification_and_version_are_checked() {
    for hello in [*b"OTHER\x01", *b"MONAD\x02"] {
        let listener = listener().await;
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(socks::socks5_handshake_with_diagnostics(&mut stream)
                .await
                .is_err());
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&[5, 2, 0, METHOD]).await.unwrap();
        let mut selection = [0; 2];
        stream.read_exact(&mut selection).await.unwrap();
        assert_eq!(selection, [5, METHOD]);
        stream.write_all(&hello).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, [1, 1]);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn fragmented_diagnostics_preserve_structured_refusal() {
    let diagnostic = detail();
    let payload = serde_json::to_vec(&diagnostic).unwrap();
    assert_eq!(
        receive_failure(payload.len() as u32, payload, true).await,
        SocksClientError::RejectedWithDiagnostic {
            code: 5,
            diagnostic: Box::new(diagnostic)
        }
    );
}

#[tokio::test]
async fn unknown_future_fields_and_codes_are_advisory_and_maximum_frame_is_accepted() {
    let mut value = serde_json::to_value(detail()).unwrap();
    value["code"] = "FUTURE_REASON".into();
    value["extra"] = "".into();
    let size = serde_json::to_vec(&value).unwrap().len();
    value["extra"] = "x".repeat(MAX_DIAGNOSTIC_BYTES - size).into();
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(bytes.len(), MAX_DIAGNOSTIC_BYTES);
    let SocksClientError::RejectedWithDiagnostic { code, diagnostic } =
        receive_failure(bytes.len() as u32, bytes, false).await
    else {
        panic!("valid diagnostic rejected");
    };
    assert_eq!(code, 5);
    assert_eq!(diagnostic.code.as_deref(), Some("FUTURE_REASON"));
}

#[tokio::test]
async fn malformed_missing_truncated_and_oversized_diagnostics_keep_the_reply_code() {
    let valid = serde_json::to_vec(&detail()).unwrap();
    let mut control = detail();
    control.message = "\x1b[31munsafe".into();
    let mut oversized_message = detail();
    oversized_message.message = "x".repeat(1025);
    let cases = [
        (0, vec![]),
        ((MAX_DIAGNOSTIC_BYTES + 1) as u32, vec![]),
        (u32::MAX, vec![]),
        (1, vec![255]),
        (1, vec![b'{']),
        (valid.len() as u32, vec![]),
        (valid.len() as u32, valid[..valid.len() - 1].to_vec()),
        (2, b"{}".to_vec()),
        {
            let bytes = serde_json::to_vec(&control).unwrap();
            (bytes.len() as u32, bytes)
        },
        {
            let bytes = serde_json::to_vec(&oversized_message).unwrap();
            (bytes.len() as u32, bytes)
        },
    ];
    for (length, bytes) in cases {
        let error = receive_failure(length, bytes, false).await;
        assert!(
            matches!(error, SocksClientError::DiagnosticFailure { code: 5, .. }),
            "{error:?}"
        );
        assert!(!error.to_string().contains("unsafe"));
    }
}

#[tokio::test]
async fn diagnostic_body_timeout_preserves_refusal_and_closes_connection() {
    let listener = listener().await;
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut stream = accept_private(listener).await;
        stream
            .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        stream.write_u32(100).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(5), stream.read(&mut [0]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    let error =
        socks_client::connect_with_diagnostics(addr, "127.0.0.1:443", Duration::from_secs(1))
            .await
            .unwrap_err();
    assert!(
        matches!(error, SocksClientError::DiagnosticFailure { code: 5, ref reason } if reason.contains("timed out"))
    );
    server.await.unwrap();
}

#[tokio::test]
async fn server_bounds_private_subnegotiation() {
    let listener = listener().await;
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let error = socks::socks5_handshake_with_diagnostics(&mut stream)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[5, 1, METHOD]).await.unwrap();
    let mut selection = [0; 2];
    stream.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, METHOD]);
    assert_eq!(
        timeout(Duration::from_secs(7), stream.read(&mut [0]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    server.await.unwrap();
}
#[tokio::test]
async fn refusal_with_missing_or_partial_length_is_not_a_plain_socks_fallback() {
    for prefix in [vec![], vec![0, 0]] {
        let listener = listener().await;
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut stream = accept_private(listener).await;
            stream
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            stream.write_all(&prefix).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        assert!(matches!(
            socks_client::connect_with_diagnostics(addr, "127.0.0.1:443", LIMIT).await,
            Err(SocksClientError::DiagnosticFailure { code: 5, .. })
        ));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn client_rejects_unoffered_method_and_bad_extension_acknowledgements() {
    for (method, acknowledgement) in [(0, None), (METHOD, Some([2, 0])), (METHOD, Some([1, 1]))] {
        let listener = listener().await;
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, METHOD]);
            stream.write_all(&[5, method]).await.unwrap();
            if let Some(ack) = acknowledgement {
                let mut hello = [0; 6];
                stream.read_exact(&mut hello).await.unwrap();
                assert_eq!(&hello, HELLO);
                stream.write_all(&ack).await.unwrap();
            }
            // Negotiation failure must not dispatch a CONNECT or retry.
            assert_eq!(
                timeout(LIMIT, stream.read(&mut [0]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        });
        assert!(matches!(
            socks_client::connect_with_diagnostics(addr, "127.0.0.1:443", LIMIT).await,
            Err(SocksClientError::Protocol(_))
        ));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn negotiated_request_rejection_has_a_complete_diagnostic() {
    let listener = listener().await;
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(socks::socks5_handshake_with_diagnostics(&mut stream)
            .await
            .is_err());
    });
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[5, 1, METHOD]).await.unwrap();
    let mut selection = [0; 2];
    stream.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, METHOD]);
    stream.write_all(HELLO).await.unwrap();
    stream.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, ACK);
    stream.write_all(&[5, 2]).await.unwrap(); // BIND is unsupported.
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 7);
    let length = stream.read_u32().await.unwrap() as usize;
    assert!(length <= MAX_DIAGNOSTIC_BYTES);
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    let diagnostic: SocksDiagnostic = serde_json::from_slice(&payload).unwrap();
    assert_eq!(diagnostic.stage, "request");
    assert_eq!(diagnostic.code, None);
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    server.await.unwrap();
}
#[tokio::test]
async fn attribution_roundtrips_and_local_failure_cannot_claim_a_reporting_relay() {
    use monad_client::socks_diagnostics::{FailureContext, RouteFailureDetail};
    let mut diagnostic = detail();
    diagnostic.context = Some(FailureContext {
        origin: "relay".into(),
        operation: "exit_connect".into(),
        reporting_hop: Some(3),
        target_hop: None,
    });
    diagnostic.last_route_failure = Some(RouteFailureDetail {
        http_status: None,
        context: FailureContext {
            origin: "local".into(),
            operation: "relay_connect".into(),
            reporting_hop: None,
            target_hop: Some(2),
        },
        code: None,
        message: "An earlier local connection attempt failed.".into(),
    });
    let bytes = serde_json::to_vec(&diagnostic).unwrap();
    assert_eq!(
        receive_failure(bytes.len() as u32, bytes, false).await,
        SocksClientError::RejectedWithDiagnostic {
            code: 5,
            diagnostic: Box::new(diagnostic.clone())
        }
    );
    diagnostic.context.as_mut().unwrap().origin = "local".into();
    let bytes = serde_json::to_vec(&diagnostic).unwrap();
    assert!(matches!(
        receive_failure(bytes.len() as u32, bytes, false).await,
        SocksClientError::DiagnosticFailure { code: 5, .. }
    ));
}
