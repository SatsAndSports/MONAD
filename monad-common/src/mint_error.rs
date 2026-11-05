use serde::{Deserialize, Serialize};

/// HTTP-origin rejection evidence. Never retains the untrusted response body.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintHttpRejection {
    pub status: u16,
    pub code: Option<u64>,
}

impl MintHttpRejection {
    pub fn from_body(status: u16, body: &str) -> Self {
        let code = cdk_spilman::MintResponse {
            status,
            body: body.to_owned(),
        }
        .into_result()
        .err()
        .and_then(|e| e.rejection().map(|r| u64::from(r.code())));
        Self { status, code }
    }

    pub fn inactive_output_keyset(&self) -> bool {
        self.status == 400 && self.code == Some(12002)
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

/// Read a complete decoded response with a hard cap and strict UTF-8. Never
/// interpret partial data as rejection evidence. Request callers set a deadline.
pub async fn read_mint_response(
    mut response: reqwest::Response,
) -> Result<String, cdk_spilman::MintRequestError> {
    use cdk_spilman::{MintRequestError, MintResponse};
    const LIMIT: usize = 4 * 1024 * 1024;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| MintRequestError::transport("mint response read failed; outcome uncertain"))?
    {
        if chunk.len() > LIMIT - body.len() {
            return Err(MintRequestError::transport(
                "mint response exceeds 4 MiB; outcome uncertain",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let body = String::from_utf8(body).map_err(|_| {
        MintRequestError::transport("mint response is not UTF-8; outcome uncertain")
    })?;
    // Classify original complete evidence, then redact human text before passing
    // errors to journal/diagnostic code. Never persist or log arbitrary mint bodies.
    match (MintResponse { status, body }).into_result() {
        Ok(body) => Ok(body),
        Err(error) => {
            if let Some(rejection) = error.rejection() {
                return (MintResponse { status, body: serde_json::json!({"code": rejection.code(), "detail": "mint rejected request"}).to_string() }).into_result();
            }
            Err(MintRequestError::Http {
                response: MintResponse {
                    status,
                    body: String::new(),
                },
            })
        }
    }
}

/// Preserve the existing journal's compact typed rejection evidence without
/// widening its retry policy or retaining untrusted body/detail text.
pub fn recovery_error(error: cdk_spilman::MintRequestError) -> anyhow::Error {
    match error.rejection() {
        Some(rejection) => MintHttpRejection {
            status: rejection.status(),
            code: Some(u64::from(rejection.code())),
        }
        .into(),
        None => error.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_authority_requires_numeric_code_and_client_error_status() {
        for (status, body, expected) in [
            (400, r#"{"code":12002,"detail":"secret-sentinel"}"#, true),
            (409, r#"{"code":12002,"detail":"secret-sentinel"}"#, false),
            (
                400,
                r#"{"code":12002,"code":12002,"detail":"secret-sentinel"}"#,
                false,
            ),
            (400, r#"{"code":12002}"#, false),
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

    #[tokio::test]
    async fn bounded_reader_rejects_invalid_utf8_and_oversize_without_rejection_authority() {
        for body in [vec![0xff], vec![b'x'; 4 * 1024 * 1024 + 1]] {
            let response = http::Response::builder()
                .status(400)
                .body(reqwest::Body::from(body))
                .unwrap();
            let error = read_mint_response(response.into()).await.unwrap_err();
            assert!(matches!(
                error,
                cdk_spilman::MintRequestError::Transport { .. }
            ));
            assert!(error.rejection().is_none());
        }
        let response = http::Response::builder()
            .status(200)
            .body(reqwest::Body::from(vec![b'x'; 4 * 1024 * 1024]))
            .unwrap();
        assert_eq!(
            read_mint_response(response.into()).await.unwrap().len(),
            4 * 1024 * 1024
        );
    }

    #[tokio::test]
    async fn bounded_reader_preserves_only_valid_rejection_codes_and_redacts_bodies() {
        for (status, body, code) in [
            (
                400,
                r#"{"code":12002,"detail":"private-sentinel"}"#,
                Some(12002),
            ),
            (500, r#"{"code":12002,"detail":"private-sentinel"}"#, None),
            (
                400,
                r#"{"code":12002,"code":11001,"detail":"private-sentinel"}"#,
                None,
            ),
        ] {
            let response = http::Response::builder()
                .status(status)
                .body(reqwest::Body::from(body))
                .unwrap();
            let error = read_mint_response(response.into()).await.unwrap_err();
            assert_eq!(error.rejection().map(|r| r.code()), code);
            assert!(!format!("{error:?}").contains("private-sentinel"));
        }
    }

    #[tokio::test]
    async fn truncated_and_timed_out_bodies_never_authorize_retry() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for stall in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(socket.read(&mut request).await.unwrap() > 0);
                socket.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n{\"code\":12002,\"detail\":\"private-sentinel\"}").await.unwrap();
                if stall {
                    std::future::pending::<()>().await;
                }
            });
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(250))
                .build()
                .unwrap();
            let response = client.get(url).send().await.unwrap();
            let error = read_mint_response(response).await.unwrap_err();
            assert!(matches!(
                error,
                cdk_spilman::MintRequestError::Transport { .. }
            ));
            assert!(!format!("{error:?}").contains("private-sentinel"));
            task.abort();
            let _ = task.await;
        }
    }
}
