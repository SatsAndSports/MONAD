use std::future::Future;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedOutputKeyset {
    pub id: String,
    pub info_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysetRetryPhase {
    First,
    Retry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetRetrySuccess<A, T> {
    pub attempt: A,
    pub value: T,
    pub retried: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysetRetryError<A, P, S> {
    Select { phase: KeysetRetryPhase, error: P },
    Prepare { phase: KeysetRetryPhase, error: P },
    Refresh { error: P },
    Cleanup { error: P },
    Submit { attempt: A, error: S, retried: bool },
}

pub fn with_active_keyset_retry<
    K,
    A,
    T,
    P,
    S,
    Select,
    Prepare,
    Submit,
    ShouldRetry,
    Refresh,
    Cleanup,
>(
    mut select: Select,
    mut prepare: Prepare,
    mut submit: Submit,
    mut should_retry: ShouldRetry,
    mut refresh: Refresh,
    mut cleanup: Cleanup,
) -> Result<KeysetRetrySuccess<A, T>, KeysetRetryError<A, P, S>>
where
    Select: FnMut(KeysetRetryPhase) -> Result<K, P>,
    Prepare: FnMut(K, KeysetRetryPhase) -> Result<A, P>,
    Submit: FnMut(&A) -> Result<T, S>,
    ShouldRetry: FnMut(&S) -> bool,
    Refresh: FnMut() -> Result<(), P>,
    Cleanup: FnMut(&A, &S) -> Result<(), P>,
{
    let keyset = select(KeysetRetryPhase::First).map_err(|error| KeysetRetryError::Select {
        phase: KeysetRetryPhase::First,
        error,
    })?;
    let attempt =
        prepare(keyset, KeysetRetryPhase::First).map_err(|error| KeysetRetryError::Prepare {
            phase: KeysetRetryPhase::First,
            error,
        })?;

    match submit(&attempt) {
        Ok(value) => Ok(KeysetRetrySuccess {
            attempt,
            value,
            retried: false,
        }),
        Err(error) if should_retry(&error) => {
            cleanup(&attempt, &error).map_err(|error| KeysetRetryError::Cleanup { error })?;
            refresh().map_err(|error| KeysetRetryError::Refresh { error })?;
            let keyset =
                select(KeysetRetryPhase::Retry).map_err(|error| KeysetRetryError::Select {
                    phase: KeysetRetryPhase::Retry,
                    error,
                })?;
            let attempt = prepare(keyset, KeysetRetryPhase::Retry).map_err(|error| {
                KeysetRetryError::Prepare {
                    phase: KeysetRetryPhase::Retry,
                    error,
                }
            })?;
            match submit(&attempt) {
                Ok(value) => Ok(KeysetRetrySuccess {
                    attempt,
                    value,
                    retried: true,
                }),
                Err(error) => Err(KeysetRetryError::Submit {
                    attempt,
                    error,
                    retried: true,
                }),
            }
        }
        Err(error) => Err(KeysetRetryError::Submit {
            attempt,
            error,
            retried: false,
        }),
    }
}

pub async fn with_active_keyset_retry_async<
    K,
    A,
    T,
    P,
    S,
    Select,
    Prepare,
    Submit,
    SubmitFuture,
    ShouldRetry,
    Refresh,
    RefreshFuture,
    Cleanup,
>(
    mut select: Select,
    mut prepare: Prepare,
    mut submit: Submit,
    mut should_retry: ShouldRetry,
    mut refresh: Refresh,
    mut cleanup: Cleanup,
) -> Result<KeysetRetrySuccess<A, T>, KeysetRetryError<A, P, S>>
where
    A: Clone,
    Select: FnMut(KeysetRetryPhase) -> Result<K, P>,
    Prepare: FnMut(K, KeysetRetryPhase) -> Result<A, P>,
    Submit: FnMut(A) -> SubmitFuture,
    SubmitFuture: Future<Output = Result<T, S>>,
    ShouldRetry: FnMut(&S) -> bool,
    Refresh: FnMut() -> RefreshFuture,
    RefreshFuture: Future<Output = Result<(), P>>,
    Cleanup: FnMut(&A, &S) -> Result<(), P>,
{
    let keyset = select(KeysetRetryPhase::First).map_err(|error| KeysetRetryError::Select {
        phase: KeysetRetryPhase::First,
        error,
    })?;
    let attempt =
        prepare(keyset, KeysetRetryPhase::First).map_err(|error| KeysetRetryError::Prepare {
            phase: KeysetRetryPhase::First,
            error,
        })?;

    match submit(attempt.clone()).await {
        Ok(value) => Ok(KeysetRetrySuccess {
            attempt,
            value,
            retried: false,
        }),
        Err(error) if should_retry(&error) => {
            cleanup(&attempt, &error).map_err(|error| KeysetRetryError::Cleanup { error })?;
            refresh()
                .await
                .map_err(|error| KeysetRetryError::Refresh { error })?;
            let keyset =
                select(KeysetRetryPhase::Retry).map_err(|error| KeysetRetryError::Select {
                    phase: KeysetRetryPhase::Retry,
                    error,
                })?;
            let attempt = prepare(keyset, KeysetRetryPhase::Retry).map_err(|error| {
                KeysetRetryError::Prepare {
                    phase: KeysetRetryPhase::Retry,
                    error,
                }
            })?;
            match submit(attempt.clone()).await {
                Ok(value) => Ok(KeysetRetrySuccess {
                    attempt,
                    value,
                    retried: true,
                }),
                Err(error) => Err(KeysetRetryError::Submit {
                    attempt,
                    error,
                    retried: true,
                }),
            }
        }
        Err(error) => Err(KeysetRetryError::Submit {
            attempt,
            error,
            retried: false,
        }),
    }
}
