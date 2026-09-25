use std::time::Duration;

use backoff::backoff::Backoff;
use backoff::ExponentialBackoffBuilder;

use crate::BeanStreamError;

/// Why a failed attempt is considered worth repeating.
///
/// Produced by [`classify_error`] and consumed by
/// [`RetryConfig::should_retry`]. The distinction that matters is transient
/// (network, server, throttling) versus permanent (validation): retrying a
/// private-network rejection or a bad header will fail identically every time,
/// so those map to [`ErrorKind::Other`] and are not retried by the default
/// configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The request timed out — transient.
    NetworkTimeout,
    /// The server answered 5xx — usually transient.
    ServerError,
    /// The server answered 429, or a local rate limiter refused — retry after a
    /// delay.
    RateLimited,
    /// The transport failed: connection refused, reset, TLS failure. Transient,
    /// though repeated failures may indicate a real outage.
    Connection,
    /// Anything else, including every validation failure. Permanent by default.
    Other,
}

/// Automatic retry with exponential backoff.
///
/// Attach with [`HttpRequest::with_retry`](crate::HttpRequest::with_retry).
/// Retries happen inside `send()`: the DNS pin is computed once before the retry
/// loop, so every attempt connects to the same validated addresses rather than
/// re-resolving (which would reopen the rebinding window).
///
/// Which failures are repeated is controlled by [`Self::retry_on`], matched
/// either against an error via [`Self::should_retry`] or against a response
/// status via [`Self::should_retry_status`].
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Total attempts including the first, so `1` means "never retry".
    pub max_attempts: u32,
    /// Delay before the second attempt. Subsequent delays grow from here.
    pub initial_delay: Duration,
    /// Ceiling for the delay, so backoff cannot grow without bound.
    pub max_delay: Duration,
    /// When `true`, delays double between attempts; when `false`, the delay
    /// stays at [`Self::initial_delay`].
    pub exponential_backoff: bool,
    /// The error classes that trigger a retry. Defaults to the three transient
    /// kinds; note that adding [`ErrorKind::Other`] would also retry permanent
    /// validation failures, which is rarely what you want.
    pub retry_on: Vec<ErrorKind>,
}

impl Default for RetryConfig {
    /// Three attempts, starting at 100ms and backing off exponentially with a
    /// 30-second ceiling, retrying timeouts, 5xx responses and rate limiting.
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            exponential_backoff: true,
            retry_on: vec![
                ErrorKind::NetworkTimeout,
                ErrorKind::ServerError,
                ErrorKind::RateLimited,
            ],
        }
    }
}

impl RetryConfig {
    /// Whether `error` belongs to a class listed in [`Self::retry_on`].
    pub fn should_retry(&self, error: &BeanStreamError) -> bool {
        self.retry_on.contains(&classify_error(error))
    }

    /// Whether an HTTP status warrants a retry: `429` if
    /// [`ErrorKind::RateLimited`] is enabled, any `5xx` if
    /// [`ErrorKind::ServerError`] is enabled, and `false` otherwise. Success
    /// statuses are never retried.
    pub fn should_retry_status(&self, status: u16) -> bool {
        if status == 429 {
            self.retry_on.contains(&ErrorKind::RateLimited)
        } else if (500..600).contains(&status) {
            self.retry_on.contains(&ErrorKind::ServerError)
        } else {
            false
        }
    }

    pub(crate) fn backoff(&self) -> backoff::ExponentialBackoff {
        let multiplier = if self.exponential_backoff { 2.0 } else { 1.0 };
        ExponentialBackoffBuilder::new()
            .with_initial_interval(self.initial_delay)
            .with_max_interval(self.max_delay)
            .with_multiplier(multiplier)
            .with_max_elapsed_time(None)
            .build()
    }

    pub(crate) fn next_delay(&self, backoff: &mut backoff::ExponentialBackoff) -> Duration {
        backoff.next_backoff().unwrap_or(self.max_delay)
    }
}

/// Map an error onto the [`ErrorKind`] that decides whether it is retried.
///
/// Only the transient variants map to a specific kind; every validation failure
/// falls through to [`ErrorKind::Other`] so the default configuration refuses to
/// retry it.
pub fn classify_error(error: &BeanStreamError) -> ErrorKind {
    match error {
        BeanStreamError::NetworkTimeout(_) => ErrorKind::NetworkTimeout,
        BeanStreamError::ServerError(_) => ErrorKind::ServerError,
        BeanStreamError::RateLimited => ErrorKind::RateLimited,
        BeanStreamError::RequestFailed(_) => ErrorKind::Connection,
        _ => ErrorKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_retries_transient_errors() {
        let config = RetryConfig::default();
        assert!(config.should_retry(&BeanStreamError::NetworkTimeout(1000)));
        assert!(config.should_retry(&BeanStreamError::ServerError(503)));
        assert!(config.should_retry(&BeanStreamError::RateLimited));
        assert!(!config.should_retry(&BeanStreamError::PrivateNetworkAccess(
            "127.0.0.1".to_string()
        )));
    }

    #[test]
    fn status_classification_respects_retry_on() {
        let config = RetryConfig {
            retry_on: vec![ErrorKind::ServerError],
            ..RetryConfig::default()
        };
        assert!(config.should_retry_status(500));
        assert!(!config.should_retry_status(429));
        assert!(!config.should_retry_status(200));
    }

    #[test]
    fn backoff_delay_is_bounded() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(50),
            ..RetryConfig::default()
        };
        let mut backoff = config.backoff();
        for _ in 0..10 {
            let delay = config.next_delay(&mut backoff);
            assert!(delay >= Duration::from_millis(1));
        }
    }
}
