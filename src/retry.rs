use std::time::Duration;

use backoff::backoff::Backoff;
use backoff::ExponentialBackoffBuilder;

use crate::BeanStreamError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    NetworkTimeout,
    ServerError,
    RateLimited,
    Connection,
    Other,
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub exponential_backoff: bool,
    pub retry_on: Vec<ErrorKind>,
}

impl Default for RetryConfig {
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
    pub fn should_retry(&self, error: &BeanStreamError) -> bool {
        self.retry_on.contains(&classify_error(error))
    }

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