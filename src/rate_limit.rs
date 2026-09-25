use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::BeanStreamError;

/// Semaphore-based rate limiter controlling concurrent in-flight requests.
/// Mirrors architecture.md:70, 356, 387, 423.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    semaphore: Arc<Semaphore>,
    min_interval: Option<Duration>,
    last_started: Arc<tokio::sync::Mutex<Option<Instant>>>,
}

impl RateLimiter {
    /// Limit the number of simultaneously in-flight requests.
    pub fn new(max_concurrent: usize) -> Self {
        let permits = NonZeroUsize::new(max_concurrent.max(1)).expect("at least one permit");
        Self {
            semaphore: Arc::new(Semaphore::new(permits.get())),
            min_interval: None,
            last_started: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Additionally enforce a minimum spacing between request starts.
    pub fn with_min_interval(mut self, interval: Duration) -> Self {
        self.min_interval = Some(interval);
        self
    }

    pub fn max_concurrent(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Acquire a permit, waiting for a free slot and honoring the minimum
    /// interval. Returns a guard that releases the slot when dropped.
    pub async fn acquire(&self) -> Result<RateLimitGuard, BeanStreamError> {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| BeanStreamError::RateLimited)?;

        if let Some(interval) = self.min_interval {
            let mut last = self.last_started.lock().await;
            if let Some(previous) = *last {
                let elapsed = previous.elapsed();
                if elapsed < interval {
                    tokio::time::sleep(interval - elapsed).await;
                }
            }
            *last = Some(Instant::now());
        }

        Ok(RateLimitGuard { _permit: permit })
    }

    /// Try to acquire without waiting.
    pub fn try_acquire(&self) -> Result<RateLimitGuard, BeanStreamError> {
        let permit = self
            .semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| BeanStreamError::RateLimited)?;
        Ok(RateLimitGuard { _permit: permit })
    }
}

#[derive(Debug)]
pub struct RateLimitGuard {
    _permit: OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limits_concurrency() {
        let limiter = RateLimiter::new(1);
        let guard = limiter.acquire().await.unwrap();
        assert!(limiter.try_acquire().is_err());
        drop(guard);
        assert!(limiter.try_acquire().is_ok());
    }

    #[tokio::test]
    async fn allows_up_to_configured_concurrency() {
        let limiter = RateLimiter::new(2);
        let a = limiter.try_acquire().unwrap();
        let b = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_err());
        drop(a);
        drop(b);
    }

    #[tokio::test]
    async fn enforces_min_interval() {
        let limiter = RateLimiter::new(1).with_min_interval(Duration::from_millis(100));
        {
            let _g1 = limiter.acquire().await.unwrap();
        }
        let start = Instant::now();
        let _g2 = limiter.acquire().await.unwrap();
        assert!(start.elapsed() >= Duration::from_millis(80));
    }
}
