use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::BeanStreamError;

/// Semaphore-based rate limiter controlling concurrent in-flight requests.
///
/// Mirrors architecture.md:70, 356, 387, 423. Two independent limits can be
/// combined: a cap on how many requests run at once, and a minimum spacing
/// between request starts.
///
/// Cloning is cheap and shares state, which is how one limiter governs several
/// requests — clone it before attaching, since
/// [`HttpRequest::with_rate_limiter`](crate::HttpRequest::with_rate_limiter)
/// consumes the value.
///
/// ```no_run
/// use std::time::Duration;
///
/// use beanstream::{HttpRequest, RateLimiter};
///
/// # fn example() -> Result<(), beanstream::BeanStreamError> {
/// let limiter = RateLimiter::new(4).with_min_interval(Duration::from_millis(100));
/// let first = HttpRequest::get("https://8.8.8.8/")?.with_rate_limiter(limiter.clone());
/// let second = HttpRequest::get("https://1.1.1.1/")?.with_rate_limiter(limiter);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct RateLimiter {
    semaphore: Arc<Semaphore>,
    min_interval: Option<Duration>,
    last_started: Arc<tokio::sync::Mutex<Option<Instant>>>,
}

impl RateLimiter {
    /// Limit the number of simultaneously in-flight requests.
    ///
    /// Zero is treated as one, since a limiter that permits nothing could never
    /// make progress.
    pub fn new(max_concurrent: usize) -> Self {
        let permits = NonZeroUsize::new(max_concurrent.max(1)).expect("at least one permit");
        Self {
            semaphore: Arc::new(Semaphore::new(permits.get())),
            min_interval: None,
            last_started: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Additionally enforce a minimum spacing between request starts.
    ///
    /// Unlike the concurrency cap this is a throughput limit: the next start
    /// waits until the interval has elapsed since the previous one.
    pub fn with_min_interval(mut self, interval: Duration) -> Self {
        self.min_interval = Some(interval);
        self
    }

    /// Permits currently available. Note this is the number *free right now*,
    /// not the configured maximum — compare with
    /// [`HttpRequest::rate_limiter`](crate::HttpRequest::rate_limiter) config or
    /// track the maximum yourself if you need it.
    pub fn max_concurrent(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Acquire a permit, waiting for a free slot and honoring the minimum
    /// interval. Returns a guard that releases the slot when dropped.
    ///
    /// Because the guard is released on drop, hold it for as long as the
    /// request should count against the limit — for the whole request lifecycle,
    /// as [`HttpRequest::send`](crate::HttpRequest::send) does.
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
    ///
    /// Returns [`BeanStreamError::RateLimited`] immediately when no slot is
    /// free. Note that this does **not** apply [`Self::with_min_interval`]: a
    /// caller that wants the spacing must use [`Self::acquire`], which waits.
    pub fn try_acquire(&self) -> Result<RateLimitGuard, BeanStreamError> {
        let permit = self
            .semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| BeanStreamError::RateLimited)?;
        Ok(RateLimitGuard { _permit: permit })
    }
}

/// Holds a rate-limit slot for as long as it is alive.
///
/// Dropping the guard frees the slot, so keeping it in scope for the duration of
/// the work is what makes the limit meaningful.
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
