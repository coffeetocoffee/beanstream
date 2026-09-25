use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::Notify;

use crate::{BeanStreamError, Result};

#[derive(Debug)]
struct Inner {
    aborted: AtomicBool,
    notify: Notify,
}

/// The cancellation handle handed to a request, or shared with the task that may
/// cancel it.
///
/// Cloning is cheap and shares state, so every clone observes the same abort.
/// Once aborted a signal stays aborted — there is no reset.
#[derive(Debug, Clone)]
pub struct AbortSignal {
    inner: Arc<Inner>,
}

/// The cancelling side of an abort pair: creates a [`AbortSignal`] and can fire
/// it.
///
/// Typically created with [`create_abort_signal`], which returns both halves.
#[derive(Debug)]
pub struct AbortController {
    inner: Arc<Inner>,
}

impl AbortController {
    /// Create a controller with a fresh, un-aborted signal.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                aborted: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    /// The signal for this controller. Calling twice yields signals sharing the
    /// same state.
    pub fn signal(&self) -> AbortSignal {
        AbortSignal {
            inner: self.inner.clone(),
        }
    }

    /// Mark the request as cancelled and wake anything awaiting
    /// [`AbortSignal::cancelled`]. Idempotent.
    pub fn abort(&self) {
        self.inner.aborted.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// Whether [`Self::abort`] has been called.
    pub fn is_aborted(&self) -> bool {
        self.inner.aborted.load(Ordering::SeqCst)
    }
}

impl Default for AbortController {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for AbortController {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl AbortSignal {
    /// Whether the paired controller has fired. A request that starts with an
    /// already-aborted signal fails immediately without opening a connection.
    pub fn is_aborted(&self) -> bool {
        self.inner.aborted.load(Ordering::SeqCst)
    }

    /// Resolve once the paired controller aborts. Returns immediately if it
    /// already has.
    pub async fn cancelled(&self) {
        loop {
            if self.is_aborted() {
                return;
            }
            self.inner.notify.notified().await;
            if self.is_aborted() {
                return;
            }
        }
    }

    /// Clearer-named alias for [`Self::cancelled`]; the intended use is racing
    /// this against a request inside `tokio::select!`.
    pub async fn wait_aborted(&self) {
        self.cancelled().await
    }
}

/// Create a linked [`AbortController`] and [`AbortSignal`].
///
/// This is the usual entry point:
///
/// ```
/// use beanstream::create_abort_signal;
///
/// let (controller, signal) = create_abort_signal();
/// assert!(!signal.is_aborted());
/// controller.abort();
/// assert!(signal.is_aborted());
/// ```
pub fn create_abort_signal() -> (AbortController, AbortSignal) {
    let controller = AbortController::new();
    let signal = controller.signal();
    (controller, signal)
}

/// Run `request`, giving up with [`BeanStreamError::RequestAborted`] if `signal`
/// fires first.
///
/// The request is consumed, so this is the form to use when the request is built
/// at the call site. An already-aborted signal fails before any connection is
/// attempted.
pub async fn execute_with_abort(
    request: crate::request_handler::HttpRequest,
    signal: AbortSignal,
) -> Result<crate::request_handler::HttpResponse> {
    if signal.is_aborted() {
        return Err(BeanStreamError::RequestAborted);
    }
    tokio::select! {
        res = request.send() => res,
        _ = signal.cancelled() => Err(BeanStreamError::RequestAborted),
    }
}

/// As [`execute_with_abort`], but borrows the request and clones it internally,
/// leaving the caller's value usable.
pub async fn execute_with_abort_ref(
    request: &crate::request_handler::HttpRequest,
    signal: &AbortSignal,
) -> Result<crate::request_handler::HttpResponse> {
    if signal.is_aborted() {
        return Err(BeanStreamError::RequestAborted);
    }
    let req = request.clone();
    tokio::select! {
        res = req.send() => res,
        _ = signal.cancelled() => Err(BeanStreamError::RequestAborted),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_handler::HttpRequest;

    #[tokio::test]
    async fn abort_signal_triggers() {
        let (controller, signal) = create_abort_signal();
        assert!(!signal.is_aborted());
        controller.abort();
        assert!(signal.is_aborted());
        assert!(controller.is_aborted());
    }

    #[tokio::test]
    async fn abort_cancels_execution() {
        let (controller, signal) = create_abort_signal();
        // Use a request that would otherwise try to connect; abort immediately
        let request = HttpRequest::get("https://8.8.8.8/").unwrap();
        controller.abort();
        let result = execute_with_abort(request, signal).await;
        assert!(matches!(result, Err(BeanStreamError::RequestAborted)));
    }

    #[tokio::test]
    async fn test_abort_cancellation_works() {
        let (controller, handle) = create_abort_signal();
        // request that will not resolve quickly; we use a non-routable but validation-passing address
        // 8.8.8.8 is valid but we abort before it completes by using a delayed future
        let request = HttpRequest::get("https://8.8.8.8/").unwrap();
        let task = tokio::spawn(async move { execute_with_abort(request, handle).await });
        controller.abort();
        let res = task.await.unwrap();
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), BeanStreamError::RequestAborted));
    }
}
