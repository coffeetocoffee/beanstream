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

#[derive(Debug, Clone)]
pub struct AbortSignal {
    inner: Arc<Inner>,
}

#[derive(Debug)]
pub struct AbortController {
    inner: Arc<Inner>,
}

impl AbortController {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                aborted: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    pub fn signal(&self) -> AbortSignal {
        AbortSignal {
            inner: self.inner.clone(),
        }
    }

    pub fn abort(&self) {
        self.inner.aborted.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

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
    pub fn is_aborted(&self) -> bool {
        self.inner.aborted.load(Ordering::SeqCst)
    }

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

    pub async fn wait_aborted(&self) {
        self.cancelled().await
    }
}

pub fn create_abort_signal() -> (AbortController, AbortSignal) {
    let controller = AbortController::new();
    let signal = controller.signal();
    (controller, signal)
}

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
