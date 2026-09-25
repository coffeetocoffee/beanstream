use std::sync::Arc;

/// Real-time progress tracking for uploads and downloads.
///
/// Attach with [`HttpRequest::with_progress`](crate::HttpRequest::with_progress).
/// The callback is invoked as the transfer proceeds, and its return value
/// controls whether to continue: returning `false` **cancels the request** and
/// surfaces [`BeanStreamError::RequestAborted`](crate::BeanStreamError::RequestAborted),
/// so it doubles as a cooperative cancellation hook.
///
/// Implemented automatically for any `Fn(u64, Option<u64>) -> bool` that is
/// `Send + Sync + 'static`, so a closure is usually enough:
///
/// ```no_run
/// use beanstream::HttpRequest;
///
/// # fn example() -> Result<(), beanstream::BeanStreamError> {
/// let request = HttpRequest::get("https://example.com/big-file")?
///     .with_progress(|transferred: u64, total: Option<u64>| {
///         println!("{transferred} / {total:?}");
///         true // return false to cancel
///     });
/// # Ok(())
/// # }
/// ```
pub trait UploadProgress: Send + Sync + 'static {
    /// Called with the number of bytes transferred so far and the total when
    /// known. Return `false` to abort the request.
    fn on_progress(&self, uploaded: u64, total: Option<u64>) -> bool;
}

impl<F> UploadProgress for F
where
    F: Fn(u64, Option<u64>) -> bool + Send + Sync + 'static,
{
    fn on_progress(&self, uploaded: u64, total: Option<u64>) -> bool {
        self(uploaded, total)
    }
}

/// A tracker that does nothing and never cancels. Useful when a `Progress`
/// value is required but no reporting is wanted.
#[derive(Clone)]
pub struct NoopProgress;
impl UploadProgress for NoopProgress {
    fn on_progress(&self, _uploaded: u64, _total: Option<u64>) -> bool {
        true
    }
}

/// Report a completed transfer to the tracker, if attached.
pub(crate) fn report_complete(progress: &Option<Arc<dyn UploadProgress>>, len: u64) -> bool {
    if let Some(p) = progress {
        if !p.on_progress(len, Some(len)) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn trait_works_for_closure() {
        let called = Arc::new(Mutex::new(Vec::new()));
        let c = called.clone();
        let prog = move |uploaded: u64, total: Option<u64>| {
            c.lock().unwrap().push((uploaded, total));
            true
        };
        assert!(prog.on_progress(5, Some(10)));
        assert_eq!(called.lock().unwrap().len(), 1);
    }

    #[test]
    fn noop_always_continues() {
        let n = NoopProgress;
        assert!(n.on_progress(0, None));
    }
}
