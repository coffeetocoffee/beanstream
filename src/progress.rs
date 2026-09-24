use std::sync::Arc;

/// Real-time progress tracking for uploads/downloads.
/// Returning `false` from `on_progress` signals cancellation.
/// Mirrors architecture.md:238-240 and 422.
pub trait UploadProgress: Send + Sync + 'static {
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
