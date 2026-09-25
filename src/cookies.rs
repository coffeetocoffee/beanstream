//! Cookie jar support, gated behind the `cookies` feature (P2-2).
//!
//! The crate deliberately treats cookies as opt-in: an always-on cookie jar
//! would let one host's `Set-Cookie` ride along to every later request, which
//! is a cross-origin leak waiting to happen in a client whose whole point is
//! host validation. Enabling the feature gets you a jar that is scoped per
//! origin by reqwest/`cookie_store`, and — importantly — one that is only ever
//! consulted through the pinned send path, so the SSRF checks still apply.
//!
//! Note that [`crate::HttpResponse::headers`] are redacted, and `set-cookie`
//! is on the sensitive list. Cookies are therefore *stored* here rather than
//! surfaced to the caller.

use std::sync::Arc;

/// A shared cookie jar.
///
/// Clone is cheap: every clone points at the same underlying store, so a jar
/// can be handed to several requests or builders and they will share session
/// state, which is what you want for a login followed by API calls.
#[derive(Clone, Default)]
pub struct CookieJar {
    inner: Option<Arc<reqwest::cookie::Jar>>,
}

impl CookieJar {
    /// An empty jar that stores nothing.
    pub fn empty() -> Self {
        Self { inner: None }
    }

    /// An enabled jar backed by reqwest's default store.
    pub fn enabled() -> Self {
        Self {
            inner: Some(Arc::new(reqwest::cookie::Jar::default())),
        }
    }

    /// Whether this jar actually stores cookies.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// The store to hand to `reqwest`'s `cookie_provider`, if enabled.
    pub(crate) fn provider(&self) -> Option<Arc<reqwest::cookie::Jar>> {
        self.inner.clone()
    }
}

impl std::fmt::Debug for CookieJar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieJar")
            .field("enabled", &self.is_enabled())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_jar_stores_nothing() {
        let jar = CookieJar::empty();
        assert!(!jar.is_enabled());
        assert!(jar.provider().is_none());
    }

    #[test]
    fn an_enabled_jar_shares_state_across_clones() {
        let jar = CookieJar::enabled();
        let clone = jar.clone();

        assert!(jar.is_enabled());
        assert!(clone.is_enabled());

        // Both clones must hand back the same store, otherwise session state
        // would silently fork between a login request and the calls after it.
        let left = jar.provider().unwrap();
        let right = clone.provider().unwrap();
        assert!(Arc::ptr_eq(&left, &right));
    }
}
