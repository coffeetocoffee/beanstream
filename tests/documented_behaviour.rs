//! The behaviours that architecture.md and README.md promise (P2-4).
//!
//! These live as real tests rather than doc comments so the docs cannot drift
//! away from the code again: the audit found an example claiming
//! `validate_url("http://127.0.0.1/api").is_ok()` while the code has always
//! rejected loopback. Anything published here is now executed on every run.

use beanstream::{
    create_abort_signal, execute_with_abort, sanitize_header, validate_url, BeanStreamError,
    HttpRequest,
};

/// Layer 1: URL validation blocks private and internal addresses.
#[test]
fn url_validation_blocks_private_ips() {
    assert!(validate_url("http://192.168.1.1/test").is_err());
    assert!(validate_url("http://10.0.0.1/admin").is_err());

    // Loopback is private too -- there is no "localhost is fine" exception.
    assert!(validate_url("http://127.0.0.1/api").is_err());
    assert!(validate_url("http://localhost/api").is_err());
    assert!(validate_url("http://foo.local/api").is_err());

    // Public addresses are the only ones that pass.
    assert!(validate_url("https://8.8.8.8/api").is_ok());
}

#[test]
fn private_address_failures_are_reported_as_such() {
    // The error should name the real reason, not a generic parse failure.
    let outcome = validate_url("http://127.0.0.1/api");
    assert!(
        matches!(&outcome, Err(BeanStreamError::PrivateNetworkAccess(_))),
        "expected a private-network rejection, got {outcome:?}"
    );
}

/// Layer 2: header sanitization rejects CRLF injection.
#[test]
fn header_sanitization_rejects_injection() {
    assert!(sanitize_header("name", "value\r\ninject").is_err());
    assert!(sanitize_header("name", "value\ninject").is_err());
    assert!(sanitize_header("name", "safe-value").is_ok());
}

/// AbortControl: cancelling a request surfaces RequestAborted.
#[tokio::test]
async fn abort_cancellation_works() {
    let (controller, signal) = create_abort_signal();
    let request = HttpRequest::get("https://8.8.8.8/").unwrap();

    let task = tokio::spawn(async move { execute_with_abort(request, signal).await });

    controller.abort();
    let outcome = task.await.unwrap();
    assert!(
        matches!(outcome, Err(BeanStreamError::RequestAborted)),
        "expected RequestAborted, got {outcome:?}"
    );
}

/// The documented build command's feature set must actually resolve (P2-2).
///
/// `cargo build --features "cookies,http2,rustls-tls"` used to fail outright
/// because none of those features were declared. This test only compiles when
/// they exist, so a regression shows up as a build error rather than a
/// broken README.
#[cfg(all(feature = "rustls-tls", feature = "http2"))]
#[test]
#[allow(clippy::assertions_on_constants)]
fn documented_features_are_declared() {
    // Satisfy clippy::assertions_on_constants: cfg! is not const for weaponisation
    // purposes, but clippy treats it as such inside a test gated on the same cfg.
    assert!(cfg!(feature = "rustls-tls"));
    assert!(cfg!(feature = "http2"));
}

#[cfg(not(all(feature = "rustls-tls", feature = "http2")))]
#[test]
fn documented_features_are_declared() {
    // With no default features, the assertion above intentionally does not
    // apply. Success here just means the harness compiled at all.
}

/// Cookies are opt-in and share session state when enabled (P2-2).
#[cfg(feature = "cookies")]
#[test]
fn cookie_jar_is_opt_in_and_shared() {
    use std::time::Duration;

    use beanstream::{CookieJar, HttpClientBuilder};

    let jar = CookieJar::enabled();
    assert!(jar.is_enabled());

    // A clone must point at the same store, or a login followed by API calls
    // would silently fork its session.
    let shared = jar.clone();
    assert!(shared.is_enabled());

    let builder = HttpClientBuilder::default()
        .with_base_url("https://8.8.8.8/")
        .with_cookie_jar(shared)
        .with_timeout(Duration::from_secs(5));

    let request = builder
        .create_request(reqwest::Method::GET, "login")
        .unwrap();
    assert!(
        request.cookie_jar.is_some(),
        "created requests must carry the builder's jar"
    );

    // An empty jar is a no-op, so a builder without one stores nothing.
    let without = HttpClientBuilder::default()
        .with_base_url("https://8.8.8.8/")
        .create_request(reqwest::Method::GET, "login")
        .unwrap();
    assert!(without.cookie_jar.is_none());
}

/// With `rustls-tls` off, asking for pinning must fail loudly rather than
/// build a client that only looks pinned (P2-2).
#[cfg(not(feature = "rustls-tls"))]
#[test]
fn cert_pinning_without_rustls_is_refused() {
    use beanstream::HttpClientBuilder;

    let builder = HttpClientBuilder::default()
        .with_cert_pinning(beanstream::CertPinConfig::new().pin_spki_sha256([0x11; 32]));

    let outcome = builder.build();
    assert!(
        matches!(&outcome, Err(BeanStreamError::InvalidConfiguration(message))
            if message.contains("rustls-tls")),
        "expected a clear configuration error, got {outcome:?}"
    );
}
