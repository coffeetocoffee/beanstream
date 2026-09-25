//! Compile-time pin for the import paths the README publishes (P2-7/P3-3).
//!
//! The README used to show `use beanstream::url_validation::validate_url;` and
//! friends. Those modules are private — only the crate-root re-exports in
//! `lib.rs` are public — so every one of those examples failed to compile if a
//! reader copied it. Nothing caught that, because README snippets are not
//! doctested.
//!
//! This file is the substitute: it imports the crate exactly the way the README
//! tells a reader to, so a re-export that disappears or is renamed breaks the
//! build instead of the documentation.
//!
//! Keep this list in sync with the code blocks in README.md. If you change an
//! example's imports there, change them here.

#![allow(dead_code, unused_variables)]

use std::time::Duration;

#[cfg(feature = "rustls-tls")]
use beanstream::CertPinConfig;
use beanstream::{
    is_private_or_loopback, is_sensitive_header, sanitize_header, validate_url, BeanStreamError,
    HttpClientBuilder, HttpRequest, RedirectPolicy,
};
use url::Url;

/// Section 1 — "URL Validation & Sanitization".
#[test]
fn documented_url_validation_paths_resolve() {
    let parsed = validate_url("https://8.8.8.8/api").unwrap();
    assert_eq!(parsed.port, 443);

    assert!(validate_url("http://192.168.1.1/test").is_err());
    assert!(validate_url("http://10.0.0.1/admin").is_err());
    assert!(validate_url("http://[::1]/").is_err());

    // The README imports this helper alongside `validate_url`; it is scoped to
    // IPv4, which is worth pinning here since the signature is easy to assume.
    let _: fn(&std::net::Ipv4Addr) -> bool = is_private_or_loopback;
}

/// Section 2 — "Header Safety".
#[test]
fn documented_header_paths_resolve() {
    let (name, value) = sanitize_header(" X-Custom-Header ", " value ").unwrap();
    assert_eq!(name, "x-custom-header");
    assert_eq!(value, "value");

    assert!(sanitize_header("x-test", "value\r\ninjected").is_err());
}

/// Section 3 — "Sensitive Data Protection".
#[test]
fn documented_sensitive_header_path_resolves() {
    assert!(is_sensitive_header("Authorization"));
    assert!(is_sensitive_header("SET-COOKIE"));
    assert!(!is_sensitive_header("content-type"));
}

/// Section 4 — "Intelligent Redirect Handling".
#[test]
fn documented_redirect_policy_path_resolves() {
    let policy = RedirectPolicy::strict(["example.com", "*.example.com"]);

    assert!(policy
        .check_redirect(&[], &Url::parse("https://api.example.com/x").unwrap())
        .is_ok());
    assert!(policy
        .check_redirect(&[], &Url::parse("https://evil.com/x").unwrap())
        .is_err());

    let chain = HttpRequest::get("https://example.com/start")
        .unwrap()
        .redirect_policy(RedirectPolicy::strict(["example.com"]).follow_redirects(true));
    assert!(chain.redirect_policy.follow_redirects);
}

/// "Quick Start" — first request.
///
/// The documented order matters: `add_header` takes `&mut self` (so it can
/// report *which* header was rejected) while `body`/`timeout` consume `self`.
/// Chaining `add_header` before them does not compile, which is exactly the
/// mistake the old README made.
#[test]
fn documented_first_request_path_resolves() {
    let mut request = HttpRequest::get("https://api.example.com/users")
        .unwrap()
        .body("{}")
        .timeout(Duration::from_secs(15));
    request.add_header("X-Test", "value").unwrap();

    request.validate().unwrap();
    let _built = request.build_request().unwrap();
}

/// "Quick Start" — shared client, and the builder table's entries.
#[test]
fn documented_builder_paths_resolve() {
    let _client = HttpClientBuilder::default()
        .with_base_url("https://api.example.com/api/")
        .with_timeout(Duration::from_secs(30))
        .with_max_redirects(5)
        .with_follow_redirects(true)
        .add_default_header("X-App", "beanstream")
        .unwrap()
        .build()
        .unwrap();
}

/// "Creating requests" — the verb helpers and the mutation-style batch call.
#[test]
fn documented_request_verb_paths_resolve() {
    let _ = HttpRequest::get("https://8.8.8.8/");
    let _ = HttpRequest::post("https://8.8.8.8/");
    let _ = HttpRequest::put("https://8.8.8.8/");
    let _ = HttpRequest::delete("https://8.8.8.8/");
    let _ = HttpRequest::patch("https://8.8.8.8/");

    let mut req = HttpRequest::post("https://api.example.com/items")
        .unwrap()
        .body(r#"{"name":"espresso"}"#)
        .timeout(Duration::from_secs(10));
    req.add_headers([("X-Env", "prod"), ("Accept", "application/json")])
        .unwrap();
}

/// "Clear Error Messages" — the error enum is public at the crate root.
#[test]
fn documented_error_path_resolves() {
    let outcome = HttpRequest::get("http://127.0.0.1/");
    match outcome {
        Err(BeanStreamError::PrivateNetworkAccess(addr)) => {
            assert!(!addr.is_empty());
        }
        Err(other) => panic!("expected PrivateNetworkAccess, got {other}"),
        Ok(_) => panic!("loopback must not validate"),
    }
}

/// The builder table lists `with_cert_pinning` and `with_cookie_jar`, which are
/// feature-gated. This pins that the methods exist under the features that
/// declare them, not that any particular build enables them.
#[test]
fn documented_feature_gated_builder_methods_exist() {
    #[cfg(feature = "cookies")]
    {
        let builder = HttpClientBuilder::default()
            .with_base_url("https://8.8.8.8/")
            .with_cookie_jar(beanstream::CookieJar::enabled());
        let _ = builder;
    }

    #[cfg(feature = "rustls-tls")]
    {
        let builder = HttpClientBuilder::default()
            .with_cert_pinning(CertPinConfig::new().pin_spki_sha256([0x11; 32]));
        let _ = builder;
    }
}
