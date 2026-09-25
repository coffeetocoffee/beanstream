//! A security-first HTTP client for Rust.
//!
//! BeanStream wraps [`reqwest`] and puts a stack of independent validation
//! layers in front of it, so the security checks happen *before* a socket
//! exists and again at connect time. The design assumption is that URLs and
//! headers may come from untrusted input — a user-supplied link, a config file,
//! a webview message — and that the library, not the caller, is responsible for
//! refusing the dangerous ones.
//!
//! # Overview
//!
//! | Layer | What it stops | Entry point |
//! |-------|---------------|-------------|
//! | URL & address validation | SSRF: private, loopback, link-local and metadata addresses; embedded credentials; path traversal | [`validate_url`], [`validate_url_async`], [`is_blocked_ip`] |
//! | Header sanitization | CRLF/header injection, forbidden headers | [`sanitize_header`], [`is_blocked_header`] |
//! | Response redaction | Token leakage into logs | [`redact_sensitive_headers`], [`HttpResponse::redact`] |
//! | Redirect policy | Open redirects, `https` → `http` downgrade, credential leakage across origins | [`RedirectPolicy`], [`ScopeValidator`] |
//! | DNS pinning | DNS-rebinding TOCTOU | [`HttpRequest::send`] resolves once and pins the validated addresses |
//!
//! # Quick start
//!
//! Validate before you connect. This needs no network access:
//!
//! ```
//! use beanstream::validate_url;
//!
//! // Public addresses pass.
//! let parsed = validate_url("https://8.8.8.8/api")?;
//! assert_eq!(parsed.port, 443);
//!
//! // Private, loopback and reserved ranges are refused, by IP or by name.
//! assert!(validate_url("http://192.168.1.1/test").is_err());
//! assert!(validate_url("http://127.0.0.1/api").is_err());
//! assert!(validate_url("http://localhost/api").is_err());
//! # Ok::<(), beanstream::BeanStreamError>(())
//! ```
//!
//! Send a request through the fully-pinned path:
//!
//! ```no_run
//! use beanstream::HttpRequest;
//!
//! # async fn example() -> Result<(), beanstream::BeanStreamError> {
//! let response = HttpRequest::get("https://example.com/data")?.send().await?;
//! println!("{}", response.status);
//! # Ok(())
//! # }
//! ```
//!
//! Or configure a shared [`HttpClientBuilder`]. Note that [`HttpClientBuilder::send`]
//! is the method that applies the validation and pinning layers;
//! [`HttpClientBuilder::build`] returns a plain [`reqwest::Client`] that trusts
//! the system resolver, and exists as an escape hatch for callers who have
//! already validated the destination themselves.
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use beanstream::HttpClientBuilder;
//!
//! let client = HttpClientBuilder::default()
//!     .with_base_url("https://api.example.com/v1/")
//!     .with_timeout(Duration::from_secs(30))
//!     .with_max_redirects(5)
//!     .add_default_header("X-Api-Client", "beanstream")?;
//!
//! # Ok::<(), beanstream::BeanStreamError>(())
//! ```
//!
//! # Cargo features
//!
//! | Feature | Default | What it does |
//! |---------|---------|--------------|
//! | `http2` | yes | Enables HTTP/2 via re-exported [`reqwest`] support |
//! | `rustls-tls` | yes | TLS via `rustls` with webpki roots. **Required for `CertPinConfig`**: without it, building a client with pinning returns [`BeanStreamError::InvalidConfiguration`] rather than silently producing an unpinned client |
//! | `cookies` | no | Enables `CookieJar` for per-origin session storage. Opt-in, because an always-on jar lets one host's `Set-Cookie` ride along to unrelated later requests |
//! | `system-proxy` | yes | Lets [`ProxyConfig::System`] read the platform's proxy settings (macOS CFNetwork, Windows registry) in addition to the environment. Without it, `System` degrades to [`ProxyConfig::Environment`] |
//! | `websocket` | no | Enables `connect_websocket` via `tokio-tungstenite` |
//!
//! # Security model, stated plainly
//!
//! - **Private networks are blocked by default and there is no "localhost is
//!   fine" exception.** Loopback, link-local, private, shared-address-space,
//!   benchmarking and multicast ranges are all refused. To reach an internal
//!   host you must opt in explicitly with
//!   [`HttpClientBuilder::allow_private_networks`], which is a visible decision
//!   rather than a default.
//! - **Only `http` and `https` are accepted.** There is no `data:` or `file:`
//!   support; a scheme with no host cannot pass the address checks.
//! - **URLs carrying credentials are refused**, e.g. `https://user:pass@host/`.
//! - **Redirects are not followed by reqwest.** [`HttpRequest::send`] pins
//!   reqwest to `Policy::none()` and walks the chain itself, re-validating,
//!   re-pinning and re-checking every hop. See [`RedirectPolicy`].
//! - **Redaction is applied to your in-memory [`HttpResponse`]**, not only to
//!   logs, and again after interceptors run so a token re-injected by an auth
//!   refresh is still caught. Redaction is destructive: the sensitive entries
//!   are removed from `headers` and are not recoverable from the response. If
//!   you need a value like `set-cookie`, read it before it is redacted — for
//!   example in an [`Interceptor::on_response`] — or configure the request so
//!   that header is not sensitive to you.
//! - **Every send path pins addresses**, not just the main one:
//!   [`HttpRequest::send`], [`HttpClientBuilder::send`],
//!   [`download_stream`] and `connect_websocket` all resolve once, validate
//!   every address, and connect to a validated address only.
//! - **A rejected header cannot be reintroduced.** `HttpRequest::validate`
//!   re-checks the forbidden list (`Host`, `Content-Length`, …) on the final
//!   header set, so neither a direct push onto the public `headers` field nor
//!   an interceptor can smuggle one past the guard that
//!   [`HttpRequest::add_header`] applies.
//! - **A proxy does not weaken the address checks.** The destination is
//!   resolved and validated locally whether or not a proxy is configured, so a
//!   proxy cannot be used to reach an internal service that a direct request
//!   would refuse. See [`ProxyConfig`], and note the corollary: a proxy that
//!   exists *because* it can resolve internal names will not help, since the
//!   name is resolved here. Reaching an internal host requires the explicit
//!   [`HttpClientBuilder::allow_private_networks`] opt-in.
//!
//! # Proxy support
//!
//! [`ProxyConfig`] chooses how requests egress: [`ProxyConfig::System`]
//! (the default, matching reqwest and curl) reads the environment and, with the
//! `system-proxy` feature on — as it is by default — the platform's settings on
//! macOS (CFNetwork) and Windows (registry). [`ProxyConfig::Environment`] reads
//! the variables only, [`ProxyConfig::Explicit`] pins one proxy, and
//! [`ProxyConfig::Disabled`] refuses proxying outright. `NO_PROXY` is honoured
//! as a bypass list in every mode that can proxy.
//!
//! # What is not implemented
//!
//! Stated here rather than left to be discovered: no benchmark suite, and no
//! JavaScript/TypeScript bridge. Two narrower gaps are worth naming:
//! [`CertPinConfig`] applies to HTTP and to [`download_stream`] but **not** to
//! the WebSocket TLS handshake, and [`ProxyConfig`] is **not** applied to
//! WebSocket connections either — a `wss://` through an HTTP proxy needs a
//! `CONNECT` upgrade that the WebSocket stack does not perform.
//!
//! See `architecture.md` in the repository for the full threat model and
//! per-module coverage table.
//!
//! # Toxicity of `Send`
//!
//! Requests and responses are plain data and can be moved across tasks.
//! [`AbortSignal`] is `Clone` and designed to be shared between the task that
//! performs the request and the one that cancels it.

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

mod abort;
mod builder;
mod cache;
mod cert_pinning;
#[cfg(feature = "cookies")]
mod cookies;
mod error_handling_impl;
mod header_validation;
mod interceptor;
mod platform_config;
mod progress;
mod proxy_config;
mod rate_limit;
mod redirect_policy;
mod request_handler;
mod retry;
mod streaming;
mod url_validation;
#[cfg(feature = "websocket")]
mod websocket;

pub use abort::{
    create_abort_signal, execute_with_abort, execute_with_abort_ref, AbortController, AbortSignal,
};
pub use builder::HttpClientBuilder;
pub use cache::{CacheConfig, InMemoryCache};
pub use cert_pinning::{spki_sha256, CertPinConfig};
#[cfg(feature = "cookies")]
pub use cookies::CookieJar;
pub use error_handling_impl::{BeanStreamError, Result};
pub use header_validation::{
    is_blocked_header, is_sensitive_header, redact_sensitive_headers, sanitize_header,
    validate_headers,
};
pub use interceptor::{AuthInterceptor, Interceptor, InterceptorChain, LoggingInterceptor};
pub use platform_config::{generate_android_network_config, generate_ios_plist, AtsException};
pub use progress::{NoopProgress, UploadProgress};
pub use proxy_config::{ProxyConfig, ProxyEndpoint};
pub use rate_limit::{RateLimitGuard, RateLimiter};
pub use redirect_policy::{RedirectPolicy, ScopeValidator};
pub use request_handler::{HttpRequest, HttpResponse};
pub use retry::{classify_error, ErrorKind, RetryConfig};
pub use streaming::{download_stream, stream_from_response, ByteStream};
pub use url_validation::{
    is_blocked_ip, is_ipv6_loopback_or_multicast, is_private_or_loopback, resolve_host,
    validate_ip_access, validate_ip_access_async, validate_url, validate_url_async, ParsedUrl,
    SanitizedPath, Scheme, ValidatedHost,
};
#[cfg(feature = "websocket")]
pub use websocket::{connect_websocket, WebSocket};
