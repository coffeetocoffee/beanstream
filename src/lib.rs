mod abort;
mod builder;
mod cache;
mod cert_pinning;
mod error_handling_impl;
mod header_validation;
mod interceptor;
mod platform_config;
mod progress;
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
pub use error_handling_impl::{BeanStreamError, Result};
pub use header_validation::{
    is_blocked_header, is_sensitive_header, redact_sensitive_headers, sanitize_header,
    validate_headers,
};
pub use interceptor::{AuthInterceptor, Interceptor, InterceptorChain, LoggingInterceptor};
pub use platform_config::{generate_android_network_config, generate_ios_plist, AtsException};
pub use progress::{NoopProgress, UploadProgress};
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
