mod builder;
mod error_handling_impl;
mod header_validation;
mod redirect_policy;
mod request_handler;
mod url_validation;

pub use builder::HttpClientBuilder;
pub use error_handling_impl::{BeanStreamError, Result};
pub use header_validation::{
    is_blocked_header, is_sensitive_header, sanitize_header, validate_headers,
};
pub use redirect_policy::{RedirectPolicy, ScopeValidator};
pub use request_handler::HttpRequest;
pub use url_validation::{
    is_blocked_ip, is_ipv6_loopback_or_multicast, is_private_or_loopback, validate_ip_access,
    validate_url, ParsedUrl, SanitizedPath, Scheme, ValidatedHost,
};
