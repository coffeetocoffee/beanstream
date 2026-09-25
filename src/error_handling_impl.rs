use thiserror::Error;

/// Every failure BeanStream can report.
///
/// The variants are deliberately specific: a caller can distinguish "this
/// address is private" ([`PrivateNetworkAccess`](Self::PrivateNetworkAccess))
/// from "this scheme is not allowed" ([`InvalidScheme`](Self::InvalidScheme))
/// and react differently, rather than pattern-matching on a string. Comparison
/// is by variant, so check the variant and not the `Display` text.
///
/// # Which failures are retryable
///
/// [`classify_error`](crate::classify_error) maps these onto
/// [`ErrorKind`](crate::ErrorKind), which is what
/// [`RetryConfig`](crate::RetryConfig) uses to decide whether a request is worth
/// repeating. As a rule the validation failures below are *permanent* — retrying
/// a private-network address will fail identically every time — while
/// [`RequestFailed`](Self::RequestFailed) and
/// [`NetworkTimeout`](Self::NetworkTimeout) are the transient ones.
#[derive(Error, Debug)]
pub enum BeanStreamError {
    /// The URL could not be parsed, or failed a structural check such as
    /// carrying embedded credentials or a dangerous path sequence.
    #[error("URL error: {0}")]
    UrlError(String),
    /// The URL's scheme is not `http` or `https`. The rejected scheme is
    /// included. There is no `data:` or `file:` support.
    #[error("Scheme '{0}' is not allowed. Only http and https schemes are permitted")]
    InvalidScheme(String),
    /// The destination resolves to a private, loopback, link-local, reserved or
    /// multicast address, and private access has not been opted into. Carries
    /// the offending address.
    ///
    /// Note that loopback is included: `127.0.0.1` and `localhost` are refused
    /// exactly like `192.168.1.1`. To reach an internal host, opt in with
    /// [`HttpClientBuilder::allow_private_networks`](crate::HttpClientBuilder::allow_private_networks).
    #[error("Access to private/internal network blocked. Address '{0}' is not accessible")]
    PrivateNetworkAccess(String),
    /// The host is malformed, empty, or rejected by name — for example
    /// `*.local` and `*.internal`, which are refused because they conventionally
    /// resolve inside a private network.
    #[error("Invalid host: {0}")]
    InvalidHost(String),
    /// A header was rejected: malformed syntax, or a name/control-character
    /// problem that is not a CRLF injection.
    #[error("Header validation error: {0}")]
    HeaderError(String),
    /// A header name or value contained CR or LF, which is the classic response-
    /// splitting / request-smuggling injection. Refused before the request is
    /// built.
    #[error("Potential header injection detected. Carriage return or line feed characters are not allowed")]
    HeaderInjectionDetected,
    /// A redirect was refused for a reason other than the chain length, such as
    /// a `https` → `http` downgrade or a host outside the policy.
    #[error("Redirect blocked: {0}")]
    RedirectBlocked(String),
    /// The redirect chain exceeded the configured maximum. Carries that maximum.
    #[error("Too many redirects ({0})")]
    TooManyRedirects(usize),
    /// The URL had no host at all, so there was no address to validate.
    #[error("No host found in URL")]
    NoHost,
    /// The redirect destination is not in the policy's allow list, or matched a
    /// deny entry. Carries the host.
    #[error("Host '{0}' is not allowed by redirect policy")]
    HostNotAllowed(String),
    /// The port was not a usable number for the scheme.
    #[error("Invalid port number: {0}")]
    InvalidPort(u16),
    /// The transport failed: connection refused, TLS handshake failure, a
    /// malformed response, and so on. This is the catch-all for errors raised by
    /// the underlying client, so it *is* usually worth classifying via
    /// [`classify_error`](crate::classify_error) before deciding to retry.
    #[error("Request failed: {0}")]
    RequestFailed(String),
    /// The request exceeded its timeout. Carries the timeout in milliseconds.
    /// Transient and normally retryable.
    #[error("Network timeout after {0}ms")]
    NetworkTimeout(u64),
    /// The server returned a 5xx status. Carries the status code; transient in
    /// practice, and retryable via
    /// [`RetryConfig::should_retry_status`](crate::RetryConfig::should_retry_status).
    #[error("Server error: {0}")]
    ServerError(u16),
    /// The configured rate limit refused this request. Wait and retry.
    #[error("Rate limit exceeded. Please try again later")]
    RateLimited,
    /// A required setting was absent — for example a relative target with no
    /// base URL configured.
    #[error("Missing required configuration: {0}")]
    MissingConfig(String),
    /// The configuration is internally inconsistent or unsupported in this build
    /// — for example asking for certificate pinning when the `rustls-tls`
    /// feature is off.
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    /// An unexpected internal failure, including I/O and encoding problems that
    /// do not fit a more specific variant.
    #[error("Internal error: {0}")]
    InternalError(String),
    /// The request was cancelled through an
    /// [`AbortSignal`](crate::AbortSignal) before it completed. Not an error in
    /// the ordinary sense: the caller asked for this.
    #[error("Request was aborted")]
    RequestAborted,
    /// Certificate pinning rejected the server's certificate: the SPKI hash did
    /// not match any configured pin. Treat as a potential MITM, not a glitch.
    #[error("Certificate pinning failed: {0}")]
    CertificatePinningFailed(String),
    /// A WebSocket operation failed. Available with the `websocket` feature.
    #[error("WebSocket error: {0}")]
    WebSocketError(String),
    /// A streaming operation failed mid-transfer — including an interceptor that
    /// refused the response before the body was yielded.
    #[error("Streaming error: {0}")]
    StreamingError(String),
}

impl From<url::ParseError> for BeanStreamError {
    fn from(error: url::ParseError) -> Self {
        Self::UrlError(error.to_string())
    }
}

impl From<reqwest::Error> for BeanStreamError {
    fn from(error: reqwest::Error) -> Self {
        Self::RequestFailed(error.to_string())
    }
}

impl From<std::io::Error> for BeanStreamError {
    fn from(error: std::io::Error) -> Self {
        Self::InternalError(error.to_string())
    }
}

impl From<std::string::FromUtf8Error> for BeanStreamError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Self::InternalError(error.to_string())
    }
}

/// Convenience alias for `Result` with [`BeanStreamError`] as the error type.
pub type Result<T> = std::result::Result<T, BeanStreamError>;
