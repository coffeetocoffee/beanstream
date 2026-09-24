use thiserror::Error;

#[derive(Error, Debug)]
pub enum BeanStreamError {
    #[error("URL error: {0}")]
    UrlError(String),
    #[error("Scheme '{0}' is not allowed. Only http and https schemes are permitted")]
    InvalidScheme(String),
    #[error("Access to private/internal network blocked. Address '{0}' is not accessible")]
    PrivateNetworkAccess(String),
    #[error("Invalid host: {0}")]
    InvalidHost(String),
    #[error("Header validation error: {0}")]
    HeaderError(String),
    #[error("Potential header injection detected. Carriage return or line feed characters are not allowed")]
    HeaderInjectionDetected,
    #[error("Redirect blocked: {0}")]
    RedirectBlocked(String),
    #[error("Too many redirects ({0})")]
    TooManyRedirects(usize),
    #[error("No host found in URL")]
    NoHost,
    #[error("Host '{0}' is not allowed by redirect policy")]
    HostNotAllowed(String),
    #[error("Invalid port number: {0}")]
    InvalidPort(u16),
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("Network timeout after {0}ms")]
    NetworkTimeout(u64),
    #[error("Server error: {0}")]
    ServerError(u16),
    #[error("Rate limit exceeded. Please try again later")]
    RateLimited,
    #[error("Missing required configuration: {0}")]
    MissingConfig(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Request was aborted")]
    RequestAborted,
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

pub type Result<T> = std::result::Result<T, BeanStreamError>;
