use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Client, Method};

use crate::header_validation::{is_blocked_header, sanitize_header, validate_headers};
use crate::redirect_policy::{RedirectPolicy, ScopeValidator};
use crate::url_validation::{validate_url, ParsedUrl};
use crate::{BeanStreamError, Result};

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub parsed_url: ParsedUrl,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub timeout: Duration,
    pub redirect_policy: RedirectPolicy,
    pub scope_validator: ScopeValidator,
}

impl HttpRequest {
    pub fn get(url: &str) -> Result<Self> {
        Self::new(Method::GET, url)
    }

    pub fn post(url: &str) -> Result<Self> {
        Self::new(Method::POST, url)
    }

    pub fn put(url: &str) -> Result<Self> {
        Self::new(Method::PUT, url)
    }

    pub fn delete(url: &str) -> Result<Self> {
        Self::new(Method::DELETE, url)
    }

    pub fn patch(url: &str) -> Result<Self> {
        Self::new(Method::PATCH, url)
    }

    pub fn new(method: Method, url: &str) -> Result<Self> {
        let parsed_url = validate_url(url)?;
        let mut scope_validator = ScopeValidator::new(true);
        scope_validator.allow_host(&parsed_url.host.host);

        Ok(Self {
            method,
            url: url.to_string(),
            parsed_url,
            headers: Vec::new(),
            body: None,
            timeout: Duration::from_secs(30),
            redirect_policy: RedirectPolicy::default(),
            scope_validator,
        })
    }

    pub fn add_header(&mut self, name: &str, value: &str) -> Result<&mut Self> {
        let (name, value) = sanitize_header(name, value)?;

        if is_blocked_header(&name) {
            return Err(BeanStreamError::HeaderError(format!(
                "Header '{name}' is forbidden"
            )));
        }

        self.headers.push((name, value));
        Ok(self)
    }

    pub fn add_headers<I, K, V>(&mut self, headers: I) -> Result<&mut Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (name, value) in headers {
            self.add_header(name.as_ref(), value.as_ref())?;
        }
        Ok(self)
    }

    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.redirect_policy = redirect_policy;
        self
    }

    pub fn scope_validator(mut self, scope_validator: ScopeValidator) -> Self {
        self.scope_validator = scope_validator;
        self
    }

    pub fn validate(&self) -> Result<()> {
        self.scope_validator.check_url(&self.url)?;
        validate_headers(&self.headers)
    }

    pub fn build_request(&self) -> Result<reqwest::Request> {
        self.validate()?;

        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout)
            .build()?;
        let mut request = client.request(self.method.clone(), &self.url);

        for (name, value) in &self.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| BeanStreamError::HeaderError("Invalid header name".to_string()))?;
            let value = HeaderValue::from_str(value)
                .map_err(|_| BeanStreamError::HeaderError("Invalid header value".to_string()))?;
            request = request.header(name, value);
        }

        if let Some(body) = &self.body {
            request = request.body(body.clone());
        }

        request.build().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_validated_requests() {
        let request = HttpRequest::get("https://8.8.8.8/api").unwrap();
        assert_eq!(request.method, Method::GET);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn rejects_private_requests() {
        assert!(matches!(
            HttpRequest::get("http://127.0.0.1/"),
            Err(BeanStreamError::PrivateNetworkAccess(_))
        ));
    }

    #[test]
    fn sanitizes_and_blocks_headers() {
        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        assert!(request.add_header("X-Test", "value\r\ninjected").is_err());
        assert!(request.add_header("Host", "evil.example").is_err());
        request.add_header("X-Test", "value").unwrap();
        assert_eq!(request.headers[0].0, "x-test");
    }

    #[test]
    fn adds_multiple_headers_and_body() {
        let request = HttpRequest::post("https://8.8.8.8/")
            .unwrap()
            .body("payload")
            .timeout(Duration::from_secs(5));
        let mut request = request;
        request
            .add_headers([("X-One", "1"), ("X-Two", "2")])
            .unwrap();
        assert_eq!(request.headers.len(), 2);
        assert_eq!(request.body.as_deref(), Some("payload"));
        assert!(request.build_request().is_ok());
    }

    #[test]
    fn scope_is_limited_to_the_request_host() {
        let request = HttpRequest::get("https://8.8.8.8/").unwrap();
        let mut request = request;
        request.url = "https://1.1.1.1/".to_string();
        assert!(request.validate().is_err());
    }

    #[test]
    fn builds_without_following_redirects() {
        let request = HttpRequest::get("https://8.8.8.8/redirect").unwrap();
        assert!(request.build_request().is_ok());
    }
}
