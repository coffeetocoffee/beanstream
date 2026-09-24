use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use url::Url;

use crate::header_validation::{is_blocked_header, sanitize_header};
use crate::redirect_policy::{RedirectPolicy, ScopeValidator};
use crate::request_handler::HttpRequest;
use crate::{BeanStreamError, Result};

#[derive(Debug, Clone)]
pub struct HttpClientBuilder {
    base_url: Option<String>,
    timeout: Duration,
    max_redirects: usize,
    follow_redirects: bool,
    connect_timeout: Duration,
    user_agent: String,
    default_headers: Vec<(String, String)>,
    check_private_ips: bool,
}

impl Default for HttpClientBuilder {
    fn default() -> Self {
        Self {
            base_url: None,
            timeout: Duration::from_secs(30),
            max_redirects: 10,
            follow_redirects: false,
            connect_timeout: Duration::from_secs(10),
            user_agent: "BeanStream/1.0".to_string(),
            default_headers: Vec::new(),
            check_private_ips: true,
        }
    }
}

impl HttpClientBuilder {
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    pub fn with_follow_redirects(mut self, follow_redirects: bool) -> Self {
        self.follow_redirects = follow_redirects;
        self
    }

    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    pub fn add_default_header(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self> {
        let (name, value) = sanitize_header(name.as_ref(), value.as_ref())?;
        if is_blocked_header(&name) {
            return Err(BeanStreamError::HeaderError(format!(
                "Header '{name}' is forbidden"
            )));
        }
        self.default_headers.push((name, value));
        Ok(self)
    }

    pub fn allow_private_networks(mut self) -> Self {
        self.check_private_ips = false;
        self
    }

    pub fn build(self) -> Result<reqwest::Client> {
        let user_agent = HeaderValue::from_str(&self.user_agent)
            .map_err(|_| BeanStreamError::InvalidConfiguration("Invalid user agent".to_string()))?;
        let mut client = reqwest::Client::builder()
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .user_agent(user_agent);

        if self.follow_redirects {
            client = client.redirect(reqwest::redirect::Policy::limited(self.max_redirects));
        } else {
            client = client.redirect(reqwest::redirect::Policy::none());
        }

        let mut headers = HeaderMap::new();
        for (name, value) in &self.default_headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                BeanStreamError::HeaderError("Invalid default header name".to_string())
            })?;
            let value = HeaderValue::from_str(value).map_err(|_| {
                BeanStreamError::HeaderError("Invalid default header value".to_string())
            })?;
            headers.insert(name, value);
        }
        client = client.default_headers(headers);

        client.build().map_err(Into::into)
    }

    pub fn get_redirect_policy(&self) -> RedirectPolicy {
        RedirectPolicy {
            max_redirects: self.max_redirects,
            track_all_redirects: self.follow_redirects,
            allow_any_redirect: false,
            ..RedirectPolicy::default()
        }
    }

    pub fn create_scope_validator(&self) -> ScopeValidator {
        let validator = ScopeValidator::new(false);
        if self.check_private_ips {
            validator.with_deny_list([
                "0.0.0.0",
                "10.*",
                "100.64.*",
                "127.0.0.1",
                "169.254.*",
                "172.16.*",
                "192.168.*",
                "198.18.*",
                "224.*",
                "240.*",
                "localhost",
                "*.localhost",
                "*.local",
                "*.internal",
            ])
        } else {
            validator
        }
    }

    pub fn create_request(&self, method: Method, target: &str) -> Result<HttpRequest> {
        let absolute = Url::parse(target).is_ok();
        let url = if absolute {
            target.to_string()
        } else if let Some(base_url) = &self.base_url {
            Url::parse(base_url)
                .and_then(|base| base.join(target))
                .map_err(BeanStreamError::from)?
                .to_string()
        } else {
            return Err(BeanStreamError::MissingConfig(
                "A base URL is required for relative request targets".to_string(),
            ));
        };

        HttpRequest::new(method, &url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_client_with_safe_defaults() {
        assert!(HttpClientBuilder::default().build().is_ok());
    }

    #[test]
    fn rejects_invalid_default_headers() {
        let result = HttpClientBuilder::default().add_default_header("Host", "evil.example");
        assert!(result.is_err());
    }

    #[test]
    fn adds_valid_default_headers() {
        let builder = HttpClientBuilder::default()
            .add_default_header("X-Test", "value")
            .unwrap();
        assert!(builder.build().is_ok());
    }

    #[test]
    fn creates_absolute_and_relative_requests() {
        let builder = HttpClientBuilder::default().with_base_url("https://8.8.8.8/api/");
        let request = builder.create_request(Method::GET, "users").unwrap();
        assert_eq!(request.url, "https://8.8.8.8/api/users");

        let absolute = builder
            .create_request(Method::GET, "https://1.1.1.1/data")
            .unwrap();
        assert_eq!(absolute.url, "https://1.1.1.1/data");
    }

    #[test]
    fn requires_base_url_for_relative_targets() {
        let result = HttpClientBuilder::default().create_request(Method::GET, "users");
        assert!(matches!(result, Err(BeanStreamError::MissingConfig(_))));
    }
}
