use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Client, Method};

use crate::abort::AbortSignal;
use crate::header_validation::{is_blocked_header, sanitize_header, validate_headers};
use crate::progress::UploadProgress;
use crate::redirect_policy::{RedirectPolicy, ScopeValidator};
use crate::url_validation::{validate_url, ParsedUrl};
use crate::{BeanStreamError, Result};

/// Response returned by [`HttpRequest::send`].
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub url: String,
}

impl HttpResponse {
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone()).map_err(|e| BeanStreamError::InternalError(e.to_string()))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub struct HttpRequest {
    pub method: Method,
    pub url: String,
    pub parsed_url: ParsedUrl,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub timeout: Duration,
    pub redirect_policy: RedirectPolicy,
    pub scope_validator: ScopeValidator,
    pub abort_signal: Option<AbortSignal>,
    progress: Option<Arc<dyn UploadProgress>>,
}

// Manual Debug: skip progress trait object
impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("parsed_url", &self.parsed_url)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .field("timeout", &self.timeout)
            .field("redirect_policy", &self.redirect_policy)
            .field("scope_validator", &self.scope_validator)
            .field("abort_signal", &self.abort_signal)
            .field("has_progress", &self.progress.is_some())
            .finish()
    }
}

impl Clone for HttpRequest {
    fn clone(&self) -> Self {
        Self {
            method: self.method.clone(),
            url: self.url.clone(),
            parsed_url: self.parsed_url.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
            timeout: self.timeout,
            redirect_policy: self.redirect_policy.clone(),
            scope_validator: self.scope_validator.clone(),
            abort_signal: self.abort_signal.clone(),
            progress: self.progress.clone(),
        }
    }
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
            abort_signal: None,
            progress: None,
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

    /// Attach an abort signal (P0-2). If aborted, `send().await` returns `RequestAborted`.
    pub fn with_signal(mut self, signal: AbortSignal) -> Self {
        self.abort_signal = Some(signal);
        self
    }

    /// Alias for `with_signal` to match `execute_with_abort` naming.
    pub fn abort_signal(mut self, signal: AbortSignal) -> Self {
        self.abort_signal = Some(signal);
        self
    }

    /// Attach progress tracker (P0-3).
    pub fn with_progress<P>(mut self, progress: P) -> Self
    where
        P: UploadProgress,
    {
        self.progress = Some(Arc::new(progress));
        self
    }

    /// Attach already-boxed progress trait object.
    pub fn with_progress_arc(mut self, progress: Arc<dyn UploadProgress>) -> Self {
        self.progress = Some(progress);
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

    // --- P0-1: actual HTTP execution ---

    async fn execute_inner(&self) -> Result<HttpResponse> {
        self.validate()?;

        // P0-3: progress hook — report upload start/end; abort if callback returns false
        if let Some(progress) = &self.progress {
            let total = self.body.as_ref().map(|b| b.len() as u64);
            if !progress.on_progress(0, total) {
                return Err(BeanStreamError::RequestAborted);
            }
        }

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

        let response = request.send().await.map_err(|e| {
            // Map timeout explicitly
            if e.is_timeout() {
                BeanStreamError::NetworkTimeout(self.timeout.as_millis() as u64)
            } else {
                BeanStreamError::RequestFailed(e.to_string())
            }
        })?;

        let status = response.status().as_u16();
        let url = response.url().to_string();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect::<Vec<_>>();

        // Keep body accessible even for 4xx/5xx — caller can inspect status

        let body = response
            .bytes()
            .await
            .map_err(|e| BeanStreamError::RequestFailed(e.to_string()))?
            .to_vec();

        if !crate::progress::report_complete(&self.progress, body.len() as u64) {
            return Err(BeanStreamError::RequestAborted);
        }

        Ok(HttpResponse { status, headers, body, url })
    }

    /// Execute the request — actually sends over the network (P0-1).
    /// Honors attached `AbortSignal` (P0-2) and `UploadProgress` (P0-3).
    pub async fn send(&self) -> Result<HttpResponse> {
        if let Some(signal) = &self.abort_signal {
            if signal.is_aborted() {
                return Err(BeanStreamError::RequestAborted);
            }
            // Clone self to move into async branch
            let this = self.clone();
            tokio::select! {
                res = this.execute_inner() => res,
                _ = signal.cancelled() => Err(BeanStreamError::RequestAborted),
            }
        } else {
            self.execute_inner().await
        }
    }

    /// Convenience: send consuming self.
    pub async fn execute(self) -> Result<HttpResponse> {
        self.send().await
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

    #[tokio::test]
    async fn send_with_abort_signal_already_aborted() {
        use crate::abort::AbortController;
        let controller = AbortController::new();
        controller.abort();
        let req = HttpRequest::get("https://8.8.8.8/")
            .unwrap()
            .with_signal(controller.signal());
        let res = req.send().await;
        assert!(matches!(res, Err(BeanStreamError::RequestAborted)));
    }

    #[tokio::test]
    async fn progress_callback_invoked_on_send() {
        use crate::progress::UploadProgress;

        // A tracker that always returns false must abort the request before it
        // touches the network (progress hook runs prior to sending).
        struct AbortTracker;
        impl UploadProgress for AbortTracker {
            fn on_progress(&self, _uploaded: u64, _total: Option<u64>) -> bool {
                false
            }
        }
        let req = HttpRequest::get("https://8.8.8.8/")
            .unwrap()
            .with_progress(AbortTracker);
        let res = req.send().await;
        assert!(matches!(res, Err(BeanStreamError::RequestAborted)));
    }
}
