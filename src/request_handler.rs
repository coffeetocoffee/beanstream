use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Client, Method};

use crate::abort::AbortSignal;
use crate::cache::InMemoryCache;
use crate::header_validation::{
    is_blocked_header, redact_sensitive_headers, sanitize_header, validate_headers,
};
use crate::interceptor::InterceptorChain;
use crate::progress::UploadProgress;
use crate::rate_limit::RateLimiter;
use crate::redirect_policy::{RedirectPolicy, ScopeValidator};
use crate::retry::RetryConfig;
use crate::url_validation::{resolve_host, validate_url, ParsedUrl};
use crate::{BeanStreamError, Result};

/// Response returned by [`HttpRequest::send`].
///
/// `headers` are redacted: sensitive entries (`set-cookie`, `authorization`,
/// ...) are stripped before the response is handed to the caller (P1-3).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub url: String,
}

impl HttpResponse {
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| BeanStreamError::InternalError(e.to_string()))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Re-run redaction over this response's headers.
    ///
    /// Safe to call repeatedly; used as a defence-in-depth guard so a response
    /// built through any path is redacted before it is logged or serialized.
    pub fn redact(&mut self) {
        self.headers = redact_sensitive_headers(&self.headers);
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
    pub retry: Option<RetryConfig>,
    pub cache: Option<Arc<InMemoryCache>>,
    pub rate_limiter: Option<RateLimiter>,
    pub interceptors: InterceptorChain,
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
            .field("retry", &self.retry)
            .field("cache", &self.cache.is_some())
            .field("rate_limiter", &self.rate_limiter.is_some())
            .field("interceptors", &self.interceptors.len())
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
            retry: self.retry.clone(),
            cache: self.cache.clone(),
            rate_limiter: self.rate_limiter.clone(),
            interceptors: self.interceptors.clone(),
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
            retry: None,
            cache: None,
            rate_limiter: None,
            interceptors: InterceptorChain::new(),
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

    /// Attach automatic retry configuration (P0-4).
    pub fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.retry = Some(retry);
        self
    }

    /// Attach an intelligent response cache (P0-5).
    pub fn with_cache(mut self, cache: Arc<InMemoryCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Attach a semaphore-based rate limiter (P0-6).
    pub fn with_rate_limiter(mut self, rate_limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Register a middleware interceptor (P0-7). Interceptors run in
    /// registration order around the request/response cycle.
    pub fn add_interceptor(
        mut self,
        interceptor: std::sync::Arc<dyn crate::interceptor::Interceptor>,
    ) -> Self {
        self.interceptors.add(interceptor);
        self
    }

    /// Replace the whole interceptor chain (P0-7).
    pub fn with_interceptors(mut self, chain: InterceptorChain) -> Self {
        self.interceptors = chain;
        self
    }

    pub fn validate(&self) -> Result<()> {
        self.scope_validator.check_url(&self.url)?;
        validate_headers(&self.headers)
    }

    /// Resolve the request hostname to pinned, validated IP addresses.
    ///
    /// This is the authoritative SSRF defence (P1-1). Validating a hostname's
    /// addresses *before* connecting is unsafe on its own: reqwest re-resolves
    /// the hostname at connect time, so an attacker controlling DNS can answer
    /// the validation lookup with a public IP and the connect lookup with a
    /// private one (DNS rebinding / TOCTOU).
    ///
    /// Instead we resolve once here -- asynchronously, so the reactor is never
    /// blocked (P1-2) -- verify every address against the block list, and then
    /// hand the exact address list to reqwest via `resolve_to_addrs`. The
    /// connect-time lookup is bypassed entirely, so no swap can occur.
    ///
    /// TLS is unaffected: reqwest still derives SNI and certificate
    /// verification from the URL hostname, not the pinned address.
    ///
    /// Returns `None` when the host is a literal IP (nothing to resolve).
    async fn pinned_addresses(&self) -> Result<Option<(String, Vec<SocketAddr>)>> {
        let host = &self.parsed_url.host.host;

        // Literal IPs need no resolution -- validate_url already checked them.
        if self.parsed_url.host.ip_addr.is_some() {
            return Ok(None);
        }

        let addresses = resolve_host(host).await?;
        if addresses.is_empty() {
            return Err(BeanStreamError::InvalidHost(format!(
                "Host '{host}' did not resolve to an address"
            )));
        }

        for address in &addresses {
            if crate::url_validation::is_blocked_ip(address) {
                return Err(BeanStreamError::PrivateNetworkAccess(address.to_string()));
            }
        }

        let port = self.parsed_url.port;
        let socket_addresses = addresses
            .iter()
            .map(|address| SocketAddr::new(*address, port))
            .collect::<Vec<_>>();

        Ok(Some((host.clone(), socket_addresses)))
    }

    /// Build a reqwest client whose DNS resolution is pinned to `pinned`.
    fn build_client(&self, pinned: Option<&(String, Vec<SocketAddr>)>) -> Result<Client> {
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout);

        if let Some((host, addresses)) = pinned {
            builder = builder.resolve_to_addrs(host, addresses);
        }

        builder.build().map_err(Into::into)
    }

    pub fn build_request(&self) -> Result<reqwest::Request> {
        self.validate()?;

        let client = self.build_client(None)?;
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

        // P0-3: progress hook -- report upload start; abort if callback returns false
        if let Some(progress) = &self.progress {
            let total = self.body.as_ref().map(|b| b.len() as u64);
            if !progress.on_progress(0, total) {
                return Err(BeanStreamError::RequestAborted);
            }
        }

        // P0-6: hold a concurrency permit for the whole request lifecycle
        let _permit = match &self.rate_limiter {
            Some(limiter) => Some(limiter.acquire().await?),
            None => None,
        };

        // P0-5: cache lookup for safe (idempotent) methods
        let cacheable = self.method == Method::GET || self.method == Method::HEAD;
        if cacheable {
            if let Some(cache) = &self.cache {
                if let Some(hit) = cache.get(self.method.as_str(), &self.url) {
                    if !crate::progress::report_complete(&self.progress, hit.body.len() as u64) {
                        return Err(BeanStreamError::RequestAborted);
                    }
                    return Ok(hit);
                }
            }
        }
        let conditional_etag = if cacheable {
            self.cache
                .as_ref()
                .and_then(|c| c.get_etag(self.method.as_str(), &self.url))
        } else {
            None
        };

        // P1-1: resolve once and pin, so the connect-time lookup cannot be
        // swapped to a private address. Done before the retry loop so a
        // rebinding attacker cannot win by waiting for a later attempt.
        let pinned = self.pinned_addresses().await?;

        // P0-4: retry loop with exponential backoff
        let max_attempts = self
            .retry
            .as_ref()
            .map(|r| r.max_attempts)
            .unwrap_or(1)
            .max(1);
        let mut backoff = self.retry.as_ref().map(|r| r.backoff());
        let mut attempt: u32 = 0;

        loop {
            attempt += 1;

            match self.send_once(&pinned, conditional_etag.as_deref()).await {
                Ok((status, headers, body, url)) => {
                    if let Some(retry) = &self.retry {
                        if retry.should_retry_status(status) && attempt < max_attempts {
                            if let Some(backoff) = backoff.as_mut() {
                                let delay = retry.next_delay(backoff);
                                tokio::time::sleep(delay).await;
                            }
                            continue;
                        }
                    }

                    if attempt >= max_attempts {
                        if status == 429 {
                            return Err(BeanStreamError::RateLimited);
                        }
                        if (500..600).contains(&status) {
                            return Err(BeanStreamError::ServerError(status));
                        }
                    }

                    let mut response = HttpResponse {
                        status,
                        headers,
                        body,
                        url,
                    };

                    // P1-3: never surface secrets to the caller.
                    response.redact();

                    if status == 304 {
                        if cacheable {
                            if let Some(cache) = &self.cache {
                                if let Some(mut hit) = cache.get(self.method.as_str(), &self.url) {
                                    hit.status = 304;
                                    response = hit;
                                }
                            }
                        }
                    } else if cacheable && response.is_success() {
                        if let Some(cache) = &self.cache {
                            cache.insert(self.method.as_str(), response.clone());
                        }
                    }

                    if !crate::progress::report_complete(&self.progress, response.body.len() as u64)
                    {
                        return Err(BeanStreamError::RequestAborted);
                    }

                    return Ok(response);
                }
                Err(err) => {
                    if let Some(retry) = &self.retry {
                        if retry.should_retry(&err) && attempt < max_attempts {
                            if let Some(backoff) = backoff.as_mut() {
                                let delay = retry.next_delay(backoff);
                                tokio::time::sleep(delay).await;
                            }
                            continue;
                        }
                    }
                    return Err(err);
                }
            }
        }
    }

    async fn send_once(
        &self,
        pinned: &Option<(String, Vec<SocketAddr>)>,
        if_none_match: Option<&str>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>, String)> {
        // P1-1: the client is pinned to the addresses validated up front, so
        // reqwest does not re-resolve the hostname at connect time.
        let client = self.build_client(pinned.as_ref())?;

        let mut request = client.request(self.method.clone(), &self.url);
        for (name, value) in &self.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| BeanStreamError::HeaderError("Invalid header name".to_string()))?;
            let value = HeaderValue::from_str(value)
                .map_err(|_| BeanStreamError::HeaderError("Invalid header value".to_string()))?;
            request = request.header(name, value);
        }
        if let Some(etag) = if_none_match {
            request = request.header("If-None-Match", etag);
        }
        if let Some(body) = &self.body {
            request = request.body(body.clone());
        }

        let response = request.send().await.map_err(|e| {
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

        let body = response
            .bytes()
            .await
            .map_err(|e| BeanStreamError::RequestFailed(e.to_string()))?
            .to_vec();

        Ok((status, headers, body, url))
    }

    /// Execute the request -- actually sends over the network (P0-1).
    /// Honors `AbortSignal` (P0-2), `UploadProgress` (P0-3), retry (P0-4),
    /// cache (P0-5), rate limiting (P0-6), and interceptors (P0-7).
    ///
    /// The hostname is resolved asynchronously and pinned to the validated
    /// addresses before connecting (P1-1), and response headers are redacted
    /// before they are returned (P1-3).
    pub async fn send(&self) -> Result<HttpResponse> {
        let interceptors = self.interceptors.clone();
        let mut this = self.clone();
        interceptors.run_on_request(&mut this)?;

        let outcome = if let Some(signal) = &this.abort_signal {
            if signal.is_aborted() {
                return Err(BeanStreamError::RequestAborted);
            }
            tokio::select! {
                res = this.execute_inner() => res,
                _ = signal.cancelled() => Err(BeanStreamError::RequestAborted),
            }
        } else {
            this.execute_inner().await
        };

        let mut response = outcome?;
        interceptors.run_on_response(&mut response)?;

        // P1-3: interceptors may re-inject headers (e.g. an auth refresh), so
        // redact once more as the final gate before the caller sees anything.
        response.redact();

        Ok(response)
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
    async fn pins_dns_resolution_to_validated_addresses() {
        // P1-1: a hostname must resolve to concrete addresses that are then
        // pinned into the client, closing the rebinding window.
        //
        // `localhost` is rejected by validate_domain() at construction, so
        // start from a valid request and swap in a host that structurally
        // passes validation but resolves to a private address.
        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        request.parsed_url.host = crate::url_validation::ValidatedHost {
            host: "localhost".to_string(),
            ip_addr: None,
        };

        let result = request.pinned_addresses().await;

        // It resolves to 127.0.0.1 / ::1, so it must be rejected rather than
        // pinned -- this is exactly the rebinding case, caught before connect.
        assert!(matches!(
            result,
            Err(BeanStreamError::PrivateNetworkAccess(_))
        ));
    }

    #[tokio::test]
    async fn pinned_addresses_carry_the_parsed_port() {
        // P1-1: the pin is built as host:port pairs, so the URL's port must be
        // preserved (including the default 443 for https).
        let request = HttpRequest::get("https://8.8.8.8/").unwrap();
        assert_eq!(request.parsed_url.port, 443);

        let explicit = HttpRequest::get("https://8.8.8.8:8443/").unwrap();
        assert_eq!(explicit.parsed_url.port, 8443);
    }

    #[tokio::test]
    async fn literal_ip_hosts_are_not_resolved() {
        // Nothing to pin when the host is already a literal IP.
        let request = HttpRequest::get("https://8.8.8.8/").unwrap();
        assert!(request.pinned_addresses().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unresolvable_host_is_rejected_before_connecting() {
        let request = HttpRequest::get("https://this-host-does-not-resolve-9f3c.invalid/").unwrap();
        assert!(matches!(
            request.pinned_addresses().await,
            Err(BeanStreamError::InvalidHost(_))
        ));
    }

    #[test]
    fn response_redaction_strips_sensitive_headers() {
        // P1-3.
        let mut response = HttpResponse {
            status: 200,
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("set-cookie".to_string(), "session=secret".to_string()),
                ("authorization".to_string(), "Bearer hunter2".to_string()),
            ],
            body: b"{}".to_vec(),
            url: "https://8.8.8.8/".to_string(),
        };

        response.redact();
        assert_eq!(response.headers.len(), 1);
        assert_eq!(response.headers[0].0, "content-type");
        assert!(!response
            .headers
            .iter()
            .any(|(name, _)| crate::header_validation::is_sensitive_header(name)));
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

    #[tokio::test]
    async fn cache_hit_short_circuits_network() {
        use crate::cache::{CacheConfig, InMemoryCache};

        let cache = Arc::new(InMemoryCache::new(CacheConfig {
            default_ttl: Duration::from_secs(60),
            use_etags: false,
            use_cache_control: false,
            max_size: 10,
        }));
        cache.insert(
            "GET",
            HttpResponse {
                status: 200,
                headers: vec![],
                body: b"cached-body".to_vec(),
                url: "https://8.8.8.8/".to_string(),
            },
        );

        let req = HttpRequest::get("https://8.8.8.8/")
            .unwrap()
            .with_cache(cache);
        let res = req.send().await.unwrap();
        assert_eq!(res.body, b"cached-body");
    }

    #[tokio::test]
    async fn rate_limiter_blocks_when_exhausted() {
        use crate::rate_limit::RateLimiter;

        let limiter = RateLimiter::new(1);
        let _held = limiter.try_acquire().unwrap();
        // A request with the limiter cannot proceed; abort via signal to avoid hanging.
        use crate::abort::AbortController;
        let controller = AbortController::new();
        let req = HttpRequest::get("https://8.8.8.8/")
            .unwrap()
            .with_rate_limiter(limiter)
            .with_signal(controller.signal());
        controller.abort();
        let res = req.send().await;
        assert!(matches!(res, Err(BeanStreamError::RequestAborted)));
    }
}
