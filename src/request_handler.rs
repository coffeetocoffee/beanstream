use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Client, Method};
use url::Url;

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
use crate::url_validation::{resolve_host, validate_url, ParsedUrl, ValidatedHost};
use crate::{BeanStreamError, Result};

/// Response returned by [`HttpRequest::send`].
///
/// [`Self::headers`] are **redacted**: sensitive entries (`set-cookie`,
/// `authorization`, `x-api-key`, …) are stripped before the response reaches the
/// caller (P1-3), and again after interceptors run. Redaction is destructive —
/// the removed values are not recoverable from this struct. If you need one,
/// read it in an [`Interceptor::on_response`](crate::Interceptor::on_response)
/// before that second pass.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers, with sensitive names removed. Names are lowercase.
    pub headers: Vec<(String, String)>,
    /// The response body. Held in full, so a large download is best streamed
    /// with [`download_stream`](crate::download_stream) instead.
    pub body: Vec<u8>,
    /// The URL that actually produced this response. After a followed redirect
    /// chain this is the final URL, not the one requested.
    pub url: String,
}

impl HttpResponse {
    /// Decode the body as UTF-8.
    ///
    /// Returns [`BeanStreamError::InternalError`] if the body is not valid
    /// UTF-8 — use [`Self::bytes`] for binary payloads.
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| BeanStreamError::InternalError(e.to_string()))
    }

    /// The raw body, without decoding.
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Whether the status is in the 2xx range.
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

/// The method, headers and body a redirect hop may carry.
///
/// Bundled so [`HttpRequest::plan_hop`] can return the whole hop as one value
/// instead of a four-element tuple.
#[derive(Debug, Clone)]
struct RedirectHop {
    url: Url,
    method: Method,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

/// A single HTTP request, already validated, ready to send.
///
/// Build one with [`Self::new`] or a verb helper ([`Self::get`], [`Self::post`],
/// …), which validate the URL up front — so an invalid target fails at
/// construction, not at send time. Chain the ownership-taking `body`, `timeout`
/// and `redirect_policy` methods to configure it, then either attach optional
/// features ([`Self::with_retry`], [`Self::with_cache`], [`Self::with_progress`],
/// [`Self::with_signal`]) or call [`Self::send`].
///
/// ```no_run
/// use std::time::Duration;
///
/// use beanstream::HttpRequest;
///
/// # fn example() -> Result<(), beanstream::BeanStreamError> {
/// let mut request = HttpRequest::post("https://api.example.com/items")?
///     .body(r#"{"name":"espresso"}"#)
///     .timeout(Duration::from_secs(10));
/// request.add_header("Content-Type", "application/json")?;
/// # Ok(())
/// # }
/// ```
///
/// [`Self::send`] is where the security layers apply: it resolves the host once,
/// validates every resolved address, pins them into the client so reqwest cannot
/// re-resolve, and walks redirects itself when the policy asks for it.
pub struct HttpRequest {
    /// The HTTP method.
    pub method: Method,
    /// The target URL, after `HttpRequest::new` normalized it against any base.
    pub url: String,
    /// The parsed and validated form of [`Self::url`].
    pub parsed_url: ParsedUrl,
    /// Headers to send. Added through [`Self::add_header`], which sanitizes.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<String>,
    /// Overall timeout for the exchange. Defaults to 30 seconds.
    pub timeout: Duration,
    /// Redirect rules. Defaults to refusing every redirect, so a 3xx is returned
    /// to the caller.
    pub redirect_policy: RedirectPolicy,
    /// Host allow/deny list for the target itself.
    pub scope_validator: ScopeValidator,
    /// Cancellation handle, if one was attached with [`Self::with_signal`].
    pub abort_signal: Option<AbortSignal>,
    /// Retry policy, if attached with [`Self::with_retry`].
    pub retry: Option<RetryConfig>,
    /// Response cache, if attached with [`Self::with_cache`].
    pub cache: Option<Arc<InMemoryCache>>,
    /// Concurrency limiter, if attached with [`Self::with_rate_limiter`].
    pub rate_limiter: Option<RateLimiter>,
    /// Middleware chain, run before the request and after the response.
    pub interceptors: InterceptorChain,
    /// Shared cookie jar, only meaningful with the `cookies` feature (P2-2).
    /// Opt-in: an implicit jar would let one host's cookies reach another.
    #[cfg(feature = "cookies")]
    pub cookie_jar: Option<crate::cookies::CookieJar>,
    /// SPKI pins to enforce on the TLS handshake, if any.
    ///
    /// This has to live on the request rather than only on the builder: the
    /// pinned send path builds its own client (so it can call
    /// `resolve_to_addrs`), and a pin set on the builder that never reached
    /// this struct would be silently ignored. Applying it requires the
    /// `rustls-tls` feature; without it, sending fails with
    /// [`BeanStreamError::InvalidConfiguration`] rather than connecting
    /// unpinned.
    pub cert_pinning: Option<crate::cert_pinning::CertPinConfig>,
    /// How this request reaches a proxy (A1-A4).
    ///
    /// Carried on the request, not only on the builder, for the same reason as
    /// the pins: the pinned send path builds its own client, so a routing
    /// decision left on the builder would be silently ignored there. Defaults to
    /// [`ProxyConfig::System`](crate::ProxyConfig::System), matching reqwest and
    /// curl.
    pub proxy: crate::proxy_config::ProxyConfig,
    /// Whether the destination's *resolved addresses* may be private.
    ///
    /// `false` (the default) means the host is resolved and every address is
    /// checked against the private/reserved block list before connecting — and
    /// that holds **even when a proxy is configured**, so a proxy cannot become
    /// a way to reach internal services a direct request would refuse.
    ///
    /// Set by [`HttpClientBuilder::allow_private_networks`](crate::HttpClientBuilder::allow_private_networks),
    /// which is the explicit opt-in for reaching an internal host. Literal
    /// private addresses and reserved names are still refused earlier by
    /// [`validate_url`](crate::validate_url) and by the scope validator, so this
    /// flag alone does not make `https://127.0.0.1/` reachable.
    pub allow_private_addresses: bool,
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
            .field("cert_pinning", &self.cert_pinning.is_some())
            .field("proxy", &self.proxy)
            .field("allow_private_addresses", &self.allow_private_addresses)
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
            #[cfg(feature = "cookies")]
            cookie_jar: self.cookie_jar.clone(),
            cert_pinning: self.cert_pinning.clone(),
            proxy: self.proxy.clone(),
            allow_private_addresses: self.allow_private_addresses,
            progress: self.progress.clone(),
        }
    }
}

impl HttpRequest {
    /// A `GET` request. Validates `url` immediately.
    pub fn get(url: &str) -> Result<Self> {
        Self::new(Method::GET, url)
    }

    /// A `POST` request. Validates `url` immediately.
    pub fn post(url: &str) -> Result<Self> {
        Self::new(Method::POST, url)
    }

    /// A `PUT` request. Validates `url` immediately.
    pub fn put(url: &str) -> Result<Self> {
        Self::new(Method::PUT, url)
    }

    /// A `DELETE` request. Validates `url` immediately.
    pub fn delete(url: &str) -> Result<Self> {
        Self::new(Method::DELETE, url)
    }

    /// A `PATCH` request. Validates `url` immediately.
    pub fn patch(url: &str) -> Result<Self> {
        Self::new(Method::PATCH, url)
    }

    /// Build a request for an arbitrary method.
    ///
    /// Validates the URL via [`validate_url`] before returning, so a private,
    /// credential-bearing or non-`http(s)` target is rejected here rather than
    /// at send time. The default scope validator is host-scoped to this URL's
    /// host, and the request defaults to a 30-second timeout.
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
            #[cfg(feature = "cookies")]
            cookie_jar: None,
            cert_pinning: None,
            // Matches reqwest and curl: platform + environment unless changed.
            proxy: crate::proxy_config::ProxyConfig::default(),
            allow_private_addresses: false,
            progress: None,
        })
    }

    /// Add one header.
    ///
    /// Takes `&mut self` rather than consuming, so a failure names the offending
    /// header while leaving the request usable. The header is sanitized for CRLF
    /// injection and checked against the forbidden list (`Host`,
    /// `Content-Length`, `Transfer-Encoding`, …).
    ///
    /// Note the ergonomics: because this borrows mutably, call it *after* the
    /// consuming methods like [`Self::body`] and [`Self::timeout`], or chain it
    /// as a statement rather than in the middle of a builder chain.
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

    /// Add many headers at once, stopping at the first rejection.
    ///
    /// Accepts any iterator of pairs whose elements are string-like, so arrays,
    /// `Vec`s and maps all work. See [`Self::add_header`] for the borrow
    /// semantics.
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

    /// Set the request body. Consumes and returns `Self`, so it cannot fail —
    /// the body is sent as given, not validated.
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Override the overall timeout, which defaults to 30 seconds.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Use a specific redirect policy instead of the default (which refuses
    /// every redirect).
    pub fn redirect_policy(mut self, redirect_policy: RedirectPolicy) -> Self {
        self.redirect_policy = redirect_policy;
        self
    }

    /// Replace the scope validator. The default one is host-scoped to this
    /// request's own host, so it permits only that host.
    pub fn scope_validator(mut self, scope_validator: ScopeValidator) -> Self {
        self.scope_validator = scope_validator;
        self
    }

    /// Attach an abort signal (P0-2). If already aborted, or aborted while in
    /// flight, `send().await` returns [`BeanStreamError::RequestAborted`](crate::BeanStreamError::RequestAborted).
    pub fn with_signal(mut self, signal: AbortSignal) -> Self {
        self.abort_signal = Some(signal);
        self
    }

    /// Alias for [`Self::with_signal`], matching the
    /// [`execute_with_abort`](crate::execute_with_abort) naming.
    pub fn abort_signal(mut self, signal: AbortSignal) -> Self {
        self.abort_signal = Some(signal);
        self
    }

    /// Attach a progress tracker (P0-3), called as the body is written.
    ///
    /// The tracker is boxed, so it needs to be `'static`; use
    /// [`Self::with_progress_arc`] to attach one already shared behind an `Arc`.
    pub fn with_progress<P>(mut self, progress: P) -> Self
    where
        P: UploadProgress,
    {
        self.progress = Some(Arc::new(progress));
        self
    }

    /// Attach an already-shared progress tracker (P0-3).
    pub fn with_progress_arc(mut self, progress: Arc<dyn UploadProgress>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Attach automatic retry with backoff (P0-4).
    ///
    /// The DNS pin is computed once, before the retry loop, so every attempt
    /// connects to the same validated addresses rather than re-resolving.
    pub fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.retry = Some(retry);
        self
    }

    /// Attach an intelligent response cache (P0-5).
    ///
    /// Passed as an `Arc` so several requests share one cache. Cached responses
    /// are the redacted ones, so a hit cannot leak what a fresh response would
    /// have stripped.
    pub fn with_cache(mut self, cache: Arc<InMemoryCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Choose how this request reaches a proxy (A1-A4).
    ///
    /// Overrides whatever the builder chose, including its default of
    /// [`ProxyConfig::System`](crate::ProxyConfig::System). Useful for sending one
    /// request directly while the rest of the client uses a proxy:
    ///
    /// ```
    /// use beanstream::{HttpRequest, ProxyConfig};
    ///
    /// // This one call bypasses any inherited proxy configuration.
    /// let direct = HttpRequest::get("https://api.example.com/health")?
    ///     .with_proxy(ProxyConfig::Disabled);
    /// # Ok::<(), beanstream::BeanStreamError>(())
    /// ```
    ///
    /// Note that a proxy does **not** relax the destination's address checks:
    /// the host is still resolved and validated locally. See
    /// [`ProxyConfig`](crate::ProxyConfig) for what a proxy does and does not
    /// change.
    pub fn with_proxy(mut self, proxy: crate::proxy_config::ProxyConfig) -> Self {
        self.proxy = proxy;
        self
    }

    /// The proxy configuration this request will use.
    pub fn proxy(&self) -> &crate::proxy_config::ProxyConfig {
        &self.proxy
    }

    /// Attach a semaphore-based rate limiter (P0-6).
    ///
    /// Caps in-flight requests and optionally enforces a minimum interval
    /// between them. The limiter is consumed, so share one by cloning the
    /// [`RateLimiter`] before attaching.
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

    /// Replace the whole interceptor chain (P0-7), discarding any already
    /// registered.
    pub fn with_interceptors(mut self, chain: InterceptorChain) -> Self {
        self.interceptors = chain;
        self
    }

    /// Re-check the request's scope and headers without sending it.
    ///
    /// Checks three things, all of which [`Self::send`] also enforces:
    ///
    /// 1. the URL passes the scope validator,
    /// 2. every header name/value survives syntax and CRLF validation, and
    /// 3. no header is one the transport owns (`Host`, `Content-Length`,
    ///    `Transfer-Encoding`, `Connection`, `TE`).
    ///
    /// Step 3 matters because this is the gate every send path goes through, and
    /// interceptors run *before* it. Checking only syntax here let a middleware
    /// or a direct push onto the public `headers` field smuggle a `Host` or
    /// `Content-Length` past the same guard `add_header` applies.
    pub fn validate(&self) -> Result<()> {
        self.scope_validator.check_url(&self.url)?;
        validate_headers(&self.headers)?;

        for (name, _) in &self.headers {
            if is_blocked_header(name) {
                return Err(BeanStreamError::HeaderError(format!(
                    "Header '{name}' is forbidden"
                )));
            }
        }

        Ok(())
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
    ///
    /// Takes the host explicitly so a redirect hop can be pinned with the same
    /// guarantees rather than falling back to reqwest's own resolution.
    async fn resolve_pin(
        &self,
        host: &ValidatedHost,
        port: u16,
    ) -> Result<Option<(String, Vec<SocketAddr>)>> {
        // Literal IPs need no resolution -- validate_url already checked them.
        if host.ip_addr.is_some() {
            return Ok(None);
        }

        let name = &host.host;
        let addresses = resolve_host(name).await?;
        if addresses.is_empty() {
            return Err(BeanStreamError::InvalidHost(format!(
                "Host '{name}' did not resolve to an address"
            )));
        }

        // The address check holds even when a proxy is configured. A proxy must
        // not become a route to internal services that a direct request would
        // refuse, and the destination is resolved here regardless — so the
        // decision is about this flag alone, not about whether traffic egresses
        // through a proxy.
        if !self.allow_private_addresses {
            for address in &addresses {
                if crate::url_validation::is_blocked_ip(address) {
                    return Err(BeanStreamError::PrivateNetworkAccess(address.to_string()));
                }
            }
        }

        let socket_addresses = addresses
            .iter()
            .map(|address| SocketAddr::new(*address, port))
            .collect::<Vec<_>>();

        Ok(Some((name.clone(), socket_addresses)))
    }

    /// Pin the request's own hostname/port. See [`HttpRequest::resolve_pin`].
    ///
    /// Shared with the streaming entry point, which needs the same validated
    /// address list to pin its own client — a second entry point that skips this
    /// reopens the DNS-rebinding window P1-1 closed.
    pub(crate) async fn pinned_addresses(&self) -> Result<Option<(String, Vec<SocketAddr>)>> {
        self.resolve_pin(&self.parsed_url.host, self.parsed_url.port)
            .await
    }

    /// Build a reqwest client whose DNS resolution is pinned to `pinned`.
    ///
    /// Redirects are always disabled at the reqwest level. When the policy asks
    /// for redirects to be followed, [`HttpRequest::execute_inner`] walks the
    /// chain itself so every hop is validated (P1-4); letting reqwest follow
    /// them would bypass the policy entirely.
    fn build_client(&self, pinned: Option<&(String, Vec<SocketAddr>)>) -> Result<Client> {
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout);

        if let Some((host, addresses)) = pinned {
            builder = builder.resolve_to_addrs(host, addresses);
        }

        // P2-2: cookies are opt-in. When a jar is attached, reqwest stores
        // Set-Cookie per origin and replays Cookie on later requests -- but
        // only through this pinned client, so validation still applies.
        #[cfg(feature = "cookies")]
        if let Some(jar) = &self.cookie_jar {
            if let Some(store) = jar.provider() {
                builder = builder.cookie_provider(store);
            }
        }

        // Certificate pinning has to be installed on *this* client, because this
        // is the client the pinned send path actually uses. Setting a pin by
        // hand and then sending through `HttpRequest`/`HttpClientBuilder::send`
        // used to hand reqwest no TLS config at all, so the pin was silently
        // inert while `build()` honoured it.
        #[cfg(feature = "rustls-tls")]
        if let Some(pinning) = &self.cert_pinning {
            let tls_config = pinning.build_rustls_config()?;
            builder = builder.use_preconfigured_tls(tls_config);
        }

        // Without the rustls backend there is no way to install a pin. Refuse
        // the request instead of connecting to a certificate nobody checked.
        #[cfg(not(feature = "rustls-tls"))]
        if self.cert_pinning.is_some() {
            return Err(BeanStreamError::InvalidConfiguration(
                "Certificate pinning requires the 'rustls-tls' feature".to_string(),
            ));
        }

        // A1-A4: proxy routing, applied through the same helper the builder uses
        // so the two clients cannot disagree.
        builder = crate::proxy_config::apply(builder, &self.proxy)?;

        builder.build().map_err(Into::into)
    }

    /// Validate one hop of a redirect chain.
    ///
    /// Every hop is checked against the redirect policy *and* re-validated as a
    /// fresh URL, so a redirect cannot be used to reach a private address, a
    /// forbidden scheme, or a host outside scope (P1-4).
    fn validate_hop(&self, visited: &[Url], next: &Url) -> Result<()> {
        self.redirect_policy.check_redirect(visited, next)?;
        validate_url(next.as_str())?;
        self.scope_validator.check_url(next.as_str())?;
        Ok(())
    }

    /// Plan the next hop of a redirect chain.
    ///
    /// Pure: resolves `location` against `current`, rejects loops and policy
    /// violations, and decides what method/headers/body the hop may carry. Kept
    /// separate from the network call so the rules are testable without a
    /// server (P1-4).
    #[allow(clippy::too_many_arguments)]
    fn plan_hop(
        &self,
        visited: &[Url],
        current: &Url,
        status: u16,
        location: &str,
        method: &Method,
        headers: &[(String, String)],
        body: &Option<String>,
    ) -> Result<RedirectHop> {
        let next = current.join(location).map_err(|_| {
            BeanStreamError::RedirectBlocked(format!("Invalid redirect target '{location}'"))
        })?;

        if visited.iter().any(|seen| seen == &next) {
            return Err(BeanStreamError::RedirectBlocked(format!(
                "Redirect loop detected at '{next}'"
            )));
        }

        self.validate_hop(visited, &next)?;

        // 303 always becomes GET; 301/302 do so for POST. Replaying a body on a
        // rewritten GET would misrepresent the request.
        let rewrite_to_get =
            status == 303 || ((status == 301 || status == 302) && *method == Method::POST);

        // A hop to another origin must not carry credentials or a body
        // addressed to the previous host.
        let same_origin = current.origin() == next.origin();

        let mut next_method = method.clone();
        let mut next_body = body.clone();
        let mut next_headers = headers.to_vec();

        if rewrite_to_get {
            next_method = Method::GET;
            next_body = None;
        }

        if !same_origin {
            next_headers.retain(|(name, _)| !crate::header_validation::is_sensitive_header(name));
            next_body = None;
        }

        Ok(RedirectHop {
            url: next,
            method: next_method,
            headers: next_headers,
            body: next_body,
        })
    }

    /// Extract the `Location` header from a redirect response's headers.
    fn location_of(headers: &[(String, String)], status: u16) -> Result<&str> {
        headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.as_str())
            .ok_or_else(|| {
                BeanStreamError::RedirectBlocked(format!(
                    "Redirect response {status} has no Location header"
                ))
            })
    }

    /// Build a plain [`reqwest::Request`] from this request, without sending it.
    ///
    /// Validates first (scope and headers), then constructs the request against
    /// a client built with no pinned addresses — so the
    /// returned request carries the transport settings but **no SSRF pinning**.
    /// Exists for callers who need to hand the request to their own reqwest
    /// client; prefer [`Self::send`], which pins the validated addresses.
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

        let outcome = loop {
            attempt += 1;

            match self
                .send_target(
                    &pinned,
                    &self.method,
                    &self.url,
                    &self.headers,
                    self.body.as_deref(),
                    conditional_etag.as_deref(),
                )
                .await
            {
                Ok(result) => {
                    // A 429 or 5xx arrives here as `Ok`, because `send_target`
                    // reports every HTTP status as a successful exchange and the
                    // status-to-error mapping happens after this loop. Deciding
                    // retryability from the status *inside* the loop is what
                    // makes `RetryConfig::retry_on` mean anything for
                    // `ServerError` and `RateLimited`: without this, those two
                    // classes could never match, since the error they would match
                    // did not exist yet.
                    let status = result.0;
                    let retryable_status = self
                        .retry
                        .as_ref()
                        .is_some_and(|retry| retry.should_retry_status(status));

                    if retryable_status && attempt < max_attempts {
                        if let (Some(retry), Some(backoff)) = (&self.retry, backoff.as_mut()) {
                            let delay = retry.next_delay(backoff);
                            tokio::time::sleep(delay).await;
                        }
                        continue;
                    }

                    break Ok(result);
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
                    break Err(err);
                }
            }
        };

        let mut outcome = outcome?;

        // P1-4: when the policy asks for redirects, walk the chain ourselves so
        // every hop is validated. Intermediate hops are not retried: a fresh
        // attempt would re-enter a chain we have already partly walked.
        if self.redirect_policy.follow_redirects {
            outcome = self.follow_chain(&pinned, outcome).await?;
        }

        let (status, headers, body, url) = outcome;

        if status == 429 {
            return Err(BeanStreamError::RateLimited);
        }
        if (500..600).contains(&status) {
            return Err(BeanStreamError::ServerError(status));
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

        if !crate::progress::report_complete(&self.progress, response.body.len() as u64) {
            return Err(BeanStreamError::RequestAborted);
        }

        Ok(response)
    }

    /// Walk a redirect chain starting from `outcome`, validating every hop.
    ///
    /// `outcome` is the result of the first request. Each subsequent hop is
    /// checked against the redirect policy, re-validated as a fresh URL, and
    /// re-pinned to its own validated addresses, so a redirect cannot be used to
    /// reach a private address or a host outside scope (P1-4).
    async fn follow_chain(
        &self,
        pinned: &Option<(String, Vec<SocketAddr>)>,
        outcome: (u16, Vec<(String, String)>, Vec<u8>, String),
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>, String)> {
        let mut current = outcome;
        let mut visited: Vec<Url> = vec![Url::parse(&self.url)?];

        let mut method = self.method.clone();
        let mut headers = self.headers.clone();
        let mut body = self.body.clone();

        loop {
            let (status, response_headers, _, url) = &current;

            // 304 is a cache validation response, not a redirect.
            if !(300..400).contains(status) || *status == 304 {
                return Ok(current);
            }

            let location = Self::location_of(response_headers, *status)?;
            let current_url = Url::parse(url)?;

            let hop = self.plan_hop(
                &visited,
                &current_url,
                *status,
                location,
                &method,
                &headers,
                &body,
            )?;

            visited.push(hop.url.clone());

            // Pin this hop's host the same way the original request was pinned.
            let parsed = validate_url(hop.url.as_str())?;
            let hop_pinned = if pinned
                .as_ref()
                .map(|(host, _)| *host == parsed.host.host)
                .unwrap_or(false)
                && parsed.port == self.parsed_url.port
            {
                pinned.clone()
            } else {
                self.resolve_pin(&parsed.host, parsed.port).await?
            };

            // The hop's own method/headers/body become the next request's, so a
            // later hop is rewritten from what was actually sent.
            method = hop.method.clone();
            headers = hop.headers.clone();
            body = hop.body.clone();

            current = self
                .send_target(
                    &hop_pinned,
                    &hop.method,
                    hop.url.as_str(),
                    &hop.headers,
                    hop.body.as_deref(),
                    None,
                )
                .await?;
        }
    }

    /// Build and send one request against `target`.
    ///
    /// `method`, `headers` and `body` are explicit so a redirect hop can change
    /// them (303 rewrites POST to GET, and credentials are dropped when the hop
    /// changes origin).
    async fn send_target(
        &self,
        pinned: &Option<(String, Vec<SocketAddr>)>,
        method: &Method,
        target: &str,
        headers: &[(String, String)],
        body: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>, String)> {
        // P1-1: the client is pinned to the addresses validated up front, so
        // reqwest does not re-resolve the hostname at connect time.
        let client = self.build_client(pinned.as_ref())?;

        let mut request = client.request(method.clone(), target);
        for (name, value) in headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| BeanStreamError::HeaderError("Invalid header name".to_string()))?;
            let value = HeaderValue::from_str(value)
                .map_err(|_| BeanStreamError::HeaderError("Invalid header value".to_string()))?;
            request = request.header(name, value);
        }
        if let Some(etag) = if_none_match {
            request = request.header("If-None-Match", etag);
        }
        if let Some(body) = body {
            request = request.body(body.to_string());
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
    ///
    /// This is where every security layer is applied, and the order matters:
    ///
    /// 1. Interceptors run `on_request`, so middleware can modify the request
    ///    before validation.
    /// 2. The scope validator and header checks run on the *final* request.
    /// 3. An already-fired abort signal short-circuits without connecting.
    /// 4. Rate-limit permit is acquired, then the cache is consulted for `GET`
    ///    and `HEAD`.
    /// 5. The host is resolved once and every address validated; the validated
    ///    list is pinned into the client, so reqwest performs no second lookup.
    ///    The pin is computed *before* the retry loop, so retries cannot
    ///    re-resolve to a different address.
    /// 6. Redirects, if the policy enables following, are walked here rather
    ///    than by reqwest — each hop re-validated and re-pinned.
    /// 7. Response headers are redacted, interceptors run `on_response`, and
    ///    redaction is applied again so an interceptor cannot re-introduce a
    ///    secret.
    ///
    /// ```no_run
    /// use beanstream::HttpRequest;
    ///
    /// # async fn example() -> Result<(), beanstream::BeanStreamError> {
    /// let response = HttpRequest::get("https://example.com/")?.send().await?;
    /// if response.is_success() {
    ///     println!("{}", response.text()?);
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

    /// Minimal HTTP/1.1 server used by the redirect tests.
    ///
    /// `route` maps a request path to a raw response; unrouted paths get a
    /// plain 200. Every request is recorded verbatim so tests can assert on
    /// what actually reached the wire.
    async fn spawn_test_server(
        route: Vec<(String, &'static str)>,
    ) -> (
        String,
        Arc<tokio::sync::Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let routes = Arc::new(route);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let recorder = seen.clone();
        let handle = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let recorder = recorder.clone();
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let mut raw = Vec::new();
                    loop {
                        match socket.try_read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                raw.extend_from_slice(&buf[..n]);
                                if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
                        }
                        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }

                    let text = String::from_utf8_lossy(&raw).to_string();
                    recorder.lock().await.push(text.clone());

                    let path = text
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let response = routes
                        .iter()
                        .find(|(prefix, _)| path == *prefix)
                        .map(|(_, body)| *body)
                        .unwrap_or(OK);

                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                    let _ = socket.shutdown().await;
                });
            }
        });

        (format!("127.0.0.1:{port}"), seen, handle)
    }

    /// Build a request against the local test server.
    ///
    /// Literal private IPs are blocked by `validate_url`, so start from a
    /// public URL and retarget the parsed parts, which is exactly what the
    /// pinning and redirect code consumes.
    fn local_request(method: Method, addr: &str, path: &str) -> HttpRequest {
        let mut request = HttpRequest::new(method, "https://8.8.8.8/").unwrap();
        let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
        request.url = format!("http://{addr}{path}");
        request.parsed_url.port = port;
        request.parsed_url.scheme = crate::url_validation::Scheme::Http;
        request.parsed_url.host = ValidatedHost {
            host: "127.0.0.1".to_string(),
            ip_addr: Some("127.0.0.1".parse().unwrap()),
        };
        request.scope_validator = ScopeValidator::new(false);
        request.timeout = Duration::from_secs(5);
        request
    }

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

    // --- P1-4: follow_redirects is honoured at runtime ---

    const OK: &str = "HTTP/1.1 200 OK\r\n\
                      Content-Type: text/plain\r\n\
                      Content-Length: 5\r\n\
                      Connection: close\r\n\r\nhello";

    fn redirect_to(location: &str) -> String {
        format!(
            "HTTP/1.1 302 Found\r\n\
             Location: {location}\r\n\
             Content-Length: 0\r\n\
             Connection: close\r\n\r\n"
        )
    }

    #[tokio::test]
    async fn redirects_are_not_followed_by_default() {
        // /start redirects to /final, which would return 200. With the default
        // policy the caller must see the 302 itself.
        let (addr, seen, _server) =
            spawn_test_server(vec![("/start".to_string(), redirect_to("/final").leak())]).await;

        let request = local_request(Method::GET, &addr, "/start");
        let response = request.send().await.unwrap();

        assert_eq!(response.status, 302);
        assert_eq!(
            seen.lock().await.len(),
            1,
            "the chain must not be walked when follow_redirects is off"
        );
    }

    #[tokio::test]
    async fn follow_redirects_is_consulted_by_send() {
        // Same server and same hop, but with follow_redirects enabled the 302 is
        // no longer handed straight back: send() walks the chain and puts the
        // hop through the redirect policy. Before P1-4 the flag was inert and
        // this returned the same 302 as the test above.
        let (addr, seen, _server) =
            spawn_test_server(vec![("/start".to_string(), redirect_to("/final").leak())]).await;

        let request = local_request(Method::GET, &addr, "/start")
            .redirect_policy(RedirectPolicy::default().follow_redirects(true));
        let outcome = request.send().await;

        assert!(
            matches!(
                &outcome,
                Err(BeanStreamError::HostNotAllowed(host)) if host == "127.0.0.1"
            ),
            "the follow_redirects hop must be policy-checked, got {outcome:?}"
        );
        assert_eq!(
            seen.lock().await.len(),
            1,
            "the refused hop must not have been connected to"
        );
    }

    #[tokio::test]
    async fn redirect_without_location_is_refused() {
        let no_location = "HTTP/1.1 302 Found\r\n\
                           Content-Length: 0\r\n\
                           Connection: close\r\n\r\n";
        let (addr, _seen, _server) =
            spawn_test_server(vec![("/start".to_string(), no_location)]).await;

        let request = local_request(Method::GET, &addr, "/start")
            .redirect_policy(RedirectPolicy::default().follow_redirects(true));
        let outcome = request.send().await;

        assert!(
            matches!(
                &outcome,
                Err(BeanStreamError::RedirectBlocked(message))
                    if message.contains("no Location header")
            ),
            "expected a missing-Location rejection, got {outcome:?}"
        );
    }

    // --- hop planning rules, tested directly (no server needed) ---
    //
    // A localhost redirect chain can never be walked end to end: hop
    // validation re-runs `validate_url`, and the local test server is by
    // definition a private address. That is the protection working, so the
    // per-hop rules are exercised through `plan_hop` instead.

    /// A GET to a public host with redirects enabled.
    fn hop_request() -> HttpRequest {
        let mut request = HttpRequest::get("https://example.com/start").unwrap();
        request.redirect_policy = RedirectPolicy::default().follow_redirects(true);
        request.redirect_policy.allow_host("example.com");
        request
    }

    fn plan(
        request: &HttpRequest,
        visited: &[&str],
        from: &str,
        status: u16,
        location: &str,
        method: Method,
    ) -> Result<RedirectHop> {
        let visited = visited
            .iter()
            .map(|url| Url::parse(url).unwrap())
            .collect::<Vec<_>>();
        request.plan_hop(
            &visited,
            &Url::parse(from).unwrap(),
            status,
            location,
            &method,
            &request.headers,
            &request.body,
        )
    }

    #[test]
    fn hop_resolves_a_relative_location_against_the_current_url() {
        let request = hop_request();
        let hop = plan(
            &request,
            &["https://example.com/start"],
            "https://example.com/start",
            302,
            "/final",
            Method::GET,
        )
        .unwrap();

        assert_eq!(hop.url.as_str(), "https://example.com/final");
        assert_eq!(hop.method, Method::GET);
    }

    #[test]
    fn hop_to_a_private_address_is_refused() {
        // Even a policy that permits any host cannot redirect into the private
        // network: every hop is re-validated as a fresh URL (P1-4).
        let mut request = hop_request();
        request.redirect_policy = RedirectPolicy::relaxed(10);

        let outcome = plan(
            &request,
            &["https://example.com/start"],
            "https://example.com/start",
            302,
            "https://127.0.0.1/admin",
            Method::GET,
        );

        assert!(
            matches!(&outcome, Err(BeanStreamError::PrivateNetworkAccess(_))),
            "expected the private hop to be refused, got {outcome:?}"
        );
    }

    #[test]
    fn hop_to_a_host_outside_the_policy_is_refused() {
        let request = hop_request();
        let outcome = plan(
            &request,
            &["https://example.com/start"],
            "https://example.com/start",
            302,
            "https://evil.com/steal",
            Method::GET,
        );

        assert!(
            matches!(&outcome, Err(BeanStreamError::HostNotAllowed(_))),
            "expected a host outside the allow list to be refused, got {outcome:?}"
        );
    }

    #[test]
    fn hop_to_a_non_http_scheme_is_refused() {
        let request = hop_request();
        let outcome = plan(
            &request,
            &["https://example.com/start"],
            "https://example.com/start",
            302,
            "file:///etc/passwd",
            Method::GET,
        );

        assert!(
            matches!(&outcome, Err(BeanStreamError::RedirectBlocked(_))),
            "expected a non-http target to be refused, got {outcome:?}"
        );
    }

    #[test]
    fn hop_loop_is_detected() {
        let request = hop_request();
        let outcome = plan(
            &request,
            &["https://example.com/a", "https://example.com/b"],
            "https://example.com/b",
            302,
            "/a",
            Method::GET,
        );

        assert!(
            matches!(
                &outcome,
                Err(BeanStreamError::RedirectBlocked(message))
                    if message.contains("loop")
            ),
            "expected loop detection, got {outcome:?}"
        );
    }

    #[test]
    fn hop_limit_is_enforced() {
        let mut request = hop_request();
        request.redirect_policy.max_redirects = 1;

        let outcome = plan(
            &request,
            &["https://example.com/a"],
            "https://example.com/a",
            302,
            "/b",
            Method::GET,
        );

        assert!(
            matches!(&outcome, Err(BeanStreamError::TooManyRedirects(1))),
            "expected the redirect budget to stop the chain, got {outcome:?}"
        );
    }

    #[test]
    fn three_oh_two_on_a_post_becomes_get_without_a_body() {
        let mut request = hop_request();
        request.body = Some("secret=payload".to_string());

        let hop = plan(
            &request,
            &["https://example.com/start"],
            "https://example.com/start",
            302,
            "/final",
            Method::POST,
        )
        .unwrap();

        assert_eq!(hop.method, Method::GET);
        assert_eq!(hop.body, None, "the body must not be replayed on a GET");
    }

    #[test]
    fn three_oh_three_always_becomes_get() {
        let mut request = hop_request();
        request.body = Some("secret=payload".to_string());

        let hop = plan(
            &request,
            &["https://example.com/start"],
            "https://example.com/start",
            303,
            "/final",
            Method::PUT,
        )
        .unwrap();

        assert_eq!(hop.method, Method::GET);
        assert_eq!(hop.body, None);
    }

    #[test]
    fn a_redirect_that_is_not_rewritten_keeps_its_method() {
        // Rewriting applies only to 303 and to 301/302 on POST, so a 307 keeps
        // the caller's method -- and its body.
        let mut request = hop_request();
        request.body = Some("payload".to_string());

        let hop = plan(
            &request,
            &["https://example.com/start"],
            "https://example.com/start",
            307,
            "/final",
            Method::PUT,
        )
        .unwrap();

        assert_eq!(hop.method, Method::PUT);
        assert_eq!(hop.body.as_deref(), Some("payload"));
    }

    #[test]
    fn credentials_are_dropped_when_a_hop_changes_origin() {
        let mut request = hop_request();
        request.redirect_policy.allow_host("other.com");
        request.scope_validator = ScopeValidator::new(false);
        request.headers = vec![
            ("authorization".to_string(), "Bearer hunter2".to_string()),
            ("x-trace".to_string(), "keep-me".to_string()),
        ];

        let hop = plan(
            &request,
            &["https://example.com/start"],
            "https://example.com/start",
            302,
            "https://other.com/final",
            Method::GET,
        )
        .unwrap();

        assert_eq!(hop.url.host_str(), Some("other.com"));
        assert_eq!(
            hop.headers,
            vec![("x-trace".to_string(), "keep-me".to_string())],
            "credentials must not follow a cross-origin hop"
        );
        assert_eq!(hop.body, None);
    }

    #[test]
    fn headers_survive_a_same_origin_hop() {
        let mut request = hop_request();
        request.headers = vec![
            ("authorization".to_string(), "Bearer hunter2".to_string()),
            ("x-trace".to_string(), "keep-me".to_string()),
        ];

        let hop = plan(
            &request,
            &["https://example.com/start"],
            "https://example.com/start",
            302,
            "/final",
            Method::GET,
        )
        .unwrap();

        assert_eq!(hop.headers.len(), 2, "same-origin hops keep their headers");
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

    // --- Retry on status actually retries (P0-4) ---

    const SERVICE_UNAVAILABLE: &str = "HTTP/1.1 503 Service Unavailable\r\n\
                                       Content-Length: 0\r\n\
                                       Connection: close\r\n\r\n";

    const TOO_MANY_REQUESTS: &str = "HTTP/1.1 429 Too Many Requests\r\n\
                                     Content-Length: 0\r\n\
                                     Connection: close\r\n\r\n";

    /// A retry config that waits ~1ms so the retry path is exercised quickly.
    fn fast_retry() -> crate::retry::RetryConfig {
        crate::retry::RetryConfig {
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
            ..crate::retry::RetryConfig::default()
        }
    }

    #[tokio::test]
    async fn a_5xx_response_is_retried_up_to_max_attempts() {
        // Regression: `send_target` reports every HTTP status as `Ok`, and the
        // status-to-error mapping runs *after* the retry loop — so before this
        // was fixed, `ErrorKind::ServerError` could never match and a 503 was
        // returned after a single attempt despite `max_attempts: 3`.
        let (addr, seen, _server) =
            spawn_test_server(vec![("/busy".to_string(), SERVICE_UNAVAILABLE)]).await;

        let request = local_request(Method::GET, &addr, "/busy").with_retry(fast_retry());
        let outcome = request.send().await;

        assert_eq!(
            seen.lock().await.len(),
            3,
            "a 5xx must be retried up to max_attempts (3)"
        );
        assert!(
            matches!(outcome, Err(BeanStreamError::ServerError(503))),
            "the caller still sees the final status as an error, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_429_response_is_retried() {
        let (addr, seen, _server) =
            spawn_test_server(vec![("/throttled".to_string(), TOO_MANY_REQUESTS)]).await;

        let request = local_request(Method::GET, &addr, "/throttled").with_retry(fast_retry());
        let outcome = request.send().await;

        assert_eq!(seen.lock().await.len(), 3, "429 must be retried");
        assert!(matches!(outcome, Err(BeanStreamError::RateLimited)));
    }

    #[tokio::test]
    async fn a_5xx_is_not_retried_when_not_in_retry_on() {
        // The retry decision still comes from `retry_on`, so removing the class
        // disables the behaviour rather than the retry being unconditional.
        let (addr, seen, _server) =
            spawn_test_server(vec![("/busy".to_string(), SERVICE_UNAVAILABLE)]).await;

        let config = crate::retry::RetryConfig {
            retry_on: vec![crate::retry::ErrorKind::NetworkTimeout],
            ..fast_retry()
        };
        let request = local_request(Method::GET, &addr, "/busy").with_retry(config);
        let _ = request.send().await;

        assert_eq!(
            seen.lock().await.len(),
            1,
            "a 5xx must not be retried when ServerError is not in retry_on"
        );
    }

    #[tokio::test]
    async fn a_success_response_is_not_retried() {
        let (addr, seen, _server) = spawn_test_server(vec![]).await;

        let request = local_request(Method::GET, &addr, "/ok").with_retry(fast_retry());
        let outcome = request.send().await;

        assert!(outcome.is_ok());
        assert_eq!(seen.lock().await.len(), 1, "2xx must never be retried");
    }

    // --- Forbidden headers cannot be smuggled past validate() ---

    #[test]
    fn validate_rejects_a_blocked_header_pushed_directly() {
        // `add_header` checks the blocked list, but `validate()` used to check
        // only name syntax and CRLF. Since every send path goes through
        // `validate()` and `headers` is a public field, that gap let `Host` and
        // `Content-Length` be smuggled in.
        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        request
            .headers
            .push(("host".to_string(), "evil.example".to_string()));

        let outcome = request.validate();
        assert!(
            matches!(&outcome, Err(BeanStreamError::HeaderError(message))
                if message.contains("host")),
            "expected the blocked-header guard to fire, got {outcome:?}"
        );
    }

    #[test]
    fn validate_rejects_every_transport_owned_header() {
        for blocked in [
            "host",
            "connection",
            "transfer-encoding",
            "content-length",
            "te",
        ] {
            let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
            request.headers.push((blocked.to_string(), "x".to_string()));
            assert!(
                request.validate().is_err(),
                "validate() must reject the transport-owned header '{blocked}'"
            );
        }
    }

    #[test]
    fn build_request_refuses_a_smuggled_host_header() {
        // `build_request` calls `validate()`, so the guard covers the
        // build-your-own-request path too — this is what the probe showed
        // produced a request carrying `Host: evil.example`.
        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        request
            .headers
            .push(("host".to_string(), "evil.example".to_string()));
        request
            .headers
            .push(("content-length".to_string(), "999".to_string()));

        assert!(request.validate().is_err());
    }

    #[tokio::test]
    async fn an_interceptor_cannot_inject_a_blocked_header() {
        // Interceptors run *before* validation by design, so the guard has to
        // catch what they add. This is the realistic middleware route to the
        // same bypass.
        use std::sync::Arc;

        use crate::interceptor::Interceptor;

        struct InjectHost;
        impl Interceptor for InjectHost {
            fn on_request(&self, req: &mut HttpRequest) -> Result<()> {
                req.headers
                    .push(("host".to_string(), "evil.example".to_string()));
                Ok(())
            }
            fn on_response(&self, _resp: &mut HttpResponse) -> Result<()> {
                Ok(())
            }
        }

        let (addr, seen, _server) = spawn_test_server(vec![]).await;
        let request =
            local_request(Method::GET, &addr, "/ok").add_interceptor(Arc::new(InjectHost));

        let outcome = request.send().await;
        assert!(
            matches!(outcome, Err(BeanStreamError::HeaderError(_))),
            "an injected Host header must be refused, got {outcome:?}"
        );
        assert_eq!(
            seen.lock().await.len(),
            0,
            "the request must not reach the server at all"
        );
    }

    // --- Certificate pinning reaches the pinned send path ---

    #[cfg(feature = "rustls-tls")]
    #[test]
    fn request_with_pinning_builds_a_pinned_client() {
        // `build_client` is the client the pinned send path uses, so this is
        // where the pin has to be installed. Before this was fixed, the TLS
        // config was applied only in `HttpClientBuilder::build()` and the
        // request carried no pin at all.
        //
        // Kept network-free by using an empty pin set: that is a configuration
        // error inside `build_rustls_config`, so it failing proves the pinning
        // code is reached on this path rather than skipped.
        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        assert!(request.cert_pinning.is_none());

        request.cert_pinning = Some(crate::cert_pinning::CertPinConfig::new());
        assert!(
            matches!(
                request.build_client(None),
                Err(BeanStreamError::InvalidConfiguration(_))
            ),
            "the pinned send path must consult cert_pinning"
        );

        // A real pin produces a usable client: reqwest accepted the TLS config.
        request.cert_pinning =
            Some(crate::cert_pinning::CertPinConfig::new().pin_spki_sha256([0x11; 32]));
        assert!(request.build_client(None).is_ok());
    }

    #[cfg(not(feature = "rustls-tls"))]
    #[test]
    fn request_with_pinning_without_rustls_is_refused() {
        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        request.cert_pinning =
            Some(crate::cert_pinning::CertPinConfig::new().pin_spki_sha256([0x11; 32]));

        let outcome = request.build_client(None);
        assert!(
            matches!(&outcome, Err(BeanStreamError::InvalidConfiguration(message))
                if message.contains("rustls-tls")),
            "expected a loud configuration error, got {outcome:?}"
        );
    }
}
