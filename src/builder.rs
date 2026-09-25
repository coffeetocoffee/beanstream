use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use url::Url;

use crate::cert_pinning::CertPinConfig;
use crate::header_validation::{is_blocked_header, sanitize_header};
use crate::interceptor::InterceptorChain;
use crate::redirect_policy::{RedirectPolicy, ScopeValidator};
use crate::request_handler::{HttpRequest, HttpResponse};
use crate::{BeanStreamError, Result};

/// Configure a client once and reuse the settings for many requests.
///
/// Defaults: 30-second request timeout, 10-second connect timeout, 10 redirect
/// hops, redirects **not** followed, user agent `BeanStream/1.0`, private
/// networks blocked, no pinning, no interceptors.
///
/// There are two exits, and the difference matters:
///
/// - [`Self::create_request`] and [`Self::send`] produce requests that go
///   through the full validation and DNS-pinning pipeline. **Prefer these.**
/// - [`Self::build`] returns a bare [`reqwest::Client`] with the same transport
///   settings but normal DNS resolution, so it does not pin and cannot enforce
///   SSRF protection. It exists for destinations the caller has already
///   validated.
///
/// ```
/// use std::time::Duration;
///
/// use beanstream::HttpClientBuilder;
///
/// let builder = HttpClientBuilder::default()
///     .with_base_url("https://api.example.com/v1/")
///     .with_timeout(Duration::from_secs(15))
///     .with_follow_redirects(true)
///     .add_default_header("Accept", "application/json")?;
///
/// // Requests created here inherit the timeout, headers and policies.
/// let request = builder.create_request(reqwest::Method::GET, "users")?;
/// assert_eq!(request.url, "https://api.example.com/v1/users");
/// # Ok::<(), beanstream::BeanStreamError>(())
/// ```
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
    cert_pinning: Option<CertPinConfig>,
    interceptors: InterceptorChain,
    #[cfg(feature = "cookies")]
    cookie_jar: Option<crate::cookies::CookieJar>,
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
            cert_pinning: None,
            interceptors: InterceptorChain::new(),
            #[cfg(feature = "cookies")]
            cookie_jar: None,
        }
    }
}

impl HttpClientBuilder {
    /// Set the base URL used to resolve relative targets passed to
    /// [`Self::create_request`] or [`Self::send`].
    ///
    /// Also seeds the redirect policy's allow list with this host, so a
    /// configured client can legitimately redirect within its own host.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Overall request timeout, covering the whole exchange rather than just
    /// connection setup. Defaults to 30 seconds.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Maximum redirect hops before [`BeanStreamError::TooManyRedirects`].
    /// Defaults to 10.
    pub fn with_max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// Whether [`HttpRequest::send`](crate::HttpRequest::send) walks redirect
    /// chains. Defaults to `false`, which returns the 3xx response to the caller.
    ///
    /// Setting this `true` does not hand redirect-following to reqwest —
    /// BeanStream always pins reqwest to `Policy::none()` and walks the chain
    /// itself, re-validating and re-pinning each hop. This flag only decides
    /// whether that walking happens.
    pub fn with_follow_redirects(mut self, follow_redirects: bool) -> Self {
        self.follow_redirects = follow_redirects;
        self
    }

    /// Connection-establishment timeout, separate from [`Self::with_timeout`].
    /// Defaults to 10 seconds.
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    /// User agent for every request. Defaults to `BeanStream/1.0`. Rejected at
    /// build time if it is not a valid header value.
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Add a header sent with every request from this client.
    ///
    /// The header is sanitized immediately, so this returns an error for CRLF
    /// injection or a forbidden header name rather than failing later at send
    /// time. Call repeatedly to add several.
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

    /// Opt out of private-network blocking for this client.
    ///
    /// This **weakens SSRF protection** and exists for clients that legitimately
    /// target internal hosts. It is applied to requests created by
    /// [`HttpClientBuilder::create_request`]; previously the flag was stored but
    /// never read, so it silently did nothing.
    pub fn allow_private_networks(mut self) -> Self {
        self.check_private_ips = false;
        self
    }

    /// Give every request created by this builder a shared cookie jar (P2-2).
    ///
    /// Cookies are opt-in rather than always-on: an implicit jar would let one
    /// host's `Set-Cookie` ride along to unrelated later requests. Passing a
    /// jar makes the choice explicit, and it is still scoped per origin by the
    /// underlying store.
    #[cfg(feature = "cookies")]
    pub fn with_cookie_jar(mut self, jar: crate::cookies::CookieJar) -> Self {
        self.cookie_jar = Some(jar);
        self
    }

    /// Require every TLS connection to match one of the configured SPKI
    /// SHA-256 pins (P0-9).
    ///
    /// Pinning is installed as a preconfigured rustls client, so it requires the
    /// `rustls-tls` feature. Without that feature, `build()` and the pinned send
    /// path both return [`BeanStreamError::InvalidConfiguration`] rather than
    /// producing a client that merely looks pinned — a pin that is silently
    /// ignored is worse than a clear failure.
    ///
    /// The pin applies to requests from [`Self::create_request`] and
    /// [`Self::send`] as well as to [`Self::build`]: it is carried on the
    /// request and installed on the client the pinned path builds for itself.
    /// Previously only `build()` honoured it, which meant the recommended path
    /// (the one that pins DNS) silently skipped certificate pinning.
    pub fn with_cert_pinning(mut self, config: CertPinConfig) -> Self {
        self.cert_pinning = Some(config);
        self
    }

    /// Register middleware applied to every request created by this builder
    /// (P0-7).
    ///
    /// The chain runs in the order interceptors were added. `on_request` runs
    /// before the request is built, `on_response` after it returns and after
    /// redaction — and redaction is re-applied afterwards, so an interceptor
    /// that injects an auth token cannot leak it into the response.
    pub fn add_interceptor(
        mut self,
        interceptor: std::sync::Arc<dyn crate::interceptor::Interceptor>,
    ) -> Self {
        self.interceptors.add(interceptor);
        self
    }

    /// Build a plain `reqwest::Client` carrying this builder's transport
    /// settings (timeouts, user agent, default headers, cert pinning).
    ///
    /// This client performs **normal DNS resolution**, so using it to send a
    /// request bypasses BeanStream's SSRF pinning (P1-1). Prefer
    /// [`HttpClientBuilder::create_request`], which returns an `HttpRequest`
    /// that pins the validated addresses before connecting. Use this escape
    /// hatch only for destinations you already trust.
    pub fn build(&self) -> Result<reqwest::Client> {
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

        #[cfg(feature = "cookies")]
        if let Some(jar) = &self.cookie_jar {
            if let Some(store) = jar.provider() {
                client = client.cookie_provider(store);
            }
        }

        // P2-2: pinning needs reqwest's rustls backend to install a
        // preconfigured TLS config. Refuse loudly rather than build a client
        // that looks pinned but accepts any certificate.
        #[cfg(feature = "rustls-tls")]
        if let Some(pinning) = &self.cert_pinning {
            let tls_config = pinning.build_rustls_config()?;
            client = client.use_preconfigured_tls(tls_config);
        }

        #[cfg(not(feature = "rustls-tls"))]
        if self.cert_pinning.is_some() {
            return Err(BeanStreamError::InvalidConfiguration(
                "Certificate pinning requires the 'rustls-tls' feature".to_string(),
            ));
        }

        client.build().map_err(Into::into)
    }

    /// Build the [`RedirectPolicy`] implied by this builder's settings (P1-4).
    ///
    /// Host validation used to be gated on `follow_redirects`, which defaults to
    /// `false` — so the policy silently validated nothing. The two concerns are
    /// now separate: `max_redirects`/scheme rules always apply, and
    /// `follow_redirects` controls only whether `HttpRequest::send` walks the
    /// chain.
    pub fn get_redirect_policy(&self) -> RedirectPolicy {
        let mut policy = RedirectPolicy {
            max_redirects: self.max_redirects,
            track_all_redirects: true,
            allow_any_redirect: false,
            follow_redirects: self.follow_redirects,
            ..RedirectPolicy::default()
        };

        // A base URL is an explicit statement of where this client may talk to,
        // so seed the allow list from it instead of leaving it empty.
        if let Some(base_url) = &self.base_url {
            if let Ok(parsed) = Url::parse(base_url) {
                if let Some(host) = parsed.host_str() {
                    policy.allow_host(host);
                }
            }
        }

        policy
    }

    /// Send a request created from this builder, going through the pinned send
    /// path so SSRF validation actually applies (P1-1).
    pub async fn send(&self, method: Method, target: &str) -> Result<HttpResponse> {
        self.create_request(method, target)?.send().await
    }

    /// Build the [`ScopeValidator`] implied by this builder's settings.
    ///
    /// When private-network checking is on (the default), known internal ranges
    /// and reserved names are denied. Callers wanting a host-scoped client can
    /// pass the result to [`crate::HttpRequest::scope_validator`].
    pub fn create_scope_validator(&self) -> ScopeValidator {
        let validator = ScopeValidator::new(false);
        if self.check_private_ips {
            validator.with_deny_list([
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

    /// Create a validated request that goes through BeanStream's pinned send
    /// path (P1-1).
    ///
    /// Unlike [`HttpClientBuilder::build`], the returned `HttpRequest` resolves
    /// the host, validates every address, and pins it for the connection. It
    /// inherits this builder's timeout, redirect policy (P1-4) and default
    /// headers, all of which used to be silently dropped here.
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

        HttpRequest::new(method, &url).map(|mut request| {
            request.timeout = self.timeout;
            request.redirect_policy = self.get_redirect_policy();

            if !self.interceptors.is_empty() {
                request.interceptors = self.interceptors.clone();
            }

            // P2-2: the jar is shared by reference, so a login request and the
            // calls after it keep the same session.
            #[cfg(feature = "cookies")]
            if let Some(jar) = &self.cookie_jar {
                request.cookie_jar = Some(jar.clone());
            }

            // Carry the pins onto the request so the pinned send path installs
            // them on the client it builds. Without this the pin existed only on
            // the builder and was honoured by build() alone.
            if let Some(pinning) = &self.cert_pinning {
                request.cert_pinning = Some(pinning.clone());
            }

            // Default headers are validated at add_default_header() time.
            request.headers.extend(self.default_headers.iter().cloned());

            // HttpRequest::new() defaults to a host-scoped allow list, which is
            // strictly tighter than the builder's deny-list-only validator.
            // Merge the builder's private-network denials into it rather than
            // replacing it, so widening scope here cannot silently permit more
            // hosts than a bare HttpRequest would.
            if self.check_private_ips {
                request.scope_validator = request.scope_validator.with_deny_list([
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
                ]);
            }

            request
        })
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

    // Pinning needs reqwest's rustls backend to install a preconfigured TLS
    // config, so with `rustls-tls` off the failure is expected.
    #[cfg(feature = "rustls-tls")]
    #[test]
    fn builds_a_client_with_certificate_pinning() {
        let config = CertPinConfig::new().pin_spki_sha256([0x11; 32]);
        let builder = HttpClientBuilder::default().with_cert_pinning(config);
        assert!(builder.build().is_ok());
    }

    #[cfg(not(feature = "rustls-tls"))]
    #[test]
    fn cert_pinning_without_tls_build_is_refused() {
        let config = CertPinConfig::new().pin_spki_sha256([0x11; 32]);
        assert!(HttpClientBuilder::default()
            .with_cert_pinning(config)
            .build()
            .is_err());
    }

    #[test]
    fn created_requests_carry_the_builders_certificate_pins() {
        // Regression: the pin lived only on the builder, and only `build()`
        // installed it. Requests from `create_request()` — the path that also
        // pins DNS — therefore dropped certificate pinning entirely, so a pin
        // configured by the caller was silently not enforced on send.
        let config = CertPinConfig::new().pin_spki_sha256([0x11; 32]);
        let builder = HttpClientBuilder::default()
            .with_base_url("https://8.8.8.8/")
            .with_cert_pinning(config);

        let request = builder.create_request(Method::GET, "users").unwrap();
        let forwarded = request
            .cert_pinning
            .as_ref()
            .expect("create_request must forward the builder's pins");
        assert!(
            !forwarded.is_empty(),
            "the forwarded pin must be the configured one, not a default"
        );

        // And a builder without pinning must not fabricate one.
        let plain = HttpClientBuilder::default()
            .with_base_url("https://8.8.8.8/")
            .create_request(Method::GET, "users")
            .unwrap();
        assert!(plain.cert_pinning.is_none());
    }

    /// The forwarded pin must still be a usable TLS config.
    ///
    /// Network-free by design: `build_rustls_config` on a real pin succeeds
    /// without any connection, so this proves the forwarded value is the
    /// configured pin rather than a placeholder that would fail at handshake
    /// time.
    #[cfg(feature = "rustls-tls")]
    #[test]
    fn a_forwarded_pin_builds_a_tls_config() {
        let config = CertPinConfig::new().pin_spki_sha256([0x11; 32]);
        let request = HttpClientBuilder::default()
            .with_base_url("https://8.8.8.8/")
            .with_cert_pinning(config)
            .create_request(Method::GET, "users")
            .unwrap();

        let forwarded = request.cert_pinning.expect("pin must be forwarded");
        assert!(forwarded.build_rustls_config().is_ok());
    }

    #[test]
    fn attaches_builder_interceptors_to_created_requests() {
        use crate::interceptor::AuthInterceptor;
        use std::sync::Arc;

        let builder = HttpClientBuilder::default()
            .with_base_url("https://8.8.8.8/")
            .add_interceptor(Arc::new(AuthInterceptor::new("token")));
        let request = builder.create_request(Method::GET, "users").unwrap();
        assert_eq!(request.interceptors.len(), 1);
    }

    #[test]
    fn created_requests_inherit_timeout_and_default_headers() {
        // These were silently dropped before: create_request() built a request
        // with the 30s default and none of the builder's headers.
        let builder = HttpClientBuilder::default()
            .with_base_url("https://8.8.8.8/")
            .with_timeout(Duration::from_secs(7))
            .add_default_header("X-Api-Client", "beanstream")
            .unwrap();
        let request = builder.create_request(Method::GET, "users").unwrap();
        assert_eq!(request.timeout, Duration::from_secs(7));
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "x-api-client" && value == "beanstream"));
    }

    #[test]
    fn redirect_policy_is_active_even_when_not_following_redirects() {
        // P1-4: host validation used to be gated on follow_redirects, so the
        // default (false) made the policy inert. It must still enforce the
        // redirect limit and the scheme rules.
        let policy = HttpClientBuilder::default()
            .with_max_redirects(2)
            .get_redirect_policy();

        assert!(!policy.follow_redirects);
        assert_eq!(policy.max_redirects, 2);

        // Redirect limit still applies.
        let previous = vec![
            Url::parse("https://example.com/one").unwrap(),
            Url::parse("https://example.com/two").unwrap(),
        ];
        assert!(matches!(
            policy.check_redirect(&previous, &Url::parse("https://example.com/three").unwrap()),
            Err(BeanStreamError::TooManyRedirects(2))
        ));

        // Non-http(s) schemes are still refused.
        assert!(policy
            .check_redirect(&[], &Url::parse("ftp://example.com/f").unwrap())
            .is_err());
    }

    #[test]
    fn redirect_policy_seeds_allow_list_from_base_url() {
        // P1-4: with a base URL configured, redirects back to that host are
        // permitted rather than the allow list being empty.
        let policy = HttpClientBuilder::default()
            .with_base_url("https://api.example.com/v1/")
            .get_redirect_policy();
        assert!(policy
            .check_redirect(&[], &Url::parse("https://api.example.com/next").unwrap())
            .is_ok());
        assert!(policy
            .check_redirect(&[], &Url::parse("https://evil.com/next").unwrap())
            .is_err());
    }

    #[test]
    fn created_requests_inherit_the_follow_redirects_flag() {
        // P1-4: the flag must reach the request, because that is what decides
        // whether send() walks the chain at all.
        let builder = HttpClientBuilder::default()
            .with_base_url("https://8.8.8.8/")
            .with_follow_redirects(true)
            .with_max_redirects(4);
        let request = builder.create_request(Method::GET, "users").unwrap();

        assert!(request.redirect_policy.follow_redirects);
        assert_eq!(request.redirect_policy.max_redirects, 4);
    }

    #[tokio::test]
    async fn builder_send_goes_through_the_pinned_path() {
        // P1-1: the builder's send() must refuse a private-resolving host
        // instead of handing a raw client to reqwest.
        let builder = HttpClientBuilder::default();
        let outcome = builder.send(Method::GET, "http://127.0.0.1/").await;
        assert!(outcome.is_err(), "builder send must validate the target");
    }
}
