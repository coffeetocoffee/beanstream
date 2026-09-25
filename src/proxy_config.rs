//! Proxy configuration (A1-A4).
//!
//! Four ways a request can reach a proxy, made explicit rather than implicit:
//!
//! | Mode | Source | Platform APIs |
//! |------|--------|---------------|
//! | [`ProxyConfig::System`] | environment **and** platform settings | macOS CFNetwork, Windows registry |
//! | [`ProxyConfig::Environment`] | environment variables only | none — portable |
//! | [`ProxyConfig::Explicit`] | one URL you supply | none |
//! | [`ProxyConfig::Disabled`] | never | none |
//!
//! The distinction between `System` and `Environment` is the reason both exist:
//! `System` picks up a proxy configured in macOS Network preferences or the
//! Windows registry, which `Environment` deliberately does not. On Linux there
//! is nothing but the environment, so the two behave identically there.
//!
//! # The environment variables
//!
//! `Environment` and `System` both read the conventional variables, checked in
//! this order, case-sensitively first as most tools do:
//!
//! - `ALL_PROXY` / `all_proxy`
//! - `HTTP_PROXY` / `http_proxy`
//! - `HTTPS_PROXY` / `https_proxy`
//! - `NO_PROXY` / `no_proxy` — a comma-separated bypass list
//!
//! `NO_PROXY` entries may be hostnames (matching subdomains), IP addresses, CIDR
//! ranges, or `*`. That is the same rule set curl uses.
//!
//! # Security: what a proxy does and does not change about SSRF protection
//!
//! **The destination is still resolved and validated, proxy or not.** The usual
//! worry about proxies is that they move address checks out of your control —
//! the client talks to the proxy, the proxy resolves the origin, and your
//! private-IP block list never sees the real address. BeanStream does not work
//! that way:
//!
//! - The destination host is resolved locally and **every** resolved address is
//!   checked against the private/reserved block list before the request is sent,
//!   whether or not a proxy is configured. A proxy therefore cannot be used to
//!   reach an internal service that a direct request would refuse.
//! - Literal private addresses, and `localhost` / `*.local` / `*.internal` by
//!   name, are refused even earlier, by
//!   [`validate_url`](crate::validate_url).
//! - The consequence to be aware of: a proxy that exists *because* it can resolve
//!   internal names will not help you, since BeanStream resolves the name itself.
//!   That is deliberate — the alternative is that setting one environment
//!   variable silently disables the SSRF protection this crate is built around.
//!   Reaching an internal host requires the explicit opt-in
//!   [`HttpClientBuilder::allow_private_networks`](crate::HttpClientBuilder::allow_private_networks).
//!
//! What a proxy *does* change is egress: your traffic leaves through a host you
//! configured rather than directly, and that host can see the request (and, for
//! plain `http://` destinations, its contents). So:
//!
//! - **Configure a proxy only if you trust it.** An `https://` proxy URL encrypts
//!   the hop to the proxy, but a proxy terminating TLS still sees plaintext.
//! - **`System` reads the environment and the OS, which are not trusted
//!   inputs.** Anyone able to set `HTTPS_PROXY`, or edit macOS/Windows proxy
//!   settings, can choose your egress. Use [`ProxyConfig::Disabled`] or
//!   [`ProxyConfig::Explicit`] when that matters.
//! - **`NO_PROXY` is honoured as a bypass list**, including for an explicit
//!   proxy, so a host can be pinned to a direct connection.
//!
//! The proxy's own host is not pinned: it is trusted by configuration, and
//! rebinding it would require an attacker to control DNS for a host you
//! deliberately named. The origin's addresses are what get pinned.

use url::Url;

use crate::{BeanStreamError, Result};

/// How a request reaches a proxy.
///
/// Construct one of these and pass it to
/// [`HttpClientBuilder::with_proxy`](crate::HttpClientBuilder::with_proxy) or
/// [`HttpRequest::with_proxy`](crate::HttpRequest::with_proxy). The
/// [module documentation](crate::ProxyConfig) covers what a proxy does to SSRF
/// protection.
///
/// ```
/// use beanstream::ProxyConfig;
///
/// // The default follows the platform and the environment, like curl does.
/// assert_eq!(ProxyConfig::default(), ProxyConfig::System);
///
/// let explicit = ProxyConfig::explicit("http://proxy.corp.example:3128")?;
/// assert!(matches!(explicit, ProxyConfig::Explicit(_)));
///
/// // Malformed proxy URLs are refused at construction, not at send time.
/// assert!(ProxyConfig::explicit("not-a-url").is_err());
/// assert!(ProxyConfig::explicit("ftp://proxy.example:3128").is_err());
/// # Ok::<(), beanstream::BeanStreamError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProxyConfig {
    /// Read the environment **and** the platform's proxy settings.
    ///
    /// On macOS this consults CFNetwork / System Configuration; on Windows, the
    /// registry. On Linux only the environment variables apply, since there is
    /// no equivalent system store.
    ///
    /// This is the default, matching `reqwest` and curl conventions, and it
    /// means a machine that already has a proxy configured keeps working. It
    /// also means the effective egress can be changed by whoever controls those
    /// settings — see the module documentation.
    #[default]
    System,

    /// Read the environment variables only.
    ///
    /// Portable and predictable: no platform API is consulted, so the same
    /// variables produce the same routing everywhere. Use this when you want
    /// proxy support for containers and CI without inheriting a developer's
    /// desktop proxy settings.
    Environment,

    /// Always use this proxy, ignoring the environment.
    ///
    /// The URL is validated when constructed, and its host is resolved and
    /// pinned on each request so the proxy hop cannot be redirected by a DNS
    /// change. `NO_PROXY` is still honoured, as a bypass list should be.
    Explicit(ProxyEndpoint),

    /// Never use a proxy, even if the environment or the platform says to.
    ///
    /// Clears any inherited configuration. Choose this when the destination must
    /// be reached directly — the environment is not a trusted input.
    Disabled,
}

impl ProxyConfig {
    /// Use `url` as the proxy for every request.
    ///
    /// Accepts `http://` (the usual case, and what a TLS destination still uses
    /// via `CONNECT`) and `https://` when the hop to the proxy itself is
    /// encrypted. Anything else, a missing host, or a malformed URL is
    /// [`BeanStreamError::InvalidConfiguration`].
    ///
    /// Credentials may be embedded (`http://user:pass@proxy:3128`) and are
    /// passed to the proxy; they are not sent to the destination. Prefer
    /// [`Self::explicit_with_auth`] when you have the parts separately, since
    /// putting a password in a URL string makes it easy to leak into logs.
    pub fn explicit(url: &str) -> Result<Self> {
        Ok(Self::Explicit(ProxyEndpoint::new(url)?))
    }

    /// Use `url` as the proxy, authenticating with the given credentials.
    ///
    /// The credentials are attached separately rather than embedded in the URL,
    /// so no password-bearing string has to exist in your configuration.
    pub fn explicit_with_auth(url: &str, username: &str, password: &str) -> Result<Self> {
        let mut endpoint = ProxyEndpoint::new(url)?;
        endpoint.username = Some(username.to_string());
        endpoint.password = Some(password.to_string());
        Ok(Self::Explicit(endpoint))
    }

    /// Whether this configuration could route through a proxy.
    ///
    /// `true` for every mode except [`Self::Disabled`]. Note this is a statement
    /// about *configuration*, not about a particular request: with `System` or
    /// `Environment` the answer depends on variables that may or may not be set,
    /// and `NO_PROXY` may exempt the specific host. Callers use this to decide
    /// whether destination address checks still apply — see the module
    /// documentation.
    pub fn may_use_proxy(&self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

/// A validated proxy URL, optionally carrying credentials.
///
/// Produced by [`ProxyConfig::explicit`] or [`ProxyConfig::explicit_with_auth`].
/// An [`Explicit`](ProxyConfig::Explicit) config always holds one of these, so
/// the URL has been checked by the time a request is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    url: Url,
    username: Option<String>,
    password: Option<String>,
}

impl ProxyEndpoint {
    /// Validate `url` as a proxy target.
    ///
    /// Checks the scheme is `http` or `https`, that a host is present, and that
    /// the port (if given) is non-zero. The private/reserved address checks are
    /// **deliberately not applied** here: a proxy is very often on the local
    /// network, which is the whole point of a corporate proxy, so blocking
    /// private addresses would refuse the primary use case. The proxy is trusted
    /// by configuration.
    pub fn new(url: &str) -> Result<Self> {
        let parsed = Url::parse(url).map_err(|error| {
            BeanStreamError::InvalidConfiguration(format!("Invalid proxy URL '{url}': {error}"))
        })?;

        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(BeanStreamError::InvalidConfiguration(format!(
                    "Proxy scheme '{other}' is not supported; use http or https"
                )))
            }
        }

        if parsed.host_str().is_none() {
            return Err(BeanStreamError::InvalidConfiguration(format!(
                "Proxy URL '{url}' has no host"
            )));
        }

        if parsed.port() == Some(0) {
            return Err(BeanStreamError::InvalidConfiguration(
                "Proxy port 0 is not usable".to_string(),
            ));
        }

        Ok(Self {
            url: parsed,
            username: None,
            password: None,
        })
    }

    /// The proxy URL as given, with any embedded credentials removed.
    ///
    /// Safe to log: a password supplied through
    /// [`ProxyConfig::explicit_with_auth`] never appears here, and one embedded
    /// in the original URL is stripped by construction.
    pub fn redacted_url(&self) -> String {
        let mut clean = self.url.clone();
        let _ = clean.set_username("");
        let _ = clean.set_password(None);
        clean.to_string()
    }

    /// The proxy's host.
    pub fn host(&self) -> &str {
        // `new` guarantees a host.
        self.url.host_str().unwrap_or_default()
    }

    /// The proxy's port, defaulted from the scheme.
    pub fn port(&self) -> u16 {
        self.url
            .port_or_known_default()
            .unwrap_or(if self.url.scheme() == "https" {
                443
            } else {
                80
            })
    }

    /// Credentials to present to the proxy, if configured.
    pub fn credentials(&self) -> Option<(&str, &str)> {
        match (&self.username, &self.password) {
            (Some(user), Some(pass)) => Some((user.as_str(), pass.as_str())),
            _ => None,
        }
    }

    pub(crate) fn url(&self) -> &Url {
        &self.url
    }
}

/// Apply a proxy configuration to a `reqwest` client builder.
///
/// Shared by [`HttpClientBuilder`](crate::HttpClientBuilder) and the pinned send
/// path so the two clients cannot disagree about routing.
///
/// The four modes map onto three reqwest behaviours, and the `System` /
/// `Environment` split is not cosmetic:
///
/// - `System` leaves reqwest's own resolution enabled. That consults the
///   environment *and*, with the `system-proxy` feature on, the platform's
///   settings — macOS CFNetwork and the Windows registry.
/// - `Environment` reads the variables here and installs the result explicitly.
///   Adding any proxy turns reqwest's automatic lookup off, so the environment
///   becomes the *only* source and the same variables route identically on every
///   platform. Nothing set means no proxy, and the platform is never consulted.
/// - `Disabled` clears everything, so an inherited environment cannot route the
///   request.
/// - `Explicit` installs one proxy, with credentials passed through the
///   dedicated API rather than left in a URL string, and still honours
///   `NO_PROXY` — a bypass list is a statement that some hosts must be reached
///   directly.
pub(crate) fn apply(
    client: reqwest::ClientBuilder,
    config: &ProxyConfig,
) -> Result<reqwest::ClientBuilder> {
    match config {
        ProxyConfig::System => Ok(client),

        ProxyConfig::Disabled => Ok(client.no_proxy()),

        ProxyConfig::Environment => {
            let (proxy_url, bypass) = environment_proxy();
            let Some(proxy_url) = proxy_url else {
                return Ok(client.no_proxy());
            };

            let mut proxy = reqwest::Proxy::all(&proxy_url).map_err(|error| {
                BeanStreamError::InvalidConfiguration(format!(
                    "Invalid proxy URL from the environment ('{proxy_url}'): {error}"
                ))
            })?;

            if let Some(list) = bypass {
                if let Some(no_proxy) = reqwest::NoProxy::from_string(&list) {
                    proxy = proxy.no_proxy(Some(no_proxy));
                }
            }

            Ok(client.proxy(proxy))
        }

        ProxyConfig::Explicit(endpoint) => {
            // Addressed with credentials stripped, so no secret is handed over
            // as a string; they go through `basic_auth` below.
            let url = endpoint.redacted_url();
            let mut proxy = match endpoint.url().scheme() {
                "https" => reqwest::Proxy::https(&url),
                _ => reqwest::Proxy::http(&url),
            }
            .map_err(|error| {
                BeanStreamError::InvalidConfiguration(format!("Invalid proxy URL '{url}': {error}"))
            })?;

            if let Some((user, pass)) = endpoint.credentials() {
                proxy = proxy.basic_auth(user, pass);
            }

            if let Some(list) = environment_proxy().1 {
                if let Some(no_proxy) = reqwest::NoProxy::from_string(&list) {
                    proxy = proxy.no_proxy(Some(no_proxy));
                }
            }

            Ok(client.proxy(proxy))
        }
    }
}

/// Read the environment's proxy variables, most specific first.
///
/// Returns `(proxy_url, bypass)` where `proxy_url` is `None` when nothing in the
/// environment asks for a proxy.
pub(crate) fn environment_proxy() -> (Option<String>, Option<String>) {
    select_proxy(|name| std::env::var(name).ok())
}

/// The variable-selection logic, with the lookup injected.
///
/// Split out so it is testable without mutating process-global environment
/// variables — a test that sets `HTTP_PROXY` would otherwise race every other
/// test in the binary, and could route them through a proxy that does not exist.
pub(crate) fn select_proxy(
    get: impl Fn(&str) -> Option<String>,
) -> (Option<String>, Option<String>) {
    let first = |names: &[&str]| -> Option<String> {
        names
            .iter()
            .find_map(|name| get(name))
            .filter(|value| !value.trim().is_empty())
    };

    // ALL_PROXY is the catch-all and wins, matching curl's precedence.
    let proxy = first(&["ALL_PROXY", "all_proxy"]).or_else(|| {
        // Otherwise prefer the https variable, since an https target is the
        // common case for an API client; the proxy URL itself is often http.
        first(&["HTTPS_PROXY", "https_proxy"]).or_else(|| first(&["HTTP_PROXY", "http_proxy"]))
    });

    let bypass = first(&["NO_PROXY", "no_proxy"]);
    (proxy, bypass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_follows_the_platform_and_environment() {
        assert_eq!(ProxyConfig::default(), ProxyConfig::System);
        assert!(ProxyConfig::default().may_use_proxy());
        assert!(!ProxyConfig::Disabled.may_use_proxy());
    }

    #[test]
    fn explicit_accepts_http_and_https_proxies() {
        assert!(ProxyConfig::explicit("http://proxy.corp.example:3128").is_ok());
        assert!(ProxyConfig::explicit("https://proxy.corp.example:3128").is_ok());
        // A private LAN proxy is the normal case and must be allowed.
        assert!(ProxyConfig::explicit("http://192.168.1.10:3128").is_ok());
        // Port is optional; the scheme default applies.
        assert!(ProxyConfig::explicit("http://proxy.corp.example").is_ok());
    }

    #[test]
    fn explicit_refuses_unsupported_schemes_and_bad_urls() {
        for bad in [
            "not-a-url",
            "ftp://proxy.example:3128",
            "socks5://proxy.example:1080",
            "http://",
        ] {
            let outcome = ProxyConfig::explicit(bad);
            assert!(
                matches!(outcome, Err(BeanStreamError::InvalidConfiguration(_))),
                "'{bad}' should be refused, got {outcome:?}"
            );
        }
    }

    #[test]
    fn explicit_refuses_port_zero() {
        assert!(ProxyConfig::explicit("http://proxy.example:0").is_err());
    }

    #[test]
    fn the_proxy_url_is_reported_without_credentials() {
        let endpoint = ProxyEndpoint::new("http://user:hunter2@proxy.example:3128").unwrap();
        let shown = endpoint.redacted_url();

        assert!(
            !shown.contains("hunter2"),
            "the password must not survive into the loggable form: {shown}"
        );
        assert!(shown.contains("proxy.example:3128"));
    }

    #[test]
    fn credentials_supplied_separately_are_available_to_the_proxy() {
        let config =
            ProxyConfig::explicit_with_auth("http://proxy.example:3128", "user", "hunter2")
                .unwrap();

        match config {
            ProxyConfig::Explicit(endpoint) => {
                assert_eq!(endpoint.credentials(), Some(("user", "hunter2")));
                assert!(
                    !endpoint.redacted_url().contains("hunter2"),
                    "separate credentials must not be rendered into the URL"
                );
            }
            other => panic!("expected an explicit config, got {other:?}"),
        }
    }

    #[test]
    fn host_and_port_are_exposed_with_scheme_defaults() {
        let endpoint = ProxyEndpoint::new("http://proxy.example").unwrap();
        assert_eq!(endpoint.host(), "proxy.example");
        assert_eq!(endpoint.port(), 80);

        let tls = ProxyEndpoint::new("https://proxy.example").unwrap();
        assert_eq!(tls.port(), 443);

        let explicit = ProxyEndpoint::new("http://proxy.example:3128").unwrap();
        assert_eq!(explicit.port(), 3128);
    }

    #[tokio::test]
    async fn a_literal_proxy_address_is_accepted_without_resolution() {
        // A loopback proxy is the normal case (a local sidecar), and the private
        // address checks that apply to destinations deliberately do not apply to
        // the proxy: it is trusted by configuration.
        let endpoint = ProxyEndpoint::new("http://127.0.0.1:3128").unwrap();
        assert_eq!(endpoint.host(), "127.0.0.1");
        assert_eq!(endpoint.port(), 3128);
    }

    // --- Environment variable selection (A2) ---
    //
    // Driven through `select_proxy` with an injected lookup rather than by
    // setting real environment variables: those are process-global, so a test
    // that set `HTTP_PROXY` would race every other test in this binary and route
    // them through a proxy that does not exist.

    /// Build an env-var lookup from a static table.
    ///
    /// `&'static` on purpose: a borrowed table would make the returned closure
    /// capture the table's lifetime, which `select_proxy`'s signature does not
    /// carry.
    fn from_pairs(
        pairs: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<String> {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_string())
        }
    }

    #[test]
    fn http_proxy_is_read_when_nothing_more_specific_is_set() {
        let (proxy, bypass) = select_proxy(from_pairs(&[("HTTP_PROXY", "http://p:3128")]));
        assert_eq!(proxy.as_deref(), Some("http://p:3128"));
        assert!(bypass.is_none());
    }

    #[test]
    fn https_proxy_wins_over_http_proxy() {
        let (proxy, _) = select_proxy(from_pairs(&[
            ("HTTP_PROXY", "http://plain:3128"),
            ("HTTPS_PROXY", "http://secure:3128"),
        ]));
        assert_eq!(
            proxy.as_deref(),
            Some("http://secure:3128"),
            "an https destination is the common case, so HTTPS_PROXY takes priority"
        );
    }

    #[test]
    fn all_proxy_wins_over_both() {
        let (proxy, _) = select_proxy(from_pairs(&[
            ("HTTP_PROXY", "http://plain:3128"),
            ("HTTPS_PROXY", "http://secure:3128"),
            ("ALL_PROXY", "http://catchall:3128"),
        ]));
        assert_eq!(proxy.as_deref(), Some("http://catchall:3128"));
    }

    #[test]
    fn lowercase_variables_are_honoured() {
        let (proxy, bypass) = select_proxy(from_pairs(&[
            ("http_proxy", "http://lower:3128"),
            ("no_proxy", "example.com"),
        ]));
        assert_eq!(proxy.as_deref(), Some("http://lower:3128"));
        assert_eq!(bypass.as_deref(), Some("example.com"));
    }

    #[test]
    fn no_proxy_is_read_independently_of_the_proxy_variables() {
        // A bypass list on its own is still meaningful: with no proxy configured
        // it changes nothing, but it must not be lost.
        let (proxy, bypass) = select_proxy(from_pairs(&[("NO_PROXY", "internal.example")]));
        assert!(proxy.is_none());
        assert_eq!(bypass.as_deref(), Some("internal.example"));
    }

    #[test]
    fn empty_and_whitespace_variables_are_treated_as_unset() {
        // `HTTP_PROXY=""` is how some tooling clears the variable, so an empty
        // value must not be handed to the proxy parser as a URL.
        let (proxy, bypass) = select_proxy(from_pairs(&[
            ("HTTP_PROXY", "   "),
            ("ALL_PROXY", ""),
            ("NO_PROXY", "  "),
        ]));
        assert!(proxy.is_none(), "blank values must not select a proxy");
        assert!(
            bypass.is_none(),
            "blank values must not become a bypass list"
        );
    }

    #[test]
    fn nothing_set_means_no_proxy() {
        let (proxy, bypass) = select_proxy(|_| None);
        assert!(proxy.is_none());
        assert!(bypass.is_none());
    }
}
