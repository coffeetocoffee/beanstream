use std::collections::HashSet;

use url::Url;

use crate::{BeanStreamError, Result};

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn matches_host_pattern(pattern: &str, host: &str) -> bool {
    let pattern = normalize_host(pattern);
    let host = normalize_host(host);

    if pattern == "*" {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.strip_suffix(&format!(".{suffix}")).is_some();
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        return host == suffix
            || host
                .strip_suffix(suffix)
                .map(|prefix| prefix.ends_with('.'))
                .unwrap_or(false);
    }

    if let Some(prefix) = pattern.strip_suffix(".*") {
        return host == prefix
            || host
                .strip_prefix(prefix)
                .map(|suffix| suffix.starts_with('.'))
                .unwrap_or(false);
    }

    pattern == host
}

#[derive(Debug, Clone)]
pub struct RedirectPolicy {
    pub max_redirects: usize,
    pub track_all_redirects: bool,
    pub allowed_hosts: HashSet<String>,
    pub denied_hosts: HashSet<String>,
    pub allow_any_redirect: bool,
    /// Whether `HttpRequest::send` should follow 3xx responses (P1-4).
    ///
    /// Defaults to `false`, so redirects are returned to the caller unless this
    /// is enabled — matching the previous behaviour. When enabled, every hop is
    /// checked with [`RedirectPolicy::check_redirect`].
    pub follow_redirects: bool,
    /// Permit a redirect from `https` to plaintext `http` (P1-5).
    ///
    /// Defaults to `false`: once any hop in a chain has used TLS, a later hop
    /// may not drop back to plaintext.
    pub allow_scheme_downgrade: bool,
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 10,
            track_all_redirects: true,
            allowed_hosts: HashSet::new(),
            denied_hosts: HashSet::new(),
            allow_any_redirect: false,
            follow_redirects: false,
            allow_scheme_downgrade: false,
        }
    }
}

impl RedirectPolicy {
    pub fn strict<I, S>(allowed_hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut policy = Self::default();
        for host in allowed_hosts {
            policy.allow_host(host.as_ref());
        }
        policy
    }

    pub fn relaxed(max_redirects: usize) -> Self {
        Self {
            max_redirects,
            track_all_redirects: false,
            allow_any_redirect: true,
            follow_redirects: true,
            ..Self::default()
        }
    }

    /// Opt in to letting a redirect move from `https` to plaintext `http`.
    ///
    /// Off by default (P1-5). Enabling this weakens transport security and
    /// should only be used when the destination genuinely cannot serve TLS.
    pub fn allow_scheme_downgrade(mut self, allow: bool) -> Self {
        self.allow_scheme_downgrade = allow;
        self
    }

    /// Whether the redirect chain should be followed by `HttpRequest::send`.
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    pub fn allow_host(&mut self, host: &str) {
        self.allowed_hosts.insert(normalize_host(host));
    }

    pub fn deny_host(&mut self, host: &str) {
        self.denied_hosts.insert(normalize_host(host));
    }

    pub fn check_redirect(&self, previous_urls: &[Url], next_url: &Url) -> Result<()> {
        if previous_urls.len() >= self.max_redirects {
            return Err(BeanStreamError::TooManyRedirects(self.max_redirects));
        }

        if next_url.scheme() != "http" && next_url.scheme() != "https" {
            return Err(BeanStreamError::RedirectBlocked(format!(
                "Redirect scheme '{}' is not allowed",
                next_url.scheme()
            )));
        }

        // P1-5: refuse to move from TLS to plaintext. If any hop so far was
        // https, a later hop must not drop to http. This is checked against the
        // whole chain, not just the immediately preceding URL, so a
        // https -> http -> https dance cannot launder the downgrade.
        if !self.allow_scheme_downgrade {
            let chain_used_tls = previous_urls
                .iter()
                .chain(std::iter::once(next_url))
                .any(|url| url.scheme() == "https");

            if chain_used_tls && next_url.scheme() == "http" {
                return Err(BeanStreamError::RedirectBlocked(
                    "Refusing https -> http downgrade: redirect would move an \
                     encrypted connection to plaintext"
                        .to_string(),
                ));
            }
        }

        let next_host = next_url.host_str().ok_or(BeanStreamError::NoHost)?;

        if self
            .denied_hosts
            .iter()
            .any(|denied| matches_host_pattern(denied, next_host))
        {
            return Err(BeanStreamError::RedirectBlocked(format!(
                "Redirect to '{next_host}' is forbidden"
            )));
        }

        if !self.track_all_redirects && self.allow_any_redirect {
            return Ok(());
        }

        if self
            .allowed_hosts
            .iter()
            .any(|allowed| matches_host_pattern(allowed, next_host))
        {
            return Ok(());
        }

        Err(BeanStreamError::HostNotAllowed(next_host.to_string()))
    }

    pub fn get_redirect_history(&self, urls: &[Url]) -> Vec<String> {
        urls.iter().map(Url::to_string).collect()
    }

    pub fn get_redirect_hosts(&self, urls: &[Url]) -> Vec<String> {
        urls.iter()
            .filter_map(Url::host_str)
            .map(normalize_host)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct ScopeValidator {
    allow_list: HashSet<String>,
    deny_list: HashSet<String>,
    default_deny: bool,
}

impl ScopeValidator {
    pub fn new(default_deny: bool) -> Self {
        Self {
            allow_list: HashSet::new(),
            deny_list: HashSet::new(),
            default_deny,
        }
    }

    pub fn with_allow_list<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.allow_list
            .extend(hosts.into_iter().map(|host| normalize_host(host.as_ref())));
        self
    }

    pub fn with_deny_list<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.deny_list
            .extend(hosts.into_iter().map(|host| normalize_host(host.as_ref())));
        self
    }

    /// Add a host to the allow list.
    ///
    /// The list is a set, so adding the same host twice is a no-op (P3-1) —
    /// previously duplicates accumulated and made matching O(n) for no benefit.
    pub fn allow_host(&mut self, host: &str) {
        self.allow_list.insert(normalize_host(host));
    }

    /// Add a host to the deny list, ignoring duplicates (P3-1).
    pub fn deny_host(&mut self, host: &str) {
        self.deny_list.insert(normalize_host(host));
    }

    /// Number of distinct allowed hosts. Exposed for tests and diagnostics.
    pub fn allow_list_len(&self) -> usize {
        self.allow_list.len()
    }

    /// Number of distinct denied hosts. Exposed for tests and diagnostics.
    pub fn deny_list_len(&self) -> usize {
        self.deny_list.len()
    }

    pub fn check_url(&self, url: &str) -> Result<()> {
        let parsed = Url::parse(url)?;

        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(BeanStreamError::InvalidScheme(parsed.scheme().to_string()));
        }

        let host = parsed.host_str().ok_or(BeanStreamError::NoHost)?;

        if self
            .deny_list
            .iter()
            .any(|denied| matches_host_pattern(denied, host))
        {
            return Err(BeanStreamError::RedirectBlocked(format!(
                "Access to '{host}' is denied"
            )));
        }

        if self
            .allow_list
            .iter()
            .any(|allowed| matches_host_pattern(allowed, host))
        {
            return Ok(());
        }

        if self.default_deny {
            return Err(BeanStreamError::RedirectBlocked(format!(
                "Access to '{host}' is not permitted by scope policy"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_requires_an_explicit_host() {
        let policy = RedirectPolicy::default();
        assert_eq!(policy.max_redirects, 10);
        assert!(policy
            .check_redirect(&[], &Url::parse("https://example.com/next").unwrap())
            .is_err());
    }

    #[test]
    fn strict_policy_matches_allowed_hosts() {
        let policy = RedirectPolicy::strict(["example.com", "*.example.com"]);
        let previous = vec![];
        assert!(policy
            .check_redirect(
                &previous,
                &Url::parse("https://api.example.com/next").unwrap()
            )
            .is_ok());
        assert!(policy
            .check_redirect(&previous, &Url::parse("https://evil.com/next").unwrap())
            .is_err());
    }

    #[test]
    fn deny_list_wins_over_allow_list() {
        let mut policy = RedirectPolicy::strict(["example.com"]);
        policy.deny_host("blocked.example.com");
        assert!(policy
            .check_redirect(
                &[],
                &Url::parse("https://blocked.example.com/next").unwrap()
            )
            .is_err());
    }

    #[test]
    fn enforces_redirect_limits_and_schemes() {
        let policy = RedirectPolicy::relaxed(1);
        let previous = vec![Url::parse("https://example.com/one").unwrap()];
        assert!(matches!(
            policy.check_redirect(&previous, &Url::parse("https://example.com/two").unwrap()),
            Err(BeanStreamError::TooManyRedirects(1))
        ));
        assert!(policy
            .check_redirect(&[], &Url::parse("ftp://example.com/file").unwrap())
            .is_err());
    }

    #[test]
    fn scope_allow_list_supports_safe_wildcards() {
        let validator = ScopeValidator::new(true).with_allow_list(["example.com", "*.github.com"]);
        assert!(validator.check_url("https://example.com/api").is_ok());
        assert!(validator.check_url("https://api.github.com/user").is_ok());
        assert!(validator
            .check_url("https://raw.githubusercontent.com/file")
            .is_err());
        assert!(validator.check_url("https://evilgithub.com/file").is_err());
    }

    #[test]
    fn scope_wildcard_matches_nested_subdomains() {
        let validator = ScopeValidator::new(true).with_allow_list(["*.internal.company.com"]);
        assert!(validator
            .check_url("https://api.internal.company.com/v1")
            .is_ok());
        assert!(validator
            .check_url("https://app.internal.company.com/dashboard")
            .is_ok());
        assert!(validator.check_url("https://external.com/page").is_err());
    }

    #[test]
    fn scope_deny_list_blocks_matching_hosts() {
        let validator = ScopeValidator::new(false).with_deny_list(["google.com", "*facebook.com"]);
        assert!(validator.check_url("https://google.com/search").is_err());
        assert!(validator
            .check_url("https://www.facebook.com/login")
            .is_err());
        assert!(validator.check_url("https://notfacebook.com/login").is_ok());
        assert!(validator.check_url("https://other-site.com/page").is_ok());
    }

    #[test]
    fn downgrade_from_https_to_http_is_refused() {
        // P1-5. `strict` seeds the allow list so we are testing the downgrade
        // rule specifically, not an unrelated HostNotAllowed rejection.
        let policy = RedirectPolicy::strict(["example.com"]);
        let previous = vec![Url::parse("https://example.com/secure").unwrap()];

        let result =
            policy.check_redirect(&previous, &Url::parse("http://example.com/plain").unwrap());
        assert!(
            matches!(&result, Err(BeanStreamError::RedirectBlocked(message))
                if message.contains("downgrade")),
            "expected a downgrade rejection, got {result:?}"
        );

        // Staying on https is fine, and http -> http is unaffected.
        assert!(policy
            .check_redirect(&previous, &Url::parse("https://example.com/also").unwrap())
            .is_ok());
        let http_chain = vec![Url::parse("http://example.com/a").unwrap()];
        assert!(policy
            .check_redirect(&http_chain, &Url::parse("http://example.com/b").unwrap())
            .is_ok());
    }

    #[test]
    fn downgrade_is_caught_even_after_an_intermediate_https_hop() {
        // P1-5: an https -> ... -> http chain must not launder the downgrade;
        // the check looks at the whole chain, not just the previous hop.
        let policy = RedirectPolicy::strict(["example.com"]);
        let chain = vec![
            Url::parse("https://example.com/start").unwrap(),
            Url::parse("https://example.com/mid").unwrap(),
        ];
        let result =
            policy.check_redirect(&chain, &Url::parse("http://example.com/plain").unwrap());
        assert!(
            matches!(&result, Err(BeanStreamError::RedirectBlocked(message))
                if message.contains("downgrade")),
            "expected a downgrade rejection, got {result:?}"
        );
    }

    #[test]
    fn downgrade_can_be_opted_into() {
        let policy = RedirectPolicy::strict(["example.com"]).allow_scheme_downgrade(true);
        let previous = vec![Url::parse("https://example.com/secure").unwrap()];
        assert!(policy
            .check_redirect(&previous, &Url::parse("http://example.com/plain").unwrap())
            .is_ok());
    }

    #[test]
    fn scope_host_lists_do_not_accumulate_duplicates() {
        // P3-1: allow_host/deny_host used Vec::push, so repeated hosts piled up.
        let mut validator = ScopeValidator::new(true);
        validator.allow_host("Example.com");
        validator.allow_host("example.com");
        validator.allow_host("example.com.");
        validator.deny_host("evil.com");
        validator.deny_host("evil.com");

        // All three spellings normalize to the same host, so one entry remains.
        assert_eq!(validator.allow_list_len(), 1);
        assert_eq!(validator.deny_list_len(), 1);
        assert!(validator.check_url("https://example.com/api").is_ok());
        assert!(validator.check_url("https://evil.com/api").is_err());
    }
}
