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
}

impl Default for RedirectPolicy {
    fn default() -> Self {
        Self {
            max_redirects: 10,
            track_all_redirects: true,
            allowed_hosts: HashSet::new(),
            denied_hosts: HashSet::new(),
            allow_any_redirect: false,
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
            ..Self::default()
        }
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
    allow_list: Vec<String>,
    deny_list: Vec<String>,
    default_deny: bool,
}

impl ScopeValidator {
    pub fn new(default_deny: bool) -> Self {
        Self {
            allow_list: Vec::new(),
            deny_list: Vec::new(),
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

    pub fn allow_host(&mut self, host: &str) {
        self.allow_list.push(normalize_host(host));
    }

    pub fn deny_host(&mut self, host: &str) {
        self.deny_list.push(normalize_host(host));
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
}
