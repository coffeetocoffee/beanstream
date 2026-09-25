use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

use crate::{BeanStreamError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn parse_scheme(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedHost {
    pub host: String,
    pub ip_addr: Option<IpAddr>,
}

/// Percent-decode `value` repeatedly so encoded traversal sequences cannot hide
/// behind multiple rounds of encoding (`%252e%252e` -> `%2e%2e` -> `..`).
///
/// Bounded: decoding either reaches a fixed point or hits the iteration cap, so
/// a hostile input cannot make this loop unbounded.
fn decode_percent_encoded(value: &str) -> String {
    const MAX_ROUNDS: usize = 5;
    let mut current = value.to_string();

    for _ in 0..MAX_ROUNDS {
        let bytes = current.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        let mut changed = false;

        while index < bytes.len() {
            if bytes[index] == b'%'
                && index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit()
            {
                let byte = u8::from_str_radix(&current[index + 1..index + 3], 16).unwrap_or(0);
                decoded.push(byte);
                changed = true;
                index += 3;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }

        if !changed {
            break;
        }
        current = String::from_utf8_lossy(&decoded).into_owned();
    }

    current
}

/// True when `path` contains a sequence that could escape or confuse path
/// handling downstream.
///
/// Checked against both the raw and the percent-decoded form, so encoded
/// traversal (`%2e%2e`) is caught and not merely normalized away (P1-6).
fn path_has_dangerous_sequence(path: &str) -> bool {
    let candidates = [path.to_string(), decode_percent_encoded(path)];

    candidates.iter().any(|candidate| {
        let lower = candidate.to_ascii_lowercase();

        // Directory traversal and path separators that should not appear once a
        // URL has been parsed into a path.
        ["..", "\\", "%2f", "%5c", "%2e", "%00", "\0", "//"]
            .iter()
            .any(|sequence| lower.contains(sequence))
    })
}

#[derive(Debug, Clone)]
pub struct SanitizedPath(String);

impl SanitizedPath {
    pub fn new(path: &str) -> Self {
        Self(path.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Detect sequences that could traverse or confuse path handling (P1-6).
    ///
    /// This inspects raw and percent-decoded forms. Note that `Url::parse`
    /// normalizes `..` and `.` segments *before* this type is constructed, so
    /// this catches what survives parsing (encoded forms, backslashes, NUL) —
    /// the raw-URL check in [`validate_url`] is what catches literal traversal.
    pub fn contains_dangerous_sequences(&self) -> bool {
        path_has_dangerous_sequence(&self.0)
    }
}

#[derive(Debug, Clone)]
pub struct ParsedUrl {
    pub scheme: Scheme,
    pub host: ValidatedHost,
    pub port: u16,
    pub path: SanitizedPath,
    pub original_url: String,
}

fn ipv4_in_network(address: Ipv4Addr, network: [u8; 4], prefix: u8) -> bool {
    Ipv4Net::new(Ipv4Addr::from(network), prefix)
        .map(|network| network.contains(&address))
        .unwrap_or(false)
}

pub fn is_private_or_loopback(address: &Ipv4Addr) -> bool {
    ipv4_in_network(*address, [0, 0, 0, 0], 8)
        || ipv4_in_network(*address, [10, 0, 0, 0], 8)
        || ipv4_in_network(*address, [100, 64, 0, 0], 10)
        || ipv4_in_network(*address, [127, 0, 0, 0], 8)
        || ipv4_in_network(*address, [169, 254, 0, 0], 16)
        || ipv4_in_network(*address, [172, 16, 0, 0], 12)
        || ipv4_in_network(*address, [192, 0, 0, 0], 24)
        || ipv4_in_network(*address, [192, 0, 2, 0], 24)
        || ipv4_in_network(*address, [192, 168, 0, 0], 16)
        || ipv4_in_network(*address, [198, 18, 0, 0], 15)
        || ipv4_in_network(*address, [198, 51, 100, 0], 24)
        || ipv4_in_network(*address, [203, 0, 113, 0], 24)
        || ipv4_in_network(*address, [224, 0, 0, 0], 4)
        || ipv4_in_network(*address, [240, 0, 0, 0], 4)
}

/// Extract the embedded IPv4 address from an IPv4-mapped (`::ffff:a.b.c.d`)
/// or IPv4-compatible (`::a.b.c.d`) IPv6 address, if present.
fn embedded_ipv4(address: &Ipv6Addr) -> Option<Ipv4Addr> {
    // The standard library already handles both mapped and compatible forms.
    address.to_ipv4()
}

pub fn is_ipv6_loopback_or_multicast(address: &Ipv6Addr) -> bool {
    let segments = address.segments();

    // IPv4-mapped / IPv4-compatible: defer to the IPv4 rules on the embedded
    // address rather than blanket-blocking the whole form (P1-7).
    if let Some(embedded) = embedded_ipv4(address) {
        return is_private_or_loopback(&embedded);
    }

    // Unique-local fc00::/7.
    let is_unique_local = segments[0] & 0xfe00 == 0xfc00;
    // Link-local fe80::/10.
    let is_link_local = segments[0] & 0xffc0 == 0xfe80;
    // Documentation range 2001:db8::/32.
    let is_documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;

    // 6to4 (2002::/16): block only when the embedded IPv4 address is itself
    // private. Previously every 2002:... address was refused regardless of the
    // embedded address, which rejected legitimate public 6to4 traffic (P1-7).
    let is_6to4 = segments[0] == 0x2002;
    let is_6to4_private = is_6to4
        && is_private_or_loopback(&Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            segments[1] as u8,
            (segments[2] >> 8) as u8,
            segments[2] as u8,
        ));

    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || is_unique_local
        || is_link_local
        || is_documentation
        || is_6to4_private
}

pub fn is_blocked_ip(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_private_or_loopback(address),
        IpAddr::V6(address) => is_ipv6_loopback_or_multicast(address),
    }
}

/// Resolve `host` to IP addresses using Tokio's non-blocking DNS resolver.
///
/// This never stalls the async runtime: the underlying `getaddrinfo` call is
/// offloaded to Tokio's blocking thread pool. Use this instead of the blocking
/// [`validate_ip_access`] from async code.
pub async fn resolve_host(host: &str) -> Result<Vec<IpAddr>> {
    let socket_addresses = tokio::net::lookup_host((host, 0u16))
        .await
        .map_err(|error| {
            BeanStreamError::InvalidHost(format!("Unable to resolve '{host}': {error}"))
        })?;

    let mut resolved = false;
    let mut addresses = Vec::new();
    for socket_address in socket_addresses {
        resolved = true;
        let address = socket_address.ip();
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }

    if resolved {
        Ok(addresses)
    } else {
        Err(BeanStreamError::InvalidHost(format!(
            "Host '{host}' did not resolve to an address"
        )))
    }
}

/// Non-blocking hostname resolution + address validation: resolves `host`
/// asynchronously and verifies that none of the resolved addresses are
/// private/internal. Returns the full list of validated public addresses.
pub async fn validate_ip_access_async(host: &str) -> Result<Vec<IpAddr>> {
    let addresses = resolve_host(host).await?;
    for address in &addresses {
        if is_blocked_ip(address) {
            return Err(BeanStreamError::PrivateNetworkAccess(address.to_string()));
        }
    }
    Ok(addresses)
}

/// Blocking hostname resolution + address validation for synchronous callers.
///
/// **Blocks the current thread** on DNS — do not call this from async code; use
/// [`validate_ip_access_async`] instead.
pub fn validate_ip_access(host: &str) -> Result<()> {
    use std::net::ToSocketAddrs;

    let addresses = (host, 0).to_socket_addrs().map_err(|error| {
        BeanStreamError::InvalidHost(format!("Unable to resolve '{host}': {error}"))
    })?;
    let mut resolved = false;

    for address in addresses {
        resolved = true;
        if is_blocked_ip(&address.ip()) {
            return Err(BeanStreamError::PrivateNetworkAccess(
                address.ip().to_string(),
            ));
        }
    }

    if resolved {
        Ok(())
    } else {
        Err(BeanStreamError::InvalidHost(format!(
            "Host '{host}' did not resolve to an address"
        )))
    }
}

fn validate_domain(domain: &str) -> Result<()> {
    if domain.len() > 253 {
        return Err(BeanStreamError::InvalidHost(
            "Domain name is too long".to_string(),
        ));
    }

    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(BeanStreamError::InvalidHost(
                "Domain contains an invalid label".to_string(),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(BeanStreamError::InvalidHost(
                "Domain labels cannot start or end with '-'".to_string(),
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(BeanStreamError::InvalidHost(
                "Domain contains invalid characters".to_string(),
            ));
        }
    }

    let lower_domain = domain.to_ascii_lowercase();
    if lower_domain == "localhost"
        || lower_domain.ends_with(".localhost")
        || lower_domain.ends_with(".local")
        || lower_domain.ends_with(".internal")
    {
        return Err(BeanStreamError::PrivateNetworkAccess(domain.to_string()));
    }

    // NOTE: hostname-to-IP resolution is deliberately NOT performed here. This
    // function is called from synchronous API entry points that are frequently
    // used inside async code, and a blocking `to_socket_addrs()` would stall
    // the runtime (P1-2). Instead, hostnames are resolved asynchronously at
    // connect time and pinned to the exact validated addresses, so a DNS
    // rebinding attack cannot swap in a private IP between validation and
    // connection (P1-1). See `HttpRequest::build_client` and
    // `validate_url_async`.

    Ok(())
}

fn validate_port(url: &Url) -> Result<u16> {
    match url.port() {
        Some(0) => Err(BeanStreamError::InvalidPort(0)),
        Some(port) => Ok(port),
        None => Ok(if url.scheme() == "https" { 443 } else { 80 }),
    }
}

fn validate_path(path: &SanitizedPath) -> Result<()> {
    if path.contains_dangerous_sequences() {
        Err(BeanStreamError::UrlError(
            "URL path contains a dangerous sequence".to_string(),
        ))
    } else {
        Ok(())
    }
}

/// Check the *raw* URL string for traversal before `Url::parse` normalizes it
/// away (P1-6).
///
/// `Url::parse` collapses `/api/../secret` to `/secret` and decodes `%2e%2e`,
/// so by the time a `SanitizedPath` exists the traversal is gone and the check
/// would pass. Validating the raw input first means traversal is rejected
/// rather than silently rewritten into a different path than the caller wrote.
fn validate_raw_url_path(url: &str) -> Result<()> {
    // Strip scheme://authority so host text (which may legitimately contain
    // dots, e.g. "example.com") is not scanned as path content, then take only
    // the path: a query or fragment may legitimately contain '.' or '//'.
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let path = match after_scheme.find('/') {
        Some(start) => {
            let from_start = &after_scheme[start..];
            let end = from_start.find(['?', '#']).unwrap_or(from_start.len());
            &from_start[..end]
        }
        None => return Ok(()),
    };

    if path_has_dangerous_sequence(path) {
        return Err(BeanStreamError::UrlError(
            "URL path contains a dangerous sequence".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_url(url: &str) -> Result<ParsedUrl> {
    // P1-6: reject traversal in the raw input before parsing normalizes it.
    validate_raw_url_path(url)?;

    let parsed = Url::parse(url)?;
    let scheme = Scheme::parse_scheme(parsed.scheme())
        .ok_or_else(|| BeanStreamError::InvalidScheme(parsed.scheme().to_string()))?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(BeanStreamError::UrlError(
            "URLs containing credentials are not allowed".to_string(),
        ));
    }

    let port = validate_port(&parsed)?;
    let path = SanitizedPath::new(parsed.path());
    validate_path(&path)?;

    let host = match parsed.host() {
        Some(url::Host::Domain(domain)) => {
            validate_domain(domain)?;
            ValidatedHost {
                host: domain.to_string(),
                ip_addr: None,
            }
        }
        Some(url::Host::Ipv4(address)) => {
            if is_private_or_loopback(&address) {
                return Err(BeanStreamError::PrivateNetworkAccess(address.to_string()));
            }
            ValidatedHost {
                host: address.to_string(),
                ip_addr: Some(IpAddr::V4(address)),
            }
        }
        Some(url::Host::Ipv6(address)) => {
            if is_ipv6_loopback_or_multicast(&address) {
                return Err(BeanStreamError::PrivateNetworkAccess(address.to_string()));
            }
            ValidatedHost {
                host: address.to_string(),
                ip_addr: Some(IpAddr::V6(address)),
            }
        }
        None => return Err(BeanStreamError::NoHost),
    };

    Ok(ParsedUrl {
        scheme,
        host,
        port,
        path,
        original_url: url.to_string(),
    })
}

/// Like [`validate_url`], but also resolves the hostname asynchronously and
/// verifies every resolved address against the private/internal block list.
///
/// This lets callers reject private-network destinations up front (matching the
/// architecture's "before they reach the network stack" promise) without
/// blocking the runtime. Connection-time pinning in [`crate::HttpRequest::send`]
/// remains the authoritative SSRF check.
pub async fn validate_url_async(url: &str) -> Result<ParsedUrl> {
    let parsed = validate_url(url)?;
    if parsed.host.ip_addr.is_none() {
        validate_ip_access_async(&parsed.host.host).await?;
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_public_ipv4_urls() {
        let parsed = validate_url("https://8.8.8.8/api").unwrap();
        assert_eq!(parsed.scheme, Scheme::Https);
        assert_eq!(parsed.port, 443);
        assert_eq!(
            parsed.host.ip_addr,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        );
    }

    #[test]
    fn blocks_private_and_reserved_ipv4_addresses() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "240.0.0.1",
        ] {
            assert!(validate_url(&format!("http://{address}/")).is_err());
        }
    }

    #[test]
    fn blocks_private_ipv6_addresses() {
        for address in ["::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1"] {
            assert!(validate_url(&format!("http://[{address}]/")).is_err());
        }
    }

    /// P1-7: an IPv4-mapped IPv6 address is judged by its embedded IPv4
    /// address, not blocked by shape alone.
    #[test]
    fn ipv4_mapped_ipv6_follows_the_embedded_ipv4_rules() {
        assert!(is_blocked_ip(&IpAddr::V6(
            "::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_blocked_ip(&IpAddr::V6(
            "::ffff:10.0.0.1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_blocked_ip(&IpAddr::V6(
            "::ffff:192.168.1.1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(is_blocked_ip(&IpAddr::V6(
            "::127.0.0.1".parse::<Ipv6Addr>().unwrap()
        )));

        assert!(!is_blocked_ip(&IpAddr::V6(
            "::ffff:8.8.8.8".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_blocked_ip(&IpAddr::V6(
            "::ffff:1.1.1.1".parse::<Ipv6Addr>().unwrap()
        )));
    }

    /// P1-7: 6to4 is blocked only when the embedded IPv4 is private, instead of
    /// rejecting the entire 2002::/16 range.
    #[test]
    fn six_to_four_is_blocked_only_for_private_embedded_addresses() {
        // 2002:7f00:0001:: == embedded 127.0.0.1 -> private, blocked.
        assert!(is_blocked_ip(&IpAddr::V6(
            "2002:7f00:1::".parse::<Ipv6Addr>().unwrap()
        )));
        // 2002:c0a8:0101:: == embedded 192.168.1.1 -> private, blocked.
        assert!(is_blocked_ip(&IpAddr::V6(
            "2002:c0a8:101::".parse::<Ipv6Addr>().unwrap()
        )));
        // 2002:0808:0808:: == embedded 8.8.8.8 -> public, allowed.
        assert!(!is_blocked_ip(&IpAddr::V6(
            "2002:808:808::".parse::<Ipv6Addr>().unwrap()
        )));
    }

    #[test]
    fn public_ipv6_addresses_are_allowed() {
        for address in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(!is_blocked_ip(&IpAddr::V6(
                address.parse::<Ipv6Addr>().unwrap()
            )));
        }
    }

    #[test]
    fn rejects_invalid_urls_and_credentials() {
        assert!(validate_url("ftp://8.8.8.8/file").is_err());
        assert!(validate_url("file:///tmp/file").is_err());
        assert!(validate_url("https://user:password@8.8.8.8/").is_err());
        assert!(validate_url("not a URL").is_err());
    }

    /// P1-6: traversal is rejected at the raw-URL stage instead of being
    /// silently normalized into a different path than the caller asked for.
    #[test]
    fn rejects_dangerous_paths() {
        for url in [
            "https://8.8.8.8/api/../secret",
            "https://8.8.8.8/api/%2e%2e/secret",
            "https://8.8.8.8/api/%2E%2E/secret",
            "https://8.8.8.8/api/..%2fsecret",
            "https://8.8.8.8/api/%252e%252e/secret",
            "https://8.8.8.8/api\\windows",
            "https://8.8.8.8/api/%5cwindows",
            "https://8.8.8.8/api/%2fetc/passwd",
        ] {
            let error = format!("{:?}", validate_url(url).unwrap_err());
            assert!(
                error.contains("dangerous sequence"),
                "{url} should be rejected as a dangerous path, got {error}"
            );
        }
    }

    /// Traversal hidden in the query string is not a path escape: the path
    /// itself is still clean, so the request goes through.
    #[test]
    fn query_string_traversal_does_not_block_a_clean_path() {
        let parsed = validate_url("https://example.com/api?next=/../admin").unwrap();
        assert_eq!(parsed.path.as_str(), "/api");
    }

    /// Ordinary paths with dots in them must still work (no false positives).
    #[test]
    fn accepts_ordinary_paths() {
        assert_eq!(
            validate_url("https://example.com/api/v1/items.json")
                .unwrap()
                .path
                .as_str(),
            "/api/v1/items.json"
        );
        assert_eq!(
            validate_url("https://example.com/a.b/c.d-e_f")
                .unwrap()
                .path
                .as_str(),
            "/a.b/c.d-e_f"
        );
        assert_eq!(
            validate_url("https://example.com/").unwrap().path.as_str(),
            "/"
        );
    }

    #[test]
    fn validates_ports() {
        assert!(validate_url("https://8.8.8.8:8443/api").is_ok());
        assert!(validate_url("https://8.8.8.8:0/api").is_err());
    }

    #[test]
    fn validate_url_no_longer_performs_blocking_dns() {
        // `.invalid` is reserved by RFC 2606 and must not resolve. Before the
        // DNS-rebinding fix, validate_url() resolved every hostname here and
        // would fail on non-resolving names. Structural validation must accept
        // a well-formed but non-resolving domain (resolution happens at send).
        assert!(validate_url("https://this-host-does-not-resolve-9f3c.invalid/").is_ok());
    }

    #[tokio::test]
    async fn resolve_host_is_non_blocking() {
        // `localhost` resolves from the local hosts file, so this does not need
        // network access and is deterministic.
        let addresses = resolve_host("localhost").await.unwrap();
        assert!(!addresses.is_empty());
    }

    #[tokio::test]
    async fn async_ip_access_rejects_private_resolutions() {
        // localhost resolves to 127.0.0.1 / ::1, both of which are blocked.
        let result = validate_ip_access_async("localhost").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn validate_url_async_checks_resolution() {
        assert!(
            validate_url_async("https://this-host-does-not-resolve-9f3c.invalid/")
                .await
                .is_err()
        );
    }
}
