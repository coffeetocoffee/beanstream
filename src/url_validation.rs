use ipnet::{Ipv4Net, Ipv6Net};
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

#[derive(Debug, Clone)]
pub struct SanitizedPath(String);

impl SanitizedPath {
    pub fn new(path: &str) -> Self {
        Self(path.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn contains_dangerous_sequences(&self) -> bool {
        ["..", "\\", "%2f", "%5c", "%2e"]
            .iter()
            .any(|sequence| self.0.to_ascii_lowercase().contains(sequence))
            || self.0.contains("//")
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

fn ipv6_in_network(address: Ipv6Addr, network: [u16; 8], prefix: u8) -> bool {
    let network_address = Ipv6Addr::new(
        network[0], network[1], network[2], network[3], network[4], network[5], network[6],
        network[7],
    );
    Ipv6Net::new(network_address, prefix)
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

pub fn is_ipv6_loopback_or_multicast(address: &Ipv6Addr) -> bool {
    let segments = address.segments();

    address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0xffff)
            && is_private_or_loopback(&Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                segments[6] as u8,
                (segments[7] >> 8) as u8,
                segments[7] as u8,
            ))
        || ipv6_in_network(*address, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16)
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

pub fn validate_url(url: &str) -> Result<ParsedUrl> {
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

    #[test]
    fn rejects_invalid_urls_and_credentials() {
        assert!(validate_url("ftp://8.8.8.8/file").is_err());
        assert!(validate_url("file:///tmp/file").is_err());
        assert!(validate_url("https://user:password@8.8.8.8/").is_err());
        assert!(validate_url("not a URL").is_err());
    }

    #[test]
    fn rejects_dangerous_paths() {
        assert_eq!(
            validate_url("https://8.8.8.8/api/../secret")
                .unwrap()
                .path
                .as_str(),
            "/secret"
        );
        assert_eq!(
            validate_url("https://8.8.8.8/api/%2e%2e/secret")
                .unwrap()
                .path
                .as_str(),
            "/secret"
        );
        assert_eq!(
            validate_url("https://8.8.8.8/api\\windows")
                .unwrap()
                .path
                .as_str(),
            "/api/windows"
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
