//! P0-10: Platform configuration generators.
//!
//! Emits ready-to-drop-in security configuration files for mobile
//! platforms: an iOS App Transport Security plist and an Android network
//! security config. Both default to the strictest posture — no cleartext,
//! no arbitrary-load exceptions.

use crate::{BeanStreamError, Result};

/// Domain-specific ATS exception (e.g. allow a partner domain that still
/// needs relaxed TLS or cleartext).
///
/// Both flags default to the *relaxing* direction when you construct this
/// struct literally — set them deliberately. Each one widens what iOS will
/// permit for [`Self::domain`] only.
#[derive(Debug, Clone)]
pub struct AtsException {
    /// The domain this exception applies to, e.g. `api.partner.example`.
    pub domain: String,
    /// Allow arbitrary (non-TLS) loads for this domain by setting
    /// `NSExceptionAllowsInsecureHTTPLoads`. Weakens transport security; use
    /// only where TLS cannot be served.
    pub allows_arbitrary_loads: bool,
    /// Allow TLS versions and ciphers below ATS's floor for this domain by
    /// setting `NSExceptionMinimumTLSVersion`. Needed for legacy endpoints.
    pub allows_insecure_httptls: bool,
}

/// Generate an iOS App Transport Security plist (P0-10).
///
/// By default `NSAllowsArbitraryLoads` is `false`; each entry in
/// `exceptions` becomes a per-domain override.
pub fn generate_ios_plist(exceptions: &[AtsException]) -> Result<String> {
    if exceptions.is_empty() {
        return Ok(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <false/>
        <key>NSExceptionDomains</key>
        <dict>
            <!-- Configure per-app exceptions -->
        </dict>
    </dict>
</dict>
</plist>"#
            .to_string());
    }

    let mut entries = String::new();
    for exception in exceptions {
        if exception.domain.is_empty()
            || !exception
                .domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(BeanStreamError::InvalidConfiguration(format!(
                "Invalid ATS exception domain: '{}'",
                exception.domain
            )));
        }
        let arbitrary = if exception.allows_arbitrary_loads {
            "<true/>"
        } else {
            "<false/>"
        };
        let insecure = if exception.allows_insecure_httptls {
            "<true/>"
        } else {
            "<false/>"
        };
        entries.push_str(&format!(
            concat!(
                "        <key>{}</key>\n",
                "        <dict>\n",
                "            <key>NSExceptionAllowsInsecureHTTPLoads</key>\n",
                "            {}\n",
                "            <key>NSIncludesSubdomains</key>\n",
                "            <true/>\n",
                "            <key>NSExceptionMinimumTLSVersion</key>\n",
                "            <string>TLSv1.2</string>\n",
                "            <key>NSAllowsArbitraryLoads</key>\n",
                "            {}\n",
                "        </dict>\n"
            ),
            xml_escape(&exception.domain),
            insecure,
            arbitrary
        ));
    }

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <false/>
        <key>NSExceptionDomains</key>
        <dict>
{}        </dict>
    </dict>
</dict>
</plist>"#,
        entries
    ))
}

/// Generate an Android network security config (P0-10).
///
/// Cleartext traffic is denied globally; each domain in `pinned_domains`
/// gets a `domain-config` entry (extend with `<pin-digest>` entries as
/// needed by your release process).
pub fn generate_android_network_config(pinned_domains: &[String]) -> Result<String> {
    for domain in pinned_domains {
        if domain.is_empty()
            || !domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*')
        {
            return Err(BeanStreamError::InvalidConfiguration(format!(
                "Invalid network security domain: '{domain}'"
            )));
        }
    }

    let mut domain_configs = String::new();
    for domain in pinned_domains {
        let include_subdomains = if domain.starts_with("*.") {
            "true"
        } else {
            "false"
        };
        let name = domain.trim_start_matches("*.");
        domain_configs.push_str(&format!(
            concat!(
                "    <domain-config cleartextTrafficPermitted=\"false\">\n",
                "        <domain includeSubdomains=\"{}\">{}</domain>\n",
                "    </domain-config>\n"
            ),
            include_subdomains,
            xml_escape(name)
        ));
    }

    Ok(format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
{}</network-security-config>"#,
        domain_configs
    ))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_a_strict_default_plist() {
        let plist = generate_ios_plist(&[]).unwrap();
        assert!(plist.starts_with("<?xml"));
        assert!(plist.contains("<key>NSAppTransportSecurity</key>"));
        assert!(plist.contains("<key>NSAllowsArbitraryLoads</key>\n        <false/>"));
        assert!(!plist.contains("<true/>"));
    }

    #[test]
    fn generates_per_domain_ats_exceptions() {
        let plist = generate_ios_plist(&[AtsException {
            domain: "cdn.partner.example".into(),
            allows_arbitrary_loads: false,
            allows_insecure_httptls: true,
        }])
        .unwrap();
        assert!(plist.contains("<key>cdn.partner.example</key>"));
        assert!(plist.contains("NSExceptionAllowsInsecureHTTPLoads"));
    }

    #[test]
    fn rejects_injection_in_ats_domains() {
        let result = generate_ios_plist(&[AtsException {
            domain: "evil.example</key><key>pwned".into(),
            allows_arbitrary_loads: true,
            allows_insecure_httptls: true,
        }]);
        assert!(result.is_err());
    }

    #[test]
    fn generates_a_strict_android_config() {
        let config = generate_android_network_config(&[]).unwrap();
        assert!(config.starts_with("<?xml"));
        assert!(config.contains("cleartextTrafficPermitted=\"false\""));
        assert!(config.contains("<certificates src=\"system\" />"));
    }

    #[test]
    fn generates_per_domain_android_entries() {
        let config = generate_android_network_config(&[
            "api.example.com".to_string(),
            "*.cdn.example.com".to_string(),
        ])
        .unwrap();
        assert!(config.contains(">api.example.com</domain>"));
        assert!(config.contains("includeSubdomains=\"true\">cdn.example.com</domain>"));
    }

    #[test]
    fn rejects_injection_in_android_domains() {
        let result = generate_android_network_config(&["evil.com</domain><domain".to_string()]);
        assert!(result.is_err());
    }
}
