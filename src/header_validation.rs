use reqwest::header::{HeaderName, HeaderValue};

use crate::{BeanStreamError, Result};

fn validate_header_name(name: &str) -> Result<()> {
    let name = name.trim();

    if name.is_empty() {
        return Err(BeanStreamError::HeaderError(
            "Header name cannot be empty".to_string(),
        ));
    }

    HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| BeanStreamError::HeaderError("Invalid header name".to_string()))?;

    Ok(())
}

fn validate_header_value(value: &str) -> Result<()> {
    let value = value.trim();

    if value.contains('\r') || value.contains('\n') {
        return Err(BeanStreamError::HeaderInjectionDetected);
    }

    if value
        .chars()
        .any(|character| character.is_control() && character != '\t')
    {
        return Err(BeanStreamError::HeaderError(
            "Header value contains control characters".to_string(),
        ));
    }

    HeaderValue::from_str(value)
        .map_err(|_| BeanStreamError::HeaderError("Invalid header value".to_string()))?;

    Ok(())
}

pub fn sanitize_header(name: &str, value: &str) -> Result<(String, String)> {
    let trimmed_name = name.trim();
    let trimmed_value = value.trim();

    validate_header_name(trimmed_name)?;
    validate_header_value(trimmed_value)?;

    Ok((trimmed_name.to_ascii_lowercase(), trimmed_value.to_string()))
}

pub fn validate_headers(headers: &[(String, String)]) -> Result<()> {
    for (name, value) in headers {
        validate_header_name(name)?;
        validate_header_value(value)?;
    }

    Ok(())
}

pub fn is_sensitive_header(name: &str) -> bool {
    [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-auth-token",
        "x-api-key",
        "x-access-token",
        "authentication",
        "proxy-authenticate",
        "www-authenticate",
    ]
    .iter()
    .any(|sensitive| name.eq_ignore_ascii_case(sensitive))
}

/// Drop sensitive headers (e.g. `set-cookie`, `authorization`) from a header
/// list, returning only the safe-to-expose pairs.
///
/// This implements the architecture's "Layer 3: Sensitive Data Protection":
/// responses never surface secrets unless the application explicitly opts in
/// (P1-3). It is applied to every network response in
/// [`crate::HttpRequest::send`] and again when a response is serialized.
pub fn redact_sensitive_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .filter(|(name, _)| !is_sensitive_header(name))
        .cloned()
        .collect()
}

pub fn is_blocked_header(name: &str) -> bool {
    [
        "host",
        "connection",
        "transfer-encoding",
        "content-length",
        "te",
    ]
    .iter()
    .any(|blocked| name.eq_ignore_ascii_case(blocked))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_names_and_values() {
        let (name, value) = sanitize_header(" X-Custom-Header ", " value ").unwrap();
        assert_eq!(name, "x-custom-header");
        assert_eq!(value, "value");
    }

    #[test]
    fn rejects_crlf_injection() {
        assert!(matches!(
            sanitize_header("x-test", "value\r\ninjected"),
            Err(BeanStreamError::HeaderInjectionDetected)
        ));
        assert!(sanitize_header("x-test", "value\ninjected").is_err());
        assert!(sanitize_header("x\r\ntest", "value").is_err());
    }

    #[test]
    fn rejects_invalid_header_tokens() {
        assert!(sanitize_header("bad header", "value").is_err());
        assert!(sanitize_header("", "value").is_err());
        assert!(sanitize_header("x-test", "bad\0value").is_err());
    }

    #[test]
    fn validates_header_collections() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Test".to_string(), "value".to_string()),
        ];
        assert!(validate_headers(&headers).is_ok());

        let invalid = vec![("X-Test".to_string(), "value\r\ninjected".to_string())];
        assert!(validate_headers(&invalid).is_err());
    }

    #[test]
    fn detects_sensitive_and_blocked_headers() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("SET-COOKIE"));
        assert!(!is_sensitive_header("content-type"));
        assert!(is_blocked_header("Host"));
        assert!(is_blocked_header("transfer-encoding"));
        assert!(!is_blocked_header("x-test"));
    }

    #[test]
    fn redacts_sensitive_headers_but_keeps_the_rest() {
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "set-cookie".to_string(),
                "session=abc; HttpOnly".to_string(),
            ),
            ("authorization".to_string(), "Bearer [REDACTED]".to_string()),
            ("x-trace-id".to_string(), "123".to_string()),
        ];

        let redacted = redact_sensitive_headers(&headers);
        assert_eq!(
            redacted,
            vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("x-trace-id".to_string(), "123".to_string()),
            ]
        );
    }
}
