//! P0-11: WebSocket support (behind the `websocket` feature).
//!
//! ```toml
//! beanstream = { version = "0.1", features = ["websocket"] }
//! ```
//!
//! [`connect_websocket`] runs the same SSRF protections as plain HTTP
//! requests before connecting: the `ws://`/`wss://` target is validated as its
//! `http`/`https` equivalent, and the host is resolved once so the validated
//! addresses can be connected to directly. Without that resolution step a
//! hostname that resolves to a private address would pass name validation —
//! [`validate_url`](crate::validate_url) performs no DNS for domains by design —
//! and the driver would resolve it again at connect time, which is the
//! DNS-rebinding window P1-1 closed for HTTP.

use std::net::SocketAddr;

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{client_async_tls_with_config, MaybeTlsStream, WebSocketStream};

use crate::request_handler::HttpRequest;
use crate::url_validation::validate_ip_access_async;
use crate::{BeanStreamError, Result};

/// An established WebSocket connection.
pub type WebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Map `ws://` and `wss://` onto `http://` and `https://` so the shared URL
/// validation pipeline can vet the target.
fn websocket_target_for_validation(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("ws://") {
        format!("http://{rest}")
    } else if let Some(rest) = url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else {
        url.to_string()
    }
}

/// Open a WebSocket connection to `url`, with BeanStream URL, scope and address
/// validation applied first.
///
/// The host is resolved asynchronously and every resolved address is checked
/// against the private/reserved block list; the connection is then made to one
/// of those validated addresses rather than letting the driver resolve the name
/// again.
///
/// Two limitations to know about, both deliberate:
///
/// - **The proxy configuration is not applied here.** A WebSocket through an
///   HTTP proxy needs a `CONNECT` upgrade that `tokio-tungstenite` does not
///   perform, so `ProxyConfig` affects HTTP paths only. A `wss://` connection
///   goes direct. If you need a proxied socket, terminate it yourself and hand
///   the stream over.
/// - **Certificate pinning is not applied to the TLS handshake either**, for the
///   same reason — the handshake is driven by the WebSocket stack, not by
///   reqwest's client configuration.
///
/// The returned [`WebSocket`] implements `Stream<Item = Message>` and
/// `Sink<Message>` from the `futures` ecosystem.
pub async fn connect_websocket(url: &str) -> Result<WebSocket> {
    let normalized = websocket_target_for_validation(url);
    if normalized == url {
        return Err(BeanStreamError::InvalidScheme(
            "WebSocket URLs must use the ws:// or wss:// scheme".to_string(),
        ));
    }

    // Validate the target through the shared pipeline; the original ws/wss URL
    // is used for the actual connection.
    let request = HttpRequest::get(&normalized)?;
    request.scope_validator.check_url(&normalized)?;

    // Resolve and validate the address list, so the private-address check
    // applies to what we actually connect to. `validate_url` deliberately does
    // no DNS for domain hosts, so this is the step that closes the gap.
    let addresses: Vec<SocketAddr> = match request.parsed_url.host.ip_addr {
        // A literal IP was already checked by validate_url.
        Some(address) => vec![SocketAddr::new(address, request.parsed_url.port)],
        None => validate_ip_access_async(&request.parsed_url.host.host)
            .await?
            .into_iter()
            .map(|address| SocketAddr::new(address, request.parsed_url.port))
            .collect(),
    };

    if addresses.is_empty() {
        return Err(BeanStreamError::InvalidHost(format!(
            "WebSocket host '{}' did not resolve to an address",
            request.parsed_url.host.host
        )));
    }

    let ws_request = url
        .into_client_request()
        .map_err(|e| BeanStreamError::WebSocketError(format!("invalid WebSocket URL: {e}")))?;

    // Connect to a validated address directly. `connect_async` would resolve
    // the hostname itself, discarding the check above (and reopening the
    // rebinding window), so the socket is opened here and handed to the
    // handshake instead.
    let mut last_error: Option<BeanStreamError> = None;
    for address in &addresses {
        let socket = match TcpStream::connect(address).await {
            Ok(socket) => socket,
            Err(error) => {
                last_error = Some(BeanStreamError::WebSocketError(format!(
                    "connecting to {address}: {error}"
                )));
                continue;
            }
        };

        match client_async_tls_with_config(ws_request.clone(), socket, None, None).await {
            Ok((stream, _response)) => return Ok(stream),
            Err(error) => {
                last_error = Some(BeanStreamError::WebSocketError(error.to_string()));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        BeanStreamError::WebSocketError("no validated address could be connected".to_string())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_websocket_schemes_for_validation() {
        assert_eq!(
            websocket_target_for_validation("wss://example.com/chat"),
            "https://example.com/chat"
        );
        assert_eq!(
            websocket_target_for_validation("ws://example.com/chat"),
            "http://example.com/chat"
        );
        assert_eq!(
            websocket_target_for_validation("https://example.com"),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn rejects_non_websocket_schemes_before_connecting() {
        let err = connect_websocket("https://8.8.8.8/not-ws")
            .await
            .unwrap_err();
        assert!(matches!(err, BeanStreamError::InvalidScheme(_)));
    }

    #[tokio::test]
    async fn rejects_private_websocket_targets_before_connecting() {
        let err = connect_websocket("ws://127.0.0.1:8080/socket")
            .await
            .unwrap_err();
        assert!(matches!(err, BeanStreamError::PrivateNetworkAccess(_)));
    }

    #[tokio::test]
    async fn rejects_a_hostname_that_resolves_privately() {
        // `localhost` is refused by name before resolution, so this asserts the
        // name path. The resolution path is covered by
        // `a_name_that_does_not_resolve_is_rejected` below, which can only fail
        // if the resolve step is on the critical path.
        let err = connect_websocket("ws://localhost:8080/socket")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            BeanStreamError::PrivateNetworkAccess(_) | BeanStreamError::InvalidHost(_)
        ));
    }

    #[tokio::test]
    async fn a_name_that_does_not_resolve_is_rejected() {
        // The resolution step is now on the critical path, so a name that does
        // not resolve must fail before any socket work rather than surfacing as
        // a driver error.
        let outcome = connect_websocket("ws://this-host-does-not-resolve-9f3c.invalid/").await;
        assert!(
            matches!(&outcome, Err(BeanStreamError::InvalidHost(_))),
            "expected a resolution failure, got {:?}",
            outcome.err().map(|e| e.to_string())
        );
    }
}
