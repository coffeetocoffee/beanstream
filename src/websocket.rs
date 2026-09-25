//! P0-11: WebSocket support (behind the `websocket` feature).
//!
//! ```toml
//! beanstream = { version = "0.1", features = ["websocket"] }
//! ```
//!
//! [`connect_websocket`] runs the same SSRF protections as plain HTTP
//! requests (private-IP blocking, scope validation) before connecting, so
//! `ws://`/`wss://` targets are validated by mapping them onto their
//! `http`/`https` equivalents.

use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::request_handler::HttpRequest;
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

/// Open a WebSocket connection to `url`, with BeanStream URL and scope
/// validation applied first.
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

    // Validate host/IP access using the shared pipeline; the original
    // ws/wss URL is used for the actual connection.
    let request = HttpRequest::get(&normalized)?;
    request.scope_validator.check_url(&normalized)?;

    let ws_request = url
        .into_client_request()
        .map_err(|e| BeanStreamError::WebSocketError(format!("invalid WebSocket URL: {e}")))?;

    let (stream, _response) = connect_async(ws_request)
        .await
        .map_err(|e| BeanStreamError::WebSocketError(e.to_string()))?;

    Ok(stream)
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
}
