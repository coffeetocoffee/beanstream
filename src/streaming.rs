//! P0-8: Streaming responses.
//!
//! `download_stream` validates a request, runs its `on_request`
//! interceptors, sends it, and returns the body as a chunk-by-chunk
//! [`ByteStream`] instead of buffering the whole response in memory.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use futures_util::StreamExt;

use crate::request_handler::HttpRequest;
use crate::{BeanStreamError, Result};

type InnerStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

/// A streaming sequence of response body chunks.
///
/// Implements [`futures_util::Stream`], so it composes with `StreamExt` /
/// `TryStreamExt`.
pub struct ByteStream {
    inner: InnerStream,
    total_received: u64,
}

impl std::fmt::Debug for ByteStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ByteStream")
            .field("total_received", &self.total_received)
            .finish()
    }
}

impl ByteStream {
    /// The number of payload bytes yielded so far.
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Read the entire remaining stream into a single buffer (with progress
    /// reporting via the stream's byte counter). Prefer consuming the
    /// [`Stream`] implementation directly for large payloads.
    pub async fn to_end(mut self) -> Result<Vec<u8>> {
        use futures_util::StreamExt;
        let mut buffer = Vec::new();
        while let Some(chunk) = self.next().await {
            buffer.extend_from_slice(&chunk?);
        }
        Ok(buffer)
    }
}

impl Stream for ByteStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                self.total_received += chunk.len() as u64;
                Poll::Ready(Some(Ok(chunk)))
            }
            other => other,
        }
    }
}

/// Send `request` and return its body as a chunk stream.
///
/// Fails before connecting if the URL/headers fail validation or if any
/// `on_request` interceptor fails; fails on the first network error while
/// streaming.
pub async fn download_stream(request: &HttpRequest) -> Result<ByteStream> {
    let interceptors = request.interceptors.clone();
    let mut prepared = request.clone();
    interceptors.run_on_request(&mut prepared)?;
    prepared.validate()?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(prepared.timeout)
        .build()?;

    let mut outbound = client.request(prepared.method.clone(), &prepared.url);
    use reqwest::header::{HeaderName, HeaderValue};
    for (name, value) in &prepared.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| BeanStreamError::HeaderError("Invalid header name".to_string()))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| BeanStreamError::HeaderError("Invalid header value".to_string()))?;
        outbound = outbound.header(name, value);
    }
    if let Some(body) = &prepared.body {
        outbound = outbound.body(body.clone());
    }

    let response = outbound.send().await.map_err(|e| {
        if e.is_timeout() {
            BeanStreamError::NetworkTimeout(prepared.timeout.as_millis() as u64)
        } else {
            BeanStreamError::RequestFailed(e.to_string())
        }
    })?;

    stream_from_response(response)
}

/// Wrap a `reqwest` response body in a [`ByteStream`], rejecting non-success
/// status codes.
pub fn stream_from_response(response: reqwest::Response) -> Result<ByteStream> {
    let status = response.status();
    if !status.is_success() {
        return Err(BeanStreamError::ServerError(status.as_u16()));
    }

    let url = response.url().to_string();
    let inner = response
        .bytes_stream()
        .map(move |res| res.map_err(|e| BeanStreamError::StreamingError(format!("{e} ({url})"))));
    Ok(ByteStream {
        inner: Box::pin(inner),
        total_received: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    #[tokio::test]
    async fn rejects_private_stream_targets_before_connecting() {
        // 127.0.0.1 is rejected at HttpRequest::new, but download_stream must
        // also reject targets smuggled in via mutation.
        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        request.url = "https://127.0.0.1/whatever".to_string();
        let err = download_stream(&request).await.unwrap_err();
        assert!(matches!(
            err,
            BeanStreamError::PrivateNetworkAccess(_)
                | BeanStreamError::HostNotAllowed(_)
                | BeanStreamError::RedirectBlocked(_)
        ));
    }

    #[tokio::test]
    async fn streams_chunks_from_a_success_response() {
        let http_response = http::Response::builder()
            .status(200)
            .body("hello stream")
            .unwrap();
        let response: reqwest::Response = http_response.into();
        let mut stream = stream_from_response(response).unwrap();

        let mut collected = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, b"hello stream");
        assert_eq!(stream.total_received(), 12);
    }

    #[tokio::test]
    async fn rejects_error_status_responses() {
        let http_response = http::Response::builder().status(503).body("").unwrap();
        let response: reqwest::Response = http_response.into();
        assert!(matches!(
            stream_from_response(response),
            Err(BeanStreamError::ServerError(503))
        ));
    }

    #[tokio::test]
    async fn failing_interceptor_blocks_the_stream() {
        use crate::interceptor::Interceptor;
        use std::sync::Arc;

        struct Failing;
        impl Interceptor for Failing {
            fn on_request(
                &self,
                _req: &mut crate::request_handler::HttpRequest,
            ) -> crate::Result<()> {
                Err(crate::BeanStreamError::InternalError("no".into()))
            }
            fn on_response(
                &self,
                _resp: &mut crate::request_handler::HttpResponse,
            ) -> crate::Result<()> {
                Ok(())
            }
        }

        let request = HttpRequest::get("https://8.8.8.8/")
            .unwrap()
            .add_interceptor(Arc::new(Failing));
        assert!(download_stream(&request).await.is_err());
    }
}
