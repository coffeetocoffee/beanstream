//! P0-7: Middleware / interceptor architecture.
//!
//! Interceptors run around every request/response cycle: `on_request` may
//! inspect and mutate the [`HttpRequest`] before it is validated and sent,
//! and `on_response` may inspect and mutate the [`HttpResponse`] before it
//! is handed back to the caller.

use std::sync::Arc;

use crate::request_handler::{HttpRequest, HttpResponse};
use crate::Result;

/// Pluggable middleware hook invoked around the request/response cycle.
pub trait Interceptor: Send + Sync {
    /// Called with the request before it is validated and sent.
    fn on_request(&self, req: &mut HttpRequest) -> Result<()>;

    /// Called with the response before it is returned to the caller.
    fn on_response(&self, resp: &mut HttpResponse) -> Result<()>;
}

/// An ordered collection of [`Interceptor`]s applied in registration order.
#[derive(Clone, Default)]
pub struct InterceptorChain {
    interceptors: Vec<Arc<dyn Interceptor>>,
}

impl std::fmt::Debug for InterceptorChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterceptorChain")
            .field("len", &self.interceptors.len())
            .finish()
    }
}

impl InterceptorChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, interceptor: Arc<dyn Interceptor>) -> &mut Self {
        self.interceptors.push(interceptor);
        self
    }

    pub fn len(&self) -> usize {
        self.interceptors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.interceptors.is_empty()
    }

    pub fn run_on_request(&self, req: &mut HttpRequest) -> Result<()> {
        for interceptor in &self.interceptors {
            interceptor.on_request(req)?;
        }
        Ok(())
    }

    pub fn run_on_response(&self, resp: &mut HttpResponse) -> Result<()> {
        for interceptor in &self.interceptors {
            interceptor.on_response(resp)?;
        }
        Ok(())
    }
}

/// Logs each request method/URL and each response status to stderr.
#[derive(Debug, Default)]
pub struct LoggingInterceptor;

impl Interceptor for LoggingInterceptor {
    fn on_request(&self, req: &mut HttpRequest) -> Result<()> {
        eprintln!("[beanstream] -> {} {}", req.method, req.url);
        Ok(())
    }

    fn on_response(&self, resp: &mut HttpResponse) -> Result<()> {
        eprintln!("[beanstream] <- {} {}", resp.status, resp.url);
        Ok(())
    }
}

/// Attaches `Authorization: Bearer <token>` to every outgoing request.
#[derive(Debug, Clone)]
pub struct AuthInterceptor {
    token: String,
    header: String,
}

impl AuthInterceptor {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            header: "authorization".to_string(),
        }
    }

    /// Use a custom header name instead of `Authorization`.
    pub fn with_header_name(mut self, name: impl Into<String>) -> Self {
        self.header = name.into();
        self
    }
}

impl Interceptor for AuthInterceptor {
    fn on_request(&self, req: &mut HttpRequest) -> Result<()> {
        let value = format!("Bearer {}", self.token);
        // Replace any previously attached value so retries don't duplicate it.
        if let Some(existing) = req
            .headers
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case(&self.header))
        {
            existing.1 = value;
        } else {
            req.headers.push((self.header.clone(), value));
        }
        Ok(())
    }

    fn on_response(&self, _resp: &mut HttpResponse) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BeanStreamError;

    struct TagInterceptor {
        tag: String,
    }

    impl Interceptor for TagInterceptor {
        fn on_request(&self, req: &mut HttpRequest) -> Result<()> {
            req.headers.push(("x-order".into(), self.tag.clone()));
            Ok(())
        }

        fn on_response(&self, resp: &mut HttpResponse) -> Result<()> {
            resp.headers.push(("x-order".into(), self.tag.clone()));
            Ok(())
        }
    }

    struct FailingInterceptor;

    impl Interceptor for FailingInterceptor {
        fn on_request(&self, _req: &mut HttpRequest) -> Result<()> {
            Err(BeanStreamError::InternalError("boom".into()))
        }

        fn on_response(&self, _resp: &mut HttpResponse) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn chain_applies_interceptors_in_registration_order() {
        let mut chain = InterceptorChain::new();
        chain
            .add(Arc::new(TagInterceptor {
                tag: "first".into(),
            }))
            .add(Arc::new(TagInterceptor {
                tag: "second".into(),
            }));

        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        chain.run_on_request(&mut request).unwrap();
        assert_eq!(
            request
                .headers
                .iter()
                .filter(|(n, _)| n == "x-order")
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );

        let mut response = HttpResponse {
            status: 200,
            headers: vec![],
            body: vec![],
            url: "https://8.8.8.8/".into(),
        };
        chain.run_on_response(&mut response).unwrap();
        assert_eq!(response.headers[0], ("x-order".to_string(), "first".into()));
    }

    #[test]
    fn failing_interceptor_stops_the_chain() {
        let mut chain = InterceptorChain::new();
        chain
            .add(Arc::new(FailingInterceptor))
            .add(Arc::new(TagInterceptor {
                tag: "after".into(),
            }));

        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        assert!(chain.run_on_request(&mut request).is_err());
        assert!(request.headers.is_empty());
    }

    #[test]
    fn auth_interceptor_attaches_and_replaces_token() {
        let interceptor = AuthInterceptor::new("secret-token");
        let mut request = HttpRequest::get("https://8.8.8.8/").unwrap();
        interceptor.on_request(&mut request).unwrap();
        assert_eq!(request.headers[0].0, "authorization");

        // Second application replaces rather than duplicates.
        interceptor.on_request(&mut request).unwrap();
        assert_eq!(request.headers.len(), 1);
        assert_eq!(request.headers[0].1, "Bearer secret-token");
    }
}
