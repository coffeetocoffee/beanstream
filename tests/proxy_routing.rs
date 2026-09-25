//! Proxy routing, verified against a local stand-in rather than a real proxy.
//!
//! Covers A1-A4 from `BeanStream_architecture_gaps.txt`: the platform/system
//! lookup, the environment variables, an explicit proxy, and the ability to
//! refuse proxying outright.
//!
//! The fake proxy is a plain TCP listener that records whether it was contacted
//! and answers `200`. That is enough to tell the four modes apart, and it needs
//! no network access — the same policy the rest of the suite follows.
//!
//! Environment variables are process-global, so these tests cannot run
//! concurrently with each other while `HTTP_PROXY` is set. They are serialised
//! behind a mutex, and each restores the variables it touched.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use beanstream::{HttpClientBuilder, ProxyConfig};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Serialises tests that mutate proxy environment variables.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// A listening socket that records how many times it was contacted.
struct FakeProxy {
    url: String,
    connections: Arc<AtomicUsize>,
}

impl FakeProxy {
    async fn start() -> Self {
        let connections = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let counter = connections.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                // Answer with something reqwest accepts, then close. The body is
                // irrelevant; being contacted at all is the signal.
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = socket.flush().await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                let _ = socket.shutdown().await;
            }
        });

        Self {
            url: format!("http://{address}"),
            connections,
        }
    }

    fn hits(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

/// A destination whose *name* is public, so the origin's address check passes.
///
/// `example.com` is only resolved to be validated; with a proxy configured the
/// request never reaches it, and the fake proxy answers instead. The test still
/// needs one DNS lookup for `example.com`, which the suite already relies on for
/// the certificate-pinning tests.
const PUBLIC_DESTINATION: &str = "http://example.com/";

/// Set the proxy environment variables, and always put them back.
struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    const VARS: [&'static str; 5] = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
    ];

    fn capture() -> Self {
        let lock = env_lock().lock().unwrap_or_else(|e| e.into_inner());
        let saved = Self::VARS
            .iter()
            .map(|name| (*name, std::env::var(name).ok()))
            .collect();

        Self { _lock: lock, saved }
    }

    fn set(&self, name: &str, value: &str) {
        std::env::set_var(name, value);
    }

    fn clear_all(&self) {
        for name in Self::VARS {
            std::env::remove_var(name);
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, value) in &self.saved {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

async fn send_with(builder: HttpClientBuilder) -> Option<u16> {
    builder
        .with_timeout(Duration::from_secs(10))
        .send(reqwest::Method::GET, PUBLIC_DESTINATION)
        .await
        .ok()
        .map(|response| response.status)
}

// --- A3: an explicit proxy is used ---

#[tokio::test]
async fn an_explicit_proxy_is_used() {
    let guard = EnvGuard::capture();
    guard.clear_all();

    let proxy = FakeProxy::start().await;
    let config = ProxyConfig::explicit(&proxy.url).unwrap();

    let status = send_with(HttpClientBuilder::default().with_proxy(config)).await;

    assert_eq!(
        proxy.hits(),
        1,
        "an explicit proxy must be the egress for the request"
    );
    assert_eq!(status, Some(200), "the fake proxy's response is returned");
}

// --- A4: proxying can be refused outright ---

#[tokio::test]
async fn disabling_the_proxy_ignores_the_environment() {
    let guard = EnvGuard::capture();
    let proxy = FakeProxy::start().await;

    // The environment asks loudly for a proxy; Disabled must not listen.
    guard.set("HTTP_PROXY", &proxy.url);
    guard.set("HTTPS_PROXY", &proxy.url);
    guard.set("ALL_PROXY", &proxy.url);

    let _ = send_with(HttpClientBuilder::default().with_proxy(ProxyConfig::Disabled)).await;

    assert_eq!(
        proxy.hits(),
        0,
        "Disabled must ignore an inherited proxy, so the request goes direct"
    );
}

// --- A2: the environment variables are honoured ---

#[tokio::test]
async fn environment_mode_uses_the_proxy_variables() {
    let guard = EnvGuard::capture();
    guard.clear_all();

    let proxy = FakeProxy::start().await;
    guard.set("HTTP_PROXY", &proxy.url);

    let _ = send_with(HttpClientBuilder::default().with_proxy(ProxyConfig::Environment)).await;

    assert_eq!(proxy.hits(), 1, "Environment mode must read HTTP_PROXY");
}

#[tokio::test]
async fn environment_mode_with_nothing_set_goes_direct() {
    let guard = EnvGuard::capture();
    guard.clear_all();

    let proxy = FakeProxy::start().await;
    guard.set("HTTP_PROXY", &proxy.url); // present, but must be cleared below

    // Prove the guard's clearing works, then send with a clean environment.
    guard.clear_all();
    let _ = send_with(HttpClientBuilder::default().with_proxy(ProxyConfig::Environment)).await;

    assert_eq!(
        proxy.hits(),
        0,
        "with no variables set, Environment mode means no proxy rather than falling back to the platform"
    );
}

// --- A1: the default consults the environment (and, with the feature, the OS) ---

#[tokio::test]
async fn the_default_mode_uses_the_proxy_variables() {
    let guard = EnvGuard::capture();
    guard.clear_all();

    let proxy = FakeProxy::start().await;
    guard.set("HTTP_PROXY", &proxy.url);

    // No with_proxy call: this is the out-of-the-box behaviour.
    let _ = send_with(HttpClientBuilder::default()).await;

    assert_eq!(
        proxy.hits(),
        1,
        "the default follows reqwest and curl, so HTTP_PROXY is honoured"
    );
}

// --- NO_PROXY is a bypass list, in every mode that can proxy ---

#[tokio::test]
async fn no_proxy_bypasses_the_proxy() {
    let guard = EnvGuard::capture();
    guard.clear_all();

    let proxy = FakeProxy::start().await;
    guard.set("HTTP_PROXY", &proxy.url);
    guard.set("NO_PROXY", "example.com");

    let _ = send_with(HttpClientBuilder::default()).await;

    assert_eq!(
        proxy.hits(),
        0,
        "NO_PROXY must route the listed host directly"
    );
}

#[tokio::test]
async fn no_proxy_also_applies_to_an_explicit_proxy() {
    let guard = EnvGuard::capture();
    guard.clear_all();

    let proxy = FakeProxy::start().await;
    guard.set("NO_PROXY", "example.com");

    let config = ProxyConfig::explicit(&proxy.url).unwrap();
    let _ = send_with(HttpClientBuilder::default().with_proxy(config)).await;

    assert_eq!(
        proxy.hits(),
        0,
        "a bypass list is a statement that some hosts are reached directly, even with a fixed proxy"
    );
}

// --- The SSRF checks are not weakened by configuring a proxy ---

#[tokio::test]
async fn a_literal_private_address_is_still_refused_with_a_proxy_configured() {
    let guard = EnvGuard::capture();
    guard.clear_all();

    let proxy = FakeProxy::start().await;
    let config = ProxyConfig::explicit(&proxy.url).unwrap();

    let outcome = HttpClientBuilder::default()
        .with_proxy(config)
        .with_timeout(Duration::from_secs(5))
        .send(
            reqwest::Method::GET,
            "http://169.254.169.254/latest/meta-data/",
        )
        .await;

    assert!(
        outcome.is_err(),
        "the cloud metadata address must be refused whether or not a proxy is set"
    );
    assert_eq!(
        proxy.hits(),
        0,
        "the refusal must happen before anything is sent to the proxy"
    );
}
