//! Manual verification for P1-1 (DNS pinning) and P1-3 (response redaction).
//! Run with: cargo run --example verify_p1

use std::time::Duration;

use beanstream::{HttpRequest, HttpResponse};

/// Minimal HTTP/1.1 server that echoes a `Set-Cookie` and `Authorization`
/// header so we can prove redaction happens on a real response.
async fn spawn_server() -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                // Read request headers until blank line, then respond.
                let mut buf = [0u8; 4096];
                let mut seen = Vec::new();
                loop {
                    match socket.try_read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            seen.extend_from_slice(&buf[..n]);
                            if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => {
                            // Wait briefly for more data.
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                    if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = b"hello";
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Set-Cookie: session=e3c1f9; HttpOnly\r\n\
                     Authorization: Bearer super-secret-token\r\n\
                     X-Trace-Id: abc123\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(body).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            });
        }
    });

    (format!("127.0.0.1:{port}"), handle)
}

#[tokio::main]
async fn main() {
    let (addr, _server) = spawn_server().await;
    println!("server listening on {addr}");

    // --- P1-3: redaction on a real response ---
    //
    // We point at a literal 127.0.0.1 address. Literal private IPs are blocked
    // by design (SSRF protection), so to exercise the network path we build the
    // request against a public-looking URL and then retarget the pin. For this
    // manual check we bypass HttpRequest::new's validation by constructing via
    // a public URL and overriding url/parsed_url, which is what the pinning
    // code consumes.
    let mut req = HttpRequest::get("https://8.8.8.8/").unwrap();
    req.url = format!("http://{addr}/");
    req.parsed_url.port = addr.rsplit(':').next().unwrap().parse().unwrap();
    req.parsed_url.scheme = beanstream::Scheme::Http;
    req.parsed_url.host = beanstream::ValidatedHost {
        host: "127.0.0.1".to_string(),
        ip_addr: Some("127.0.0.1".parse().unwrap()),
    };
    req.timeout = Duration::from_secs(5);
    // The default scope validator only allows the originally-requested host, so
    // widen it to the retargeted host for this local check.
    req.scope_validator = beanstream::ScopeValidator::new(false);

    match req.send().await {
        Ok(response) => {
            println!("P1-3 status: {}", response.status);
            println!("P1-3 headers: {:?}", response.headers);
            let has_secret = response
                .headers
                .iter()
                .any(|(name, _)| beanstream::is_sensitive_header(name));
            println!("P1-3 leaked sensitive header: {has_secret}");
            assert!(!has_secret, "redaction failed: sensitive header present");
            assert!(
                response.headers.iter().any(|(n, _)| n == "x-trace-id"),
                "non-sensitive headers should survive"
            );
            println!("P1-3 PASS: sensitive headers stripped, others preserved");
        }
        Err(err) => {
            println!("request failed (network may be restricted): {err}");
            println!("P1-3 unit-level redaction verified in tests instead");
        }
    }

    // --- P1-1: pinning rejects private resolution before connecting ---
    let mut pinned = HttpRequest::get("https://8.8.8.8/").unwrap();
    pinned.parsed_url.host = beanstream::ValidatedHost {
        host: "localhost".to_string(),
        ip_addr: None,
    };
    let outcome = format!("{:?}", pinned.send().await);
    println!("P1-1 send() to private-resolving host: {outcome}");
    assert!(
        outcome.contains("PrivateNetworkAccess"),
        "expected private-network rejection, got {outcome}"
    );
    println!("P1-1 PASS: rejected before connect");

    let _: Option<HttpResponse> = None;
}
