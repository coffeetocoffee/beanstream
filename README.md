# BeanStream ☕

> **From bean to bit — pure delivery**  
> *Where security brews perfectly, every single request*

[![CI](https://github.com/coffeetocoffee/beanstream/actions/workflows/ci.yml/badge.svg)](https://github.com/coffeetocoffee/beanstream/actions/workflows/ci.yml)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

A security-first HTTP client for Rust that keeps your requests as safe as a carefully roasted espresso — fast enough to keep up with your workflow, robust enough to protect your users' data around the clock.

---

## Why BeanStream?

Most HTTP clients make you choose between speed and safety. BeanStream gives you both in one cohesive package. It bakes **defense-in-depth security** right into the request pipeline, so you don't have to think about it.

- 🔒 **Uncompromising Security** — SSRF protection, header injection prevention, smart IP range blocking
- ⚡ **Blazing Performance** — Built on `reqwest` + `tokio`, zero-waste processing
- 🌍 **Universal Compatibility** — Works across all major platforms
- 🆓 **Truly Free Forever** — MIT/Apache-2.0, no hidden costs, no premium tiers

---

## Security, Brewed In

Every request passes through a stack of independent validation layers. Nothing is left to chance.

### 1. URL Validation & Sanitization

Before a single connection is attempted, URLs are rigorously checked. Private IPs, loopback addresses, and metadata endpoints are blocked outright — no more SSRF surprises.

```rust
use beanstream::{is_private_or_loopback, validate_url};

// Public URLs are fine
let parsed = validate_url("https://8.8.8.8/api")?;
assert_eq!(parsed.port, 443);

// Private & reserved networks are blocked
assert!(validate_url("http://192.168.1.1/test").is_err());
assert!(validate_url("http://10.0.0.1/admin").is_err());
assert!(validate_url("http://[::1]/").is_err());
```

### 2. Header Safety

User-provided headers are sanitized against CRLF injection and control characters, and forbidden headers (`Host`, `Content-Length`, `Transfer-Encoding`…) are rejected automatically.

```rust
use beanstream::sanitize_header;

let (name, value) = sanitize_header(" X-Custom-Header ", " value ")?;
assert_eq!(name, "x-custom-header"); // normalized
assert_eq!(value, "value");          // trimmed

assert!(sanitize_header("x-test", "value\r\ninjected").is_err()); // injection blocked
```

### 3. Sensitive Data Protection

Sensitive headers (`authorization`, `set-cookie`, `x-api-key`, …) are automatically detected and kept out of logs and responses.

```rust
use beanstream::is_sensitive_header;

assert!(is_sensitive_header("Authorization"));
assert!(is_sensitive_header("SET-COOKIE"));
assert!(!is_sensitive_header("content-type"));
```

### 4. Intelligent Redirect Handling

Redirects are tracked and validated against scope policies — stop open-redirect attacks while letting legitimate chains through.

```rust
use beanstream::RedirectPolicy;
use url::Url;

// Strict: only allow this host (and subdomains)
let policy = RedirectPolicy::strict(["example.com", "*.example.com"]);

assert!(policy.check_redirect(&[], &Url::parse("https://api.example.com/x")?).is_ok());
assert!(policy.check_redirect(&[], &Url::parse("https://evil.com/x")?).is_err());
```

`RedirectPolicy::follow_redirects` is what actually drives the send path. It
defaults to `false`, so a 3xx is handed back to the caller. Set it to `true` and
`HttpRequest::send` walks the chain itself — it has to, because reqwest's own
redirect policy is pinned to `none`. Walking it here means every hop gets the
full treatment:

- re-validated as a fresh URL, so a public start cannot redirect into the
  private network;
- re-checked against the redirect policy, scope and scheme rules, so an
  `https` → `http` downgrade is refused;
- re-pinned to its own validated addresses, closing the DNS-rebinding window on
  each hop;
- loop-checked, and stopped at `max_redirects`.

Method and credentials follow the HTTP rules: 303 always becomes `GET`, and so
does 301/302 on a `POST` (the body is dropped rather than replayed). A hop that
changes origin loses its sensitive headers and its body, so credentials cannot
leak to a second host.

```rust
use beanstream::RedirectPolicy;
use beanstream::HttpRequest;

async fn fetch() -> Result<(), Box<dyn std::error::Error>> {
    let response = HttpRequest::get("https://example.com/start")?
        .redirect_policy(RedirectPolicy::strict(["example.com"]).follow_redirects(true))
        .send()
        .await?;
    println!("{}", response.status);
    Ok(())
}
```

---

## Quick Start

### Make your first request

```rust
use beanstream::HttpRequest;
use std::time::Duration;

fn main() -> Result<(), beanstream::BeanStreamError> {
    // `add_header` takes `&mut self` so a single call can report which header
    // was rejected; the ownership-taking `body`/`timeout` follow it.
    let mut request = HttpRequest::get("https://api.example.com/users")?
        .body("{}")
        .timeout(Duration::from_secs(15));
    request.add_header("X-Test", "value")?;

    request.validate()?;
    let built = request.build_request()?;
    // send with any reqwest client
    let _ = built;
    Ok(())
}
```

### Configure a shared client

```rust
use beanstream::HttpClientBuilder;
use std::time::Duration;

let client = HttpClientBuilder::default()
    .with_base_url("https://api.example.com/api/")
    .with_timeout(Duration::from_secs(30))
    .with_max_redirects(5)
    .with_follow_redirects(true)
    .add_default_header("X-App", "beanstream")?
    .build()?;
```

> `build()` returns a plain `reqwest::Client`, which trusts the system resolver
> and therefore cannot pin addresses. Use `send()` on the builder, or
> `HttpRequest` directly, when you want the SSRF checks and DNS pinning applied.

### Builder options at a glance

| Method | What it does |
|--------|--------------|
| `with_base_url(url)` | Set a base URL for relative targets |
| `with_timeout(d)` | Overall request timeout |
| `with_connect_timeout(d)` | Connection establishment timeout |
| `with_max_redirects(n)` | Maximum redirect hops |
| `with_follow_redirects(bool)` | Follow (or refuse) redirects |
| `with_user_agent(ua)` | Custom User-Agent |
| `add_default_header(name, value)` | Add a sanitized default header |
| `allow_private_networks()` | Opt in to private IP access (not recommended) |
| `with_cert_pinning(cfg)` | SPKI pinning; needs the `rustls-tls` feature |
| `with_cookie_jar(jar)` | Share session cookies; needs the `cookies` feature |

### Creating requests

`HttpRequest` offers ergonomic helpers for common verbs:

```rust
HttpRequest::get(url)?;
HttpRequest::post(url)?;
HttpRequest::put(url)?;
HttpRequest::delete(url)?;
HttpRequest::patch(url)?;
```

Mutation-style methods take `&mut self` and can therefore fail per header;
ownership-style methods consume and return `Self` and cannot fail:

```rust
use beanstream::HttpRequest;
use std::time::Duration;

let mut req = HttpRequest::post("https://api.example.com/items")?
    .body(r#"{"name":"espresso"}"#)
    .timeout(Duration::from_secs(10));
req.add_headers([("X-Env", "prod"), ("Accept", "application/json")])?;
```

---

## Clear Error Messages

Errors speak human. No more cryptic stack dives.

```rust
use beanstream::BeanStreamError;

match HttpRequest::get("http://127.0.0.1/") {
    Err(BeanStreamError::PrivateNetworkAccess(addr)) => {
        eprintln!("Blocked access to private network: {addr}");
    }
    Err(e) => eprintln!("Something else: {e}"),
    Ok(_) => {}
}
```

| Error | Meaning |
|-------|---------|
| `PrivateNetworkAccess` | Tried to reach a private/reserved IP |
| `InvalidScheme` | Scheme isn't `http`/`https` |
| `HeaderInjectionDetected` | CR/LF found in a header |
| `HeaderError` | Malformed or forbidden header |
| `TooManyRedirects` | Redirect chain exceeded the limit |
| `HostNotAllowed` | Redirect/scope policy rejected the host |
| `RateLimited` | Back off and retry later |

---

## Architecture

A clean, modular pipeline keeps concerns separated and everything testable.

```
Request Object → Middleware/Validation → Scope Validator → Executor → Response
```

- **Request Object** — fluent, immutable-by-convention request builder
- **Validation Engine** — URL, IP, path & header checks
- **Scope Validator** — allow/deny host lists with safe wildcards
- **Redirect Policy** — chain limits + destination checks
- **Executor** — `reqwest` + `tokio` doing the heavy lifting

Each component operates independently, so the system is resilient to individual failures and a joy to test.

---

## Platform Support

BeanStream rides on `reqwest` with `rustls`, so it compiles and runs cleanly on:

- 🪟 Windows
- 🍎 macOS
- 🐧 Linux
- 📱 iOS & Android

---

## Status

Everything originally listed as a future milestone is implemented and gated in
CI. The crate version in `Cargo.toml` is still `0.1.0`; the `v0.4.0`–`v0.8.4`
tags are release markers, so nothing has been published to crates.io.

| Capability | State |
|-----------|-------|
| URL, IP, path & header validation | ✅ implemented |
| Builder and request handling | ✅ implemented |
| Response caching (TTL, ETag, Cache-Control) | ✅ implemented |
| Retry with exponential backoff | ✅ implemented, by error class and by status |
| Streaming, progress tracking, rate limiting | ✅ implemented |
| WebSocket, middleware chain | ✅ implemented (feature-gated) |
| DNS pinning + SSRF checks on every send path | ✅ implemented |
| Certificate pinning | ✅ implemented, needs the `rustls-tls` feature |
| Proxy support | ⬜ not implemented |
| Benchmarks, licence audit, JS/TS bridge | ⬜ not started |

---

## Documentation

The API is documented with rustdoc, and the crate root is the place to start:

```bash
cargo doc --open
```

What's covered:

- **Crate overview** — the security model stated plainly: private networks are
  blocked with no loopback exception, only `http`/`https` are accepted, URLs
  with embedded credentials are refused, reqwest never follows redirects on its
  own, and redaction is destructive.
- **Every public item** — the builder methods, the `HttpRequest` pipeline, the
  `BeanStreamError` variants (including which failures are retryable and which
  are permanent), `RedirectPolicy`, `ScopeValidator`, `RetryConfig`, the cache,
  the rate limiter, `CertPinConfig`, and the feature-gated `CookieJar` and
  WebSocket support.
- **The `send()` pipeline order** — why interceptors run before validation, and
  why redaction is applied twice.

`#![warn(missing_docs)]` is enabled, so a new public item without documentation
is a warning rather than an oversight, and `cargo doc` runs in CI with
`RUSTDOCFLAGS=-D warnings`.

There are also 15 doctests, run on default, `--all-features` and
`--no-default-features`, so the examples in the docs are executed rather than
merely written.

---

## Contributing

Want to help brew something great? Contributions are welcome and appreciated.

1. Fork it
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes
4. Push & open a Pull Request

Keep the code clean: `cargo fmt`, `cargo clippy --all-targets`, and `cargo test --all-features`.

---

## Continuous Integration

Every push and pull request runs `.github/workflows/ci.yml` on GitHub Actions:

| Job | What it covers |
|-----|----------------|
| `lint` | `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`, on default, all and no-default features |
| `test` | `build` / `test` / `build --release` across 7 entries: default, `--no-default-features`, `--all-features`, `--features cookies,http2,rustls-tls`, `--features websocket`, Windows, macOS |
| `coverage` | `cargo llvm-cov --all-features`, failing the build under **80%** lines |
| `docs` | `cargo doc` with `RUSTDOCFLAGS=-D warnings`, plus doc tests |

The suite is deliberately **network-free**: DNS cases use the hosts file or the
reserved `.invalid` TLD, and nothing connects to a socket. CI is therefore
deterministic and works offline.

Current coverage is **85.3% of lines** (`cargo llvm-cov --all-features
--workspace --summary-only`). The per-module table, including which modules are
below the floor and why, is in `architecture.md`.

`tests/documented_api_paths.rs` imports the crate exactly the way this README
does, so if an example here stops compiling, CI fails rather than the reader
finding out.

---

## License

BeanStream is licensed under the **MIT** or **Apache-2.0** licenses, at your option. Fully open source, community-driven, forever free. ☕

---

**Project Name:** BeanStream  
**Tagline:** *"From bean to bit — pure delivery"*  
**Version:** 0.1.0  
**License:** MIT/Apache-2.0

*Like the perfect cup of coffee, BeanStream is crafted with care, attention to detail, and respect for every user who interacts with it — pure excellence, every time.* ☕✨