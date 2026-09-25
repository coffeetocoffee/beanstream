# BeanStream ☕

> **From bean to bit — pure delivery**  
> *Where security brews perfectly, every single request*

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
use beanstream::url_validation::{validate_url, is_private_or_loopback};

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
use beanstream::header_validation::sanitize_header;

let (name, value) = sanitize_header(" X-Custom-Header ", " value ")?;
assert_eq!(name, "x-custom-header"); // normalized
assert_eq!(value, "value");          // trimmed

assert!(sanitize_header("x-test", "value\r\ninjected").is_err()); // injection blocked
```

### 3. Sensitive Data Protection

Sensitive headers (`authorization`, `set-cookie`, `x-api-key`, …) are automatically detected and kept out of logs and responses.

```rust
use beanstream::header_validation::is_sensitive_header;

assert!(is_sensitive_header("Authorization"));
assert!(is_sensitive_header("SET-COOKIE"));
assert!(!is_sensitive_header("content-type"));
```

### 4. Intelligent Redirect Handling

Redirects are tracked and validated against scope policies — stop open-redirect attacks while letting legitimate chains through.

```rust
use beanstream::redirect_policy::RedirectPolicy;
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
use beanstream::redirect_policy::RedirectPolicy;
use beanstream::request_handler::HttpRequest;

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
use beanstream::request_handler::HttpRequest;

fn main() -> Result<()> {
    let request = HttpRequest::get("https://api.example.com/users")?
        .add_header("X-Test", "value")?
        .body("{}")
        .timeout(Duration::from_secs(15));

    request.validate()?;
    let built = request.build_request()?;
    // send with any reqwest client
    Ok(())
}
```

### Configure a shared client

```rust
use beanstream::builder::HttpClientBuilder;
use std::time::Duration;

let client = HttpClientBuilder::default()
    .with_base_url("https://api.example.com/api/")
    .with_timeout(Duration::from_secs(30))
    .with_max_redirects(5)
    .with_follow_redirects(true)
    .add_default_header("X-App", "beanstream")?
    .build()?;
```

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

### Creating requests

`HttpRequest` offers ergonomic helpers for common verbs:

```rust
HttpRequest::get(url)?;
HttpRequest::post(url)?;
HttpRequest::put(url)?;
HttpRequest::delete(url)?;
HttpRequest::patch(url)?;
```

Fluent methods chain cleanly:

```rust
let req = HttpRequest::post("https://api.example.com/items")?
    .body(r#"{"name":"espresso"}"#)
    .timeout(Duration::from_secs(10))
    .add_headers([("X-Env", "prod"), ("Accept", "application/json")])?;
```

---

## Clear Error Messages

Errors speak human. No more cryptic stack dives.

```rust
use beanstream::error_handling_impl::BeanStreamError;

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

## Roadmap

| Version | Focus |
|---------|-------|
| v0.1.x | Core validation, builder, request handling *(current)* |
| v1.0.x | Response caching, retry w/ backoff |
| v1.1.x | Streaming, progress tracking, rate limiting |
| v1.2.x | WebSocket support, middleware chain |

---

## Contributing

Want to help brew something great? Contributions are welcome and appreciated.

1. Fork it
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes
4. Push & open a Pull Request

Keep the code clean: `cargo fmt`, `cargo clippy --all-targets`, and `cargo test --all-features`.

---

## License

BeanStream is licensed under the **MIT** or **Apache-2.0** licenses, at your option. Fully open source, community-driven, forever free. ☕

---

**Project Name:** BeanStream  
**Tagline:** *"From bean to bit — pure delivery"*  
**Version:** 0.1.0  
**License:** MIT/Apache-2.0

*Like the perfect cup of coffee, BeanStream is crafted with care, attention to detail, and respect for every user who interacts with it — pure excellence, every time.* ☕✨