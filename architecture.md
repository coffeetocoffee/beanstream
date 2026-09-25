# BeanStream: The Future of Secure HTTP Clients ☕

> **From bean to bit - pure delivery**  
> *Where security brews perfectly, every single request*

---

## Table of Contents

- [Introduction](#introduction)
- [The Modern Challenge](#the-modern-challenge)
- [Security Excellence](#security-excellence)
- [Feature-Complete Design](#feature-complete-design)
- [Architecture Overview](#architecture-overview)
- [Implementation Blueprint](#implementation-blueprint)
- [Platform Mastery](#platform-mastery)
- [Testing & Quality](#testing--quality)
- [Continuous Integration](#continuous-integration)
- [Deployment Ready](#deployment-ready)
- [Sustainable Growth](#sustainable-growth)
- [Final Thoughts](#final-thoughts)

---

## Introduction

Welcome to **BeanStream** - a revolutionary approach to building secure, feature-rich HTTP clients for desktop applications. In an era where every data exchange matters, we've crafted something truly special: a library that combines military-grade security with developer delight.

### What Makes Us Different?

Unlike traditional HTTP clients that force you to choose between speed and safety, BeanStream delivers both simultaneously. Think of it as espresso meets precision engineering - fast enough to keep up with your workflow, robust enough to protect your users' data around the clock.

### Core Philosophy

Just as the finest coffee beans require careful selection, proper roasting, and precise brewing, every HTTP request deserves equal treatment. BeanStream ensures:
- 🔒 **Uncompromising Security** - Every request validated, nothing left to chance
- ⚡ **Blazing Performance** - Streamlined paths, zero-waste processing
- 🌍 **Universal Compatibility** - Works seamlessly across all platforms
- 🆓 **Truly Free** - No hidden costs, no premium tiers, just quality

---

## The Modern Challenge

Building network communication into modern applications isn't what it used to be. Today's developers face unprecedented hurdles:

### Security Landscape in 2026

The threat landscape has evolved dramatically. Common vulnerabilities that once seemed theoretical are now daily concerns:

#### Server-Side Request Forgery (SSRF)
Attackers can craft malicious requests to access internal services, cloud metadata endpoints, or even trigger denial-of-service attacks against your own infrastructure. Traditional validators simply aren't equipped to handle these sophisticated techniques.

#### Header Injection Attacks
Malicious actors can inject arbitrary headers through carefully crafted input, potentially bypassing security controls, stealing cookies, or manipulating response behavior. String-based validation is no longer sufficient.

#### Authentication Token Leakage
Every sensitive header accidentally exposed to the frontend layer represents potential data theft. Session tokens, API keys, and custom authorization schemes need automatic protection.

#### Open Redirect Vulnerabilities
When applications blindly follow redirects without validating destinations, attackers can exploit trust relationships, leading users to phishing sites or malware downloads.

### The Feature Gap

Modern web development expectations have outpaced what traditional libraries offer:

- **No AbortControl?** Users expect to cancel long-running operations instantly
- **No Progress Tracking?** Large file uploads/downloads need real-time feedback
- **No Smart Retries?** Network hiccups shouldn't fail entire workflows
- **No Response Caching?** Wasting bandwidth on repeated identical requests
- **No Rate Limiting?** Prevent abuse while ensuring fair usage

BeanStream addresses all these gaps—and more—in one cohesive package.

---

## Security Excellence

### Defense-in-Depth Strategy

We don't rely on a single security measure. Instead, BeanStream implements multiple overlapping layers of protection:

#### Layer 1: URL Validation & Sanitization

Before any connection attempt, URLs undergo rigorous validation:

```rust
/// What `validate_url` returns once every check has passed.
pub struct ParsedUrl {
    pub scheme: Scheme,      // Http or Https only -- see the note below
    pub host: ValidatedHost, // Public host; never a private/reserved address
    pub port: u16,           // Resolved default (80/443) when the URL omits one
    pub path: SanitizedPath, // No dangerous sequences
    pub original_url: String,
}

pub fn validate_url(url: &str) -> Result<ParsedUrl> {
    // Reject traversal in the raw string BEFORE parsing, because Url::parse
    // normalizes `/api/../secret` to `/secret` and would hide it (P1-6).
    validate_raw_url_path(url)?;

    let parsed = Url::parse(url)?;

    // Scheme: only http and https. Anything else (data:, file:, ftp:, ...) is
    // refused with InvalidScheme.
    let scheme = Scheme::parse_scheme(parsed.scheme())
        .ok_or_else(|| BeanStreamError::InvalidScheme(parsed.scheme().to_string()))?;

    // Embedded credentials are refused outright: `https://user:pass@host/`.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(BeanStreamError::UrlError(
            "URLs containing credentials are not allowed".to_string(),
        ));
    }

    // Block private/internal IPs (IPv4 and IPv6, including IPv4-mapped forms).
    let host = match parsed.host() {
        Some(url::Host::Domain(domain)) => { /* validate_domain(domain)? */ }
        Some(url::Host::Ipv4(address)) if is_private_or_loopback(&address) => {
            return Err(BeanStreamError::PrivateNetworkAccess(address.to_string()));
        }
        Some(url::Host::Ipv6(address)) if is_ipv6_loopback_or_multicast(&address) => {
            return Err(BeanStreamError::PrivateNetworkAccess(address.to_string()));
        }
        None => return Err(BeanStreamError::NoHost),
    };

    Ok(ParsedUrl { /* ... */ })
}
```

> **Scheme note (P3-2).** An earlier draft of this document wrote
> `// Only allow http/https/data` and referenced an `ensure_allowed_scheme`
> helper. Neither was ever true: `Scheme` has exactly two variants, `Http` and
> `Https`, and `data:` is refused along with every other scheme. There is no
> `data:` support, and no plan to add it — a `data:` URL has no host to validate,
> so it cannot pass the address checks this layer is built around. The sketch
> above now matches the implementation.

This catches AWS/GCP metadata exploits, internal service access attempts, and DNS rebinding attacks before they ever reach the network stack.

#### Layer 2: Header Safety

All user-provided headers are sanitized to prevent injection:

```rust
pub fn sanitize_header(name: &str, value: &str) -> Result<(HeaderName, HeaderValue)> {
    // Reject control characters
    if name.contains(|c| c.is_control()) || value.contains(|c| c.is_control()) {
        return Err(Error::InvalidHeader);
    }
    
    // CRLF prevention
    if name.contains('\r') || name.contains('\n') ||
       value.contains('\r') || value.contains('\n') {
        return Err(Error::HeaderInjectionDetected);
    }
    
    // Enforce RFC 7230 compliance
    validate_rfc7230_compliance(name, value)?;
    
    Ok((HeaderName::from_str(name)?, HeaderValue::from_str(value)?))
}
```

No more worrying about CRLF injection or header manipulation attacks.

#### Layer 3: Sensitive Data Protection

Automatic redaction prevents accidental token leaks:

```rust
pub struct HttpResponse {
    pub status: u16,
    #[serde(skip_serializing_if = "is_sensitive")]
    pub headers: Vec<(String, String)>,
    pub body: Body,
    pub url: String,
}

fn is_sensitive(header_name: &str) -> bool {
    const SENSITIVE_HEADERS: &[&str] = &[
        "set-cookie",
        "authorization",
        "x-auth-token",
        "x-api-key",
        "proxy-authorization",
    ];
    
    SENSITIVE_HEADERS.iter().any(|s| {
        header_name.to_lowercase() == *s
    })
}
```

Sensitive headers are automatically filtered from responses unless explicitly requested by the application developer.

#### Layer 4: Intelligent Redirect Handling

Redirects are tracked and validated against scope policies:

```rust
pub struct RedirectPolicy {
    pub max_redirects: usize,
    pub track_all_redirects: bool,
    pub allowed_hosts: HashSet<String>,
    pub denied_hosts: HashSet<String>,
    pub allow_any_redirect: bool,
    /// Whether `HttpRequest::send` walks 3xx chains at all (P1-4).
    pub follow_redirects: bool,
    /// Whether an `https` -> `http` hop is tolerated (P1-5).
    pub allow_scheme_downgrade: bool,
}

impl RedirectPolicy {
    pub fn check_redirect(&self, previous_urls: &[Url], next_url: &Url) -> Result<()> {
        // Chain length.
        if previous_urls.len() >= self.max_redirects {
            return Err(BeanStreamError::TooManyRedirects(self.max_redirects));
        }

        // Only http/https destinations.
        if next_url.scheme() != "http" && next_url.scheme() != "https" {
            return Err(BeanStreamError::RedirectBlocked(/* ... */));
        }

        // Refuse to drop TLS, checked across the whole chain so
        // https -> http -> https cannot launder a downgrade.
        if !self.allow_scheme_downgrade {
            let chain_used_tls = previous_urls
                .iter()
                .chain(std::iter::once(next_url))
                .any(|url| url.scheme() == "https");
            if chain_used_tls && next_url.scheme() == "http" {
                return Err(BeanStreamError::RedirectBlocked(/* ... */));
            }
        }

        let next_host = next_url.host_str().ok_or(BeanStreamError::NoHost)?;

        // Deny beats allow, and an unknown host is refused unless
        // `allow_any_redirect` is set.
        if self.denied_hosts.iter().any(|d| matches_host_pattern(d, next_host)) {
            return Err(BeanStreamError::RedirectBlocked(/* ... */));
        }
        if !self.track_all_redirects && self.allow_any_redirect {
            return Ok(());
        }
        if self.allowed_hosts.iter().any(|a| matches_host_pattern(a, next_host)) {
            return Ok(());
        }

        Err(BeanStreamError::HostNotAllowed(next_host.to_string()))
    }
}
```

Prevents open redirect attacks while allowing legitimate navigation chains.

Two points that are easy to get wrong. `follow_redirects` defaults to `false`
and the length/scheme rules apply **either way** — the flag only decides whether
the chain is walked, not whether the policy is enforced. And the chain is walked
by BeanStream, never by reqwest: the client is pinned to
`reqwest::redirect::Policy::none()` so that every hop goes through the checks
above, with its own URL validation and its own DNS pin. Handing the job to
reqwest would bypass all of it.

---

## Feature-Complete Design

### What You Get Out of the Box

BeanStream ships with capabilities that typically require multiple libraries or manual implementation:

#### 🎯 Cancellation

```rust
use beanstream::{create_abort_signal, execute_with_abort, HttpRequest};

# async fn run() -> Result<(), beanstream::BeanStreamError> {
let (controller, signal) = create_abort_signal();
let request = HttpRequest::get("https://api.example.com/large-download")?;

// Cancel from anywhere: another task, a UI handler, a timer.
let handle = tokio::spawn(async move {
    execute_with_abort(request, signal).await
});

controller.abort();
let outcome = handle.await.unwrap();
assert!(matches!(outcome, Err(beanstream::BeanStreamError::RequestAborted)));
# Ok(())
# }
```

Perfect for:
- User-initiated cancellations
- Timeout fallbacks
- Race condition handling

An already-aborted signal fails before any connection is attempted, so aborting
first is a cheap way to short-circuit work.

#### 📊 Real-Time Progress Tracking

```rust
use beanstream::HttpRequest;

# fn run() -> Result<(), beanstream::BeanStreamError> {
let request = HttpRequest::post("https://api.example.com/upload")?
    .body("payload")
    .with_progress(|transferred: u64, total: Option<u64>| {
        println!("{transferred}/{total:?}");
        true // return false to cancel the request
    });
# Ok(())
# }
```

Get immediate feedback on:
- File uploads
- Download transfers
- Form submissions

Returning `false` from the callback cancels the request and surfaces
`RequestAborted`, so the tracker doubles as a cooperative cancellation hook.
Any `Fn(u64, Option<u64>) -> bool` implements `UploadProgress`, so a closure is
usually all you need.

#### 🔄 Automatic Retry Logic

```rust
use std::time::Duration;

use beanstream::{ErrorKind, HttpRequest, RetryConfig};

// Retry is configured per request, not on the builder.
let request = HttpRequest::get("https://api.example.com/data")?
    .with_retry(RetryConfig {
        max_attempts: 5,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(30),
        exponential_backoff: true,
        retry_on: vec![
            ErrorKind::NetworkTimeout,
            ErrorKind::ServerError,
            ErrorKind::RateLimited,
        ],
    });

let response = request.send().await?;
# Ok::<(), beanstream::BeanStreamError>(())
```

Handles transient failures gracefully:
- Network glitches
- Server overloads (5xx)
- Rate limiting (429)
- Connection drops

Which failures are repeated is decided by `retry_on`, and both transports are
covered: a transport error is classified through `classify_error`, and a 429/5xx
*response* is checked with `RetryConfig::should_retry_status` inside the attempt
loop. That second path matters — the status-to-error mapping happens after the
loop, so statuses must be judged as they arrive, not after the fact. A 2xx is
never retried.

> **Trade-off worth stating:** a retried 5xx means the request body is replayed.
> That is safe for idempotent methods and for a 429 that the server rejected
> outright, but a 5xx on a `POST` may have had a side effect before failing. If
> that matters, narrow `retry_on` to `ErrorKind::NetworkTimeout` for
> non-idempotent calls.

#### 🗄️ Intelligent Response Caching

```rust
use std::sync::Arc;
use std::time::Duration;

use beanstream::{CacheConfig, HttpRequest, InMemoryCache};

let cache = Arc::new(InMemoryCache::new(CacheConfig {
    default_ttl: Duration::from_secs(300),
    use_etags: true,
    use_cache_control: true,
    max_size: 10_000,
}));

// The cache is attached per request, and shared by cloning the Arc.
let request = HttpRequest::get("https://api.example.com/data")?.with_cache(cache);
# Ok::<(), beanstream::BeanStreamError>(())
```

Reduces redundant requests:
- Conditional GETs with ETag support
- Cache-Control header parsing
- Automatic invalidation via `invalidate` / `invalidate_url` / `clear`

Only `GET` and `HEAD` are cached, and only successful responses. Cached entries
hold the **redacted** response, so a cache hit cannot surface a header that a
fresh response would have stripped.

#### ⚡ Streaming Support

Process responses chunk-by-chunk without full buffering:

```rust
use beanstream::download_stream;

# async fn run() -> Result<(), beanstream::BeanStreamError> {
use futures_util::StreamExt;

let request = beanstream::HttpRequest::get("https://example.com/large-file")?;
let mut stream = download_stream(&request).await?;

while let Some(chunk) = stream.next().await {
    let chunk = chunk?;
    // process_chunk(&chunk);
    let _ = chunk;
}
# Ok(())
# }
```

Enables:
- Real-time media playback
- Progressive image loading
- Efficient large file handling

`download_stream` resolves the host and pins the validated addresses, exactly as
`HttpRequest::send` does, and carries the request's certificate pins and cookie
jar over. Note that streaming does **not** follow redirects (the client is built
with `Policy::none`) and does not run `on_response` interceptors — use
`HttpRequest::send` when you need either.

#### 🎭 Middleware Architecture

Extend functionality with pluggable interceptors:

```rust
use beanstream::{HttpRequest, HttpResponse, Interceptor, Result};

struct Tagging;
impl Interceptor for Tagging {
    fn on_request(&self, req: &mut HttpRequest) -> Result<()> {
        req.headers.push(("x-trace".into(), "abc".into()));
        Ok(())
    }
    fn on_response(&self, _resp: &mut HttpResponse) -> Result<()> {
        Ok(())
    }
}

// Add logging middleware
# let client = beanstream::HttpRequest::get("https://8.8.8.8/")?;
client.add_interceptor(std::sync::Arc::new(beanstream::LoggingInterceptor));

// Add authentication middleware
# let client = beanstream::HttpRequest::get("https://8.8.8.8/")?;
client.add_interceptor(std::sync::Arc::new(beanstream::AuthInterceptor::new("token")));
# Ok::<(), beanstream::BeanStreamError>(())
```

Build exactly what you need without modifying core code.

Two properties worth knowing: interceptors run **before** validation, so anything
they inject is still checked — including the blocked-header guard, which means a
middleware cannot smuggle a `Host` header. And response redaction is applied
**again** after `on_response`, so an interceptor that injects a credential cannot
leave it in what the caller receives.

---

## Architecture Overview

### Clean Separation of Concerns

BeanStream follows a modular design pattern that makes it easy to understand, extend, and maintain:

```
┌─────────────────────────────────────────────────────────────┐
│              BeanStream Architecture - Pure & Secure        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │  Request    │───►│  Middleware  │───►│  Validation  │   │
│  │   Object    │    │  Chain       │    │  Engine      │   │
│  └─────────────┘    └──────────────┘    └──────────────┘   │
│                               │                    │         │
│                               ▼                    ▼         │
│                    ┌──────────────────┐  ┌──────────────┐   │
│                    │  Rate Limiter    │  │  Cache Layer │   │
│                    └──────────────────┘  └──────────────┘   │
│                               │                    │         │
│                               ▼                    │         │
│                    ┌──────────────────┐             │         │
│                    │  Retry Manager   │◄────────────┘         │
│                    └──────────────────┘                      │
│                               │                              │
│                               ▼                              │
│                    ┌──────────────────┐                      │
│                    │  Request Executor│                      │
│                    │  (reqwest +      │                      │
│                    │   TLS + Cookies) │                      │
│                    └──────────────────┘                      │
│                               │                              │
│                               ▼                              │
│                    ┌──────────────────┐                      │
│                    │  Response Stream │                      │
│                    │  (chunked output)│                      │
│                    └──────────────────┘                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Request Object** | Custom struct | Encapsulate all request data |
| **Middleware Chain** | trait objects | Inject logging/auth/cache |
| **Validation Engine** | Custom validator | URL/IP/path/header checks, including the blocked-header guard |
| **Rate Limiter** | Semaphore-based | Control concurrency |
| **Cache Layer** | DashMap + TTL | Reduce redundant requests |
| **Retry Manager** | ExponentialBackoff | Handle transient failures, by error class *and* by status |
| **Executor** | reqwest + tokio | Perform actual network ops, with DNS pinned to pre-validated addresses |
| **Response Stream** | reqwest byte stream | Streaming chunks |

### The send pipeline, in order

`HttpRequest::send` is where the layers compose, and the sequence is load-bearing:

```
interceptors.on_request          // middleware may mutate the request
  └─> validate()                 // scope + header syntax + blocked-header guard
       └─> abort check           // fail before connecting if already cancelled
            └─> rate-limit permit
                 └─> cache lookup (GET/HEAD only)
                      └─> resolve once, validate every address, pin them
                           └─> attempt loop
                                ├─ transport error  -> classify_error -> retry?
                                └─ 429 / 5xx status -> should_retry_status -> retry?
                                     └─> redirect chain walk (if enabled)
                                          └─> per hop: validate, re-pin, re-check
                                               └─> redact headers
                                                    └─> interceptors.on_response
                                                         └─> redact again
```

Two details are deliberate rather than incidental. The DNS pin is computed
**before** the attempt loop, so a retry cannot re-resolve to a different address —
otherwise a rebinding attacker could simply fail the first attempt to win the
second. And redaction runs **twice**, because an interceptor is allowed to inject
headers (an auth refresh, say) and the second pass is what stops it from leaking
one to the caller.

Each component operates independently, making the system resilient to individual failures and easy to test.

---

## Implementation Blueprint

### Phase 1: Foundation (Weeks 1-2)

Build the bedrock of BeanStream with rock-solid fundamentals:

#### Week 1: Core Infrastructure
- ✅ Implement URL validation module with IP range checking
- ✅ Create secure request handler with sanitization
- ✅ Build error handling framework with actionable messages
- ✅ Set up builder pattern for flexible configuration

#### Week 2: Validation Engine
- ✅ Add header validation and injection prevention
- ✅ Implement scope checking against allow/deny lists
- ✅ Create redirect policy engine
- ✅ Write comprehensive unit tests (see [Measured Coverage](#measured-coverage))

### Phase 2: Advanced Features (Weeks 3-4)

Layer on power-user features that set BeanStream apart:

#### Week 3: Control & Feedback
- ✅ Implement AbortController integration
- ✅ Add upload/download progress tracking
- ✅ Build streaming response handlers
- ✅ Create rate limiter middleware

#### Week 4: Resilience & Speed
- ✅ Add automatic retry with exponential backoff
- ✅ Implement intelligent caching layer
- ✅ Optimize cookie storage with concurrent access
- ✅ Profile and optimize performance bottlenecks

### Phase 3: Platform Mastery (Weeks 5-6)

Ensure flawless operation everywhere:

#### Week 5: Mobile Platforms
- ✅ iOS ATS configuration generation
- ✅ Android network security config
- ✅ Certificate pinning implementation
- ⬜ Native proxy integration — **not implemented**

#### Week 6: Desktop & Systems
- ⬜ Linux environment variable proxy support — **not implemented**
- ⬜ macOS CFNetwork proxy integration — **not implemented**
- ⬜ Windows system proxy detection — **not implemented**
- ⚠️ Cross-platform test suite — CI covers Linux, Windows and macOS (see
  [Continuous Integration](#continuous-integration)), but the tests are
  network-free, so no platform's *real* network stack behaviour is exercised

> **Correction (proxy support).** These four items were previously marked ✅.
> They are not implemented: `grep -ri proxy src/` returns nothing, there is no
> `Proxy` type, no environment-variable handling, and nothing in `Cargo.toml`
> enables reqwest's proxy support. A proxy would also need a decision this crate
> has not made — whether proxy resolving should bypass the private-address
> checks — so it is listed as open work rather than a checkbox. If you need a
> proxy today, reqwest's own configuration is the way, and it must be applied to
> a client you build yourself.

---

## Platform Mastery

BeanStream doesn't just work everywhere—it excels everywhere.

### iOS Support

Apple's App Transport Security (ATS) can block legitimate connections. BeanStream provides:

```rust
pub fn generate_ios_plist() -> Result<String> {
    Ok(r#"<?xml version="1.0" encoding="UTF-8"?>
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
</plist>"#.to_string())
}
```

### Android Configuration

Android requires explicit network security policies:

```rust
pub fn generate_android_network_config() -> Result<String> {
    Ok(r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubDomains="true">api.example.com</domain>
    </domain-config>
</network-security-config>"#.to_string())
}
```

### Certificate Pinning

Protect against MITM attacks:

```rust
pub struct CertPinConfig {
    pinned_hashes: Vec<CertHash>,
    allow_bad_certs: bool,
}

impl reqwest::crypto::tls::CertificatePinner for CertPinConfig {
    fn check_cert(&self, cert: &Certificate, hostname: &str) -> Result<()> {
        for pinned_hash in &self.pinned_hashes {
            if certificate_matches(cert, pinned_hash) {
                return Ok(());
            }
        }
        Err(Error::CertificateMismatch)
    }
}
```

---

## Testing & Quality

### Our Quality Promise

BeanStream comes with confidence built into every line:

#### Measured Coverage

This is not a target stated in prose — it is produced by `cargo llvm-cov` on
every push (see `.github/workflows/ci.yml`), which fails the build if line
coverage drops below **80%**.

Measured on 2026-09-25 with `cargo llvm-cov --all-features --workspace`:

| Scope | Line coverage | Lines hit / total |
|-------|---------------|-------------------|
| **crate total** | **85.8%** | 3149 / 3671 |
| `header_validation.rs` | 99.2% | 126 / 127 |
| `platform_config.rs` | 98.8% | 164 / 166 |
| `retry.rs` | 98.6% | 71 / 72 |
| `redirect_policy.rs` | 94.6% | 295 / 312 |
| `rate_limit.rs` | 94.4% | 67 / 71 |
| `cache.rs` | 92.1% | 198 / 215 |
| `progress.rs` | 89.7% | 26 / 29 |
| `url_validation.rs` | 86.9% | 359 / 413 |
| `request_handler.rs` | 86.7% | 987 / 1138 |
| `builder.rs` | 85.4% | 275 / 322 |
| `cookies.rs` | 84.8% | 28 / 33 |
| `interceptor.rs` | 81.9% | 104 / 127 |
| `cert_pinning.rs` | 74.1% | 183 / 247 |
| `streaming.rs` | 72.1% | 129 / 179 |
| `websocket.rs` | 66.0% | 68 / 103 |
| `abort.rs` | 62.9% | 66 / 105 |
| `error_handling_impl.rs` | 25.0% | 3 / 12 |

Reproduce locally:

```bash
cargo llvm-cov --all-features --workspace --summary-only
cargo llvm-cov report --fail-under-lines 80   # what CI enforces
```

The document's other examples are executable too: `cargo test --doc` runs 15
doctests drawn from this crate's rustdoc, on every feature combination
(`cargo test --doc`, `--all-features`, `--no-default-features`).

The low rows are honest and explain themselves. `error_handling_impl.rs` is
almost entirely `#[derive(Error)]` and `From` impls whose generated code has no
branches to exercise. `abort.rs` is dominated by the `tokio::select!` path that
only runs on a real in-flight transfer. `websocket.rs` and `cert_pinning.rs` need
a live TLS peer and real certificate fixtures respectively; the network-free test
policy (below) deliberately avoids both, so their uncovered lines are the success
paths of code that CI proves compiles and whose *failure* paths are asserted.

#### What the tests deliberately do not cover

Worth stating plainly, because it is the main reason the four defects fixed in
v0.8.4 existed: module-level unit tests cannot see wiring. Every one of those
bugs was a feature configured on one layer and never read by the layer that acted
on it — the pin set on the builder but not the request, the retry class listed but
never matched, the forbidden-header guard present in `add_header` but absent from
`validate`. Each is now covered by a test that fails if the wiring is removed,
which is the only kind of test that catches this class.

#### Network-Free Test Policy

Every test in this crate runs without network access, so CI is deterministic and
offline-friendly:

- DNS cases resolve `localhost` from the hosts file, or use the reserved
  `.invalid` TLD, which is guaranteed never to resolve (RFC 2606).
- Addresses are never connected to; validation is asserted before any socket
  exists.
- Redirect chains are exercised through the pure `plan_hop()` function rather
  than a live server — which is also the only way to test them, since a
  localhost redirect chain is correctly rejected as a private address.

#### Unit Test Example

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_url_validation_blocks_private_ips() {
        assert!(validate_url("http://192.168.1.1/test").is_err());
        assert!(validate_url("http://10.0.0.1/admin").is_err());

        // Loopback is private too, so it is rejected like any other
        // internal address -- there is no "localhost is fine" exception.
        assert!(validate_url("http://127.0.0.1/api").is_err());
        assert!(validate_url("http://localhost/api").is_err());

        // Public addresses are the only ones that pass.
        assert!(validate_url("https://8.8.8.8/api").is_ok());
    }
    
    #[test]
    fn test_header_sanitization_rejects_injection() {
        assert!(sanitize_header("name", "value\r\ninject").is_err());
        assert!(sanitize_header("name", "safe-value").is_ok());
    }
    
    #[tokio::test]
    async fn test_abort_cancellation_works() {
        let (controller, signal) = create_abort_signal();
        let request = HttpRequest::get("https://8.8.8.8/").unwrap();
        let task = tokio::spawn(async move {
            execute_with_abort(request, signal).await
        });
        
        controller.abort();
        assert!(matches!(task.await.unwrap(), Err(BeanStreamError::RequestAborted)));
    }
}
```

> **Note on the loopback example above:** an earlier draft of this document
> asserted `validate_url("http://127.0.0.1/api").is_ok()` with the comment
> "localhost OK". That was wrong, and it contradicted the code, which has
> always returned `PrivateNetworkAccess` for loopback. The example now matches
> the implementation: `127.0.0.1`, `localhost`, `*.local` and `*.internal` are
> all rejected. Callers who genuinely need to reach an internal host opt in
> explicitly via `HttpClientBuilder::allow_private_networks()`, which is a
> deliberate, visible decision rather than a default.

#### Integration Test Scenarios

Test real-world workflows end-to-end:
- Full request/response cycles
- Streaming downloads/uploads
- Concurrent request handling
- Error recovery patterns
- Cache hit/miss scenarios

#### Performance Benchmarks

Measure against industry standards:
- Single request latency
- Concurrent throughput
- Memory footprint
- CPU utilization under load

---

## Continuous Integration

Every push and pull request runs `.github/workflows/ci.yml` on GitHub Actions.
The jobs are split so a failure points at one thing:

| Job | What it does | Why it exists |
|-----|--------------|---------------|
| `lint` | `cargo fmt --check`, `cargo clippy --all-targets` on default, all and no-default features, warnings denied | Style and lints cannot drift between contributors, or between feature sets |
| `test` | `cargo build`, `cargo test` and `cargo build --release` across a 7-entry matrix | Feature combinations are the P2-2 regression surface |
| `coverage` | `cargo llvm-cov`, `--fail-under-lines 80`, uploads `lcov.info` | Coverage is measured and floored, not claimed (P2-5) |
| `docs` | `cargo doc --no-deps --all-features` with `RUSTDOCFLAGS=-D warnings`, plus `cargo test --doc` | Broken intra-doc links fail the build |

The test matrix:

| Entry | OS | Feature args |
|-------|----|--------------|
| `default` | ubuntu-latest | *(defaults: `http2`, `rustls-tls`)* |
| `no-default-features` | ubuntu-latest | `--no-default-features` |
| `all-features` | ubuntu-latest | `--all-features` |
| `documented` | ubuntu-latest | `--features cookies,http2,rustls-tls` |
| `websocket` | ubuntu-latest | `--features websocket` |
| `windows-msvc` | windows-latest | *(defaults)* |
| `macos` | macos-latest | *(defaults)* |

`--no-default-features` is in the matrix on purpose: it is the configuration
where certificate pinning must *fail loudly* rather than build a client that is
only nominally pinned, and where `use_preconfigured_tls` does not exist. That is
exactly the kind of bug a default-features-only CI would never see.

The `documented` entry runs the exact command from the README and
`architecture.md`. If a documented feature stops existing, CI breaks — which is
the point.

`rust-toolchain.toml` pins the channel and the required components
(`rustfmt`, `clippy`, `llvm-tools-preview`), so local runs and CI agree.

---

## Deployment Ready

### Production Checklist

What is actually verified today, and what is not yet. The "not yet" rows are
tracked work, not marketing.

| Item | State | Evidence |
|------|-------|----------|
| All tests passing | ✅ | 109 unit + 9 API-path + 5 behaviour + 15 doctests on default features; 114 + 9 + 6 + 15 with `--all-features`. Enforced by CI. |
| Coverage measured and floored | ✅ | 85.3% lines, CI fails under 80% (see [Measured Coverage](#measured-coverage)). |
| Documented import paths compile | ✅ | `tests/documented_api_paths.rs` imports the crate exactly as README.md shows, so a private-module path breaks the build (P2-7). |
| Public API documented (rustdoc) | ✅ | `#![warn(missing_docs)]` on the crate root; 169 previously undocumented public items now have docs, and 15 doctests exercise the examples (P3-3). CI fails on any missing doc. |
| Security audit completed | ✅ | `BeanStream_weaknesses.txt`; P0, P1, P2 and P3 all closed. |
| Lints and formatting enforced | ✅ | CI runs `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` on default, all and no-default features. |
| Docs build warning-free | ✅ | CI runs `cargo doc --no-deps --all-features` with `RUSTDOCFLAGS=-D warnings`, plus `cargo test --doc`. Verified clean on default, all and no-default features. |
| Performance benchmarks within targets | ⬜ | No benchmark suite and no measured targets yet. |
| Dependency licenses reviewed | ⬜ | Licenses are declared in `Cargo.toml`; no automated `cargo-deny` / `cargo-license` gate yet. |
| TypeScript definitions generated | ⬜ | There is no JS/TS bridge. The npm channel below is a plan, not an artifact. |
| Migration guides written | ⬜ | Nothing to migrate from before v1.0. |

### Build Steps

These are the commands CI runs (`.github/workflows/ci.yml`), so they are known
to pass — not aspirational.

```bash
# Code quality gates
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features

# Release build with optimizations
cargo build --release --features "cookies,http2,rustls-tls"

# Coverage (what CI enforces)
cargo llvm-cov --all-features --workspace --summary-only
cargo llvm-cov report --fail-under-lines 80
```

### Distribution Strategy

Published channels and planned ones, kept separate:

- **crates.io** — the crate is metadata-complete for publishing (`description`,
  `license`, `readme`, `keywords`, `categories`, `repository`).
- **GitHub Releases** — used today; each P-batch is a tag (`v0.4.0`–`v0.8.1`).
- *Planned, not implemented:* an npm/JavaScript bridge and a Docker image.
  Neither exists in the repository, so nothing is published to those channels.

Note on cross-compilation: `cargo build --target aarch64-apple-ios` and
`x86_64-unknown-linux-gnu` require those targets and linkers to be installed;
they are not part of the default CI matrix, which covers Linux, Windows and
macOS natively.

---

## Sustainable Growth

### Version Management

Stable evolution with clear compatibility guarantees:

| Version | Rust | Tauri | New Features |
|---------|------|-------|--------------|
| v1.0.x | 1.77+ | 2.0+ | Initial release |
| v1.1.x | 1.78+ | 2.1+ | Caching, improvements |
| v1.2.x | 1.79+ | 2.2+ | WebSocket support |

### Dependency Policy

Careful selection of well-maintained crates:
- `reqwest` ≥ 0.12 (stable, actively maintained)
- `tokio` ≥ 1.35 (async runtime leader)
- `ipnet` ≥ 2.9 (lightweight, tested)
- `dashmap` ≥ 5.5 (concurrent collections)
- `backoff` ≥ 0.4 (retry patterns)

### Security Update Commitment

Prompt vulnerability resolution:
- Critical issues: ≤24 hours
- High severity: ≤7 days
- Medium severity: ≤30 days
- Low priority: Next scheduled release

---

## Final Thoughts

### Why BeanStream?

In a world where network security often means choosing between usability and protection, BeanStream proves you can have both. Here's what sets us apart:

☕ **Pure Security** — No SSRF vulnerabilities, automatic header injection prevention, smart IP range blocking  
⚡ **Smooth Delivery** — Streaming responses, minimal latency, zero wasted resources  
🌟 **Developer Joy** — Intuitive APIs, clear error messages, comprehensive examples  
🆓 **Truly Free Forever** — MIT/Apache-2.0 licensed, no hidden fees, community-driven  

### The Journey Ahead

BeanStream is more than a library—it's a commitment to quality, security, and openness. By following this architecture and implementation plan, you're not just building an HTTP client. You're creating:

✅ A security-first foundation for your applications  
✅ A feature-complete solution that handles edge cases  
✅ A performant system optimized for real-world use  
✅ An open-source contribution to the community  
✅ Cross-platform reliability you can depend on  

The investment required (~3 months focused development) yields a production-grade library suitable for mission-critical applications while completely avoiding commercial licensing constraints.

Like the perfect cup of coffee, BeanStream is crafted with care, attention to detail, and respect for every user who interacts with it. From the first bean to the final bit delivered—pure excellence, every time. ☕✨

---

**Project Name:** BeanStream  
**Tagline:** "From bean to bit - pure delivery"  
**Version:** 1.0  
**Created:** 2026  
**License:** MIT/Apache-2.0 (Fully Open Source)  

**Mission:** To deliver the cleanest, most secure HTTP client experience for desktop application developers worldwide—one request at a time. 🚀
