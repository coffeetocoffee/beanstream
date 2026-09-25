use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::request_handler::HttpResponse;

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub default_ttl: Duration,
    pub use_etags: bool,
    pub use_cache_control: bool,
    pub max_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            default_ttl: Duration::from_secs(300),
            use_etags: true,
            use_cache_control: true,
            max_size: 10_000,
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    response: HttpResponse,
    stored_at: Instant,
    ttl: Duration,
    etag: Option<String>,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.stored_at.elapsed() >= self.ttl
    }
}

#[derive(Debug)]
pub struct InMemoryCache {
    config: CacheConfig,
    entries: DashMap<String, CacheEntry>,
}

impl InMemoryCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: DashMap::new(),
        }
    }

    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    pub fn cache_key(method: &str, url: &str) -> String {
        format!("{} {}", method.to_ascii_uppercase(), url)
    }

    pub fn get(&self, method: &str, url: &str) -> Option<HttpResponse> {
        let key = Self::cache_key(method, url);
        if let Some(entry) = self.entries.get(&key) {
            if entry.is_expired() {
                drop(entry);
                self.entries.remove(&key);
                return None;
            }
            return Some(entry.response.clone());
        }
        None
    }

    /// Returns the stored ETag for conditional GETs, if enabled.
    pub fn get_etag(&self, method: &str, url: &str) -> Option<String> {
        if !self.config.use_etags {
            return None;
        }
        let key = Self::cache_key(method, url);
        self.entries.get(&key).and_then(|e| e.etag.clone())
    }

    pub fn insert(&self, method: &str, response: HttpResponse) {
        let ttl = self.resolve_ttl(&response);
        if ttl.is_zero() {
            return;
        }
        let etag = if self.config.use_etags {
            response
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("etag"))
                .map(|(_, v)| v.clone())
        } else {
            None
        };

        // Simple size cap: evict an arbitrary expired entry, then enforce max_size.
        if self.entries.len() >= self.config.max_size {
            self.evict_one();
        }

        let key = Self::cache_key(method, &response.url);
        self.entries.insert(
            key,
            CacheEntry {
                response,
                stored_at: Instant::now(),
                ttl,
                etag,
            },
        );
    }

    fn resolve_ttl(&self, response: &HttpResponse) -> Duration {
        if self.config.use_cache_control {
            if let Some((_, value)) = response
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
            {
                let lower = value.to_ascii_lowercase();
                if lower.contains("no-store") || lower.contains("no-cache") {
                    return Duration::ZERO;
                }
                if let Some(seconds) = parse_max_age(&lower) {
                    return Duration::from_secs(seconds);
                }
            }
        }
        self.config.default_ttl
    }

    fn evict_one(&self) {
        // NOTE: iterator temporaries in an `if let` scrutinee live through the
        // whole `if` body, keeping the shard read-guard held while `remove()`
        // needs the write lock. Bind keys in separate statements so every
        // iterator is dropped before any mutation.
        let expired: Option<String> = self
            .entries
            .iter()
            .find(|e| e.value().is_expired())
            .map(|e| e.key().clone());
        if let Some(key) = expired {
            self.entries.remove(&key);
            return;
        }
        let oldest: Option<String> = self.entries.iter().next().map(|e| e.key().clone());
        if let Some(key) = oldest {
            self.entries.remove(&key);
        }
    }

    pub fn invalidate(&self, method: &str, url: &str) {
        self.entries.remove(&Self::cache_key(method, url));
    }

    pub fn invalidate_url(&self, url: &str) {
        let suffix = format!(" {url}");
        let keys: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.key().ends_with(&suffix))
            .map(|e| e.key().clone())
            .collect();
        for key in keys {
            self.entries.remove(&key);
        }
    }

    pub fn clear(&self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new(CacheConfig::default())
    }
}

fn parse_max_age(cache_control: &str) -> Option<u64> {
    for directive in cache_control.split(',') {
        let directive = directive.trim();
        if let Some(value) = directive.strip_prefix("max-age=") {
            if let Ok(seconds) = value.trim().parse::<u64>() {
                return Some(seconds);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(url: &str, headers: Vec<(&str, &str)>) -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: b"hello".to_vec(),
            url: url.to_string(),
        }
    }

    #[test]
    fn stores_and_retrieves_by_method_and_url() {
        let cache = InMemoryCache::default();
        cache.insert("GET", response("https://example.com/a", vec![]));
        assert!(cache.get("GET", "https://example.com/a").is_some());
        assert!(cache.get("POST", "https://example.com/a").is_none());
    }

    #[test]
    fn honors_cache_control_max_age() {
        let cache = InMemoryCache::default();
        cache.insert(
            "GET",
            response(
                "https://example.com/a",
                vec![("cache-control", "max-age=0")],
            ),
        );
        assert!(cache.get("GET", "https://example.com/a").is_none());
    }

    #[test]
    fn no_store_is_not_cached() {
        let cache = InMemoryCache::default();
        cache.insert(
            "GET",
            response("https://example.com/a", vec![("cache-control", "no-store")]),
        );
        assert!(cache.get("GET", "https://example.com/a").is_none());
    }

    #[test]
    fn captures_etag_when_enabled() {
        let cache = InMemoryCache::default();
        cache.insert(
            "GET",
            response("https://example.com/a", vec![("etag", "\"abc\"")]),
        );
        assert_eq!(
            cache.get_etag("GET", "https://example.com/a"),
            Some("\"abc\"".to_string())
        );
    }

    #[test]
    fn invalidates_specific_and_url() {
        let cache = InMemoryCache::default();
        cache.insert("GET", response("https://example.com/a", vec![]));
        cache.insert("POST", response("https://example.com/a", vec![]));
        cache.invalidate_url("https://example.com/a");
        assert!(cache.is_empty());
    }

    #[test]
    fn expired_entries_are_evicted_on_read() {
        let cache = InMemoryCache::new(CacheConfig {
            default_ttl: Duration::from_millis(1),
            use_etags: true,
            use_cache_control: false,
            max_size: 10,
        });
        cache.insert("GET", response("https://example.com/a", vec![]));
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.get("GET", "https://example.com/a").is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn respects_max_size() {
        let cache = InMemoryCache::new(CacheConfig {
            max_size: 2,
            use_cache_control: false,
            ..CacheConfig::default()
        });
        for i in 0..5 {
            cache.insert("GET", response(&format!("https://example.com/{i}"), vec![]));
        }
        assert!(cache.len() <= 2);
    }
}
