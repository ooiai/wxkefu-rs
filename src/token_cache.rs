#![allow(dead_code)]
//! Redis-backed access_token manager with refresh-ahead and distributed lock.
//!
//! Goals:
//! - Cache `access_token` in Redis with proper TTL to avoid rate limits.
//! - Refresh-ahead to minimize chances of using an about-to-expire token.
//! - Distributed lock to prevent thundering herd across multiple instances.
//! - Safe logging (no secrets); concurrency-aware behavior.
//!
//! Design notes:
//! - The manager is instantiated per credential (`Auth`) identity.
//! - Tokens are stored as JSON with an `expires_at` epoch timestamp and Redis TTL.
//! - Refresh-ahead triggers a background refresh when the token is close to expiry.
//! - When the token is missing/expired, one instance acquires a lock and refreshes;
//!   others will wait briefly and re-check the cache to avoid calling upstream too frequently.
//!
//! Example usage (WeCom/Kf):
//! ```ignore
//! use wxkefu_rs::{Auth, KfClient};
//! use wxkefu_rs::token_cache::TokenManager;
//! use redis::aio::ConnectionManager;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Prepare Redis connection manager
//!     let client = redis::Client::open("redis://127.0.0.1/")?;
//!     let mut redis = ConnectionManager::new(client).await?;
//!
//!     // Prepare KfClient & Auth
//!     let kf_client = KfClient::default();
//!     let auth = Auth::WeCom {
//!         corp_id: std::env::var("WXKF_CORP_ID")?,
//!         corp_secret: std::env::var("WXKF_APP_SECRET")?,
//!     };
//!
//!     // Create the TokenManager
//!     let mut tm = TokenManager::new(redis, kf_client, auth).with_namespace("wxkefu:token");
//!
//!     // Obtain a token (cached or freshly fetched)
//!     let token = tm.get_access_token().await?;
//!     println!("wecom access_token (redacted len): {}", token.len());
//!
//!     Ok(())
//! }
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redis::{AsyncCommands, RedisResult, aio::ConnectionManager};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::time::sleep;
use tracing::{debug, instrument, warn};

use crate::token::{AccessToken, Auth, Error as TokenError, KfClient};

/// JSON payload stored in Redis for a cached token
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedToken {
    access_token: String,
    /// Epoch seconds when the token should be considered expired locally
    expires_at: i64,
}

/// Unified error for token caching/refreshing
#[derive(Debug, Error)]
pub enum TokenCacheError {
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("token fetch error: {0}")]
    Fetch(#[from] TokenError),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("time error")]
    Time,
}

/// Manages access_token caching in Redis with refresh-ahead and distributed lock
#[derive(Clone)]
pub struct TokenManager {
    /// Redis connection manager (async)
    redis: ConnectionManager,
    /// Namespacing for keys, e.g. "wxkefu:token"
    namespace: String,
    /// HTTP client for WeChat Kf APIs
    client: KfClient,
    /// Identity (WeCom or OA/MP). This determines the cache key and which endpoint to call.
    auth: Auth,
    /// Refresh-ahead threshold in seconds (default: 300s)
    refresh_ahead_secs: u32,
    /// Safety margin subtracted from upstream `expires_in` (default: 120s)
    safety_margin_secs: u32,
    /// Distributed lock TTL in seconds (default: 30s)
    lock_ttl_secs: u32,
    /// Maximum total wait when another worker holds the lock (default: 5s)
    max_wait_secs: u32,
}

impl TokenManager {
    /// Create a new `TokenManager` with sensible defaults
    pub fn new(redis: ConnectionManager, client: KfClient, auth: Auth) -> Self {
        Self {
            redis,
            namespace: "wxkefu:token".to_string(),
            client,
            auth,
            refresh_ahead_secs: 300, // 5 minutes
            safety_margin_secs: 120, // 2 minutes
            lock_ttl_secs: 30,       // 30 seconds
            max_wait_secs: 5,        // 5 seconds
        }
    }

    /// Override the Redis key namespace
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Override refresh-ahead threshold
    pub fn with_refresh_ahead(mut self, secs: u32) -> Self {
        self.refresh_ahead_secs = secs;
        self
    }

    /// Override safety margin (subtracted from `expires_in`)
    pub fn with_safety_margin(mut self, secs: u32) -> Self {
        self.safety_margin_secs = secs;
        self
    }

    /// Override lock TTL seconds
    pub fn with_lock_ttl(mut self, secs: u32) -> Self {
        self.lock_ttl_secs = secs;
        self
    }

    /// Override max wait seconds when lock is held by another worker
    pub fn with_max_wait(mut self, secs: u32) -> Self {
        self.max_wait_secs = secs;
        self
    }

    /// Get current access_token, refreshing if missing or expired.
    ///
    /// Behavior:
    /// - If a valid token exists, return it immediately.
    /// - If valid but expiring soon, attempt a background refresh (non-blocking).
    /// - If missing/expired, acquire a distributed lock and fetch; otherwise, wait briefly
    ///   for another worker to populate and then return.
    #[instrument(level = "debug", skip(self))]
    pub async fn get_access_token(&mut self) -> Result<String, TokenCacheError> {
        let key = self.token_key();
        if let Some(ct) = self.read_cached_token(&key).await? {
            let now = epoch()?;
            if ct.expires_at > now {
                // Valid token
                let remaining = ct.expires_at - now;
                debug!("token valid, remaining={}s", remaining);

                // Refresh-ahead if close to expiry (best-effort, non-blocking)
                if remaining <= self.refresh_ahead_secs as i64 {
                    debug!("token is close to expiry; attempting refresh-ahead");
                    self.try_refresh_ahead(&key).await?;
                }

                return Ok(ct.access_token);
            } else {
                debug!("token expired locally; will refresh synchronously");
            }
        } else {
            debug!("no token found in cache; will refresh synchronously");
        }

        // Missing or expired: refresh synchronously with distributed lock
        self.refresh_with_lock(&key).await
    }

    /// Force refresh now (ignoring cache content), using distributed lock
    pub async fn force_refresh(&mut self) -> Result<String, TokenCacheError> {
        let key = self.token_key();
        self.refresh_with_lock(&key).await
    }

    /// Explicitly invalidate the cache for this identity
    pub async fn invalidate(&mut self) -> Result<(), TokenCacheError> {
        let key = self.token_key();
        let _: () = self.redis.del(key).await?;
        Ok(())
    }

    /// Internal: read and decode token JSON from Redis
    async fn read_cached_token(
        &mut self,
        key: &str,
    ) -> Result<Option<CachedToken>, TokenCacheError> {
        let raw: Option<String> = self.redis.get(key).await?;
        if let Some(s) = raw {
            let ct: CachedToken = serde_json::from_str(&s)?;
            Ok(Some(ct))
        } else {
            Ok(None)
        }
    }

    /// Internal: compute the token cache key for the given identity
    fn token_key(&self) -> String {
        let ident = match &self.auth {
            Auth::OfficialAccount { appid, .. } => format!("oa:{}", appid),
            Auth::WeCom { corp_id, .. } => format!("wecom:{}", corp_id),
        };
        format!("{}:{}", self.namespace, ident)
    }

    /// Internal: compute the lock key for the given identity
    fn lock_key(&self) -> String {
        format!("{}:lock", self.token_key())
    }

    /// Internal: refresh token with distributed lock.
    ///
    /// - Try to acquire the lock via SET NX EX.
    /// - If acquired, fetch upstream token and populate Redis.
    /// - If not acquired, wait with jitter and re-check the cache for a limited time.
    async fn refresh_with_lock(&mut self, key: &str) -> Result<String, TokenCacheError> {
        let lock_key = self.lock_key();

        if self.try_acquire_lock(&lock_key).await? {
            debug!("lock acquired; fetching upstream token");
            match self.fetch_and_store(key).await {
                Ok(ct) => Ok(ct.access_token),
                Err(e) => {
                    warn!("fetch_and_store failed: {e}");
                    // Let the lock expire; others may retry after lock TTL.
                    Err(e)
                }
            }
        } else {
            debug!("lock held by another worker; waiting and re-checking cache");
            let start = epoch()?;
            let max_wait = self.max_wait_secs as i64;
            let mut attempt = 0;

            loop {
                if let Some(ct) = self.read_cached_token(key).await? {
                    let now = epoch()?;
                    if ct.expires_at > now {
                        debug!("another worker populated token; returning cached value");
                        return Ok(ct.access_token);
                    }
                }

                let now = epoch()?;
                if now - start >= max_wait {
                    warn!(
                        "waited {}s for token, still unavailable; attempting to acquire lock again",
                        max_wait
                    );
                    // As a last attempt, try to acquire the lock again
                    if self.try_acquire_lock(&lock_key).await? {
                        debug!("lock acquired on second attempt; fetching upstream token");
                        let ct = self.fetch_and_store(key).await?;
                        return Ok(ct.access_token);
                    } else {
                        return Err(TokenCacheError::Fetch(TokenError::Wx {
                            code: 40001,
                            message:
                                "timeout waiting for token; lock held by another worker; try again"
                                    .to_string(),
                        }));
                    }
                }

                attempt += 1;
                let sleep_ms = 100 + ((attempt * 37) % 200); // lightweight jitter without extra deps
                sleep(Duration::from_millis(sleep_ms as u64)).await;
            }
        }
    }

    /// Internal: best-effort, non-blocking refresh-ahead.
    ///
    /// - Attempt to acquire the lock (SET NX EX).
    /// - If acquired, spawn a background task to refresh and store.
    /// - If not acquired, do nothing (another worker is likely refreshing).
    async fn try_refresh_ahead(&mut self, key: &str) -> Result<(), TokenCacheError> {
        let lock_key = self.lock_key();
        if self.try_acquire_lock(&lock_key).await? {
            let redis = self.redis.clone();
            let client = self.client.clone();
            let auth = self.auth.clone();
            let key = key.to_string();
            let safety_margin = self.safety_margin_secs;

            tokio::spawn(async move {
                if let Err(e) = refresh_task(redis, client, auth, &key, safety_margin).await {
                    warn!("refresh-ahead task failed: {e}");
                } else {
                    debug!("refresh-ahead task completed");
                }
                // lock expires automatically (EX)
            });
        } else {
            debug!("refresh-ahead skipped; lock is held by another worker");
        }
        Ok(())
    }

    /// Internal: try to acquire a distributed lock with TTL.
    ///
    /// Uses `SET key value NX EX ttl`. We do not implement ownership-based release here;
    /// the lock expires automatically.
    async fn try_acquire_lock(&mut self, lock_key: &str) -> Result<bool, TokenCacheError> {
        let ttl = self.lock_ttl_secs;
        let val = lock_value();

        // Equivalent Redis command: SET lock_key val NX EX ttl
        let acquired: RedisResult<Option<String>> = redis::cmd("SET")
            .arg(lock_key)
            .arg(val)
            .arg("NX")
            .arg("EX")
            .arg(ttl)
            .query_async(&mut self.redis)
            .await;

        match acquired {
            Ok(Some(_)) => Ok(true),
            Ok(None) => Ok(false), // Not set → lock exists
            Err(e) => Err(TokenCacheError::Redis(e)),
        }
    }

    /// Internal: fetch upstream token and store to Redis with safety margin and TTL
    async fn fetch_and_store(&mut self, key: &str) -> Result<CachedToken, TokenCacheError> {
        // Call upstream
        let resp: AccessToken = self.client.get_access_token(&self.auth).await?;
        // Compute TTL with safety margin, minimum clamp
        let ttl = compute_ttl(resp.expires_in, self.safety_margin_secs);
        let now = epoch()?;
        let ct = CachedToken {
            access_token: resp.access_token,
            expires_at: now + ttl as i64,
        };

        // Store JSON with EX TTL
        let json = serde_json::to_string(&ct)?;
        let _: () = redis::pipe()
            .cmd("SET")
            .arg(key)
            .arg(&json)
            .arg("EX")
            .arg(ttl)
            .ignore()
            .query_async(&mut self.redis)
            .await?;

        Ok(ct)
    }
}

/// Background refresh task for refresh-ahead
#[instrument(level = "debug", skip(redis, client, auth))]
async fn refresh_task(
    mut redis: ConnectionManager,
    client: KfClient,
    auth: Auth,
    key: &str,
    safety_margin_secs: u32,
) -> Result<(), TokenCacheError> {
    let resp: AccessToken = client.get_access_token(&auth).await?;
    let ttl = compute_ttl(resp.expires_in, safety_margin_secs);
    let now = epoch()?;
    let ct = CachedToken {
        access_token: resp.access_token,
        expires_at: now + ttl as i64,
    };
    let json = serde_json::to_string(&ct)?;

    let _: () = redis::pipe()
        .cmd("SET")
        .arg(key)
        .arg(&json)
        .arg("EX")
        .arg(ttl)
        .ignore()
        .query_async(&mut redis)
        .await?;

    Ok(())
}

/// Compute TTL with a safety margin and minimum clamp
fn compute_ttl(expires_in: u32, safety_margin: u32) -> u32 {
    let min_ttl = 60; // never store very short TTL
    let ttl = expires_in.saturating_sub(safety_margin);
    ttl.max(min_ttl)
}

/// Get current epoch seconds
fn epoch() -> Result<i64, TokenCacheError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TokenCacheError::Time)?;
    Ok(now.as_secs() as i64)
}

/// Redact an ID for keys/logs: keep first 2 and last 2 chars where possible
fn redact_id(id: &str) -> String {
    if id.len() <= 4 {
        format!("{}***", id)
    } else {
        format!("{}***{}", &id[..2], &id[id.len().saturating_sub(2)..])
    }
}

/// Generate a simple lock value string (timestamp-based)
fn lock_value() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("ts-{}", now)
}

// Re-export for users
pub use TokenCacheError as Error;
pub use TokenManager as RedisTokenManager;
