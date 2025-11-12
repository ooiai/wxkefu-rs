#![allow(dead_code)]
//! One-call utility to get WeCom (Kf) access_token using Redis for caching.
//!
//! This utility exposes a single async function `get_token(...)` that:
//! - Connects to Redis
//! - Uses a Redis-backed token manager to return a cached `access_token`
//! - Refreshes the token automatically when missing/expired
//! - Performs refresh-ahead via background task as the token approaches expiry
//!
//! Intended usage:
//! ```ignore
//! use wxkefu_rs::token_tool::{get_token, get_token_with};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let token = get_token().await?;
//!
//!     // Use `token` to call Kf APIs (do NOT log the raw token in production)
//!     println!("token length: {}", token.len());
//!     Ok(())
//! }
//! ```
//!
//! Notes:
//! - This is for WeCom (Enterprise WeChat) WeChat Customer Service (Kf) only.
//! - You must use `corpid` (usually starts with "ww") and the Kf Secret from the Kf Admin Portal.
//! - Do not use OA/MP appid/appsecret for Kf APIs.
//! - The manager applies sensible defaults:
//!   - Namespace: `wxkefu:token`
//!   - Refresh-ahead threshold: 300s
//!   - Safety margin from `expires_in`: 120s
//!   - Lock TTL: 30s
//!   - Max wait when another worker holds the lock: 5s
//!
//! Environment convenience:
//! - If you prefer, call `get_token()` which uses:
//!   - REDIS_URL (default: redis://127.0.0.1/)
//!   - WXKF_CORP_ID
//!   - WXKF_APP_SECRET
//!
//! Performance and alternatives:
//! - Redis-backed caching is great for multi-instance deployments where you need a single shared token across processes or languages.
//! - If Redis/network hops add too much latency for your workload, consider an in-process memory cache (e.g., Arc + DashMap + per-key async lock).
//! - Recommended usage:
//!   - Single-process or ultra-low-latency path: prefer in-process memory cache to avoid network overhead.
//!   - Multi-instance / horizontally scaled services: prefer Redis to share one token and avoid N concurrent refreshes across replicas.
//! - Pitfalls:
//!   - Memory cache is per-process. Multiple replicas will each fetch once per expiry window (WeCom typically returns the same token while valid).
//!   - Redis adds a network round-trip but prevents thundering herds across instances and centralizes invalidation.
//! - Hybrid approach:
//!   - Memory-first with a Redis second-level cache, or accept per-replica fetches with in-process cache only.
//! - The refresh policy here (refresh-ahead, safety margin, and backoff) can be reused in an Arc-based manager if you roll your own.

use anyhow::Result;
use redis::aio::ConnectionManager;

use crate::token_cache::RedisTokenManager;
use crate::{Auth, KfClient};

/// Get a WeCom (Kf) access_token using Redis-backed caching and auto-refresh.
///
/// - `redis_url`: Redis connection string (e.g., "redis://127.0.0.1/")
/// - `corp_id`: WeCom corpid (usually starts with "ww")
/// - `corp_secret`: WeChat Customer Service Secret (from Kf Admin → Developer Config)
///
/// Behavior:
/// - Returns cached token if valid
/// - If missing/expired, acquires a distributed lock and refreshes from upstream
/// - If near expiry, triggers refresh-ahead in a background task
pub async fn get_token_with(redis_url: &str, corp_id: &str, corp_secret: &str) -> Result<String> {
    // Prepare Redis connection manager
    let redis_client = redis::Client::open(redis_url)?;
    let redis = ConnectionManager::new(redis_client).await?;

    // Prepare WeCom/Kf client and auth
    let kf_client = KfClient::default();
    let auth = Auth::WeCom {
        corp_id: corp_id.to_string(),
        corp_secret: corp_secret.to_string(),
    };

    // Construct Redis-backed token manager with sensible defaults
    let mut tm = RedisTokenManager::new(redis, kf_client, auth)
        .with_namespace("wxkefu:token")
        .with_refresh_ahead(300) // 5 minutes
        .with_safety_margin(120) // subtract 2 minutes from expires_in
        .with_lock_ttl(30) // lock key TTL
        .with_max_wait(5); // max wait seconds if another worker holds the lock

    // Get a token (cached or freshly fetched)
    let token = tm.get_access_token().await?;
    Ok(token)
}

/// Convenience helper: read env vars and get token with one call.
///
/// Environment variables:
/// - REDIS_URL: Redis connection string (default: redis://127.0.0.1/)
/// - WXKF_CORP_ID: WeCom corpid (ww...)
/// - WXKF_APP_SECRET: Kf Secret from the Admin Portal
pub async fn get_token() -> Result<String> {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let corp_id = std::env::var("WXKF_CORP_ID")?;
    let corp_secret = std::env::var("WXKF_APP_SECRET")?;
    get_token_with(&redis_url, &corp_id, &corp_secret).await
}

/// Parameterized single-call: supply redis_url, corp_id, corp_secret, and an explicit redis_key to use.
pub async fn get_token_with_key(
    redis_url: &str,
    corp_id: &str,
    corp_secret: &str,
    redis_key: &str,
) -> Result<String> {
    // Prepare Redis connection manager
    let redis_client = redis::Client::open(redis_url)?;
    let redis = ConnectionManager::new(redis_client).await?;

    // Prepare WeCom/Kf client and auth
    let kf_client = KfClient::default();
    let auth = Auth::WeCom {
        corp_id: corp_id.to_string(),
        corp_secret: corp_secret.to_string(),
    };

    // Construct Redis-backed token manager with explicit key override
    let mut tm = RedisTokenManager::new(redis, kf_client, auth)
        .with_key_override(redis_key.to_string())
        .with_refresh_ahead(300) // 5 minutes
        .with_safety_margin(120) // subtract 2 minutes from expires_in
        .with_lock_ttl(30) // lock key TTL
        .with_max_wait(5); // max wait seconds if another worker holds the lock

    // Get a token (cached or freshly fetched)
    let token = tm.get_access_token().await?;
    Ok(token)
}
