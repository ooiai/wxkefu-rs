#![allow(dead_code)]
//! One-call utility to get WeCom (Kf) access_token with optimized performance.
//!
//! Design
//! - L1: In-process cache (DashMap) with per-key async locks (Tokio Mutex) for ultra-low latency.
//! - L2: Redis-backed cache via `RedisTokenManager` with distributed lock for multi-instance safety.
//! - Reusable clients: singleton `KfClient` and pooled Redis `ConnectionManager` per redis_url.
//!
//! Behavior
//! - Keep public function signatures unchanged:
//!   - `get_token()` reads env + calls `get_token_with(...)`
//!   - `get_token_with(redis_url, corp_id, corp_secret)`
//!   - `get_token_with_key(redis_url, corp_id, corp_secret, redis_key)`
//! - L1 fast path: return in-process token if valid; if near expiry, kick off background refresh.
//! - On L1 miss/expiry: try in-process per-key lock, call L2 `RedisTokenManager` to get or refresh,
//!   then update both L2 (already handled) and L1 (updated here).
//! - When L2 used, we best-effort read back the JSON payload from Redis to get accurate `expires_at`
//!   and set L1 accordingly; otherwise fallback to a short local TTL to avoid stale cache.
//!
//! Defaults
//! - Namespace: `wxkefu:token`
//! - L1 refresh-ahead threshold: 300s
//! - Safety margin from `expires_in`: 120s
//! - In-process lock wait: 5s
//! - L1 fallback TTL when unable to read Redis JSON: 180s
//! - L2 Redis lock TTL: 30s
//!
//! Notes
//! - Only for WeCom Kf. Use corp_id (starts with "ww") + Kf Secret (corpsecret).
//! - OA/MP appid/appsecret is not accepted by Kf APIs.
//! - For multi-instance deployments, L2 prevents thundering herds; L1 reduces per-process latency.

use anyhow::{Result, bail};
use dashmap::DashMap;
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use serde::Deserialize;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::time::sleep;
use tracing::{debug, instrument, warn};

use crate::token_cache::RedisTokenManager;
use crate::{Auth, KfClient};

// ===============================
// Constants and configuration
// ===============================

const DEFAULT_NAMESPACE: &str = "wxkefu:token";
const L1_REFRESH_AHEAD_SECS: u32 = 300; // 5 minutes
const SAFETY_MARGIN_SECS: u32 = 120; // subtract 2 minutes from upstream expires_in (for L1 fallback)
const L1_MAX_WAIT_SECS: u32 = 5; // in-process lock wait seconds
const L2_LOCK_TTL_SECS: u32 = 30; // Redis distributed lock TTL
const L1_FALLBACK_TTL_SECS: u32 = 180; // when we cannot read Redis JSON, use a short local TTL

// ===============================
// Global singletons
// ===============================

fn global_http() -> &'static KfClient {
    static HTTP: OnceLock<KfClient> = OnceLock::new();
    HTTP.get_or_init(|| KfClient::default())
}

fn l1_token_map() -> &'static DashMap<String, CachedToken> {
    static MAP: OnceLock<DashMap<String, CachedToken>> = OnceLock::new();
    MAP.get_or_init(DashMap::new)
}

fn l1_lock_map() -> &'static DashMap<String, Arc<Mutex<()>>> {
    static LOCKS: OnceLock<DashMap<String, Arc<Mutex<()>>>> = OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}

fn redis_cm_map() -> &'static DashMap<String, ConnectionManager> {
    static CMS: OnceLock<DashMap<String, ConnectionManager>> = OnceLock::new();
    CMS.get_or_init(DashMap::new)
}

fn redis_init_locks() -> &'static DashMap<String, Arc<Mutex<()>>> {
    static INIT_LOCKS: OnceLock<DashMap<String, Arc<Mutex<()>>>> = OnceLock::new();
    INIT_LOCKS.get_or_init(DashMap::new)
}

// ===============================
// Types
// ===============================

#[derive(Clone, Debug)]
struct CachedToken {
    access_token: String,
    expires_at: i64, // epoch seconds for local expiry
}

#[derive(Clone, Debug, Deserialize)]
struct RedisCachedToken {
    access_token: String,
    expires_at: i64,
}

// ===============================
// Public API (signatures preserved)
// ===============================

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

/// Get a WeCom (Kf) access_token using L1 in-process cache + L2 Redis cache.
pub async fn get_token_with(redis_url: &str, corp_id: &str, corp_secret: &str) -> Result<String> {
    let auth = Auth::WeCom {
        corp_id: corp_id.to_string(),
        corp_secret: corp_secret.to_string(),
    };
    let key = token_key(DEFAULT_NAMESPACE, None, &auth);
    get_token_core(redis_url, &auth, &key).await
}

/// Parameterized single-call: supply redis_url, corp_id, corp_secret, and an explicit redis_key to use.
pub async fn get_token_with_key(
    redis_url: &str,
    corp_id: &str,
    corp_secret: &str,
    redis_key: &str,
) -> Result<String> {
    let auth = Auth::WeCom {
        corp_id: corp_id.to_string(),
        corp_secret: corp_secret.to_string(),
    };
    let key = token_key(DEFAULT_NAMESPACE, Some(redis_key), &auth);
    get_token_core(redis_url, &auth, &key).await
}

// ===============================
// Core orchestration
// ===============================

#[instrument(level = "debug", skip(auth))]
async fn get_token_core(redis_url: &str, auth: &Auth, key: &str) -> Result<String> {
    // L1 fast path
    if let Some(ct) = l1_read(key) {
        let now = epoch()?;
        if ct.expires_at > now {
            let remaining = ct.expires_at - now;
            debug!("L1 hit, remaining={}s", remaining);
            if remaining <= L1_REFRESH_AHEAD_SECS as i64 {
                debug!("L1 refresh-ahead trigger");
                try_refresh_ahead(redis_url, auth.clone(), key.to_string()).await?;
            }
            return Ok(ct.access_token);
        } else {
            debug!("L1 token expired; going to refresh");
        }
    } else {
        debug!("L1 miss; going to refresh");
    }

    // L1 miss/expired: synchronize refresh with per-key in-process lock
    let lock_key = lock_key_for(key);
    if let Some(_guard) = try_acquire_l1_lock(&lock_key).await {
        debug!("L1 lock acquired; fetching via L2");
        fetch_via_l2_and_update_l1(redis_url, auth, key).await
    } else {
        debug!("L1 lock held by another task; waiting and re-checking L1");
        let start = epoch()?;
        let max_wait = L1_MAX_WAIT_SECS as i64;
        let mut attempt = 0;

        loop {
            if let Some(ct) = l1_read(key) {
                let now = epoch()?;
                if ct.expires_at > now {
                    debug!("L1 populated by another task; returning cached value");
                    return Ok(ct.access_token);
                }
            }

            let now = epoch()?;
            if now - start >= max_wait {
                warn!(
                    "waited {}s for L1, still unavailable; attempting to acquire lock again",
                    max_wait
                );
                if let Some(_guard) = try_acquire_l1_lock(&lock_key).await {
                    debug!("L1 lock acquired on second attempt; fetching via L2");
                    return fetch_via_l2_and_update_l1(redis_url, auth, key).await;
                } else {
                    bail!("timeout waiting for token; lock held by another task; try again");
                }
            }

            attempt += 1;
            let sleep_ms = 100 + ((attempt * 37) % 200); // lightweight jitter
            sleep(Duration::from_millis(sleep_ms as u64)).await;
        }
    }
}

// ===============================
// L1 helpers
// ===============================

fn token_key(namespace: &str, key_override: Option<&str>, auth: &Auth) -> String {
    if let Some(k) = key_override {
        return k.to_string();
    }
    let ident = match auth {
        Auth::OfficialAccount { appid, .. } => format!("oa:{}", appid),
        Auth::WeCom { corp_id, .. } => format!("wecom:{}", corp_id),
    };
    format!("{}:{}", namespace, ident)
}

fn lock_key_for(token_key: &str) -> String {
    format!("{}:lock", token_key)
}

fn l1_read(key: &str) -> Option<CachedToken> {
    l1_token_map().get(key).map(|v| v.clone())
}

fn l1_write_with_ttl(key: &str, token: String, ttl_secs: u32) -> Result<()> {
    let now = epoch()?;
    let ct = CachedToken {
        access_token: token,
        expires_at: now + ttl_secs as i64,
    };
    l1_token_map().insert(key.to_string(), ct);
    Ok(())
}

fn l1_write_until(key: &str, token: String, expires_at: i64) {
    l1_token_map().insert(
        key.to_string(),
        CachedToken {
            access_token: token,
            expires_at,
        },
    );
}

async fn try_acquire_l1_lock(lock_key: &str) -> Option<OwnedMutexGuard<()>> {
    let arc = l1_lock_map()
        .entry(lock_key.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();
    match arc.try_lock_owned() {
        Ok(guard) => Some(guard),
        Err(_) => None,
    }
}

#[instrument(level = "debug", skip(auth))]
async fn try_refresh_ahead(redis_url: &str, auth: Auth, key: String) -> Result<()> {
    let lock_key = lock_key_for(&key);
    if let Some(guard) = try_acquire_l1_lock(&lock_key).await {
        let key2 = key.clone();
        let auth2 = auth.clone();
        let redis_url2 = redis_url.to_string();
        tokio::spawn(async move {
            let _g = guard; // hold during refresh
            if let Err(e) = fetch_via_l2_and_update_l1(&redis_url2, &auth2, &key2).await {
                warn!("refresh-ahead failed: {e}");
            } else {
                debug!("refresh-ahead completed");
            }
        });
    } else {
        debug!("refresh-ahead skipped; L1 lock is held by another task");
    }
    Ok(())
}

// ===============================
// L2 helpers (Redis)
// ===============================

#[instrument(level = "debug", skip(auth))]
async fn fetch_via_l2_and_update_l1(redis_url: &str, auth: &Auth, key: &str) -> Result<String> {
    let client = global_http().clone();
    let mut tm =
        RedisTokenManager::new(get_or_init_redis_cm(redis_url).await?, client, auth.clone())
            .with_key_override(key.to_string())
            .with_refresh_ahead(L1_REFRESH_AHEAD_SECS)
            .with_safety_margin(SAFETY_MARGIN_SECS)
            .with_lock_ttl(L2_LOCK_TTL_SECS)
            .with_max_wait(L1_MAX_WAIT_SECS);

    // Get token via L2; this ensures distributed locking across instances.
    let token = tm.get_access_token().await?;

    // Try to read Redis JSON to set accurate L1 expiry; fallback to short TTL if not available.
    match read_redis_cached_token(redis_url, key).await {
        Ok(Some(rc)) => {
            let now = epoch()?;
            if rc.expires_at > now {
                l1_write_until(key, rc.access_token.clone(), rc.expires_at);
            } else {
                // Redis says expired (rare race). Use short TTL for L1 to avoid stale.
                let _ = l1_write_with_ttl(key, token.clone(), L1_FALLBACK_TTL_SECS);
            }
        }
        Ok(None) => {
            // No JSON found (race or non-Redis use path). Use short TTL.
            let _ = l1_write_with_ttl(key, token.clone(), L1_FALLBACK_TTL_SECS);
        }
        Err(e) => {
            warn!("failed to read Redis JSON for L1 expiry: {e}");
            let _ = l1_write_with_ttl(key, token.clone(), L1_FALLBACK_TTL_SECS);
        }
    }

    Ok(token)
}

async fn read_redis_cached_token(redis_url: &str, key: &str) -> Result<Option<RedisCachedToken>> {
    let mut cm = get_or_init_redis_cm(redis_url).await?;
    let raw: Option<String> = cm.get(key).await?;
    if let Some(s) = raw {
        let ct: RedisCachedToken = serde_json::from_str(&s)?;
        Ok(Some(ct))
    } else {
        Ok(None)
    }
}

async fn get_or_init_redis_cm(redis_url: &str) -> Result<ConnectionManager> {
    if let Some(cm) = redis_cm_map().get(redis_url) {
        return Ok(cm.clone());
    }

    // Serialize init per URL
    let lock = redis_init_locks()
        .entry(redis_url.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone();
    let _g = lock.lock().await;

    // Double-check after acquiring the init lock
    if let Some(cm) = redis_cm_map().get(redis_url) {
        return Ok(cm.clone());
    }

    let client = redis::Client::open(redis_url)?;
    let cm = ConnectionManager::new(client).await?;
    redis_cm_map().insert(redis_url.to_string(), cm.clone());
    Ok(cm)
}

// ===============================
// Utilities
// ===============================

fn epoch() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("time error"))?;
    Ok(now.as_secs() as i64)
}

#[allow(unused)]
fn compute_ttl(expires_in: u32, safety_margin: u32) -> u32 {
    let min_ttl = 60; // never store very short TTL
    let ttl = expires_in.saturating_sub(safety_margin);
    ttl.max(min_ttl)
}

#[allow(unused)]
fn redact_id(id: &str) -> String {
    if id.len() <= 4 {
        format!("{}***", id)
    } else {
        format!("{}***{}", &id[..2], &id[id.len().saturating_sub(2)..])
    }
}
