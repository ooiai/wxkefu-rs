use dotenvy::dotenv;
use redis::aio::ConnectionManager;
use std::env;
use tokio::task::JoinHandle;
use wxkefu_rs::{Auth, KfClient, RedisTokenManager};

/// Example: Redis-based access_token caching with concurrency-safe refresh
///
/// What this example demonstrates
/// - Cache access_token in Redis with TTL and safety margin
/// - Refresh-ahead behavior to proactively renew tokens
/// - Distributed locking to prevent thundering herd under concurrency
///
/// Environment variables
/// - REDIS_URL: Redis connection string (default: redis://127.0.0.1/)
/// - WXKF_CORP_ID: WeCom corpid (usually starts with "ww")
/// - WXKF_APP_SECRET: WeChat Customer Service Secret (from the Kf Admin → Developer Config)
///
/// Run:
///   cargo run --example get_token_redis
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenv();

    // Read credentials
    let (corp_id, corp_secret) = match (env::var("WXKF_CORP_ID"), env::var("WXKF_APP_SECRET")) {
        (Ok(id), Ok(sec)) => (id, sec),
        _ => {
            eprintln!("Missing env WXKF_CORP_ID or WXKF_APP_SECRET.");
            eprintln!("Please set them to test WeCom (Kf) token caching with Redis.");
            return Ok(());
        }
    };

    // Redis URL (default to local)
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());

    // Prepare Redis connection manager
    let redis_client = redis::Client::open(redis_url.clone())?;
    let redis = ConnectionManager::new(redis_client).await?;

    // Prepare WeCom/Kf client & auth
    let kf_client = KfClient::default();
    let auth = Auth::WeCom {
        corp_id: corp_id.clone(),
        corp_secret: corp_secret.clone(),
    };

    // Create a Redis-backed TokenManager
    // - namespace isolates keys per application
    // - refresh ahead: attempt background renewal when remaining lifetime is low
    // - safety margin subtracts a buffer from upstream expires_in to avoid edge cases
    let mut tm = RedisTokenManager::new(redis, kf_client, auth)
        .with_namespace("wxkefu:token")
        .with_refresh_ahead(300) // refresh when <= 5 minutes remain
        .with_safety_margin(120) // subtract 2 minutes from expires_in
        .with_lock_ttl(30) // lock key TTL
        .with_max_wait(5); // max wait seconds if another worker holds the lock

    println!("Redis token cache example started.");
    println!("- Using Redis: {}", redis_url);
    println!("- Namespaced key: wxkefu:token:wecom:<redacted>");

    // 1) Single get: returns cached token or fetches & caches if missing/expired.
    println!("\n[Single] Getting access_token...");
    let token = tm.get_access_token().await?;
    println!(
        "[OK] access_token received (redacted). length={}",
        token.len()
    );

    // 2) Concurrency demo: spawn multiple tasks calling get_access_token()
    // Each task clones the manager; they coordinate via Redis lock to avoid thundering herd.
    println!("\n[Concurrency] Spawning concurrent token requests...");
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    let tasks = 8;
    for i in 0..tasks {
        let mut tm_i = tm.clone(); // derives Clone; each task has its own manager instance
        let h = tokio::spawn(async move {
            match tm_i.get_access_token().await {
                Ok(tok) => {
                    println!("[task {i}] got token len: {}", tok.len());
                }
                Err(e) => {
                    eprintln!("[task {i}] error: {e}");
                }
            }
        });
        handles.push(h);
    }
    for h in handles {
        let _ = h.await;
    }

    // 3) Force a refresh through the distributed lock (use sparingly).
    println!("\n[Force refresh] Invalidating cache and forcing refresh...");
    tm.invalidate().await?;
    let refreshed = tm.force_refresh().await?;
    println!(
        "[OK] forced refresh completed. access_token length={}",
        refreshed.len()
    );

    // 4) Normal get after refresh: should return cached token immediately.
    println!("\n[Post-refresh] Getting token from cache again...");
    let cached = tm.get_access_token().await?;
    println!("[OK] got cached token, length={}", cached.len());

    println!("\nDone. Note:");
    println!("- Avoid calling gettoken too frequently; rely on cache.");
    println!("- Handle early invalidation by catching API errors and refreshing.");
    println!("- Keep enough storage for tokens (>= 512 bytes).");

    Ok(())
}
