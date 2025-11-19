#![allow(dead_code)]
//! Redis-backed concurrent kf/sync_msg tool.
//!
//! This module provides a simple, production-friendly orchestration around
//! the WeCom Kf `sync_msg` API to handle concurrent callbacks for the same
//! `open_kfid` across multiple service instances.
//!
//! Features
//! - Per-`open_kfid` Redis queue: `LPUSH` tokens from callback (short-lived `<Token>`).
//! - Per-`open_kfid` cursor storage: persist `next_cursor` for incremental pulling.
//! - Per-`open_kfid` worker lock: distributed lock with `SET NX EX` to serialize pulling.
//! - Access token retrieval via `token_tool::get_token_with(...)` (L1+L2 caching).
//! - Pluggable message handler (trait) to process pulled messages.
//!
//! Keys (prefix defaults to `wxkf`):
//! - Queue: `{prefix}:queue:{open_kfid}`
//! - Cursor: `{prefix}:cursor:{open_kfid}`
//! - Lock: `{prefix}:lock:{open_kfid}`
//!
//! Typical flow
//! 1) Your callback decrypts XML and extracts `<OpenKfId>` + `<Token>`
//! 2) Call `enqueue_and_start(open_kfid, token, handler)`
//!    - Enqueue token into Redis list
//!    - Try to acquire distributed lock
//!    - If acquired, spawn a worker loop to pop tokens and call `sync_msg` until:
//!      queue empty and `has_more == 0`
//!
//! Usage (example)
//! ```ignore
//! use std::sync::Arc;
//! use wxkefu_rs::kf_sync_tool::{KfSyncTool, SyncOptions, MsgHandler};
//! use wxkefu_rs::sync_msg::SyncMsgItem;
//!
//! struct Printer;
//! #[async_trait::async_trait]
//! impl MsgHandler for Printer {
//!     async fn handle(&self, item: &SyncMsgItem) {
//!         println!("msgid={}, open_kfid={}", item.common.msgid, item.common.open_kfid);
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Env:
//!     //   REDIS_URL (optional, default: redis://127.0.0.1/)
//!     //   REDIS_PREFIX (optional, default: wxkf)
//!     //   WXKF_CORP_ID
//!     //   WXKF_APP_SECRET
//!
//!     let tool = KfSyncTool::from_env(None).await?;
//!     let handler = Arc::new(Printer);
//!
//!     // From callback: open_kfid + token
//!     tool.enqueue_and_start("wk_xxx", "event_token_xyz", handler.clone()).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! Notes
//! - `<Token>` must be used within ~10 minutes; enqueue quickly.
//! - `sync_msg` has strong rate limits when not using `<Token>`; always pass the token when available.
//! - For high throughput, you can run multiple service instances; the distributed lock ensures only one worker per `open_kfid` runs at a time.

use anyhow::{Context, Result};
use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::KfClient;
use crate::sync_msg::{SyncMsgItem, SyncMsgRequest};
use crate::token_tool::get_token_with;

/// Handler trait to process each `SyncMsgItem` pulled by `sync_msg`.
#[async_trait::async_trait]
pub trait MsgHandler: Send + Sync + 'static {
    async fn handle(&self, item: &SyncMsgItem);
}

/// Options to tune sync behavior.
#[derive(Clone, Debug)]
pub struct SyncOptions {
    /// Desired batch size; max 1000 per API doc
    pub limit: u32,
    /// Voice format: 0-Amr, 1-Silk (default None = server default)
    pub voice_format: Option<u32>,
    /// Queue TTL (seconds) to keep tokens available; default 600 (10 minutes)
    pub queue_ttl_secs: u32,
    /// Worker lock TTL (seconds); default 60
    pub lock_ttl_secs: u32,
    /// Cursor TTL (seconds) to retain incremental state; default 7 days
    pub cursor_ttl_secs: u32,
    /// Sleep between `has_more == 1` rounds to be polite; default 50ms
    pub has_more_sleep_ms: u64,
    /// Backoff sleep on error; default 200ms
    pub error_backoff_ms: u64,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            limit: 1000,
            voice_format: None,
            queue_ttl_secs: 10 * 60,
            lock_ttl_secs: 60,
            cursor_ttl_secs: 7 * 24 * 3600,
            has_more_sleep_ms: 50,
            error_backoff_ms: 200,
        }
    }
}

/// Main tool orchestrator: manages Redis queue/cursor/lock and calls `sync_msg`.
#[derive(Clone)]
pub struct KfSyncTool {
    redis_url: String,
    redis_prefix: String,
    corp_id: String,
    corp_secret: String,
    redis: ConnectionManager,
    http: KfClient,
    opts: SyncOptions,
}

impl KfSyncTool {
    /// Build a tool from environment variables.
    ///
    /// Env:
    /// - REDIS_URL: default "redis://127.0.0.1/"
    /// - REDIS_PREFIX: default "wxkf"
    /// - WXKF_CORP_ID
    /// - WXKF_APP_SECRET
    pub async fn from_env(opts: Option<SyncOptions>) -> Result<Self> {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
        let redis_prefix = std::env::var("REDIS_PREFIX").unwrap_or_else(|_| "wxkf".to_string());
        let corp_id = std::env::var("WXKF_CORP_ID")
            .context("missing WXKF_CORP_ID (WeCom corpid starting with 'ww')")?;
        let corp_secret = std::env::var("WXKF_APP_SECRET")
            .context("missing WXKF_APP_SECRET (WeChat Customer Service Secret)")?;

        Self::new(
            &redis_url,
            &redis_prefix,
            &corp_id,
            &corp_secret,
            opts.unwrap_or_default(),
        )
        .await
    }

    /// Build a tool from explicit parameters.
    pub async fn new(
        redis_url: &str,
        redis_prefix: &str,
        corp_id: &str,
        corp_secret: &str,
        opts: SyncOptions,
    ) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .with_context(|| format!("Redis open error: {}", redis_url))?;
        let cm = client
            .get_connection_manager()
            .await
            .context("Redis connection manager error")?;
        Ok(Self {
            redis_url: redis_url.to_string(),
            redis_prefix: redis_prefix.to_string(),
            corp_id: corp_id.to_string(),
            corp_secret: corp_secret.to_string(),
            redis: cm,
            http: KfClient::default(),
            opts,
        })
    }

    /// Enqueue an event `<Token>` for the given `open_kfid`, set TTL, and try to start a worker.
    ///
    /// This is the most convenient entry in your callback handler.
    pub async fn enqueue_and_start(
        &self,
        open_kfid: &str,
        token: &str,
        handler: Arc<dyn MsgHandler>,
    ) -> Result<()> {
        self.enqueue_token(open_kfid, token).await?;
        let _ = self.try_start_worker(open_kfid, handler).await?;
        Ok(())
    }

    /// Enqueue the short-lived event token into the per-`open_kfid` queue.
    pub async fn enqueue_token(&self, open_kfid: &str, token: &str) -> Result<()> {
        let queue_key = self.key_queue(open_kfid);
        let mut r = self.redis.clone();

        let _: () = r
            .lpush::<_, _, ()>(&queue_key, token)
            .await
            .context("Redis LPUSH failed")?;
        let _: () = r
            .expire(&queue_key, self.opts.queue_ttl_secs as i64)
            .await
            .context("Redis EXPIRE failed")?;
        debug!("Token enqueued for open_kfid={}", open_kfid);
        Ok(())
    }

    /// Try to acquire the worker lock for `open_kfid` and spawn a background worker if successful.
    /// Returns `true` when a worker was started, `false` if a worker is already running.
    pub async fn try_start_worker(
        &self,
        open_kfid: &str,
        handler: Arc<dyn MsgHandler>,
    ) -> Result<bool> {
        let lock_key = self.key_lock(open_kfid);
        let mut r = self.redis.clone();

        // SET NX
        let acquired: bool = r
            .set_nx(&lock_key, "1")
            .await
            .context("Redis SET NX failed")?;
        if acquired {
            // Attach TTL
            let _: () = r
                .expire(&lock_key, self.opts.lock_ttl_secs as i64)
                .await
                .context("Redis EXPIRE lock failed")?;
            info!("Worker lock acquired for {}", open_kfid);

            // Spawn worker
            let tool = self.clone();
            let open_kfid = open_kfid.to_string();
            tokio::spawn(async move {
                if let Err(e) = tool.worker_loop(open_kfid.clone(), handler.clone()).await {
                    warn!("worker_loop error for {}: {}", open_kfid, e);
                } else {
                    info!("worker_loop finished for {}", open_kfid);
                }
            });

            Ok(true)
        } else {
            debug!("Worker already running for {}", open_kfid);
            Ok(false)
        }
    }

    /// The worker loop: pop tokens, call `sync_msg`, persist cursor, refresh lock TTL, and continue until done.
    pub async fn worker_loop(&self, open_kfid: String, handler: Arc<dyn MsgHandler>) -> Result<()> {
        let queue_key = self.key_queue(&open_kfid);
        let cursor_key = self.key_cursor(&open_kfid);
        let lock_key = self.key_lock(&open_kfid);

        let mut redis = self.redis.clone();

        // If we already have a cursor, allow the loop to start even when no token is present.
        let initial_cursor_present = redis
            .get::<_, Option<String>>(&cursor_key)
            .await
            .unwrap_or(None)
            .is_some();
        let mut has_more = initial_cursor_present;
        let mut round = 0u32;

        loop {
            round += 1;

            // Refresh lock TTL to keep ownership while working
            let _: () = redis
                .expire(&lock_key, self.opts.lock_ttl_secs as i64)
                .await
                .unwrap_or_default();

            // Pop one token (FIFO when using LPUSH + RPOP)
            let token_opt: Option<String> = redis.rpop(&queue_key, None).await.unwrap_or(None);
            // Read last cursor
            let cursor_opt: Option<String> = redis
                .get::<_, Option<String>>(&cursor_key)
                .await
                .unwrap_or(None);

            // If no token and not has_more, we are done
            if token_opt.is_none() && !has_more {
                break;
            }

            // Acquire access_token via token_tool (L1+L2 caching)
            let access_token =
                get_token_with(&self.redis_url, &self.corp_id, &self.corp_secret).await?;

            let mut req = SyncMsgRequest {
                cursor: cursor_opt.clone(),
                token: token_opt.clone(),
                limit: Some(self.opts.limit.min(1000)),
                voice_format: self.opts.voice_format,
                open_kfid: Some(open_kfid.clone()),
            };

            debug!(
                "sync_msg round={}, open_kfid={}, cursor={:?}, token_present={}",
                round,
                open_kfid,
                req.cursor,
                req.token.is_some()
            );

            match self.http.sync_msg(&access_token, &req).await {
                Ok(resp) => {
                    debug!(
                        "sync_msg ok: has_more={}, next_cursor={:?}, msg_count={}",
                        resp.has_more,
                        resp.next_cursor,
                        resp.msg_list.len()
                    );

                    // Process messages
                    for item in resp.msg_list.iter() {
                        handler.handle(item).await;
                    }

                    // Persist next_cursor
                    if let Some(next) = resp.next_cursor {
                        let _: () = redis
                            .set(&cursor_key, &next)
                            .await
                            .context("Redis SET cursor failed")?;
                        let _: () = redis
                            .expire(&cursor_key, self.opts.cursor_ttl_secs as i64)
                            .await
                            .context("Redis EXPIRE cursor failed")?;
                        req.cursor = Some(next);
                    } else {
                        req.cursor = None;
                    }

                    has_more = resp.has_more == 1;
                    if has_more {
                        sleep(Duration::from_millis(self.opts.has_more_sleep_ms)).await;
                        continue;
                    }
                }
                Err(e) => {
                    warn!("sync_msg error: {}", e);
                    sleep(Duration::from_millis(self.opts.error_backoff_ms)).await;
                }
            }

            // If queue empty and not has_more, exit
            let qlen: i64 = redis.llen(&queue_key).await.unwrap_or(0);
            if qlen == 0 && !has_more {
                break;
            }
        }

        // Release lock (best-effort)
        let _: () = redis.del(&lock_key).await.unwrap_or_default();
        Ok(())
    }

    #[inline]
    fn key_queue(&self, open_kfid: &str) -> String {
        format!("{}:queue:{}", self.redis_prefix, open_kfid)
    }
    #[inline]
    fn key_cursor(&self, open_kfid: &str) -> String {
        format!("{}:cursor:{}", self.redis_prefix, open_kfid)
    }
    #[inline]
    fn key_lock(&self, open_kfid: &str) -> String {
        format!("{}:lock:{}", self.redis_prefix, open_kfid)
    }

    /// Override options after construction.
    pub fn with_options(mut self, opts: SyncOptions) -> Self {
        self.opts = opts;
        self
    }
}
