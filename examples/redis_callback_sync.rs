/*!
Example: Redis-backed concurrent WeChat Kf callback + sync_msg server

Goals:
- Verify + decrypt Kf callback (cannot modify `callback.rs`)
- Extract `<Token>` and `<OpenKfId>` from plaintext XML
- Use Redis to coordinate concurrent pulls per `open_kfid`
- Efficiently pull messages via `sync_msg` (cannot modify `sync_msg.rs`)
- Serialize work per `open_kfid` across multiple concurrent callbacks and even multiple service instances

Redis strategy (simple and production-friendly):
- Queue per Kf account: list key `wxkf:queue:{open_kfid}` holding short-lived callback tokens
- Cursor per Kf account: string key `wxkf:cursor:{open_kfid}` holding last `next_cursor`
- Worker lock per Kf account: key `wxkf:lock:{open_kfid}` acquired with SET NX EX (distributed lock)
  - Only the holder processes the queue and pulls messages until queue empty and has_more=0
  - Refresh the lock TTL while working to avoid expiry
- Access token cache: key `wxkf:access_token` with EX based on `expires_in` minus safety buffer

Environment variables:
- WXKF_TOKEN: callback token for signature verification
- WXKF_ENCODING_AES_KEY: 43-char EncodingAESKey (base64 for AES-256 key)
- WXKF_CORP_ID: WeCom corp id (starts with "ww")
- WXKF_APP_SECRET: WeChat Kf Secret from admin (used to fetch `access_token`)
- REDIS_URL: Redis connection string (default: redis://127.0.0.1/)
- REDIS_PREFIX: Optional Redis key prefix (default: "wxkf")
- BIND_ADDR: Optional bind address (default: 0.0.0.0:3000)

Run:
  WXKF_TOKEN=... \
  WXKF_ENCODING_AES_KEY=... \
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=... \
  REDIS_URL=redis://127.0.0.1/ \
  cargo run --example redis_callback_sync

Notes:
- The short-lived event `<Token>` must be used within ~10 minutes; we enqueue quickly and process promptly.
- This example prints pulled messages to logs; integrate your own handlers as needed.
*/

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use dotenvy::dotenv;
use redis::{AsyncCommands, aio::ConnectionManager};
use serde::Deserialize;
use tokio::time::sleep;
use tracing::{info, warn};
use wxkefu_rs::callback::{CallbackCrypto, VerifyError};
use wxkefu_rs::sync_msg::{MsgPayload, SyncMsgItem, SyncMsgRequest};
use wxkefu_rs::{Auth, KfClient};

#[derive(Clone)]
struct AppState {
    crypto: CallbackCrypto,
    redis: ConnectionManager,
    // Config
    corp_id: String,
    corp_secret: String,
    redis_prefix: String,
}

#[derive(Debug, Deserialize)]
struct WxQuery {
    msg_signature: String,
    timestamp: String,
    nonce: String,
    echostr: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let _ = dotenv();

    // Required env
    let token = get_env("WXKF_TOKEN")?;
    let encoding_aes_key = get_env("WXKF_ENCODING_AES_KEY")?;
    let corp_id = get_env("WXKF_CORP_ID")?;
    let corp_secret = get_env("WXKF_APP_SECRET")?;

    // Optional env
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let redis_prefix = std::env::var("REDIS_PREFIX").unwrap_or_else(|_| "wxkf".to_string());
    let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
        .parse()
        .expect("invalid BIND_ADDR");

    // Crypto helper (cannot modify callback.rs)
    let crypto = CallbackCrypto::new(token, encoding_aes_key, corp_id.clone())
        .map_err(|e| anyhow::anyhow!("CallbackCrypto init error: {e}"))?;

    // Redis connection manager
    let redis_client = redis::Client::open(redis_url.clone())
        .map_err(|e| anyhow::anyhow!("Redis open error: {e}"))?;
    let redis = redis_client
        .get_connection_manager()
        .await
        .map_err(|e| anyhow::anyhow!("Redis connection error: {e}"))?;

    let state = Arc::new(AppState {
        crypto,
        redis,
        corp_id,
        corp_secret,
        redis_prefix,
    });

    // GET: URL verification
    async fn verify(
        State(state): State<Arc<AppState>>,
        Query(q): Query<WxQuery>,
    ) -> axum::response::Response {
        match q.echostr {
            Some(echostr) => match state.crypto.verify_and_decrypt_echostr(
                &q.msg_signature,
                &q.timestamp,
                &q.nonce,
                &echostr,
            ) {
                Ok(plain) => {
                    info!("URL verification ok");
                    plain.into_response()
                }
                Err(err) => {
                    warn!("URL verification failed: {}", err);
                    (StatusCode::BAD_REQUEST, "invalid").into_response()
                }
            },
            None => (StatusCode::BAD_REQUEST, "missing echostr").into_response(),
        }
    }

    // POST: encrypted callback body
    async fn callback(
        State(state): State<Arc<AppState>>,
        Query(q): Query<WxQuery>,
        body: String,
    ) -> axum::response::Response {
        match state
            .crypto
            .verify_and_decrypt_xml(&q.msg_signature, &q.timestamp, &q.nonce, &body)
        {
            Ok(plaintext_xml) => {
                // Extract needed fields
                let event = extract_xml_field(&plaintext_xml, b"Event");
                let open_kfid = extract_xml_field(&plaintext_xml, b"OpenKfId");
                let token = extract_xml_field(&plaintext_xml, b"Token");
                info!(
                    "Callback decrypted, Event={:?}, OpenKfId={:?}, Token={:?}",
                    event, open_kfid, token
                );

                if let (Some(open_kfid), Some(token)) = (open_kfid, token) {
                    // Enqueue token for this open_kfid and start worker if not running
                    if let Err(e) = enqueue_and_maybe_start_worker(&state, &open_kfid, &token).await
                    {
                        warn!("enqueue/start worker failed: {}", e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
                    }
                }

                // Ack "success"
                "success".into_response()
            }
            Err(err) => {
                match err {
                    VerifyError::SignatureMismatch => {
                        warn!("Signature mismatch: {}", err);
                    }
                    _ => {
                        warn!("Decrypt/verify failed: {}", err);
                    }
                }
                (StatusCode::BAD_REQUEST, "invalid").into_response()
            }
        }
    }

    let app = Router::new()
        .route("/wx/kf/callback", get(verify))
        .route("/wx/kf/callback", post(callback))
        .route("/callback", get(verify))
        .route("/callback", post(callback))
        .with_state(state);

    info!("Redis-backed Kf callback server listening on {}", bind_addr);
    axum::serve(tokio::net::TcpListener::bind(bind_addr).await?, app).await?;
    Ok(())
}

/// Enqueue the short-lived event token for a specific open_kfid, then try to start a worker.
/// Uses Redis SET NX EX to serialize processing per open_kfid across processes.
async fn enqueue_and_maybe_start_worker(
    state: &Arc<AppState>,
    open_kfid: &str,
    token: &str,
) -> anyhow::Result<()> {
    let queue_key = format!("{}:queue:{}", state.redis_prefix, open_kfid);

    // 1) Enqueue token (LPUSH), keep queue for 10 minutes (token lifetime); refresh TTL on each push
    {
        let mut redis = state.redis.clone();
        let _: () = redis.lpush::<_, _, ()>(&queue_key, token).await?;
        // Set or refresh TTL
        let _: () = redis.expire(&queue_key, 10 * 60).await?;
        info!("Enqueued token for open_kfid={}", open_kfid);
    }

    // 2) Try to acquire worker lock and spawn if acquired
    try_start_worker_for(state.clone(), open_kfid).await?;

    Ok(())
}

/// Attempt to acquire a per-open_kfid lock and start a worker task.
/// Lock TTL is short but refreshed periodically by the worker.
async fn try_start_worker_for(state: Arc<AppState>, open_kfid: &str) -> anyhow::Result<()> {
    let lock_key = format!("{}:lock:{}", state.redis_prefix, open_kfid);

    let mut redis = state.redis.clone();
    // SET lock NX EX 60
    let acquired: bool = redis
        .set_nx(&lock_key, "1")
        .await
        .map_err(|e| anyhow::anyhow!("redis set_nx error: {}", e))?;
    if acquired {
        // Attach TTL
        let _: () = redis.expire(&lock_key, 60).await?;
        info!("Worker lock acquired for {}", open_kfid);

        // Spawn worker that will refresh TTL while processing
        let open_kfid = open_kfid.to_string();
        tokio::spawn(async move {
            if let Err(e) = sync_worker(state, &open_kfid, &lock_key).await {
                warn!("sync_worker error for {}: {}", open_kfid, e);
            } else {
                info!("sync_worker finished for {}", open_kfid);
            }
        });
    } else {
        // Another worker already owns the lock
        info!("Worker already running for {}", open_kfid);
    }

    Ok(())
}

/// Worker: process queued tokens and pull messages until queue empty and has_more==0.
/// Refreshes the lock TTL periodically to keep ownership while working.
async fn sync_worker(state: Arc<AppState>, open_kfid: &str, lock_key: &str) -> anyhow::Result<()> {
    let queue_key = format!("{}:queue:{}", state.redis_prefix, open_kfid);
    let cursor_key = format!("{}:cursor:{}", state.redis_prefix, open_kfid);

    let mut redis = state.redis.clone();
    let mut kf_client = KfClient::default();

    // Pull loop:
    // - While queue has tokens OR has_more==1, keep pulling
    // - Keep/refresh cursor per open_kfid
    // - Refresh lock TTL every iteration
    let initial_cursor_present = redis
        .get::<_, Option<String>>(&cursor_key)
        .await
        .ok()
        .flatten()
        .is_some();
    let mut has_more = initial_cursor_present;
    let mut round = 0u32;

    loop {
        round += 1;

        // Refresh lock TTL (keep-ownership) to 60s
        let _: () = redis.expire(lock_key, 60).await.unwrap_or_default();

        // Check for token from queue (RPOP to process in FIFO order with LPUSH above)
        let token_opt: Option<String> = redis.rpop(&queue_key, None).await?;
        // Load last cursor
        let cursor_opt: Option<String> = redis.get(&cursor_key).await.ok().flatten();

        // If no token and not has_more, we're done
        if token_opt.is_none() && !has_more {
            break;
        }

        let access_token = get_access_token_cached(
            &mut redis,
            &mut kf_client,
            &state.corp_id,
            &state.corp_secret,
            &state.redis_prefix,
        )
        .await?;

        let mut req = SyncMsgRequest {
            cursor: cursor_opt.clone(),
            token: token_opt.clone(),
            limit: Some(1000),
            voice_format: None,
            open_kfid: Some(open_kfid.to_string()),
        };

        info!(
            "sync_msg start round={}, open_kfid={}, cursor={:?}, token_present={}",
            round,
            open_kfid,
            req.cursor,
            req.token.is_some()
        );

        match kf_client.sync_msg(&access_token, &req).await {
            Ok(resp) => {
                info!(
                    "sync_msg ok: has_more={}, next_cursor={:?}, msg_count={}",
                    resp.has_more,
                    resp.next_cursor,
                    resp.msg_list.len()
                );

                // Print/process messages
                for (i, item) in resp.msg_list.iter().enumerate() {
                    print_item(i, item);
                }

                // Persist next_cursor for incremental pulls
                if let Some(next) = resp.next_cursor {
                    let _: () = redis.set(&cursor_key, &next).await?;
                    // Keep cursor for several days
                    let _: () = redis.expire(&cursor_key, 7 * 24 * 3600).await?;
                    req.cursor = Some(next);
                } else {
                    req.cursor = None;
                }

                has_more = resp.has_more == 1;

                // If has_more==1, continue immediately with same cursor (token may be None)
                // Otherwise, continue to next token (outer loop will pop again)
                if has_more {
                    // Small delay to be polite; adjust as needed
                    sleep(Duration::from_millis(50)).await;
                    continue;
                }
            }
            Err(e) => {
                warn!("sync_msg error: {}", e);
                // On error, small backoff then continue to next token or exit
                sleep(Duration::from_millis(200)).await;
            }
        }

        // If no more and queue looks empty, we exit; otherwise loop pops next token
        let qlen: i64 = redis.llen(&queue_key).await.unwrap_or(0);
        if qlen == 0 && !has_more {
            break;
        }
    }

    // Release lock (best-effort), allowing next worker to start if needed
    let _: () = redis.del(lock_key).await.unwrap_or_default();
    Ok(())
}

/// Cache and reuse access_token in Redis to avoid rate limiting.
/// Stores token with TTL of expires_in - 300 seconds as a safety buffer.
async fn get_access_token_cached(
    redis: &mut ConnectionManager,
    kf_client: &mut KfClient,
    corp_id: &str,
    corp_secret: &str,
    prefix: &str,
) -> anyhow::Result<String> {
    let key = format!("{}:access_token", prefix);
    if let Ok(Some(cached)) = redis.get::<_, Option<String>>(&key).await {
        return Ok(cached);
    }

    let token_resp = kf_client
        .get_access_token(&Auth::WeCom {
            corp_id: corp_id.to_string(),
            corp_secret: corp_secret.to_string(),
        })
        .await?;
    let ttl = token_resp.expires_in.saturating_sub(300).max(60);
    let _: () = redis
        .set_ex(&key, &token_resp.access_token, ttl as u64)
        .await?;
    Ok(token_resp.access_token)
}

/// Helper to read a required env var with a friendly error.
fn get_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing env var: {}", key))
}

/// Extract a field's text from a simple XML string.
/// Supports both CDATA and plain text nodes.
fn extract_xml_field(xml: &str, field: &[u8]) -> Option<String> {
    let field_str = std::str::from_utf8(field).ok()?;

    // Prefer CDATA: <Field><![CDATA[value]]></Field>
    let open_cdata = format!("<{}><![CDATA[", field_str);
    if let Some(start) = xml.find(&open_cdata) {
        let from = start + open_cdata.len();
        let close_cdata = format!("]]></{}>", field_str);
        if let Some(end_rel) = xml[from..].find(&close_cdata) {
            return Some(xml[from..from + end_rel].to_string());
        }
    }

    // Fallback plain text: <Field>value</Field>
    let open = format!("<{}>", field_str);
    if let Some(start) = xml.find(&open) {
        let from = start + open.len();
        let close = format!("</{}>", field_str);
        if let Some(end_rel) = xml[from..].find(&close) {
            return Some(xml[from..from + end_rel].to_string());
        }
    }

    None
}

// Minimal printer (adapt from examples) for demonstration
fn print_item(idx: usize, item: &SyncMsgItem) {
    info!(
        "[{}] msgid={}, open_kfid={}, external_userid={:?}, send_time={}, origin={:?}",
        idx,
        item.common.msgid,
        item.common.open_kfid,
        item.common.external_userid,
        item.common.send_time,
        item.common.origin
    );

    match &item.payload {
        MsgPayload::Text { text } => {
            info!(
                "    [text] content={:?}, menu_id={:?}",
                text.content, text.menu_id
            );
        }
        MsgPayload::Image { image } => {
            info!("    [image] media_id={}", image.media_id);
        }
        MsgPayload::Voice { voice } => {
            info!("    [voice] media_id={}", voice.media_id);
        }
        MsgPayload::Video { video } => {
            info!("    [video] media_id={}", video.media_id);
        }
        MsgPayload::File { file } => {
            info!("    [file] media_id={}", file.media_id);
        }
        MsgPayload::Location { location } => {
            info!(
                "    [location] lat={}, lng={}, name={:?}, address={:?}",
                location.latitude, location.longitude, location.name, location.address
            );
        }
        MsgPayload::MiniProgram { miniprogram } => {
            info!(
                "    [miniprogram] title={:?}, appid={}, pagepath={}, thumb_media_id={}",
                miniprogram.title,
                miniprogram.appid,
                miniprogram.pagepath,
                miniprogram.thumb_media_id
            );
        }
        MsgPayload::ChannelsShopProduct {
            channels_shop_product: p,
        } => {
            info!(
                "    [channels_shop_product] product_id={}, title={:?}, sales_price={}, shop={:?}",
                p.product_id, p.title, p.sales_price, p.shop_nickname
            );
        }
        MsgPayload::ChannelsShopOrder {
            channels_shop_order: o,
        } => {
            info!(
                "    [channels_shop_order] order_id={}, titles={:?}, price_wording={}, shop={:?}",
                o.order_id, o.product_titles, o.price_wording, o.shop_nickname
            );
        }
        MsgPayload::MergedMsg { merged_msg } => {
            info!(
                "    [merged_msg] title={:?}, items={}",
                merged_msg.title,
                merged_msg.item.len()
            );
        }
        MsgPayload::Channels { channels } => {
            info!(
                "    [channels] sub_type={}, nickname={:?}, title={:?}",
                channels.sub_type, channels.nickname, channels.title
            );
        }
        MsgPayload::Note {} => {
            info!("    [note] (no additional content)");
        }
        MsgPayload::Event { event } => {
            info!(
                "    [event] type={}, open_kfid={:?}, external_userid={:?}, scene={:?}, scene_param={:?}, welcome_code={:?}, fail_msgid={:?}, fail_type={:?}, recall_msgid={:?}",
                event.event_type,
                event.open_kfid,
                event.external_userid,
                event.scene,
                event.scene_param,
                event.welcome_code,
                event.fail_msgid,
                event.fail_type,
                event.recall_msgid
            );
        }
    }
}
