use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use dashmap::DashMap;
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::{info, warn};
use wxkefu_rs::{
    Auth, KfClient,
    callback::CallbackCrypto,
    sync_msg::{MsgPayload, SyncMsgRequest},
};

/// Shared application state for end-to-end demo.
#[derive(Clone)]
struct AppState {
    /// Crypto helper for callback signature verification and AES decryption
    crypto: CallbackCrypto,
    /// WeCom Kf API client
    kf: KfClient,
    /// WeCom corp id (ww...)
    corp_id: String,
    /// WeChat Customer Service (Kf) Secret
    corp_secret: String,
    /// In-memory per-account sync state map: key=open_kfid
    states: Arc<DashMap<String, AccountSyncState>>,
    /// Cached access_token with expiry
    at_cache: Arc<Mutex<Option<AccessTokenCache>>>,
    /// Poll settings
    poll_interval: Duration,
    max_pages_per_tick: usize,
    /// If true, skip polling when no fresh callback token is present for the account
    skip_without_token: bool,
}

/// Per-account sync state stored in DashMap
#[derive(Debug, Clone)]
struct AccountSyncState {
    /// Last short-lived callback token and the time we received it
    token: Option<(String, Instant)>,
    /// Last next_cursor returned by sync_msg
    next_cursor: Option<String>,
    /// A simple flag to avoid overlapping polls for this account
    is_polling: bool,
    /// For debugging
    last_event: Option<String>,
    last_plain_xml_snippet: Option<String>,
}

/// Cached access token with expiry time
#[derive(Debug, Clone)]
struct AccessTokenCache {
    token: String,
    expires_at: Instant,
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
    // Logging
    tracing_subscriber::fmt().with_target(false).init();
    let _ = dotenvy::dotenv();

    // Load env
    let corp_id = env("WXKF_CORP_ID")?;
    let corp_secret = env("WXKF_APP_SECRET")?;

    let callback_token = env("WXKF_CALLBACK_TOKEN")?;
    let encoding_aes_key = env("WXKF_ENCODING_AES_KEY")?;
    let crypto = CallbackCrypto::new(callback_token, encoding_aes_key, corp_id.clone())
        .map_err(|e| anyhow::anyhow!("CallbackCrypto init error: {e}"))?;

    // Poll settings (optional)
    let poll_interval = std::env::var("WXKF_POLL_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_millis(2000));
    let max_pages_per_tick = std::env::var("WXKF_MAX_PAGES_PER_TICK")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3);
    let skip_without_token = std::env::var("WXKF_SKIP_WITHOUT_TOKEN")
        .ok()
        .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let app_state = Arc::new(AppState {
        crypto,
        kf: KfClient::default(),
        corp_id,
        corp_secret,
        states: Arc::new(DashMap::new()),
        at_cache: Arc::new(Mutex::new(None)),
        poll_interval,
        max_pages_per_tick,
        skip_without_token,
    });

    // Spawn background task to poll sync_msg periodically
    spawn_background_poll(app_state.clone());

    // Build Axum app: expose both /callback and /wx/kf/callback
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/callback", get(verify_handler).post(callback_handler))
        .route(
            "/wx/kf/callback",
            get(verify_handler).post(callback_handler),
        )
        .with_state(app_state);

    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    info!("End-to-end demo listening on {}", addr);
    info!("Callback routes enabled at /callback and /wx/kf/callback");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

/// GET handler for URL verification (echostr flow)
async fn verify_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<WxQuery>,
) -> impl IntoResponse {
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

/// POST handler for encrypted callback payload
async fn callback_handler(
    State(state): State<Arc<AppState>>,
    Query(q): Query<WxQuery>,
    body: String,
) -> impl IntoResponse {
    match state
        .crypto
        .verify_and_decrypt_xml(&q.msg_signature, &q.timestamp, &q.nonce, &body)
    {
        Ok(plaintext_xml) => {
            // Extract fields from plaintext XML
            let event = extract_xml_field(&plaintext_xml, "Event");
            let token = extract_xml_field(&plaintext_xml, "Token");
            let open_kfid = extract_xml_field(&plaintext_xml, "OpenKfId")
                .or_else(|| extract_xml_field(&plaintext_xml, "open_kfid")); // tolerant

            info!(
                "Callback decrypted: event={:?}, open_kfid={:?}, token_present={}",
                event,
                open_kfid,
                token.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
            );

            // Update per-account state
            if let Some(okf) = open_kfid {
                let mut entry = state.states.entry(okf.clone()).or_insert(AccountSyncState {
                    token: None,
                    next_cursor: None,
                    is_polling: false,
                    last_event: None,
                    last_plain_xml_snippet: None,
                });

                if let Some(tk) = token {
                    entry.token = Some((tk, Instant::now()));
                }
                entry.last_event = event.clone();
                entry.last_plain_xml_snippet =
                    Some(plaintext_xml.chars().take(200).collect::<String>());

                // If we just received a token, optionally trigger a quick poll (best-effort)
                // to reduce latency. We'll spawn a single-page poll without blocking the handler.
                let app = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = quick_one_page_poll(&app, &okf).await {
                        warn!("quick poll error for {}: {}", okf, e);
                    }
                });
            } else {
                warn!("Callback plaintext missing <OpenKfId>; cannot bind token/cursor to account");
            }

            "success".into_response()
        }
        Err(err) => {
            warn!("Callback decrypt/verify failed: {}", err);
            (StatusCode::BAD_REQUEST, "invalid").into_response()
        }
    }
}

/// Spawn a background polling loop to iterate accounts and pull messages incrementally.
fn spawn_background_poll(app: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            // Iterate all accounts that have state
            for mut kv in app.states.iter_mut() {
                let open_kfid = kv.key().clone();
                let st = kv.value_mut();

                // Prevent overlapping polls
                if st.is_polling {
                    continue;
                }

                // Token freshness: 10 minutes by spec; use a conservative 9 minutes window
                let token_fresh = st
                    .token
                    .as_ref()
                    .map(|(_t, at)| at.elapsed() < Duration::from_secs(9 * 60))
                    .unwrap_or(false);

                if app.skip_without_token && !token_fresh {
                    // Skip polling to avoid strict rate limit when no fresh event token
                    continue;
                }

                st.is_polling = true;
                let app_cloned = app.clone();
                let open_kfid_cloned = open_kfid.clone();

                tokio::spawn(async move {
                    if let Err(e) = poll_account(&app_cloned, &open_kfid_cloned).await {
                        warn!("poll error for {}: {}", open_kfid_cloned, e);
                    }
                    // Clear polling flag
                    if let Some(mut s) = app_cloned.states.get_mut(&open_kfid_cloned) {
                        s.is_polling = false;
                    }
                });
            }

            tokio::time::sleep(app.poll_interval).await;
        }
    });
}

/// Perform a quick one-page poll for an account (best-effort, no loop).
async fn quick_one_page_poll(app: &Arc<AppState>, open_kfid: &str) -> anyhow::Result<()> {
    if let Some(st) = app.states.get(open_kfid) {
        let token = st
            .token
            .as_ref()
            .map(|(t, at)| {
                if at.elapsed() < Duration::from_secs(9 * 60) {
                    Some(t.clone())
                } else {
                    None
                }
            })
            .flatten();
        let cursor = st.next_cursor.clone();
        drop(st);

        let access_token = get_access_token_cached(app).await?;
        let req = SyncMsgRequest {
            cursor,
            token,
            limit: Some(1000),
            voice_format: None,
            open_kfid: Some(open_kfid.to_string()),
        };

        let resp = app.kf.sync_msg(&access_token, &req).await?;
        handle_sync_resp(app, open_kfid, &resp).await;

        // update cursor
        if let Some(mut s) = app.states.get_mut(open_kfid) {
            s.next_cursor = resp.next_cursor;
        }
    }
    Ok(())
}

/// Poll one account with pagination up to max_pages_per_tick
async fn poll_account(app: &Arc<AppState>, open_kfid: &str) -> anyhow::Result<()> {
    let access_token = get_access_token_cached(app).await?;
    let (token, cursor) = {
        let s = app.states.get(open_kfid);
        if let Some(st) = s {
            let token = st
                .token
                .as_ref()
                .map(|(t, at)| {
                    if at.elapsed() < Duration::from_secs(9 * 60) {
                        Some(t.clone())
                    } else {
                        None
                    }
                })
                .flatten();
            (token, st.next_cursor.clone())
        } else {
            (None, None)
        }
    };

    let mut req = SyncMsgRequest {
        cursor,
        token,
        limit: Some(1000),
        voice_format: None,
        open_kfid: Some(open_kfid.to_string()),
    };

    let mut pages = 0usize;
    loop {
        pages += 1;
        let resp = app.kf.sync_msg(&access_token, &req).await?;
        handle_sync_resp(app, open_kfid, &resp).await;

        // Update cursor for next page
        if let Some(mut st) = app.states.get_mut(open_kfid) {
            st.next_cursor = resp.next_cursor.clone();
        }

        if resp.has_more == 1 && pages < app.max_pages_per_tick {
            req.cursor = resp.next_cursor.clone();
            continue;
        }
        break;
    }

    Ok(())
}

/// Handle a sync_msg response: print messages/events for demo purpose
async fn handle_sync_resp(
    _app: &Arc<AppState>,
    open_kfid: &str,
    resp: &wxkefu_rs::sync_msg::SyncMsgResponse,
) {
    info!(
        "[{}] sync_msg: errcode={}, errmsg={}, has_more={}, next_cursor={:?}, msg_count={}",
        open_kfid,
        resp.errcode,
        resp.errmsg,
        resp.has_more,
        resp.next_cursor,
        resp.msg_list.len()
    );

    for (i, item) in resp.msg_list.iter().enumerate() {
        print_item(i, item);
    }

    // In a real system you would persist resp.next_cursor and msg_list into your DB here.
}

/// Pretty-print a message item for demo
fn print_item(idx: usize, item: &wxkefu_rs::sync_msg::SyncMsgItem) {
    let ext = item.common.external_userid.as_deref().unwrap_or("-");
    let origin = item.common.origin.unwrap_or_default();
    info!(
        "  [{}] msgid={}, open_kfid={}, external_userid={}, send_time={}, origin={}",
        idx, item.common.msgid, item.common.open_kfid, ext, item.common.send_time, origin
    );

    match &item.payload {
        MsgPayload::Text { text } => info!(
            "      [text] content={:?}, menu_id={:?}",
            text.content, text.menu_id
        ),
        MsgPayload::Image { image } => info!("      [image] media_id={}", image.media_id),
        MsgPayload::Voice { voice } => info!("      [voice] media_id={}", voice.media_id),
        MsgPayload::Video { video } => info!("      [video] media_id={}", video.media_id),
        MsgPayload::File { file } => info!("      [file] media_id={}", file.media_id),
        MsgPayload::Location { location } => info!(
            "      [location] lat={}, lng={}, name={:?}, address={:?}",
            location.latitude, location.longitude, location.name, location.address
        ),
        MsgPayload::MiniProgram { miniprogram } => info!(
            "      [miniprogram] title={:?}, appid={}, pagepath={}, thumb_media_id={}",
            miniprogram.title, miniprogram.appid, miniprogram.pagepath, miniprogram.thumb_media_id
        ),
        MsgPayload::ChannelsShopProduct {
            channels_shop_product: p,
        } => info!(
            "      [channels_shop_product] product_id={}, title={:?}, sales_price={}, shop={:?}",
            p.product_id, p.title, p.sales_price, p.shop_nickname
        ),
        MsgPayload::ChannelsShopOrder {
            channels_shop_order: o,
        } => info!(
            "      [channels_shop_order] order_id={}, titles={:?}, price_wording={}, shop={:?}",
            o.order_id, o.product_titles, o.price_wording, o.shop_nickname
        ),
        MsgPayload::MergedMsg { merged_msg } => {
            info!(
                "      [merged_msg] title={:?}, items={}",
                merged_msg.title,
                merged_msg.item.len()
            );
            for (j, it) in merged_msg.item.iter().enumerate() {
                let snippet = it.msg_content.chars().take(120).collect::<String>();
                info!(
                    "        [{}] time={}, type={}, sender={}, content_snippet={:?}...",
                    j, it.send_time, it.msgtype, it.sender_name, snippet
                );
            }
        }
        MsgPayload::Channels { channels } => info!(
            "      [channels] sub_type={}, nickname={:?}, title={:?}",
            channels.sub_type, channels.nickname, channels.title
        ),
        MsgPayload::Note {} => info!("      [note] (no additional content)"),
        MsgPayload::Event { event } => {
            info!(
                "      [event] type={}, open_kfid={:?}, external_userid={:?}, scene={:?}, scene_param={:?}, welcome_code={:?}, fail_msgid={:?}, fail_type={:?}, recall_msgid={:?}",
                event.event_type,
                event.open_kfid,
                event.external_userid,
                event.scene,
                event.scene_param,
                event.welcome_code,
                event.fail_msgid,
                event.fail_type,
                event.recall_msgid,
            );
            if let Some(ch) = &event.wechat_channels {
                info!(
                    "        wechat_channels: scene={}, nickname={:?}, shop_nickname={:?}",
                    ch.scene, ch.nickname, ch.shop_nickname
                );
            }
        }
    }
}

/// Get an access_token with a simple in-memory cache.
async fn get_access_token_cached(app: &Arc<AppState>) -> anyhow::Result<String> {
    // Fast path
    if let Some(at) = app.at_cache.lock().await.as_ref() {
        if Instant::now() < at.expires_at {
            return Ok(at.token.clone());
        }
    }

    // Refresh
    let token_resp = app
        .kf
        .get_access_token(&Auth::WeCom {
            corp_id: app.corp_id.clone(),
            corp_secret: app.corp_secret.clone(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("get_access_token error: {e}"))?;
    let ttl = token_resp.expires_in.saturating_sub(60); // refresh 60s earlier
    let at = AccessTokenCache {
        token: token_resp.access_token.clone(),
        expires_at: Instant::now() + Duration::from_secs(ttl as u64),
    };
    *app.at_cache.lock().await = Some(at.clone());
    Ok(at.token)
}

/// Extract a field's text from a simple XML string.
/// Prefers CDATA: <Field><![CDATA[value]]></Field>, falls back to <Field>value</Field>.
fn extract_xml_field(xml: &str, field: &str) -> Option<String> {
    // CDATA first
    let open_cdata = format!("<{}><![CDATA[", field);
    if let Some(start) = xml.find(&open_cdata) {
        let from = start + open_cdata.len();
        let close_cdata = format!("]]></{}>", field);
        if let Some(end_rel) = xml[from..].find(&close_cdata) {
            return Some(xml[from..from + end_rel].to_string());
        }
    }
    // Plain text fallback
    let open = format!("<{}>", field);
    if let Some(start) = xml.find(&open) {
        let from = start + open.len();
        let close = format!("</{}>", field);
        if let Some(end_rel) = xml[from..].find(&close) {
            return Some(xml[from..from + end_rel].to_string());
        }
    }
    None
}

/// Small helper to read required env var with a friendly error
fn env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing env var: {}", key))
}
