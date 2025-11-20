use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use dotenvy::dotenv;
use serde::Deserialize;
use tracing::{info, warn};
use tracing_subscriber::FmtSubscriber;
use wxkefu_rs::callback::{CallbackCrypto, VerifyError};
use wxkefu_rs::kf_sync_tool::{KfSyncTool, MsgHandler, SyncOptions};
use wxkefu_rs::sync_msg::{MsgPayload, SyncMsgItem};

#[derive(Clone)]
struct AppState {
    crypto: CallbackCrypto,
    tool: KfSyncTool,
    handler: Arc<dyn MsgHandler>,
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
    // Initialize logging
    let subscriber = FmtSubscriber::builder().with_target(false).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    // Optional .env for local dev
    let _ = dotenv();

    // Required environment variables:
    // - WXKF_TOKEN: token used for signature verification (ASCII, <=32)
    // - WXKF_ENCODING_AES_KEY: 43-char base64 key (EncodingAESKey)
    // - WXKF_CORP_ID: your WeCom corp id (starts with "ww")
    let token = get_env("WXKF_TOKEN")?;
    let encoding_aes_key = get_env("WXKF_ENCODING_AES_KEY")?;
    let corpid = get_env("WXKF_CORP_ID")?;

    // Build crypto helper for callback (verify + decrypt)
    let crypto = CallbackCrypto::new(token, encoding_aes_key, corpid)
        .map_err(|e| anyhow::anyhow!("CallbackCrypto init error: {e}"))?;

    // Build kf_sync_tool from env (reads REDIS_URL, REDIS_PREFIX, WXKF_CORP_ID, WXKF_APP_SECRET)
    let tool = KfSyncTool::from_env(Some(SyncOptions {
        limit: 1000,
        voice_format: None,
        queue_ttl_secs: 10 * 60,
        lock_ttl_secs: 60,
        cursor_ttl_secs: 7 * 24 * 3600,
        has_more_sleep_ms: 50,
        error_backoff_ms: 200,
    }))
    .await?;

    // Message handler: log essentials
    let handler = Arc::new(Logger);

    let state = Arc::new(AppState {
        crypto,
        tool,
        handler,
    });

    // GET handler: URL verification (echostr flow)
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

    // POST handler: encrypted callback payload
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
                // Extract callback fields we need
                let event = extract_xml_field(&plaintext_xml, b"Event");
                let open_kfid = extract_xml_field(&plaintext_xml, b"OpenKfId");
                let token = extract_xml_field(&plaintext_xml, b"Token");
                info!(
                    "Callback decrypted, Event={:?}, OpenKfId={:?}, Token={:?}",
                    event, open_kfid, token
                );

                // Enqueue token and start worker per open_kfid
                if let (Some(open_kfid), Some(token)) = (open_kfid, token) {
                    if let Err(e) = state
                        .tool
                        .enqueue_and_start(&open_kfid, &token, state.handler.clone())
                        .await
                    {
                        warn!("enqueue/start worker failed: {}", e);
                        return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
                    }
                }

                // Must respond "success"
                "success".into_response()
            }
            Err(err) => {
                match err {
                    VerifyError::SignatureMismatch => warn!("Signature mismatch: {}", err),
                    _ => warn!("Decrypt/verify failed: {}", err),
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

    // Bind
    let bind_addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
        .parse()
        .expect("invalid BIND_ADDR");
    info!("Redis tool server listening on {}", bind_addr);

    axum::serve(tokio::net::TcpListener::bind(bind_addr).await?, app).await?;
    Ok(())
}

/// Simple XML field extractor supporting CDATA and plain text nodes.
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

/// Helper to read a required env var with a friendly error.
fn get_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing env var: {}", key))
}

/// Demo message handler: logs essentials per message.
struct Logger;

#[async_trait]
impl MsgHandler for Logger {
    async fn handle(&self, item: &SyncMsgItem) {
        info!(
            "msgid={}, open_kfid={}, external_userid={:?}, send_time={}, origin={:?}",
            item.common.msgid,
            item.common.open_kfid,
            item.common.external_userid,
            item.common.send_time,
            item.common.origin
        );

        match &item.payload {
            MsgPayload::Text { text } => {
                info!(
                    "  [text] content={:?}, menu_id={:?}",
                    text.content, text.menu_id
                );
            }
            MsgPayload::Image { image } => {
                info!("  [image] media_id={}", image.media_id);
            }
            MsgPayload::Voice { voice } => {
                info!("  [voice] media_id={}", voice.media_id);
            }
            MsgPayload::Video { video } => {
                info!("  [video] media_id={}", video.media_id);
            }
            MsgPayload::File { file } => {
                info!("  [file] media_id={}", file.media_id);
            }
            MsgPayload::Location { location } => {
                info!(
                    "  [location] lat={}, lng={}, name={:?}, address={:?}",
                    location.latitude, location.longitude, location.name, location.address
                );
            }
            MsgPayload::MiniProgram { miniprogram } => {
                info!(
                    "  [miniprogram] title={:?}, appid={}, pagepath={}, thumb_media_id={}",
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
                    "  [channels_shop_product] product_id={}, title={:?}, sales_price={}, shop={:?}",
                    p.product_id, p.title, p.sales_price, p.shop_nickname
                );
            }
            MsgPayload::ChannelsShopOrder {
                channels_shop_order: o,
            } => {
                info!(
                    "  [channels_shop_order] order_id={}, titles={:?}, price_wording={}, shop={:?}",
                    o.order_id, o.product_titles, o.price_wording, o.shop_nickname
                );
            }
            MsgPayload::MergedMsg { merged_msg } => {
                info!(
                    "  [merged_msg] title={:?}, items={}",
                    merged_msg.title,
                    merged_msg.item.len()
                );
            }
            MsgPayload::Channels { channels } => {
                info!(
                    "  [channels] sub_type={}, nickname={:?}, title={:?}",
                    channels.sub_type, channels.nickname, channels.title
                );
            }
            MsgPayload::Note {} => {
                info!("  [note] (no additional content)");
            }
            MsgPayload::Event { event } => {
                info!(
                    "  [event] type={}, open_kfid={:?}, external_userid={:?}, scene={:?}, scene_param={:?}, welcome_code={:?}, fail_msgid={:?}, fail_type={:?}, recall_msgid={:?}",
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
}
