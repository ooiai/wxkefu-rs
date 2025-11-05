use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use wxkefu_rs::callback::{CallbackCrypto, VerifyError};

#[derive(Clone)]
struct AppState {
    crypto: CallbackCrypto,
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
    tracing_subscriber::fmt().with_target(false).init();

    // Optionally load from .env for local development
    let _ = dotenvy::dotenv();

    // Required environment variables:
    // - WXKF_TOKEN: token used for signature verification (ASCII, <=32)
    // - WXKF_ENCODING_AES_KEY: 43-char base64 key (EncodingAESKey)
    // - WXKF_CORP_ID: your WeCom corp id (starts with "ww")
    let token = get_env("WXKF_TOKEN")?;
    let encoding_aes_key = get_env("WXKF_ENCODING_AES_KEY")?;
    let corpid = get_env("WXKF_CORP_ID")?;

    // Build crypto helper
    let crypto = CallbackCrypto::new(token, encoding_aes_key, corpid)
        .map_err(|e| anyhow::anyhow!("CallbackCrypto init error: {e}"))?;

    let state = Arc::new(AppState { crypto });

    // GET handler for URL verification (echostr flow).
    async fn verify(
        State(state): State<Arc<AppState>>,
        Query(q): Query<WxQuery>,
    ) -> axum::response::Response {
        match q.echostr {
            Some(echostr) => {
                match state.crypto.verify_and_decrypt_echostr(
                    &q.msg_signature,
                    &q.timestamp,
                    &q.nonce,
                    &echostr,
                ) {
                    Ok(plain) => {
                        tracing::info!("URL verification ok");
                        // Must return the decrypted plain echostr
                        plain.into_response()
                    }
                    Err(err) => {
                        tracing::warn!("URL verification failed: {}", err);
                        (StatusCode::BAD_REQUEST, "invalid").into_response()
                    }
                }
            }
            None => (StatusCode::BAD_REQUEST, "missing echostr").into_response(),
        }
    }

    // POST handler for encrypted callback payload
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
                // For kf_msg_or_event, you will get an XML like:
                // <xml>
                //   <ToUserName><![CDATA[ww...]]></ToUserName>
                //   <CreateTime>...</CreateTime>
                //   <MsgType><![CDATA[event]]></MsgType>
                //   <Event><![CDATA[kf_msg_or_event]]></Event>
                //   <Token><![CDATA[...]]></Token>
                //   <OpenKfId><![CDATA[wk...]]></OpenKfId>
                // </xml>
                // The <Token> here is used to call sync_msg within 10 minutes.
                if let Some(token) = extract_xml_field(&plaintext_xml, b"Token") {
                    tracing::info!(
                        "Decrypted callback ok. event_token(for sync_msg): {}",
                        token
                    );
                } else {
                    tracing::info!("Decrypted callback ok (no <Token> found).");
                }

                if let Some(event) = extract_xml_field(&plaintext_xml, b"Event") {
                    tracing::info!("Event: {}", event);
                }
                if let Some(open_kfid) = extract_xml_field(&plaintext_xml, b"OpenKfId") {
                    tracing::info!("OpenKfId: {}", open_kfid);
                }

                tracing::debug!("Plaintext XML:\n{}", plaintext_xml);

                // Respond "success" to acknowledge. Do NOT echo the plaintext xml.
                "success".into_response()
            }
            Err(err) => {
                match err {
                    VerifyError::SignatureMismatch => {
                        tracing::warn!("Signature mismatch: {}", err);
                    }
                    _ => {
                        tracing::warn!("Decrypt/verify failed: {}", err);
                    }
                }
                (StatusCode::BAD_REQUEST, "invalid").into_response()
            }
        }
    }

    let app = Router::new()
        .route("/wx/kf/callback", get(verify))
        .route("/wx/kf/callback", post(callback))
        .with_state(state);

    // Bind and serve
    let addr: SocketAddr = "0.0.0.0:3000".parse().unwrap();
    tracing::info!("WeChat Kf callback server listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

/// Helper to read a required env var with a friendly error.
fn get_env(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("missing env var: {}", key))
}

/// Extract a field's text from a simple XML string.
/// Looks for the first occurrence of <FieldName>...</FieldName>, supporting both
/// CDATA and plain text nodes.
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
