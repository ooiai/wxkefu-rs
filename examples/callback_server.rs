use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use dotenvy::dotenv;
use serde::Deserialize;
use std::{env, net::SocketAddr, sync::Arc};
use wxkefu_rs::callback::{self, KfEvent, KfMessage};

#[derive(Clone)]
struct AppState {
    token: String,
    encoding_aes_key: String,
    // Optional receiver verification (e.g., your corpid 'ww...').
    expected_receiver_id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct CallbackQuery {
    // Kf (encrypted) URL verification uses msg_signature + echostr
    msg_signature: Option<String>,
    // OA (plaintext) URL verification uses signature + echostr
    signature: Option<String>,
    timestamp: Option<String>,
    nonce: Option<String>,
    echostr: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenv();

    let token =
        env::var("WXKF_TOKEN").expect("Set WXKF_TOKEN to the callback Token you configured");
    let encoding_aes_key = env::var("WXKF_ENCODING_AES_KEY")
        .expect("Set WXKF_ENCODING_AES_KEY to the 43-char EncodingAESKey");

    // Optional; for Kf this is commonly the corpid (ww...).
    let expected_receiver_id = env::var("WXKF_RECEIVER_ID")
        .ok()
        .or_else(|| env::var("WXKF_CORP_ID").ok());

    // Validate EncodingAESKey early to surface misconfiguration quickly.
    if !callback::verify_encoding_aes_key(&encoding_aes_key) {
        panic!("WXKF_ENCODING_AES_KEY is invalid: it must be 43 chars and decode to 32 bytes");
    }

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    let state = Arc::new(AppState {
        token,
        encoding_aes_key,
        expected_receiver_id,
    });

    let app = Router::new()
        .route("/callback", get(callback_get).post(callback_post))
        .with_state(state);

    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    println!("WeChat Kf callback server listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;

    Ok(())
}

// GET /callback
// - Kf (encrypted): verify msg_signature and decrypt echostr, then return the plaintext echo.
// - OA (plaintext): verify signature and return echostr as-is.
async fn callback_get(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CallbackQuery>,
) -> impl IntoResponse {
    let ts = match &q.timestamp {
        Some(s) => s.as_str(),
        None => return (StatusCode::BAD_REQUEST, "missing timestamp").into_response(),
    };
    let nonce = match &q.nonce {
        Some(s) => s.as_str(),
        None => return (StatusCode::BAD_REQUEST, "missing nonce").into_response(),
    };

    if let (Some(sig), Some(echo)) = (&q.msg_signature, &q.echostr) {
        // Kf encrypted URL verification
        match callback::verify_and_decrypt_echostr(
            &state.token,
            &state.encoding_aes_key,
            ts,
            nonce,
            sig,
            echo,
            state.expected_receiver_id.as_deref(),
        ) {
            Ok(plain_echo) => plain_echo.into_response(),
            Err(_) => (StatusCode::FORBIDDEN, "signature/decrypt error").into_response(),
        }
    } else if let (Some(sig), Some(echo)) = (&q.signature, &q.echostr) {
        // OA plaintext URL verification
        if callback::verify_url_signature(&state.token, ts, nonce, sig) {
            echo.clone().into_response()
        } else {
            (StatusCode::FORBIDDEN, "signature mismatch").into_response()
        }
    } else {
        (StatusCode::BAD_REQUEST, "missing signature/echostr").into_response()
    }
}

// POST /callback
// - Query: msg_signature, timestamp, nonce
// - Body: XML or JSON containing Encrypt/encrypt, or plaintext for specific notifications.
// Behavior:
//   1) If Encrypt present: verify signature and decrypt to plaintext
//   2) Otherwise: treat body as plaintext
//   3) Optionally parse minimal event info; always reply "success"
async fn callback_post(
    State(state): State<Arc<AppState>>,
    Query(q): Query<CallbackQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid utf-8 body").into_response(),
    };

    let ts = match &q.timestamp {
        Some(s) => s.as_str(),
        None => return (StatusCode::BAD_REQUEST, "missing timestamp").into_response(),
    };
    let nonce = match &q.nonce {
        Some(s) => s.as_str(),
        None => return (StatusCode::BAD_REQUEST, "missing nonce").into_response(),
    };
    let sig = match &q.msg_signature {
        Some(s) => s.as_str(),
        None => return (StatusCode::BAD_REQUEST, "missing msg_signature").into_response(),
    };

    let plaintext = match callback::handle_callback_raw(
        &state.token,
        &state.encoding_aes_key,
        ts,
        nonce,
        sig,
        body_str,
        state.expected_receiver_id.as_deref(),
    ) {
        Ok(p) => p,
        Err(_) => return (StatusCode::BAD_REQUEST, "decrypt/verify error").into_response(),
    };

    // Minimal, deterministic handling:
    // - Attempt to parse a simple event envelope; otherwise treat as plain.
    match callback::parse_kf_plaintext(&plaintext) {
        Ok(KfMessage::Event(KfEvent::KfMsgOrEventNotification {
            to_user_name,
            create_time,
            token,
            open_kfid,
        })) => {
            // Use fields or log as needed; keep deterministic and minimal.
            if let Some(t) = token {
                println!(
                    "kf_msg_or_event: to={:?} time={:?} token=***{} open_kfid={:?}",
                    to_user_name,
                    create_time,
                    &t.chars().rev().take(6).collect::<String>(), // masked tail
                    open_kfid
                );
            } else {
                println!(
                    "kf_msg_or_event: to={:?} time={:?} token=None open_kfid={:?}",
                    to_user_name, create_time, open_kfid
                );
            }
        }
        Ok(KfMessage::Plain(s)) => {
            // Decrypted or plaintext callback body; application can parse as needed.
            println!("plain callback body ({} bytes)", s.len());
        }
        Ok(KfMessage::Event(KfEvent::Unknown(_))) => {
            println!("unknown event");
        }
        Ok(KfMessage::Unknown(_)) | Err(_) => {
            println!("unrecognized callback content");
        }
    }

    // Per WeChat convention, respond with "success"
    "success".into_response()
}
