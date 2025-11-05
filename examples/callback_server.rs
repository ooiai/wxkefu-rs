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
use wxkefu_rs::callback;

#[derive(Clone)]
struct AppState {
    token: String,
    encoding_aes_key: String,
    /// Optional receiver id verification. For Kf (WeCom) this is typically the corpid (ww...).
    expected_receiver_id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct CallbackQuery {
    // Both forms are accepted; WeCom(Kf) typically uses msg_signature with encrypt.
    signature: Option<String>,
    msg_signature: Option<String>,
    timestamp: Option<String>,
    nonce: Option<String>,
    echostr: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Run with:
    //   WXKF_TOKEN=your_token \
    //   WXKF_ENCODING_AES_KEY=your_43_char_key \
    //   WXKF_CORP_ID=your_ww..._corpid \
    //   cargo run --example callback_server
    //
    // Then configure the callback URL in the Kf admin console like:
    //   https://your.domain/callback
    //
    // Note:
    // - For URL verification (GET), WeCom/Kf uses msg_signature + echostr (encrypted echo).
    // - For message delivery (POST), body contains Encrypt field in XML or JSON,
    //   and query includes msg_signature, timestamp, nonce.

    let _ = dotenv();

    let token = env::var("WXKF_TOKEN")
        .expect("Please set WXKF_TOKEN to the callback token you configured in Kf admin.");
    let encoding_aes_key = env::var("WXKF_ENCODING_AES_KEY").expect(
        "Please set WXKF_ENCODING_AES_KEY to the 43-char EncodingAESKey from Kf admin (Developer Config).",
    );
    // Optional; if provided, will be checked against the decrypted tail.
    // For WeCom/Kf this is commonly the corpid (ww...).
    let expected_receiver_id = env::var("WXKF_RECEIVER_ID")
        .ok()
        .or_else(|| env::var("WXKF_CORP_ID").ok());

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
    println!("Kf callback server listening on http://{addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;

    Ok(())
}

// GET /callback: URL verification
// - Kf/WeCom: msg_signature + echostr (encrypted); verify and decrypt echostr, then return the plaintext echo.
// - OA (unencrypted): signature + echostr; verify and return echostr as-is.
// This example supports both for convenience, but Kf should use the encrypted form.
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
        // Encrypted URL verification (WeCom/Kf)
        // Non-sensitive diagnostics: echo length and tail to help identify malformed inputs.
        let elen = echo.len();
        let etail = if elen >= 4 {
            &echo[elen - 4..]
        } else {
            echo.as_str()
        };
        eprintln!("echo info: len={}, tail='{}'", elen, etail);
        // Use shared helper which verifies signature and decrypts (handles URL-safe base64 and padding).
        match callback::verify_and_decrypt_echostr(
            &state.token,
            &state.encoding_aes_key,
            ts,
            nonce,
            sig,
            echo,
            state.expected_receiver_id.as_deref(),
        ) {
            Ok(plain_echo) => {
                // Must return the plaintext echo for verification to succeed.
                plain_echo.into_response()
            }
            Err(e) => {
                eprintln!("echo decrypt error: {e}");
                (StatusCode::BAD_REQUEST, "decrypt error").into_response()
            }
        }
    } else if let (Some(sig), Some(echo)) = (&q.signature, &q.echostr) {
        // Unencrypted URL verification (OA style)
        if !callback::verify_url_signature(&state.token, ts, nonce, sig) {
            return (StatusCode::FORBIDDEN, "signature mismatch").into_response();
        }
        echo.clone().into_response()
    } else {
        (StatusCode::BAD_REQUEST, "missing signature/echostr").into_response()
    }
}

// POST /callback: receive encrypted messages/events
// - Query: msg_signature, timestamp, nonce
// - Body: XML or JSON containing Encrypt/encrypt
// Steps:
//   1) Extract Encrypt from body (XML or JSON).
//   2) Verify signature with token, timestamp, nonce, Encrypt.
//   3) Decrypt with EncodingAESKey.
//   4) Process the decrypted payload (often JSON for Kf).
//   5) Return "success".
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

    match callback::handle_callback_raw(
        &state.token,
        &state.encoding_aes_key,
        ts,
        nonce,
        sig,
        body_str,
        state.expected_receiver_id.as_deref(),
    ) {
        Ok(plaintext) => {
            // The plaintext is the actual event/message content.
            // For Kf, this is typically JSON. Print it for demo purposes.
            // In production, parse it and implement your business logic.
            println!("Decrypted Kf message:\n{}", plaintext);

            // Per WeChat convention, responding with "success" acknowledges receipt.
            "success".into_response()
        }
        Err(e) => {
            eprintln!("callback decrypt/verify error: {e}");
            (StatusCode::BAD_REQUEST, "decrypt/verify error").into_response()
        }
    }
}
