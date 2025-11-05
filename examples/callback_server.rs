use axum::extract::OriginalUri;
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
        .expect("Please set WXKF_TOKEN to the callback token you configured in Kf admin.")
        .trim()
        .to_string();
    let encoding_aes_key = env::var("WXKF_ENCODING_AES_KEY").expect(
        "Please set WXKF_ENCODING_AES_KEY to the 43-char EncodingAESKey from Kf admin (Developer Config).",
    ).trim().to_string();
    // Validate EncodingAESKey format early to surface misconfiguration quickly.
    if !callback::verify_encoding_aes_key(&encoding_aes_key) {
        eprintln!(
            "Warning: WXKF_ENCODING_AES_KEY appears invalid (must be 43 chars and decode to 32 bytes). The server will continue, but decryption will likely fail."
        );
    }
    // Optional; if provided, will be checked against the decrypted tail.
    // For WeCom/Kf this is commonly the corpid (ww...).
    let expected_receiver_id = env::var("WXKF_RECEIVER_ID")
        .ok()
        .or_else(|| env::var("WXKF_CORP_ID").ok())
        .map(|s| s.trim().to_string());

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
    original_uri: OriginalUri,
) -> impl IntoResponse {
    // Log the raw request URI (includes original path and query) to diagnose signature issues.
    eprintln!("raw request uri: {:?}", original_uri);
    let ts = match &q.timestamp {
        Some(s) => s.as_str(),
        None => {
            let resp_body = "missing timestamp";
            eprintln!("GET /callback response: {}", resp_body);
            return (StatusCode::BAD_REQUEST, resp_body).into_response();
        }
    };
    let nonce = match &q.nonce {
        Some(s) => s.as_str(),
        None => {
            let resp_body = "missing nonce";
            eprintln!("GET /callback response: {}", resp_body);
            return (StatusCode::BAD_REQUEST, resp_body).into_response();
        }
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
        // Token fingerprint to ensure correct token is used (length and head/tail only).
        let tlen = state.token.len();
        let thead = &state.token[..tlen.min(4)];
        let ttail = &state.token[tlen.saturating_sub(4)..];
        eprintln!(
            "token dbg: len={}, head='{}', tail='{}'",
            tlen, thead, ttail
        );

        // Compute signatures using the raw echostr as it appears in the OriginalUri (percent-encoded).
        let raw_uri_str = original_uri.to_string();
        let raw_echostr_opt = raw_uri_str
            .split('?')
            .nth(1)
            .and_then(|q| q.split('&').find(|kv| kv.starts_with("echostr=")))
            .map(|kv| kv["echostr=".len()..].to_string());
        if let Some(raw_echostr) = raw_echostr_opt.as_deref() {
            let raw_tail = if raw_echostr.len() >= 4 {
                &raw_echostr[raw_echostr.len() - 4..]
            } else {
                raw_echostr
            };
            let calc_sorted_raw = callback::sha1_signature(&[&state.token, ts, nonce, raw_echostr]);
            let calc_concat_raw =
                callback::sha1_signature_concat(&[&state.token, ts, nonce, raw_echostr]);
            eprintln!(
                "sig dbg (raw echostr): sorted_raw={}, concat_raw={}, raw_tail='{}'",
                calc_sorted_raw, calc_concat_raw, raw_tail
            );
        }
        // Additional signature diagnostics to help identify mismatches.
        let echo_norm = echo.replace(' ', "+");
        let calc_sorted = callback::sha1_signature(&[&state.token, ts, nonce, &echo_norm]);
        let calc_concat = callback::sha1_signature_concat(&[&state.token, ts, nonce, &echo_norm]);
        let ntail = if echo_norm.len() >= 4 {
            &echo_norm[echo_norm.len() - 4..]
        } else {
            echo_norm.as_str()
        };
        eprintln!(
            "sig dbg: provided={}, sorted={}, concat={}, ts={}, nonce_len={}, echo_norm_tail='{}'",
            sig,
            calc_sorted,
            calc_concat,
            ts,
            nonce.len(),
            ntail
        );
        // Use shared helper which verifies signature and decrypts (handles URL-safe base64 and padding).
        match callback::verify_and_decrypt_echostr_candidates(
            &state.token,
            &state.encoding_aes_key,
            ts,
            nonce,
            sig,
            echo,
            raw_echostr_opt.as_deref(),
            state.expected_receiver_id.as_deref(),
        ) {
            Ok(plain_echo) => {
                // Must return the plaintext echo for verification to succeed.
                println!("GET /callback response: {}", plain_echo);
                plain_echo.into_response()
            }
            Err(e) => {
                eprintln!("echo decrypt error: {e}");
                // Fallback: verify signature against raw percent-encoded echostr,
                // then decrypt using the decoded echostr from the parsed query.
                if let Some(raw_echostr) = raw_echostr_opt.as_deref() {
                    if callback::verify_msg_signature(&state.token, ts, nonce, raw_echostr, sig) {
                        match callback::decrypt_b64_message(
                            &state.encoding_aes_key,
                            echo,
                            state.expected_receiver_id.as_deref(),
                        ) {
                            Ok(plain_echo) => {
                                println!("GET /callback response: {}", plain_echo);
                                return plain_echo.into_response();
                            }
                            Err(e2) => {
                                eprintln!("echo decrypt error (fallback verified): {e2}");
                            }
                        }
                    }
                }
                {
                    let resp_body = "decrypt error";
                    eprintln!("GET /callback response: {}", resp_body);
                    (StatusCode::BAD_REQUEST, resp_body).into_response()
                }
            }
        }
    } else if let (Some(sig), Some(echo)) = (&q.signature, &q.echostr) {
        // Unencrypted URL verification (OA style)
        if !callback::verify_url_signature(&state.token, ts, nonce, sig) {
            {
                let resp_body = "signature mismatch";
                eprintln!("GET /callback response: {}", resp_body);
                return (StatusCode::FORBIDDEN, resp_body).into_response();
            }
        }
        {
            println!("GET /callback response: {}", echo);
            echo.clone().into_response()
        }
    } else {
        {
            let resp_body = "missing signature/echostr";
            eprintln!("GET /callback response: {}", resp_body);
            (StatusCode::BAD_REQUEST, resp_body).into_response()
        }
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
    original_uri: OriginalUri,
    body: Bytes,
) -> impl IntoResponse {
    // Log the raw request URI (includes original path and query) to diagnose signature issues.
    eprintln!("raw request uri: {:?}", original_uri);
    let body_str = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => {
            let resp_body = "invalid utf-8 body";
            eprintln!("POST /callback response: {}", resp_body);
            return (StatusCode::BAD_REQUEST, resp_body).into_response();
        }
    };

    // Debug: log Encrypt field info from POST body before verify/decrypt
    let enc_dbg = match callback::detect_format(body_str.as_bytes()) {
        callback::CallbackFormat::Xml => callback::extract_encrypt_from_xml(body_str),
        callback::CallbackFormat::Json => {
            callback::extract_encrypt_from_json(body_str).ok().flatten()
        }
    };
    match enc_dbg.as_deref() {
        Some(enc) => {
            let elen = enc.len();
            let etail = if elen >= 4 { &enc[elen - 4..] } else { enc };
            eprintln!("POST body Encrypt info: len={}, tail='{}'", elen, etail);
        }
        None => {
            eprintln!("POST body Encrypt info: not found");
        }
    }

    let ts = match &q.timestamp {
        Some(s) => s.as_str(),
        None => {
            let resp_body = "missing timestamp";
            eprintln!("POST /callback response: {}", resp_body);
            return (StatusCode::BAD_REQUEST, resp_body).into_response();
        }
    };
    let nonce = match &q.nonce {
        Some(s) => s.as_str(),
        None => {
            let resp_body = "missing nonce";
            eprintln!("POST /callback response: {}", resp_body);
            return (StatusCode::BAD_REQUEST, resp_body).into_response();
        }
    };
    let sig = match &q.msg_signature {
        Some(s) => s.as_str(),
        None => {
            let resp_body = "missing msg_signature";
            eprintln!("POST /callback response: {}", resp_body);
            return (StatusCode::BAD_REQUEST, resp_body).into_response();
        }
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

            // Try to extract event 'token' (for sys_msg usage; valid for ~10 minutes).
            if let Some(t) = callback::extract_event_token(&plaintext) {
                println!("Event token: {}", t);
            }

            // Parse plaintext into typed message and log essential fields.
            if let Ok(msg) = callback::parse_kf_plaintext(&plaintext) {
                match msg {
                    KfMessage::Text(t) => {
                        println!(
                            "Parsed: text content='{}' menu_id={:?}",
                            t.content, t.menu_id
                        );
                    }
                    KfMessage::Image(m) => println!("Parsed: image media_id='{}'", m.media_id),
                    KfMessage::Voice(m) => println!("Parsed: voice media_id='{}'", m.media_id),
                    KfMessage::Video(m) => println!("Parsed: video media_id='{}'", m.media_id),
                    KfMessage::File(m) => println!("Parsed: file media_id='{}'", m.media_id),
                    KfMessage::Location(loc) => {
                        println!(
                            "Parsed: location lat={} lng={} name={:?} address={:?}",
                            loc.latitude, loc.longitude, loc.name, loc.address
                        );
                    }
                    KfMessage::Miniprogram(mp) => {
                        println!(
                            "Parsed: miniprogram title={:?} appid={:?} pagepath={:?} thumb_media_id={:?}",
                            mp.title, mp.appid, mp.pagepath, mp.thumb_media_id
                        );
                    }
                    KfMessage::ChannelsShopProduct(p) => {
                        println!(
                            "Parsed: channels_shop_product id={:?} title={:?} price={:?}",
                            p.product_id, p.title, p.sales_price
                        );
                    }
                    KfMessage::ChannelsShopOrder(o) => {
                        println!(
                            "Parsed: channels_shop_order order_id={:?} titles={:?} state={:?}",
                            o.order_id, o.product_titles, o.state
                        );
                    }
                    KfMessage::MergedMsg(m) => {
                        println!(
                            "Parsed: merged_msg title={:?} items={}",
                            m.title,
                            m.item.len()
                        );
                    }
                    KfMessage::Channels(c) => {
                        println!(
                            "Parsed: channels sub_type={:?} nickname={:?} title={:?}",
                            c.sub_type, c.nickname, c.title
                        );
                    }
                    KfMessage::Note => println!("Parsed: note"),
                    KfMessage::Event(ev) => match ev {
                        KfEvent::EnterSession {
                            open_kfid,
                            external_userid,
                            scene,
                            scene_param,
                            welcome_code,
                            wechat_channels_nickname,
                            wechat_channels_scene,
                        } => {
                            println!(
                                "Parsed: event enter_session open_kfid={:?} external_userid={:?} scene={:?} scene_param={:?} welcome_code={:?} wc_nickname={:?} wc_scene={:?}",
                                open_kfid,
                                external_userid,
                                scene,
                                scene_param,
                                welcome_code,
                                wechat_channels_nickname,
                                wechat_channels_scene
                            );
                        }
                        KfEvent::MsgSendFail {
                            open_kfid,
                            external_userid,
                            fail_msgid,
                            fail_type,
                        } => {
                            println!(
                                "Parsed: event msg_send_fail open_kfid={:?} external_userid={:?} fail_msgid={:?} fail_type={:?}",
                                open_kfid, external_userid, fail_msgid, fail_type
                            );
                        }
                        KfEvent::UserRecallMsg {
                            open_kfid,
                            external_userid,
                            recall_msgid,
                        } => {
                            println!(
                                "Parsed: event user_recall_msg open_kfid={:?} external_userid={:?} recall_msgid={:?}",
                                open_kfid, external_userid, recall_msgid
                            );
                        }
                        KfEvent::KfMsgOrEventNotification {
                            to_user_name,
                            create_time,
                            token,
                            open_kfid,
                        } => {
                            println!(
                                "Parsed: event kf_msg_or_event to_user_name={:?} create_time={:?} token={:?} open_kfid={:?}",
                                to_user_name, create_time, token, open_kfid
                            );
                        }
                        KfEvent::Unknown { event_type, .. } => {
                            println!("Parsed: event unknown type={:?}", event_type);
                        }
                    },
                    KfMessage::UnknownJson { msgtype, .. } => {
                        println!("Parsed: unknown json msgtype='{}'", msgtype);
                    }
                    KfMessage::UnknownXml { name, .. } => {
                        println!("Parsed: unknown xml '{}'", name);
                    }
                }
            }

            // Per WeChat convention, responding with "success" acknowledges receipt.
            {
                let resp_body = "success";
                println!("POST /callback response: {}", resp_body);
                resp_body.into_response()
            }
        }
        Err(e) => {
            eprintln!("callback decrypt/verify error: {e}");
            {
                let resp_body = "decrypt/verify error";
                eprintln!("POST /callback response: {}", resp_body);
                (StatusCode::BAD_REQUEST, resp_body).into_response()
            }
        }
    }
}
