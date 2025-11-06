# wxkefu-rs

WeChat Customer Service (WeCom Kf) client for Rust. This crate focuses on integrating WeChat Customer Service APIs: token acquisition (WeCom Kf), encrypted callback helpers, message pull and send, media upload/get, welcome message, recall, customer profiles, Kf account management, error helpers, and runnable examples.

Official product info and docs:

- Product: https://kf.weixin.qq.com/
- API docs: https://kf.weixin.qq.com/api/doc/path/93304

Highlights

- WeCom (Enterprise WeChat) Customer Service (Kf) API client in Rust
- Encrypted callback utilities (signature verification + AES decryption)
- Message sync (pull) and message sending (text, image, link, etc.)
- Welcome message on event (enter_session)
- Media upload/get (temporary materials)
- Message recall (2-minute window)
- Customer basic info (batchget)
- Kf account management (add, delete, update, list, add_contact_way)
- Global error-code helpers and examples
- Minimal dependencies with clear, typed requests/responses

Important scope notes

- WeCom Kf vs Official Account/Mini Program tokens:
  - Kf APIs require WeCom credentials: corpid (starts with ww) + WeChat Customer Service Secret (corpsecret).
  - OA/MP appid/appsecret tokens are NOT accepted by Kf endpoints.
- Token endpoints:
  - WeCom (Kf): https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=ID&corpsecret=SECRET
  - OA/MP: https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=APPSECRET
- Cache access_token and handle early invalidation (errcode 40014/40001).

## Install / Setup

Add this crate to your Cargo.toml. If you’re using the repository directly, a typical local path dependency looks like:

    [dependencies]
    wxkefu-rs = { path = "./wxkefu-rs" }

In your code, import with the underscore name (Rust turns '-' into '\_'):

    use wxkefu_rs::{Auth, KfClient};

Environment variables used by examples:

- WeCom (Kf): WXKF_CORP_ID, WXKF_APP_SECRET
- Callback development: WXKF_TOKEN, WXKF_AES_KEY
- Other examples may use additional vars (e.g., WXKF_OPEN_KFID, WXKF_TOUSER, WXKF_MEDIA_ID, etc.)

## Quick Start

Minimal example: fetch a WeCom (Kf) access token.

    use wxkefu_rs::{Auth, KfClient};

    #[tokio::main]
    async fn main() -> anyhow::Result<()> {
        let client = KfClient::default();
        let token = client
            .get_access_token(&Auth::WeCom {
                corp_id: std::env::var("WXKF_CORP_ID")?,
                corp_secret: std::env::var("WXKF_APP_SECRET")?,
            })
            .await?;
        println!("access_token={}, expires_in={}", token.access_token, token.expires_in);
        Ok(())
    }

Send a simple text message (requires valid external_userid and open_kfid). See examples/send_text.rs for a full runnable sample.

    use wxkefu_rs::{Auth, KfClient};
    use wxkefu_rs::send_msg::{SendMsgRequest, SendMsgPayload, TextContent};

    #[tokio::main]
    async fn main() -> anyhow::Result<()> {
        let corp_id = std::env::var("WXKF_CORP_ID")?;
        let corp_secret = std::env::var("WXKF_APP_SECRET")?;
        let access = KfClient::default()
            .get_access_token(&Auth::WeCom { corp_id, corp_secret })
            .await?;

        let req = SendMsgRequest {
            touser: std::env::var("WXKF_TOUSER")?, // external_userid
            open_kfid: std::env::var("WXKF_OPEN_KFID")?,
            msgid: None,
            payload: SendMsgPayload::Text { text: TextContent { content: "hello from wxkefu-rs".into() } },
        };
        let resp = KfClient::default().send_msg(&access.access_token, &req).await?;
        println!("send_msg: errcode={}, errmsg={}", resp.errcode, resp.errmsg);
        Ok(())
    }

Notes

- Respect WeChat Kf delivery limits: Up to 5 messages within 48 hours after the user sends a message.
- Recall is allowed only within 2 minutes for API-sent messages.
- Temporary media_id is valid for 3 days.

## Key APIs (modules)

Token and client

- token (re-exported at crate root)
  - Auth (WeCom | OfficialAccount)
  - KfClient
    - get_access_token(&Auth) -> AccessToken
  - Error / Result (unified error handling)

Callback utilities (framework-agnostic)

- callback
  - verify_and_decrypt_echostr(...) // URL verification
  - verify_and_decrypt_post_body(...) // handle POST callbacks
  - decrypt_b64_message(...) // low-level AES helper

Message sync (pull messages)

- sync_msg
  - KfClient::sync_msg(access_token, req) -> SyncMsgResponse
  - Handles pagination via next_cursor/has_more

Send messages

- send_msg
  - KfClient::send_msg(access_token, &SendMsgRequest) -> SendMsgResponse
  - Supports text, image, voice, video, file, link, miniprogram, msgmenu, location, business_card, ca_link

Welcome messages (on event)

- send_msg_on_event
  - KfClient::send_msg_on_event(access_token, &SendMsgOnEventRequest) -> ...
  - Use the one-time welcome_code from the enter_session event

Recall messages

- recall_msg
  - KfClient::recall_msg(access_token, &RecallMsgRequest) -> RecallMsgResponse
  - Only for API-sent messages within 2 minutes

Media management (temporary)

- media
  - KfClient::media_upload(access_token, media_type, filename, content_type, data) -> MediaUploadResponse
  - KfClient::media_get(access_token, media_id, range) -> MediaGetOk
  - Supports HTTP Range (206 Partial Content)

Customer profiles

- customer
  - KfClient::customer_batchget(access_token, &CustomerBatchGetRequest) -> CustomerBatchGetResponse

Kf account management

- account
  - KfClient::account_add(access_token, &AccountAddRequest) -> AccountAddResponse
  - KfClient::account_del(access_token, &AccountDelRequest) -> AccountDelResponse
  - KfClient::account_update(access_token, &AccountUpdateRequest) -> AccountUpdateResponse
  - KfClient::account_list(access_token, &AccountListRequest) -> AccountListResponse
  - KfClient::add_contact_way(access_token, &AddContactWayRequest) -> AddContactWayResponse

Key generation (token, EncodingAESKey)

- keygen
  - generate_token(len)
  - generate_encoding_aes_key()
  - verify_encoding_aes_key(key)

Global error helpers

- errors
  - explain(errcode, errmsg) -> String // one-line human-readable guidance
  - lookup/hint_for/category_for/should_retry/should_refresh_token
  - contains_wrong_json_format(errmsg) // detect “Warning: wrong json format.”

## Examples

Run any example with cargo run --example <name>. Supply required environment variables as described in the file headers.

- Token
  - examples/get_token.rs
- Sending messages
  - examples/send_text.rs
  - examples/send_image.rs
  - examples/send_link.rs
  - examples/send_welcome_text.rs
  - examples/send_welcome_menu.rs
- Sync (pull) messages
  - examples/pull_messages.rs
- Recall
  - examples/recall_msg.rs
- Media
  - examples/media_upload.rs
  - examples/media_get.rs
- Customer info
  - examples/customer_batchget.rs
- Kf account management
  - examples/account_add.rs
  - examples/account_del.rs
  - examples/account_more.rs // update, list, add_contact_way
- Callback utilities (echo + decrypt demo)
  - examples/callback_server.rs
- Keygen and error helpers
  - examples/keygen_example.rs
  - examples/error_help.rs

More examples:
See the examples/ directory for all runnable samples.

## Callback Setup

Configure your callback service with three items: URL, Token, and EncodingAESKey.

- URL: Your public callback endpoint (e.g., https://your.domain/callback). It must be reachable by WeChat Kf.
- Token: Alphanumeric (letters/digits), length up to 32. Used for SHA1 signature verification. Only you and WeChat Kf know it; it never appears in transit.
- EncodingAESKey: 43-character letters/digits only. Append a single '=' and Base64-decode to 32 bytes. Used to derive the AES-256 key (IV = first 16 bytes) for decrypting callback payloads.

Generate Token and EncodingAESKey

- Use the provided key generator example to produce values locally:
  - Run: cargo run --example keygen_example
  - TOKEN: random alphanumeric, default 32 chars
  - ENCODING_AES_KEY: 43 chars, letters/digits only; verify by appending '=' and Base64-decoding to 32 bytes

Set environment variables for the callback server (examples/callback_server.rs)

- WXKF_TOKEN: TOKEN from the key generator
- WXKF_ENCODING_AES_KEY: 43-char ENCODING_AES_KEY from the key generator
- WXKF_CORP_ID (or WXKF_RECEIVER_ID): Optional but recommended; typically your corpid (ww...) to validate the decrypted receiver id tail
- PORT: Optional, defaults to 3000

URL verification (GET /callback)

- WeCom/Kf sends msg_signature, timestamp, nonce, echostr (encrypted echo; Base64).
- The server verifies signature with Token and decrypts echostr using EncodingAESKey, and returns the plaintext echo.
- Important: echostr is provided by WeChat. Do not use your EncodingAESKey as echostr. If you see invalid base64 errors, ensure echostr is intact and not modified by proxies (e.g., plus signs must not become spaces).

Message/event delivery (POST /callback)

- Body contains Encrypt (XML or JSON wrapper). Query includes msg_signature, timestamp, nonce.
- Steps:
  1. Extract Encrypt
  2. Verify signature with Token, timestamp, nonce, Encrypt
  3. Decrypt using EncodingAESKey
  4. Process the decrypted payload (for Kf, this is typically JSON)
- For the kf_msg_or_event event, the decrypted JSON includes a short-lived token to call the kf/sync_msg API and an open_kfid that has new messages.

Library notes

- The callback helper normalizes Base64 to tolerate URL-safe alphabets and missing padding during decryption.
- Helper functions:
  - verify_and_decrypt_echostr(...) for GET verification
  - handle_callback_raw(...) or verify_and_decrypt_post_body(...) for POST decryption
- After decrypting kf_msg_or_event, call sync_msg with the short-lived token and paginate using next_cursor while has_more is true.

## Best Practices

- Cache access_token (typical 7200s). Implement auto-refresh and handle early invalidation (errcode 40014/40001).
- Do not log secrets or tokens. Redact sensitive values.
- Verify callback signatures and decrypt payloads per spec (SHA1 signature over token/timestamp/nonce/encrypt; AES-256-CBC).
- Comply with Kf constraints:
  - 48-hour + 5-message rule
  - Recall only within 2 minutes
  - Temporary media_id validity: 3 days
- UnionID availability depends on developer account binding (see official docs). Third-party service providers may not receive unionid via Kf API.

## Contributing

Issues and PRs welcome. For major changes, please start a discussion to align on direction.

## License

Add a LICENSE file (e.g., MIT/Apache-2.0) that suits your project’s needs.
