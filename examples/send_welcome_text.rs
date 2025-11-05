/*!
Example: Send a welcome text message via WeCom (Kf) send_msg_on_event

This example demonstrates sending a customer service welcome message using the one-time
`welcome_code` (aka `code`) included in the "enter_session" event callback.

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_WELCOME_CODE=code_from_event \    # preferred env var
  [optional] WXKF_CODE=code_from_event \ # fallback env var name
  [optional] WXKF_TEXT="Welcome!" \
  [optional] WXKF_MSGID=custom_msg_id \
  cargo run --example send_welcome_text

Notes:
- The code (welcome_code) can be used only once and typically must be used within ~20 seconds
  after receiving the event, otherwise it becomes invalid.
- Only an access_token obtained using the WeChat Customer Service (Kf) Secret can call this API.
*/

use anyhow::{Context, Result};
use dotenvy::dotenv;
use std::env;
use wxkefu_rs::send_msg::TextContent;
use wxkefu_rs::send_msg_on_event::{SendMsgOnEventPayload, SendMsgOnEventRequest};
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();

    // Required environment variables
    let corp_id =
        env::var("WXKF_CORP_ID").context("set WXKF_CORP_ID (WeCom corpid, starts with 'ww')")?;
    let corp_secret = env::var("WXKF_APP_SECRET")
        .context("set WXKF_APP_SECRET (WeChat Customer Service Secret)")?;

    // The event one-time code (welcome_code). Prefer WXKF_WELCOME_CODE; fallback to WXKF_CODE.
    let code = env::var("WXKF_WELCOME_CODE")
        .or_else(|_| env::var("WXKF_CODE"))
        .context("set WXKF_WELCOME_CODE (or WXKF_CODE) to the one-time code from event callback")?;

    // Optional environment variables
    let text = env::var("WXKF_TEXT").unwrap_or_else(|_| "Welcome!".to_string());
    let msgid = env::var("WXKF_MSGID").ok();

    // 1) Acquire WeCom Kf access_token
    let client = KfClient::default();
    let at = client
        .get_access_token(&Auth::WeCom {
            corp_id,
            corp_secret,
        })
        .await
        .context("failed to get WeCom (Kf) access_token")?;

    // 2) Build the send_msg_on_event request (text only)
    let req = SendMsgOnEventRequest {
        code,
        msgid,
        payload: SendMsgOnEventPayload::Text {
            text: TextContent { content: text },
        },
    };

    // 3) Call kf/send_msg_on_event
    let resp = client
        .send_msg_on_event(&at.access_token, &req)
        .await
        .context("send_msg_on_event request failed")?;

    println!(
        "send_msg_on_event ok: errcode={}, errmsg={}, msgid={:?}",
        resp.errcode, resp.errmsg, resp.msgid
    );

    Ok(())
}
