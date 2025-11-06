/*!
Example: Send a text message via WeCom (Kf) send_msg

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_TOUSER=EXTERNAL_USERID \
  WXKF_OPEN_KFID=OPEN_KFID \
  [optional] WXKF_TEXT="hello from wxkefu-rs" \
  [optional] WXKF_MSGID=custom_msg_id \
  cargo run --example send_text

Notes:
- Only an access_token obtained using the WeChat Customer Service (Kf) Secret can call this API.
- Within 48 hours after a customer sends a message, you may send up to 5 messages to that customer.
- If WXKF_MSGID is provided, ensure it is unique within the same open_kfid; otherwise, the API will return an error.
*/

use anyhow::{Context, Result};
use dotenvy::dotenv;
use std::env;
use wxkefu_rs::send_msg::{SendMsgPayload, SendMsgRequest, TextContent};
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();

    // Required environment variables
    let corp_id =
        env::var("WXKF_CORP_ID").context("set WXKF_CORP_ID (WeCom corpid, starts with 'ww')")?;
    let corp_secret = env::var("WXKF_APP_SECRET")
        .context("set WXKF_APP_SECRET (WeChat Customer Service Secret)")?;
    let touser = env::var("WXKF_TOUSER")
        .or_else(|_| env::var("WXKF_EXTERNAL_USERID"))
        .context("set WXKF_TOUSER (or WXKF_EXTERNAL_USERID) to the target external_userid")?;
    let open_kfid = env::var("WXKF_OPEN_KFID").context("set WXKF_OPEN_KFID (Kf account ID)")?;

    // Optional environment variables
    let text = env::var("WXKF_TEXT").unwrap_or_else(|_| "hello from wxkefu-rs".to_string());
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

    // 2) Build the send_msg request
    let req = SendMsgRequest {
        touser,
        open_kfid,
        msgid,
        payload: SendMsgPayload::Text {
            text: TextContent { content: text },
        },
    };

    // 3) Call kf/send_msg
    let resp = client
        .send_msg(&at.access_token, &req)
        .await
        .context("send_msg request failed")?;

    println!(
        "send_msg ok: errcode={}, errmsg={}, msgid={:?}",
        resp.errcode, resp.errmsg, resp.msgid
    );

    Ok(())
}
