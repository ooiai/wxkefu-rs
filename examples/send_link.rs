/*!
Example: Send a link message via WeCom (Kf) send_msg

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_TOUSER=EXTERNAL_USERID \
  WXKF_OPEN_KFID=OPEN_KFID \
  WXKF_LINK_TITLE="Your Title" \
  WXKF_LINK_URL="https://example.com" \
  WXKF_LINK_THUMB_MEDIA_ID=MEDIA_ID \
  [optional] WXKF_LINK_DESC="Your Description" \
  [optional] WXKF_MSGID=custom_msg_id \
  cargo run --example send_link

Notes:
- Only an access_token obtained using the WeChat Customer Service (Kf) Secret can call this API.
- Within 48 hours after a customer sends a message, you may send up to 5 messages to that customer.
- If WXKF_MSGID is provided, ensure it is unique within the same open_kfid; otherwise, the API will return an error.
- WXKF_LINK_THUMB_MEDIA_ID must be obtained from the temporary material upload API.
*/

use anyhow::{Context, Result};
use dotenvy::dotenv;
use std::env;
use wxkefu_rs::send_msg::{LinkContent, SendMsgPayload, SendMsgRequest};
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
    let title = env::var("WXKF_LINK_TITLE").context("set WXKF_LINK_TITLE (link title)")?;
    let url = env::var("WXKF_LINK_URL").context("set WXKF_LINK_URL (link url)")?;
    let thumb_media_id = env::var("WXKF_LINK_THUMB_MEDIA_ID")
        .context("set WXKF_LINK_THUMB_MEDIA_ID (thumb media_id from upload API)")?;

    // Optional environment variables
    let desc = env::var("WXKF_LINK_DESC").ok();
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

    // 2) Build the send_msg request for a link
    let req = SendMsgRequest {
        touser,
        open_kfid,
        msgid,
        payload: SendMsgPayload::Link {
            link: LinkContent {
                title,
                desc,
                url,
                thumb_media_id,
            },
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
