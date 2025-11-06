/*!
Example: Recall a sent message via WeCom (Kf) recall_msg

This example recalls a message that was previously sent using the send_msg API.
You must recall within 2 minutes after sending. Recalled messages still count
against the "5 messages within 48 hours" limit.

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_MSGID=the_message_id_to_recall \
  WXKF_OPEN_KFID=the_kf_account_id \
  cargo run --example recall_msg
*/

use anyhow::{Context, Result};
use dotenvy::dotenv;
use std::env;
use wxkefu_rs::recall_msg::RecallMsgRequest;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();

    // Required environment variables
    let corp_id =
        env::var("WXKF_CORP_ID").context("set WXKF_CORP_ID (WeCom corpid, starts with 'ww')")?;
    let corp_secret = env::var("WXKF_APP_SECRET")
        .context("set WXKF_APP_SECRET (WeChat Customer Service Secret)")?;
    let msgid = env::var("WXKF_MSGID")
        .context("set WXKF_MSGID (the message id to recall within 2 minutes)")?;
    let open_kfid = env::var("WXKF_OPEN_KFID").context("set WXKF_OPEN_KFID (the Kf account id)")?;

    // 1) Acquire WeCom Kf access_token
    let client = KfClient::default();
    let at = client
        .get_access_token(&Auth::WeCom {
            corp_id,
            corp_secret,
        })
        .await
        .context("failed to get WeCom (Kf) access_token")?;

    // 2) Build recall_msg request
    let req = RecallMsgRequest { msgid, open_kfid };

    // 3) Call kf/recall_msg
    let resp = client
        .recall_msg(&at.access_token, &req)
        .await
        .context("recall_msg request failed")?;

    println!(
        "recall_msg ok: errcode={}, errmsg={}",
        resp.errcode, resp.errmsg
    );

    Ok(())
}
