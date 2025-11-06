/*!
Example: Send a welcome menu message via WeCom (Kf) send_msg_on_event (msgmenu)

This example demonstrates sending a customer service welcome "menu" message using the one-time
`welcome_code` (aka `code`) included in the "enter_session" event callback.

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_WELCOME_CODE=code_from_event \    # preferred env var
  [optional] WXKF_CODE=code_from_event \ # fallback env var name
  [optional] WXKF_MSGID=custom_msg_id \
  [optional] WXKF_MENU_HEAD="Are you satisfied with the service?" \
  [optional] WXKF_MENU_TAIL="Thanks for your feedback!" \
  cargo run --example send_welcome_menu

Notes:
- The code (welcome_code) can be used only once and typically must be used within ~20 seconds
  after receiving the event, otherwise it becomes invalid.
- Only an access_token obtained using the WeChat Customer Service (Kf) Secret can call this API.
*/

use anyhow::{Context, Result};
use dotenvy::dotenv;
use std::env;
use wxkefu_rs::send_msg::{
    MsgMenuClick, MsgMenuContent, MsgMenuItem, MsgMenuMiniProgram, MsgMenuText, MsgMenuView,
};
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
    let msgid = env::var("WXKF_MSGID").ok();
    let head = env::var("WXKF_MENU_HEAD")
        .unwrap_or_else(|_| "Are you satisfied with the service?".to_string());
    let tail =
        env::var("WXKF_MENU_TAIL").unwrap_or_else(|_| "Thanks for your feedback!".to_string());

    // 1) Acquire WeCom Kf access_token
    let client = KfClient::default();
    let at = client
        .get_access_token(&Auth::WeCom {
            corp_id,
            corp_secret,
        })
        .await
        .context("failed to get WeCom (Kf) access_token")?;

    // 2) Build a menu message (msgmenu)
    // You can customize by editing env-based values above or modify items here.
    let mut list = Vec::new();

    // Click items (user reply is a text with attached menu id)
    list.push(MsgMenuItem::Click {
        click: MsgMenuClick {
            id: Some("101".into()),
            content: "Satisfied".into(),
        },
    });
    list.push(MsgMenuItem::Click {
        click: MsgMenuClick {
            id: Some("102".into()),
            content: "Not satisfied".into(),
        },
    });

    // View item (jump to URL)
    list.push(MsgMenuItem::View {
        view: MsgMenuView {
            url: "https://work.weixin.qq.com".into(),
            content: "Open self-service portal".into(),
        },
    });

    // Mini program item (sample values; replace with your appid and pagepath)
    list.push(MsgMenuItem::MiniProgram {
        miniprogram: MsgMenuMiniProgram {
            appid: "wx123123123123123".into(),
            pagepath: "pages/index?userid=zhangsan&orderid=123123123".into(),
            content: "Open Mini Program".into(),
        },
    });

    // Plain text item (supports literal '\n')
    list.push(MsgMenuItem::Text {
        text: MsgMenuText {
            content: "Plain text item\nSupports newline".into(),
            no_newline: Some(0),
        },
    });

    let msgmenu = MsgMenuContent {
        head_content: Some(head),
        list,
        tail_content: Some(tail),
    };

    // 3) Build the send_msg_on_event request
    let req = SendMsgOnEventRequest {
        code,
        msgid,
        payload: SendMsgOnEventPayload::MsgMenu { msgmenu },
    };

    // 4) Call kf/send_msg_on_event
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
