/*!
Example: Fetch customer basic info via WeCom (Kf) customer/batchget

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_EXTERNAL_USERIDS="wmxxxxxxxxxxxxxxxxxxxxxx, zhangsan" \
  [optional] WXKF_NEED_ENTER_SESSION_CONTEXT=1 \
  cargo run --example customer_batchget

Notes:
- Only an access_token obtained using the WeChat Customer Service (Kf) Secret can call this API.
- Each external_userid must have interacted (entered session or sent a message) within the last 48 hours,
  otherwise it will appear in invalid_external_userid.
*/

use anyhow::{Context, Result};
use dotenvy::dotenv;
use std::env;
use wxkefu_rs::customer::CustomerBatchGetRequest;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();

    // Read WeCom (Kf) credentials
    let corp_id = env::var("WXKF_CORP_ID")
        .context("set WXKF_CORP_ID (WeCom corpid, usually starts with 'ww')")?;
    let corp_secret = env::var("WXKF_APP_SECRET")
        .context("set WXKF_APP_SECRET (WeChat Customer Service Secret)")?;

    // External userids: prefer WXKF_EXTERNAL_USERIDS (comma/whitespace separated), fall back to WXKF_EXTERNAL_USERID
    let ids_raw = env::var("WXKF_EXTERNAL_USERIDS")
        .or_else(|_| env::var("WXKF_EXTERNAL_USERID"))
        .context("set WXKF_EXTERNAL_USERIDS (comma/space separated) or WXKF_EXTERNAL_USERID")?;
    let external_userid_list: Vec<String> = ids_raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    if external_userid_list.is_empty() {
        anyhow::bail!(
            "No valid external_userid provided. Set WXKF_EXTERNAL_USERIDS (comma/space separated) or WXKF_EXTERNAL_USERID."
        );
    }

    // Optional: whether to return 48h enter-session context
    let need_enter_session_context = env::var("WXKF_NEED_ENTER_SESSION_CONTEXT").ok().map(|v| {
        let v = v.trim().to_lowercase();
        v == "1" || v == "true" || v == "yes" || v == "y"
    });

    // Build client and fetch access_token
    let client = KfClient::default();
    let token = client
        .get_access_token(&Auth::WeCom {
            corp_id,
            corp_secret,
        })
        .await
        .context("failed to get access_token (ensure corpid + Kf Secret are correct)")?;

    // Build request
    let req = match need_enter_session_context {
        Some(flag) => {
            CustomerBatchGetRequest::new(external_userid_list).with_need_enter_session_context(flag)
        }
        None => CustomerBatchGetRequest::new(external_userid_list),
    };

    // Call API
    let resp = client
        .customer_batchget(&token.access_token, &req)
        .await
        .context("customer/batchget request failed")?;

    // Pretty print results
    println!("errcode: {}, errmsg: {}", resp.errcode, resp.errmsg);
    println!("-- customer_list ({}):", resp.customer_list.len());
    for (i, c) in resp.customer_list.iter().enumerate() {
        println!("  [{}] external_userid: {}", i, c.external_userid);
        if let Some(nick) = c.nickname.as_deref() {
            println!("       nickname: {}", nick);
        }
        if let Some(u) = c.unionid.as_deref() {
            println!("       unionid: {}", u);
        }
        if let Some(g) = c.gender {
            println!("       gender: {}", g);
        }
        if let Some(avatar) = c.avatar.as_deref() {
            println!("       avatar: {}", avatar);
        }
        if let Some(ctx) = c.enter_session_context.as_ref() {
            println!("       enter_session_context:");
            if let Some(scene) = ctx.scene.as_deref() {
                println!("         scene: {}", scene);
            }
            if let Some(sp) = ctx.scene_param.as_deref() {
                println!("         scene_param: {}", sp);
            }
            if let Some(ch) = ctx.wechat_channels.as_ref() {
                println!("         wechat_channels:");
                if let Some(n) = ch.nickname.as_deref() {
                    println!("           nickname: {}", n);
                }
                if let Some(n) = ch.shop_nickname.as_deref() {
                    println!("           shop_nickname: {}", n);
                }
                if let Some(s) = ch.scene {
                    println!("           scene: {}", s);
                }
            }
        }
    }

    if !resp.invalid_external_userid.is_empty() {
        println!(
            "-- invalid_external_userid ({}): {:?}",
            resp.invalid_external_userid.len(),
            resp.invalid_external_userid
        );
    }

    Ok(())
}
