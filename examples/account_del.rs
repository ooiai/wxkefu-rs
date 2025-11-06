/*!
Example: Delete a WeCom (WeChat Customer Service, Kf) account

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_OPEN_KFID="wkAJ2GCAAAZSfhHCt7IFSvLKtMPxyJTw" \
  cargo run --example account_del

Notes:
- Only an access_token obtained using the WeChat Customer Service (Kf) Secret can call this API.
- open_kfid must be a valid Kf account ID (<=64 bytes).
*/

use anyhow::{Context, Result, bail};
use dotenvy::dotenv;
use std::env;
use wxkefu_rs::account::AccountDelRequest;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();

    // Read WeCom (Kf) credentials
    let corp_id = env::var("WXKF_CORP_ID")
        .context("set WXKF_CORP_ID (WeCom corpid, usually starts with 'ww')")?;
    let corp_secret = env::var("WXKF_APP_SECRET")
        .context("set WXKF_APP_SECRET (WeChat Customer Service Secret)")?;

    // Read target Kf account ID to delete
    let open_kfid = env::var("WXKF_OPEN_KFID")
        .or_else(|_| env::var("WXKF_ACCOUNT_OPEN_KFID"))
        .or_else(|_| env::var("OPEN_KFID"))
        .context("set WXKF_OPEN_KFID (or WXKF_ACCOUNT_OPEN_KFID / OPEN_KFID) to the Kf account ID to delete")?;

    if open_kfid.trim().is_empty() {
        bail!("open_kfid is empty");
    }
    if open_kfid.len() > 64 {
        bail!(
            "open_kfid length must be <= 64 bytes; current length = {}",
            open_kfid.len()
        );
    }

    // Build client and fetch access_token
    let client = KfClient::default();
    let token = client
        .get_access_token(&Auth::WeCom {
            corp_id,
            corp_secret,
        })
        .await
        .context("failed to get access_token (ensure corpid + Kf Secret are correct)")?;

    // Call delete API
    let req = AccountDelRequest { open_kfid };
    let resp = client
        .account_del(&token.access_token, &req)
        .await
        .context("kf/account/del request failed")?;

    // Print results
    println!("errcode: {}, errmsg: {}", resp.errcode, resp.errmsg);
    if resp.errcode == 0 {
        println!("Account deleted successfully.");
    }

    Ok(())
}
