/*!
Example: Add a new WeCom (WeChat Customer Service, Kf) account

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_ACCOUNT_NAME="Agent Name" \
  WXKF_MEDIA_ID="MEDIA_ID_FROM_UPLOAD" \
  cargo run --example account_add

Notes:
- Only an access_token obtained using the WeChat Customer Service (Kf) Secret can call this API.
- name must be no more than 16 characters.
- media_id must be a temporary material media_id (e.g., from the temporary media upload API).
- An enterprise can add up to 5000 Kf accounts.

Tip:
- You can obtain media_id using the temporary media upload example (examples/media_upload.rs).
*/

use anyhow::{Context, Result, bail};
use dotenvy::dotenv;
use std::env;
use wxkefu_rs::account::AccountAddRequest;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();

    // Read WeCom (Kf) credentials
    let corp_id = env::var("WXKF_CORP_ID")
        .context("set WXKF_CORP_ID (WeCom corpid, usually starts with 'ww')")?;
    let corp_secret = env::var("WXKF_APP_SECRET")
        .context("set WXKF_APP_SECRET (WeChat Customer Service Secret)")?;

    // Read account display name (<= 16 characters)
    let name = env::var("WXKF_ACCOUNT_NAME")
        .or_else(|_| env::var("WXKF_NAME"))
        .context(
            "set WXKF_ACCOUNT_NAME (or WXKF_NAME) to the new account display name (<=16 chars)",
        )?;
    let name_len = name.chars().count();
    if name_len == 0 {
        bail!("WXKF_ACCOUNT_NAME is empty");
    }
    if name_len > 16 {
        bail!(
            "WXKF_ACCOUNT_NAME must be <= 16 characters; current length = {}",
            name_len
        );
    }

    // Read avatar media_id (temporary media from upload API)
    let media_id = env::var("WXKF_MEDIA_ID")
        .context("set WXKF_MEDIA_ID (temporary media_id for the avatar, from media upload API)")?;
    if media_id.is_empty() {
        bail!("WXKF_MEDIA_ID is empty");
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

    // Create the account
    let req = AccountAddRequest { name, media_id };
    let resp = client
        .account_add(&token.access_token, &req)
        .await
        .context("kf/account/add request failed")?;

    // Print results
    println!("errcode: {}, errmsg: {}", resp.errcode, resp.errmsg);
    println!("open_kfid (new account id): {}", resp.open_kfid);

    Ok(())
}
