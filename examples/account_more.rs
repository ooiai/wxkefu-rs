/*!
Examples: Update account, list accounts, and generate contact link for WeCom (WeChat Customer Service, Kf)

Select an action with WXKF_EXAMPLE_ACTION ∈ { update | list | link }

Common env:
  WXKF_CORP_ID=ww...
  WXKF_APP_SECRET=your_kf_secret
  WXKF_EXAMPLE_ACTION=update|list|link

Action=update:
  Required:
    WXKF_OPEN_KFID=wkAJ2GCAAAZSfhHCt7IFSvLKtMPxyJTw
  Optional (at least one must be provided):
    WXKF_ACCOUNT_NAME="New Name"           # <= 16 chars
    WXKF_MEDIA_ID="MEDIA_ID_FROM_UPLOAD"   # <= 128 bytes (temporary media id)

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=... \
  WXKF_EXAMPLE_ACTION=update \
  WXKF_OPEN_KFID=wkAJ2G... \
  WXKF_ACCOUNT_NAME="New Name" \
  cargo run --example account_more

Action=list:
  Optional:
    WXKF_OFFSET=0
    WXKF_LIMIT=100  # 1..=100, default 100

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=... \
  WXKF_EXAMPLE_ACTION=list \
  cargo run --example account_more

Action=link:
  Required:
    WXKF_OPEN_KFID=wkAJ2GCAAAZSfhHCt7IFSvLKtMPxyJTw
  Optional:
    WXKF_SCENE="12345"   # <= 32 bytes, [0-9a-zA-Z_-]*

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=... \
  WXKF_EXAMPLE_ACTION=link \
  WXKF_OPEN_KFID=wkAJ2G... \
  WXKF_SCENE="12345" \
  cargo run --example account_more
*/

use anyhow::{Context, Result, bail};
use dotenvy::dotenv;
use std::env;
use wxkefu_rs::account::{AccountListRequest, AccountUpdateRequest, AddContactWayRequest};
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();

    let action = env::var("WXKF_EXAMPLE_ACTION")
        .unwrap_or_else(|_| "list".to_string())
        .to_lowercase();

    let corp_id = env::var("WXKF_CORP_ID")
        .context("set WXKF_CORP_ID (WeCom corpid, usually starts with 'ww')")?;
    let corp_secret = env::var("WXKF_APP_SECRET")
        .context("set WXKF_APP_SECRET (WeChat Customer Service Secret)")?;

    let client = KfClient::default();
    let token = client
        .get_access_token(&Auth::WeCom {
            corp_id,
            corp_secret,
        })
        .await
        .context("failed to get access_token (ensure corpid + Kf Secret are correct)")?;

    match action.as_str() {
        "update" => run_update(&client, &token.access_token).await?,
        "list" => run_list(&client, &token.access_token).await?,
        "link" => run_link(&client, &token.access_token).await?,
        other => {
            eprintln!(
                "Unknown WXKF_EXAMPLE_ACTION={}. Use one of: update | list | link",
                other
            );
            bail!("invalid action");
        }
    }

    Ok(())
}

async fn run_update(client: &KfClient, access_token: &str) -> Result<()> {
    let open_kfid = env::var("WXKF_OPEN_KFID")
        .or_else(|_| env::var("WXKF_ACCOUNT_OPEN_KFID"))
        .or_else(|_| env::var("OPEN_KFID"))
        .context("set WXKF_OPEN_KFID (or WXKF_ACCOUNT_OPEN_KFID / OPEN_KFID) to the Kf account ID to update")?;

    let name = env::var("WXKF_ACCOUNT_NAME")
        .ok()
        .or_else(|| env::var("WXKF_NAME").ok());
    let media_id = env::var("WXKF_MEDIA_ID").ok();

    if name.as_deref().map(|s| s.chars().count()).unwrap_or(0) > 16 {
        bail!("WXKF_ACCOUNT_NAME must be <= 16 characters");
    }
    if let Some(mid) = media_id.as_deref() {
        if mid.is_empty() {
            bail!("WXKF_MEDIA_ID provided but empty");
        }
        if mid.len() > 128 {
            bail!("WXKF_MEDIA_ID length must be <= 128 bytes");
        }
    }

    if name.is_none() && media_id.is_none() {
        bail!("Provide at least one of WXKF_ACCOUNT_NAME or WXKF_MEDIA_ID to update");
    }

    let req = AccountUpdateRequest {
        open_kfid,
        name,
        media_id,
    };

    let resp = client
        .account_update(access_token, &req)
        .await
        .context("kf/account/update request failed")?;
    println!("errcode: {}, errmsg: {}", resp.errcode, resp.errmsg);
    if resp.errcode == 0 {
        println!("Account updated successfully.");
    }
    Ok(())
}

async fn run_list(client: &KfClient, access_token: &str) -> Result<()> {
    let offset = parse_u32_env("WXKF_OFFSET");
    let limit = parse_u32_env("WXKF_LIMIT");

    if let Some(l) = limit {
        if l == 0 || l > 100 {
            bail!("WXKF_LIMIT must be in 1..=100");
        }
    }

    let req = AccountListRequest { offset, limit };
    let resp = client
        .account_list(access_token, &req)
        .await
        .context("kf/account/list request failed")?;

    println!("errcode: {}, errmsg: {}", resp.errcode, resp.errmsg);
    println!("account_list ({}):", resp.account_list.len());
    for (i, a) in resp.account_list.iter().enumerate() {
        println!(
            "  [{}] open_kfid={}, name={}, avatar={}",
            i, a.open_kfid, a.name, a.avatar
        );
    }
    Ok(())
}

async fn run_link(client: &KfClient, access_token: &str) -> Result<()> {
    let open_kfid = env::var("WXKF_OPEN_KFID")
        .or_else(|_| env::var("WXKF_ACCOUNT_OPEN_KFID"))
        .or_else(|_| env::var("OPEN_KFID"))
        .context("set WXKF_OPEN_KFID (or WXKF_ACCOUNT_OPEN_KFID / OPEN_KFID) to the Kf account ID for link generation")?;
    let scene = env::var("WXKF_SCENE").ok();

    if let Some(sc) = scene.as_deref() {
        if sc.len() > 32 {
            bail!("WXKF_SCENE must be <= 32 bytes");
        }
        if !sc
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            bail!("WXKF_SCENE must match [0-9a-zA-Z_-]*");
        }
    }

    let req = AddContactWayRequest { open_kfid, scene };
    let resp = client
        .add_contact_way(access_token, &req)
        .await
        .context("kf/add_contact_way request failed")?;

    println!("errcode: {}, errmsg: {}", resp.errcode, resp.errmsg);
    if resp.errcode == 0 {
        println!("url: {}", resp.url);
    }
    Ok(())
}

fn parse_u32_env(key: &str) -> Option<u32> {
    match env::var(key) {
        Ok(v) => match v.trim().parse::<u32>() {
            Ok(n) => Some(n),
            Err(_) => {
                eprintln!("Warning: {} is not a valid u32: {:?}", key, v);
                None
            }
        },
        Err(_) => None,
    }
}
