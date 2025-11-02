#![doc = r#"
wxkefu-rs

Crate root for WeChat Customer Service (WeChat Kefu) APIs.

This crate exposes the token client and related types at the crate level.
There is no `kf` submodule; import items directly from the crate root.

Currently included:
- token: Access token client and types for both Official Account / Mini Program and WeCom (Enterprise WeChat).

Quick usage:

```ignore
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = KfClient::default();

    // WeCom (Enterprise WeChat)
    let wecom = client
        .get_access_token(&Auth::WeCom {
            corp_id: "your_corp_id".into(),
            corp_secret: "your_corp_secret".into(),
        })
        .await?;
    println!("wecom access_token: {}, expires_in: {}", wecom.access_token, wecom.expires_in);

    // Official Account / Mini Program
    let mp = client
        .get_access_token(&Auth::OfficialAccount {
            appid: "your_appid".into(),
            secret: "your_appsecret".into(),
        })
        .await?;
    println!("mp access_token: {}, expires_in: {}", mp.access_token, mp.expires_in);

    Ok(())
}
```
"#]

pub mod token;
pub use token::*;
