#![doc = r#"
wxkefu-rs

A lightweight, extensible Rust crate for WeChat Customer Service (WeCom Kf) APIs.

What this crate does
- Provides a small HTTP client (`KfClient`) plus basic types for fetching access_token.
- Supports two credential systems:
  1) WeCom (Enterprise WeChat, for WeChat Customer Service/Kf)
     - Use corpid (typically starts with `ww`) and the WeChat Customer Service Secret (corpsecret)
     - Endpoint: https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=ID&corpsecret=SECRET
  2) Official Account / Mini Program (OA/MP)
     - Use appid (starts with `wx`) and appsecret
     - Endpoint: https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=APPSECRET

Important
- If your goal is to call WeChat Customer Service (Kf) APIs (agent management, message send/receive, session routing, etc.), you must use WeCom credentials (corpid + WeCom Kf Secret). OA/MP tokens are NOT accepted by Kf endpoints.
- Official Kf docs for acquiring access_token (WeCom): https://kf.weixin.qq.com/api/doc/path/93304

Included
- `Auth` enum for selecting the auth mode (`WeCom` or `OfficialAccount`)
- `AccessToken` type with `access_token` and `expires_in`
- `Error` enum for unified error handling (HTTP, WeChat error code, decoding issues, etc.)
- `KfClient` with a simple `get_access_token(&Auth)` API

Quick start (WeCom/Kf)
- Get your corpid and the WeChat Customer Service Secret from: WeChat Customer Service Admin Portal → Developer Config.
- Cache the access_token in your service to avoid hitting rate limits.

Example (WeCom/Kf)
```ignore
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Read from environment or your secure config center.
    let corpid = std::env::var("WXKF_CORP_ID")?;
    let corpsecret = std::env::var("WXKF_APP_SECRET")?;

    let client = KfClient::default();
    let token = client
        .get_access_token(&Auth::WeCom {
            corp_id: corpid,
            corp_secret: corpsecret,
        })
        .await?;

    // For demo only. Do NOT print sensitive values in production.
    println!("access_token: {}, expires_in: {}", token.access_token, token.expires_in);

    // Persist the token in your cache (memory/Redis/DB) and refresh on expiry.
    Ok(())
}
```

Optional (OA/MP) example
- Only use this if you are working with OA/MP APIs (not Kf).
```ignore
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let appid = std::env::var("WX_APPID")?;
    let appsecret = std::env::var("WX_APPSECRET")?;

    let client = KfClient::default();
    let token = client
        .get_access_token(&Auth::OfficialAccount {
            appid,
            secret: appsecret,
        })
        .await?;

    println!("access_token: {}, expires_in: {}", token.access_token, token.expires_in);
    Ok(())
}
```

Using a .env for local development
```ignore
use dotenvy::dotenv;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenv();

    let client = KfClient::default();

    // WeCom / Kf
    if let (Ok(corpid), Ok(corpsecret)) = (std::env::var("WXKF_CORP_ID"), std::env::var("WXKF_APP_SECRET")) {
        let token = client
            .get_access_token(&Auth::WeCom {
                corp_id: corpid,
                corp_secret: corpsecret,
            })
            .await?;
        println!("wecom access_token: {}, expires_in: {}", token.access_token, token.expires_in);
    }

    // OA/MP (not needed for Kf)
    if let (Ok(appid), Ok(appsecret)) = (std::env::var("WX_APPID"), std::env::var("WX_APPSECRET")) {
        let token = client
            .get_access_token(&Auth::OfficialAccount {
                appid,
                secret: appsecret,
            })
            .await?;
        println!("mp access_token: {}, expires_in: {}", token.access_token, token.expires_in);
    }

    Ok(())
}
```

Best practices and notes (aligned with the official Kf docs)
- Cache access_token and reuse it until it expires; do not call gettoken too frequently or you will be rate-limited.
- expires_in is typically 7200 seconds. Repeated fetches during the valid window return the same token; new tokens are returned after expiry.
- access_token may be invalidated early for operational reasons; always handle invalidation by re-fetching.
- Reserve enough storage (at least 512 bytes) for the token string.
- Never print secrets or tokens in logs. Redact sensitive data.

Error handling
- Non-zero WeChat error codes are mapped to `Error::Wx { code, message }`.
- If the response body cannot be decoded, you get `Error::UnexpectedTokenResponse` with details to aid debugging.
- Network/HTTP/decoding issues appear as `Error::Http` or similar.

Roadmap
- Add Kf account management, message send/receive, and session routing APIs on top of `KfClient`.
- Provide an optional middleware for in-crate token caching and auto-refresh (currently expected to be implemented in your application layer).
"#]

pub mod token;
pub use token::{AccessToken, Auth, Error, KfClient, Result};
pub mod token_cache;
pub use token_cache::{Error as TokenCacheError, RedisTokenManager, TokenManager};

pub mod account;
pub mod callback;
pub mod customer;
pub mod errors;
pub mod keygen;
pub mod media;
pub mod recall_msg;
pub mod send_msg;
pub mod send_msg_on_event;
pub mod sync_msg;
