#![allow(dead_code)]
//! WeChat Customer Service (kf) token module.
//!
//! This module provides basic types and a client to fetch access tokens,
//! designed to be extended with more APIs later.
//!
//! Design:
//! - Use `Auth` to distinguish auth types (Official Account / Mini Program vs WeCom).
//! - `KfClient` handles HTTP and basic error mapping; token caching/refresh should
//!   be implemented at a higher layer.
//! - Errors are unified via `Error`.
//!
//! Token endpoints:
//! - Official Account / Mini Program: GET https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=APPSECRET
//! - WeCom (Enterprise WeChat): GET https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=CORP_ID&corpsecret=CORP_SECRET
//!
//! Note: Endpoints or parameters may vary across product lines or documentation
//! versions. Always refer to the official documentation.
//!
//! Example (pseudo usage):
//! ```ignore
//! use wxkefu_rs::kf::{KfClient, Auth};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Official Account / Mini Program
//!     let client = KfClient::default();
//!     let token = client
//!         .get_access_token(&Auth::OfficialAccount {
//!             appid: "your_appid".into(),
//!             secret: "your_appsecret".into(),
//!         })
//!         .await?;
//!     println!("mp token: {}, expires_in: {}", token.access_token, token.expires_in);
//!
//!     // WeCom
//!     let wecom_token = client
//!         .get_access_token(&Auth::WeCom {
//!             corp_id: "your_corp_id".into(),
//!             corp_secret: "your_corp_secret".into(),
//!         })
//!         .await?;
//!     println!("wecom token: {}, expires_in: {}", wecom_token.access_token, wecom_token.expires_in);
//!
//!     Ok(())
//! }
//! ```

use reqwest::Url;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, instrument};

/// Auth method
///
/// - OfficialAccount: Official Account / Mini Program uses appid + secret
/// - WeCom: Enterprise WeChat uses corp_id + corp_secret
#[derive(Clone, Debug)]
pub enum Auth {
    /// Official Account / Mini Program
    OfficialAccount { appid: String, secret: String },
    /// WeCom (Enterprise WeChat)
    WeCom {
        corp_id: String,
        corp_secret: String,
    },
}

/// Successful token response
#[derive(Clone, Debug, Deserialize)]
pub struct AccessToken {
    /// Access token string
    pub access_token: String,
    /// Expiration in seconds
    pub expires_in: u32,
}

/// WeChat API error response
#[derive(Clone, Debug, Deserialize)]
pub struct WxError {
    pub errcode: i64,
    pub errmsg: String,
}

/// Raw token response (either success or error)
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum TokenRawResp {
    Ok(AccessToken),
    Err(WxError),
}

/// Unified error type
#[derive(Debug, Error)]
pub enum Error {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid url: {0}")]
    InvalidUrl(String),

    #[error("weixin error {code}: {message}")]
    Wx { code: i64, message: String },

    #[error("unexpected token response (status {status}): {error}; body: {body}")]
    UnexpectedTokenResponse {
        status: u16,
        error: String,
        body: String,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Base client for WeChat Kefu
///
/// - Wraps `reqwest::Client`
/// - Provides token fetching (no caching/refresh here)
/// - Easy to extend for more APIs
#[derive(Clone, Debug)]
pub struct KfClient {
    http: reqwest::Client,
}

impl Default for KfClient {
    fn default() -> Self {
        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .expect("reqwest::Client build must succeed");
        Self { http }
    }
}

impl KfClient {
    /// Use a custom `reqwest::Client`
    pub fn with_http(http: reqwest::Client) -> Self {
        Self { http }
    }

    /// Fetch access_token
    ///
    /// - OfficialAccount:
    ///   GET https://api.weixin.qq.com/cgi-bin/token
    ///   params: grant_type=client_credential, appid, secret
    ///
    /// - WeCom:
    ///   GET https://qyapi.weixin.qq.com/cgi-bin/gettoken
    ///   params: corpid, corpsecret
    #[instrument(level = "debug", skip(self, auth))]
    pub async fn get_access_token(&self, auth: &Auth) -> Result<AccessToken> {
        match auth {
            Auth::OfficialAccount { appid, secret } => {
                let mut url = Url::parse("https://api.weixin.qq.com/cgi-bin/token")
                    .map_err(|e| Error::InvalidUrl(e.to_string()))?;
                {
                    let mut qp = url.query_pairs_mut();
                    qp.append_pair("grant_type", "client_credential");
                    qp.append_pair("appid", appid);
                    qp.append_pair("secret", secret);
                }
                debug!(%url, "requesting OfficialAccount token");
                self.request_token(url).await
            }
            Auth::WeCom {
                corp_id,
                corp_secret,
            } => {
                let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/gettoken")
                    .map_err(|e| Error::InvalidUrl(e.to_string()))?;
                {
                    let mut qp = url.query_pairs_mut();
                    qp.append_pair("corpid", corp_id);
                    qp.append_pair("corpsecret", corp_secret);
                }
                debug!(%url, "requesting WeCom token");
                self.request_token(url).await
            }
        }
    }

    async fn request_token(&self, url: Url) -> Result<AccessToken> {
        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;

        // Try to decode as a success or error union first
        match serde_json::from_slice::<TokenRawResp>(&bytes) {
            Ok(TokenRawResp::Ok(ok)) => Ok(ok),
            Ok(TokenRawResp::Err(err)) => Err(Error::Wx {
                code: err.errcode,
                message: err.errmsg,
            }),
            Err(de_err) => {
                // If decoding fails, include more information to help diagnose
                let body = String::from_utf8_lossy(&bytes).to_string();
                Err(Error::UnexpectedTokenResponse {
                    status: status.as_u16(),
                    error: de_err.to_string(),
                    body,
                })
            }
        }
    }
}
