#![allow(dead_code)]
//! WeChat Customer Service (Kf) token module.
//!
//! Provides basic types and a client to fetch access_token,
//! designed to be extended with more APIs.
//!
//! Design:
//! - Use `Auth` to distinguish auth types (Official Account / Mini Program vs WeCom Kf).
//! - `KfClient` handles HTTP and basic error mapping; token caching/refresh should
//!   be implemented by the application layer.
//! - Errors are unified via `Error`.
//!
//! Endpoints:
//! - Official Account / Mini Program: GET https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=APPSECRET
//! - WeCom (WeChat Customer Service): GET https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=CORP_ID&corpsecret=CORP_SECRET
//!
//! Note: Always refer to the official documentation for the most up-to-date details.
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
//!     // WeCom (WeChat Customer Service)
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
use tracing::{debug, instrument, warn};

/// Authentication method
///
/// - OfficialAccount: Official Account / Mini Program uses appid + appsecret
/// - WeCom: WeCom (WeChat Customer Service) uses corp_id + corp_secret
#[derive(Clone, Debug)]
pub enum Auth {
    /// Official Account / Mini Program
    OfficialAccount { appid: String, secret: String },
    /// WeCom (WeChat Customer Service)
    WeCom {
        corp_id: String,
        corp_secret: String,
    },
}

/// Successful access_token response
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

/// Base client for WeChat Customer Service
///
/// - Wraps `reqwest::Client`
/// - Provides token fetching (no caching/auto-refresh here)
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
    /// - Official Account / Mini Program:
    ///   GET https://api.weixin.qq.com/cgi-bin/token
    ///   params: grant_type=client_credential, appid, secret (do not log secrets)
    ///
    /// - WeCom (WeChat Customer Service):
    ///   GET https://qyapi.weixin.qq.com/cgi-bin/gettoken
    ///   params: corpid, corpsecret (do not log secrets)
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
                // Shape check and safe logging (no secrets)
                let appid_hint = {
                    let id = appid.as_str();
                    if id.len() <= 4 {
                        format!("{}***", id)
                    } else {
                        format!("{}***{}", &id[..2], &id[id.len().saturating_sub(2)..])
                    }
                };
                if appid.starts_with("ww") {
                    warn!(
                        "Detected appid starting with 'ww' (likely a WeCom corpid). If you intend to call WeChat Customer Service (Kf) APIs, use corpid + Kf Secret (Auth::WeCom)."
                    );
                }
                debug!(
                    "Requesting Official Account / Mini Program access_token (no secrets), appid hint: {}",
                    appid_hint
                );
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
                // Shape check and safe logging (no secrets)
                let corp_id_hint = {
                    let id = corp_id.as_str();
                    if id.len() <= 4 {
                        format!("{}***", id)
                    } else {
                        format!("{}***{}", &id[..2], &id[id.len().saturating_sub(2)..])
                    }
                };
                if corp_id.starts_with("wx") {
                    warn!(
                        "Detected corpid starting with 'wx' (likely an OA/MP appid). WeChat Customer Service should use corpid (starts with 'ww') with the Kf Secret."
                    );
                }
                debug!(
                    "Requesting WeCom (Kf) access_token (no secrets), corpid hint: {}",
                    corp_id_hint
                );
                self.request_token(url).await
            }
        }
    }

    async fn request_token(&self, url: Url) -> Result<AccessToken> {
        // Determine whether this is a WeCom endpoint before moving url into the request
        let is_wecom = url
            .host_str()
            .map(|h| h.contains("qyapi.weixin.qq.com"))
            .unwrap_or(false);

        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;

        // Try to decode as a success/error union first
        match serde_json::from_slice::<TokenRawResp>(&bytes) {
            Ok(TokenRawResp::Ok(ok)) => Ok(ok),
            Ok(TokenRawResp::Err(err)) => {
                // Add hints for common WeCom (Kf) errors to avoid mixing appid/appsecret with corpid/corpsecret
                let mut msg = err.errmsg.clone();
                if is_wecom {
                    let hint = match err.errcode {
                        40013 => {
                            "; hint: invalid corpid, ensure you are using a corpid that starts with 'ww'"
                        }
                        40001 | 42001 => {
                            "; hint: token invalid or expired; ensure corpsecret is the WeChat Customer Service Secret from the Admin Portal (Developer Config) and implement caching/refresh"
                        }
                        40014 | 40125 => {
                            "; hint: secret does not match corpid; avoid using an OA/MP appsecret"
                        }
                        _ => {
                            "; hint: verify corpid matches the WeChat Customer Service Secret; do not use OA/MP appid/appsecret"
                        }
                    };
                    msg.push_str(hint);
                }
                Err(Error::Wx {
                    code: err.errcode,
                    message: msg,
                })
            }
            Err(de_err) => {
                // On decode failure, redact and truncate body when possible to avoid leaking sensitive data (e.g., access_token)
                let mut body = String::from_utf8_lossy(&bytes).to_string();
                if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(obj) = v.as_object_mut() {
                        if obj.get("access_token").is_some() {
                            obj.insert(
                                "access_token".to_string(),
                                serde_json::Value::String("[redacted]".into()),
                            );
                        }
                    }
                    if let Ok(s) = serde_json::to_string(&v) {
                        body = s;
                    }
                }
                if body.len() > 2048 {
                    body.truncate(2048);
                    body.push_str("...");
                }
                Err(Error::UnexpectedTokenResponse {
                    status: status.as_u16(),
                    error: de_err.to_string(),
                    body,
                })
            }
        }
    }
}
