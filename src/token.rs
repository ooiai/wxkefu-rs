#![allow(dead_code)]
//! 微信客服（kf）token 模块。
//!
//! 提供获取 access_token 的基础类型与客户端封装，
//! 便于后续继续扩展更多接口能力。
//!
//! 设计思路：
//! - 使用 `Auth` 区分两类鉴权（公众号/小程序 与 微信客服/企业微信）
//! - 通过 `KfClient` 统一封装 HTTP 与错误映射；token 缓存/刷新应由更高层实现
//! - 错误统一为 `Error`
//!
//! 接口地址：
//! - 公众号 / 小程序：GET https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=APPSECRET
//! - 微信客服（企业微信）：GET https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=CORP_ID&corpsecret=CORP_SECRET
//!
//! 注意：不同产品线/文档版本可能存在差异，请以官方文档为准。
//!
//! 示例（伪代码）：
//! ```ignore
//! use wxkefu_rs::kf::{KfClient, Auth};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // 公众号 / 小程序
//!     let client = KfClient::default();
//!     let token = client
//!         .get_access_token(&Auth::OfficialAccount {
//!             appid: "your_appid".into(),
//!             secret: "your_appsecret".into(),
//!         })
//!         .await?;
//!     println!("mp token: {}, expires_in: {}", token.access_token, token.expires_in);
//!
//!     // 微信客服（企业微信）
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

/// 鉴权方式
///
/// - OfficialAccount：公众号 / 小程序使用 appid + appsecret
/// - WeCom：微信客服（企业微信）使用 corp_id + corp_secret
#[derive(Clone, Debug)]
pub enum Auth {
    /// 公众号 / 小程序
    OfficialAccount { appid: String, secret: String },
    /// 微信客服（企业微信）
    WeCom {
        corp_id: String,
        corp_secret: String,
    },
}

/// 成功返回的 access_token 响应
#[derive(Clone, Debug, Deserialize)]
pub struct AccessToken {
    /// 调用凭证（access_token）
    pub access_token: String,
    /// 有效期（秒）
    pub expires_in: u32,
}

/// 微信接口错误响应
#[derive(Clone, Debug, Deserialize)]
pub struct WxError {
    pub errcode: i64,
    pub errmsg: String,
}

/// 原始返回（成功或错误）
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum TokenRawResp {
    Ok(AccessToken),
    Err(WxError),
}

/// 统一错误类型
#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP 错误: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL 无效: {0}")]
    InvalidUrl(String),

    #[error("微信接口错误 {code}: {message}")]
    Wx { code: i64, message: String },

    #[error("获取 access_token 的返回异常（状态 {status}）：{error}；body: {body}")]
    UnexpectedTokenResponse {
        status: u16,
        error: String,
        body: String,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

/// 微信客服基础客户端
///
/// - 封装 `reqwest::Client`
/// - 提供获取 access_token 的基础能力（不包含缓存/自动刷新）
/// - 便于后续扩展更多 API
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
    /// 使用自定义的 `reqwest::Client`
    pub fn with_http(http: reqwest::Client) -> Self {
        Self { http }
    }

    /// 获取 access_token
    ///
    /// - 公众号 / 小程序：
    ///   GET https://api.weixin.qq.com/cgi-bin/token
    ///   参数：grant_type=client_credential, appid, secret（注意请勿在日志中输出密钥）
    ///
    /// - 微信客服（企业微信）：
    ///   GET https://qyapi.weixin.qq.com/cgi-bin/gettoken
    ///   参数：corpid, corpsecret（注意请勿在日志中输出密钥）
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
                // 形态校验与安全日志（不输出密钥）
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
                        "检测到 appid 以 ww 开头，这通常是企业微信 corpid；如需调用『微信客服』接口，请使用 corpid + 微信客服 Secret（Auth::WeCom）。"
                    );
                }
                debug!(
                    "请求公众平台 access_token（不包含密钥），appid 提示: {}",
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
                // 形态校验与安全日志（不输出密钥）
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
                        "检测到 corpid 以 wx 开头，这通常是公众平台 appid；『微信客服』应使用 corpid（以 ww 开头）与微信客服 Secret。"
                    );
                }
                debug!(
                    "请求企业微信 access_token（不包含密钥），corpid 提示: {}",
                    corp_id_hint
                );
                self.request_token(url).await
            }
        }
    }

    async fn request_token(&self, url: Url) -> Result<AccessToken> {
        // 在移动 url 进入请求之前先判断是否为企业微信接口
        let is_wecom = url
            .host_str()
            .map(|h| h.contains("qyapi.weixin.qq.com"))
            .unwrap_or(false);

        let resp = self.http.get(url).send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;

        // 优先按成功/错误联合类型解码
        match serde_json::from_slice::<TokenRawResp>(&bytes) {
            Ok(TokenRawResp::Ok(ok)) => Ok(ok),
            Ok(TokenRawResp::Err(err)) => {
                // 为企业微信（微信客服）常见错误增加提示，避免混用 appid/appsecret 与 corpid/corpsecret
                let mut msg = err.errmsg.clone();
                if is_wecom {
                    let hint = match err.errcode {
                        40013 => "；提示：corpid 不正确，请确认使用以 ww 开头的企业ID",
                        40001 | 42001 => {
                            "；提示：凭证无效或已过期，请检查 corpsecret 是否为『微信客服管理后台-开发配置』处获取，并实现缓存与过期刷新"
                        }
                        40014 | 40125 => {
                            "；提示：secret 与 corpid 不匹配，避免误用公众号 appsecret"
                        }
                        _ => {
                            "；提示：请核对 corpid 与『微信客服』Secret 是否对应，勿使用公众平台的 appid/appsecret"
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
                // 解码失败时，尽量脱敏并截断 body，避免泄露 access_token 等敏感信息
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
