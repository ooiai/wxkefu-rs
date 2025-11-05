#![allow(dead_code)]
//! WeCom (WeChat Customer Service, Kf) customer batchget API
//!
//! Fetch basic customer information by external_userid list.
//!
//! API Doc (CN reference):
//! - Request:  POST https://qyapi.weixin.qq.com/cgi-bin/kf/customer/batchget?access_token=ACCESS_TOKEN
//! - Body:
//!   {
//!     "external_userid_list": ["wmxxxxxxxxxxxxxxxxxxxxxx", "zhangsan"],
//!     "need_enter_session_context": 0
//!   }
//! - Notes:
//!   * Only the access_token acquired using the WeCom Kf Secret can call this API.
//!   * external_userid must have interacted with the Kf account within the last 48 hours,
//!     otherwise it will be returned in invalid_external_userid.
//!
//! Response example:
//! {
//!   "errcode": 0,
//!   "errmsg": "ok",
//!   "customer_list": [
//!     {
//!       "external_userid": "wmxxxxxxxxxxxxxxxxxxxxxx",
//!       "nickname": "张三",
//!       "avatar": "http://xxxxx",
//!       "gender": 1,
//!       "unionid": "oxasdaosaosdasdasdasd",
//!       "enter_session_context": {
//!         "scene": "123",
//!         "scene_param": "abc",
//!         "wechat_channels": {
//!           "nickname": "进入会话的视频号名称",
//!           "shop_nickname": "视频号小店名称",
//!           "scene": 1
//!         }
//!       }
//!     }
//!   ],
//!   "invalid_external_userid": ["zhangsan"]
//! }
//!
//! Field notes:
//! - gender: third-party service providers cannot obtain this value; for safety treat it as optional.
//! - unionid: requires binding developer account; may be absent.
//! - enter_session_context is returned only if need_enter_session_context = 1.

use crate::{Error, KfClient, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

/// Request for kf/customer/batchget
#[derive(Debug, Clone, Serialize)]
pub struct CustomerBatchGetRequest {
    /// List of external_userid to fetch
    pub external_userid_list: Vec<String>,
    /// 0 or 1; default 0 (do not return 48h enter-session context)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub need_enter_session_context: Option<u8>,
}

impl CustomerBatchGetRequest {
    /// Convenience constructor
    pub fn new<I, S>(ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            external_userid_list: ids.into_iter().map(Into::into).collect(),
            need_enter_session_context: None,
        }
    }

    /// Set whether to return 48h enter-session context (0 or 1)
    pub fn with_need_enter_session_context(mut self, flag: bool) -> Self {
        self.need_enter_session_context = Some(if flag { 1 } else { 0 });
        self
    }
}

/// Response for kf/customer/batchget
#[derive(Debug, Clone, Deserialize)]
pub struct CustomerBatchGetResponse {
    pub errcode: i32,
    pub errmsg: String,
    #[serde(default)]
    pub customer_list: Vec<CustomerInfo>,
    #[serde(default)]
    pub invalid_external_userid: Vec<String>,
}

/// Customer basic info item
#[derive(Debug, Clone, Deserialize)]
pub struct CustomerInfo {
    /// WeChat customer's external_userid
    pub external_userid: String,
    /// WeChat nickname (may be missing in some cases)
    #[serde(default)]
    pub nickname: Option<String>,
    /// Avatar URL (third-party cannot obtain; optional for robustness)
    #[serde(default)]
    pub avatar: Option<String>,
    /// Gender; third-party cannot obtain, typically 0; optional for robustness
    #[serde(default)]
    pub gender: Option<i32>,
    /// Unionid (requires binding to developer account/platform)
    #[serde(default)]
    pub unionid: Option<String>,
    /// 48h last enter-session context information (present only if requested)
    #[serde(default)]
    pub enter_session_context: Option<EnterSessionContext>,
}

/// 48h last enter-session context info
#[derive(Debug, Clone, Deserialize)]
pub struct EnterSessionContext {
    /// Developer-defined scene value
    #[serde(default)]
    pub scene: Option<String>,
    /// Developer-defined scene_param (as appended to the Kf link)
    #[serde(default)]
    pub scene_param: Option<String>,
    /// WeChat Channels (video account) info; only present if the session was entered from Channels
    #[serde(default)]
    pub wechat_channels: Option<WechatChannels>,
}

/// WeChat Channels info for enter-session context
#[derive(Debug, Clone, Deserialize)]
pub struct WechatChannels {
    /// Channels nickname; returned when scene value is 1, 2, or 3
    #[serde(default)]
    pub nickname: Option<String>,
    /// Channels shop nickname; returned when scene value is 4 or 5
    #[serde(default)]
    pub shop_nickname: Option<String>,
    /// Channels scene value:
    /// 1: homepage, 2: live room product list, 3: product showcase, 4: shop product detail, 5: shop order page
    #[serde(default)]
    pub scene: Option<u32>,
}

impl KfClient {
    /// Call kf/customer/batchget to fetch customer basic information.
    ///
    /// - access_token: WeCom (Kf) access_token
    /// - req: request body containing external_userid_list and optional need_enter_session_context
    #[instrument(level = "debug", skip(self, req))]
    pub async fn customer_batchget(
        &self,
        access_token: &str,
        req: &CustomerBatchGetRequest,
    ) -> Result<CustomerBatchGetResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/customer/batchget")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "customer_batchget request");

        // Use a short-lived client for this call
        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;
        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        match serde_json::from_slice::<CustomerBatchGetResponse>(&bytes) {
            Ok(ok) => {
                if ok.errcode == 0 {
                    Ok(ok)
                } else {
                    Err(Error::Wx {
                        code: ok.errcode as i64,
                        message: ok.errmsg,
                    })
                }
            }
            Err(de_err) => {
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
