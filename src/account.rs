#![allow(dead_code)]
//! WeCom (WeChat Customer Service, Kf) account add API
//!
//! Add a new customer service account and set its display name and avatar.
//!
//! Endpoint (POST):
//!   https://qyapi.weixin.qq.com/cgi-bin/kf/account/add?access_token=ACCESS_TOKEN
//!
//! Request body example:
//! {
//!   "name": "新建的客服账号",
//!   "media_id": "294DpAog3YA5b9rTK4PjjfRfYLO0L5qpDHAJIzhhQ2jAEWjb9i661Q4lk8oFnPtmj"
//! }
//!
//! Notes:
//! - Only the access_token obtained using the WeChat Customer Service (Kf) Secret can call this API.
//! - name: up to 16 characters (server-side validation).
//! - media_id: temporary material media_id for the avatar (obtained from the temporary media upload API),
//!             up to 128 bytes.
//! - An enterprise can add up to 5000 Kf accounts.
//!
//! Successful response example:
//! {
//!   "errcode": 0,
//!   "errmsg": "ok",
//!   "open_kfid": "wkAJ2GCAAAZSfhHCt7IFSvLKtMPxyJTw"
//! }
//!
//! Usage:
//!   let client = KfClient::default();
//!   let token = client.get_access_token(&Auth::WeCom { corp_id, corp_secret }).await?;
//!   let req = AccountAddRequest { name: "Agent A".into(), media_id: media_id_string };
//!   let resp = client.account_add(&token.access_token, &req).await?;
//!   println!("New Kf account open_kfid={}", resp.open_kfid);

use crate::{Error, KfClient, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

/// Request for kf/account/add
#[derive(Debug, Clone, Serialize)]
pub struct AccountAddRequest {
    /// Customer service account display name (<=16 characters)
    pub name: String,
    /// Temporary media_id for the avatar (from media upload API) (<=128 bytes)
    pub media_id: String,
}

/// Response for kf/account/add
#[derive(Debug, Clone, Deserialize)]
pub struct AccountAddResponse {
    pub errcode: i32,
    pub errmsg: String,
    /// Newly created Kf account ID
    pub open_kfid: String,
}

impl KfClient {
    /// Call kf/account/add to create a new customer service account.
    ///
    /// - access_token: WeCom (Kf) access_token
    /// - req: request body with name and media_id
    #[instrument(level = "debug", skip(self, req))]
    pub async fn account_add(
        &self,
        access_token: &str,
        req: &AccountAddRequest,
    ) -> Result<AccountAddResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/account/add")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "account_add request");

        // Short-lived HTTP client for this call
        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;

        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        match serde_json::from_slice::<AccountAddResponse>(&bytes) {
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
