#![allow(dead_code)]
//! WeCom (WeChat Customer Service, Kf) account management APIs: add and delete.
//!
//! Add a new customer service account (set display name and avatar) and delete an existing one.
//!
//! Endpoints (POST):
//! - Add: https://qyapi.weixin.qq.com/cgi-bin/kf/account/add?access_token=ACCESS_TOKEN
//! - Del: https://qyapi.weixin.qq.com/cgi-bin/kf/account/del?access_token=ACCESS_TOKEN
//!
//! Notes:
//! - Only the access_token obtained using the WeChat Customer Service (Kf) Secret can call these APIs.
//! - For add:
//!   * name: up to 16 characters
//!   * media_id: temporary material media_id for the avatar (obtained from the temporary media upload API), up to 128 bytes
//!   * An enterprise can add up to 5000 Kf accounts.
//!
//! Usage (add):
//!   let client = KfClient::default();
//!   let token = client.get_access_token(&Auth::WeCom { corp_id, corp_secret }).await?;
//!   let req = AccountAddRequest { name: "Agent A".into(), media_id: media_id_string };
//!   let resp = client.account_add(&token.access_token, &req).await?;
//!   println!("New Kf account open_kfid={}", resp.open_kfid);
//!
//! Usage (delete):
//!   let del = AccountDelRequest { open_kfid: "wkAJ2G...".into() };
//!   let ok = client.account_del(&token.access_token, &del).await?;

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

/// Request for kf/account/del
#[derive(Debug, Clone, Serialize)]
pub struct AccountDelRequest {
    /// Kf account ID to delete (<=64 bytes)
    pub open_kfid: String,
}

/// Response for kf/account/del
#[derive(Debug, Clone, Deserialize)]
pub struct AccountDelResponse {
    pub errcode: i32,
    pub errmsg: String,
}

/// Request for kf/account/update
#[derive(Debug, Clone, Serialize)]
pub struct AccountUpdateRequest {
    /// Kf account ID to update (<=64 bytes)
    pub open_kfid: String,
    /// New display name (<=16 chars); omit to keep unchanged
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// New avatar temporary media_id (<=128 bytes); omit to keep unchanged
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_id: Option<String>,
}

/// Response for kf/account/update
#[derive(Debug, Clone, Deserialize)]
pub struct AccountUpdateResponse {
    pub errcode: i32,
    pub errmsg: String,
}

/// Request for kf/account/list
#[derive(Debug, Clone, Serialize)]
pub struct AccountListRequest {
    /// Pagination offset, defaults to 0 if None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// Page size 1..=100, defaults to 100 if None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Response for kf/account/list
#[derive(Debug, Clone, Deserialize)]
pub struct AccountListResponse {
    pub errcode: i32,
    pub errmsg: String,
    #[serde(default)]
    pub account_list: Vec<AccountListItem>,
}

/// Account item in list
#[derive(Debug, Clone, Deserialize)]
pub struct AccountListItem {
    pub open_kfid: String,
    pub name: String,
    pub avatar: String,
}

/// Request for kf/add_contact_way
#[derive(Debug, Clone, Serialize)]
pub struct AddContactWayRequest {
    /// Kf account ID
    pub open_kfid: String,
    /// Optional scene value (<=32 bytes, [0-9a-zA-Z_-]*). If provided, you can append scene_param when using the link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scene: Option<String>,
}

/// Response for kf/add_contact_way
#[derive(Debug, Clone, Deserialize)]
pub struct AddContactWayResponse {
    pub errcode: i32,
    pub errmsg: String,
    /// The generated Kf URL. You can embed it in H5 or generate a QR from it.
    pub url: String,
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

    /// Call kf/account/del to delete an existing customer service account.
    ///
    /// - access_token: WeCom (Kf) access_token
    /// - req: request body with open_kfid
    #[instrument(level = "debug", skip(self, req))]
    pub async fn account_del(
        &self,
        access_token: &str,
        req: &AccountDelRequest,
    ) -> Result<AccountDelResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/account/del")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "account_del request");

        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;

        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        match serde_json::from_slice::<AccountDelResponse>(&bytes) {
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

    /// Call kf/account/update to modify an existing customer service account (name and/or avatar).
    ///
    /// - access_token: WeCom (Kf) access_token
    /// - req: request body with open_kfid and optional name/media_id
    #[instrument(level = "debug", skip(self, req))]
    pub async fn account_update(
        &self,
        access_token: &str,
        req: &AccountUpdateRequest,
    ) -> Result<AccountUpdateResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/account/update")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "account_update request");

        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;

        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        match serde_json::from_slice::<AccountUpdateResponse>(&bytes) {
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

    /// Call kf/account/list to fetch Kf account list (supports pagination with offset/limit).
    ///
    /// - access_token: WeCom (Kf) access_token
    /// - req: optional pagination settings
    #[instrument(level = "debug", skip(self, req))]
    pub async fn account_list(
        &self,
        access_token: &str,
        req: &AccountListRequest,
    ) -> Result<AccountListResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/account/list")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "account_list request");

        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;

        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        match serde_json::from_slice::<AccountListResponse>(&bytes) {
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

    /// Call kf/add_contact_way to generate a Kf contact URL (H5 link).
    ///
    /// - access_token: WeCom (Kf) access_token
    /// - req: open_kfid and optional scene
    #[instrument(level = "debug", skip(self, req))]
    pub async fn add_contact_way(
        &self,
        access_token: &str,
        req: &AddContactWayRequest,
    ) -> Result<AddContactWayResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/add_contact_way")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "add_contact_way request");

        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;

        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        match serde_json::from_slice::<AddContactWayResponse>(&bytes) {
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
