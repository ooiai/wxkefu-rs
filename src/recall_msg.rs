#![allow(dead_code)]
//! WeCom Kf recall_msg API
//!
//! Recall a message sent via the customer service send_msg API within 2 minutes.
//! Recalled messages still count against the "5 messages within 48 hours" limit.
//!
//! Endpoint: POST https://qyapi.weixin.qq.com/cgi-bin/kf/recall_msg?access_token=ACCESS_TOKEN
//!
//! Example:
//! ```ignore
//! use wxkefu_rs::{Auth, KfClient};
//! use wxkefu_rs::recall_msg::RecallMsgRequest;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = KfClient::default();
//!     let at = client.get_access_token(&Auth::WeCom {
//!         corp_id: "ww...".into(),
//!         corp_secret: "your_kf_secret".into(),
//!     }).await?;
//!
//!     let req = RecallMsgRequest {
//!         msgid: "MSGID".into(),
//!         open_kfid: "OPEN_KFID".into(),
//!     };
//!
//!     let resp = client.recall_msg(&at.access_token, &req).await?;
//!     println!("ok: errcode={}, errmsg={}", resp.errcode, resp.errmsg);
//!     Ok(())
//! }
//! ```
use crate::{Error, KfClient, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

/// Request body for kf/recall_msg
#[derive(Debug, Clone, Serialize)]
pub struct RecallMsgRequest {
    /// The message ID to recall (must be a message previously sent via send_msg)
    pub msgid: String,
    /// The Kf account ID that sent the message
    pub open_kfid: String,
}

/// Success response for kf/recall_msg
#[derive(Debug, Clone, Deserialize)]
pub struct RecallMsgResponse {
    pub errcode: i32,
    pub errmsg: String,
}

impl KfClient {
    /// Call kf/recall_msg to recall a previously sent message.
    ///
    /// - Only messages sent within the last 2 minutes are eligible for recall.
    /// - Recalled messages still count towards the 5-message limit within 48 hours.
    /// - The access_token must be obtained using the WeCom Kf Secret.
    #[instrument(level = "debug", skip(self, req))]
    pub async fn recall_msg(
        &self,
        access_token: &str,
        req: &RecallMsgRequest,
    ) -> Result<RecallMsgResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/recall_msg")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "recall_msg request");

        // Use a short-lived client to avoid exposing internal fields
        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;
        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        match serde_json::from_slice::<RecallMsgResponse>(&bytes) {
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
