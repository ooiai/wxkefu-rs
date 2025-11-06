#![allow(dead_code)]
//! WeCom Kf send_msg_on_event API
//!
//! Send a message in response to a specific event using a one-time `code` (e.g., welcome_code).
//! This is typically used to send a customer service welcome message after the "enter_session" event,
//! subject to the official constraints (call within ~20 seconds after receiving the event, only once).
//!
//! Endpoint: POST https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg_on_event?access_token=ACCESS_TOKEN
//!
//! Supported msgtype for this API: text, msgmenu
//!
//! Example:
//! ```ignore
//! use wxkefu_rs::{Auth, KfClient};
//! use wxkefu_rs::send_msg_on_event::{SendMsgOnEventRequest, SendMsgOnEventPayload};
//! use wxkefu_rs::send_msg::TextContent;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = KfClient::default();
//!     let at = client.get_access_token(&Auth::WeCom {
//!         corp_id: "ww...".into(),
//!         corp_secret: "your_kf_secret".into(),
//!     }).await?;
//!
//!     let req = SendMsgOnEventRequest {
//!         code: "WELCOME_CODE_FROM_EVENT".into(),
//!         msgid: None,
//!         payload: SendMsgOnEventPayload::Text {
//!             text: TextContent { content: "Welcome!".into() },
//!         },
//!     };
//!
//!     let resp = client.send_msg_on_event(&at.access_token, &req).await?;
//!     println!("ok: errcode={}, errmsg={}, msgid={:?}", resp.errcode, resp.errmsg, resp.msgid);
//!     Ok(())
//! }
//! ```

use crate::send_msg::{MsgMenuContent, TextContent};
use crate::{Error, KfClient, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

/// Request body for kf/send_msg_on_event
#[derive(Debug, Clone, Serialize)]
pub struct SendMsgOnEventRequest {
    /// One-time code from the event callback (e.g., welcome_code). Only valid for a short time and
    /// can be used once.
    pub code: String,
    /// Optional message ID. If provided, it must be unique within the Kf account; otherwise the
    /// server returns an error. If omitted, the server generates one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msgid: Option<String>,
    /// Message payload (only "text" and "msgmenu" are supported by this API).
    #[serde(flatten)]
    pub payload: SendMsgOnEventPayload,
}

/// Supported payloads for send_msg_on_event (tagged by "msgtype").
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "msgtype")]
pub enum SendMsgOnEventPayload {
    /// Text message
    #[serde(rename = "text")]
    Text { text: TextContent },

    /// Menu message
    #[serde(rename = "msgmenu")]
    MsgMenu { msgmenu: MsgMenuContent },
}

/// Success response
#[derive(Debug, Clone, Deserialize)]
pub struct SendMsgOnEventResponse {
    pub errcode: i32,
    pub errmsg: String,
    #[serde(default)]
    pub msgid: Option<String>,
}

impl KfClient {
    /// Call kf/send_msg_on_event to send a message in response to an event (e.g., welcome message).
    ///
    /// - access_token: WeCom Kf access_token
    /// - req: includes the one-time `code` from the event and the message payload
    #[instrument(level = "debug", skip(self, req))]
    pub async fn send_msg_on_event(
        &self,
        access_token: &str,
        req: &SendMsgOnEventRequest,
    ) -> Result<SendMsgOnEventResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg_on_event")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "send_msg_on_event request");

        // Use a short-lived client to avoid relying on private fields
        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;
        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        match serde_json::from_slice::<SendMsgOnEventResponse>(&bytes) {
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
