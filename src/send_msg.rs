#![allow(dead_code)]
//! WeCom Kf send_msg API
//!
//! Implements sending customer service messages within the 48-hour window.
//! API doc (CN): https://kf.weixin.qq.com/api/doc/ (send_msg endpoint)
//!
//! Endpoint: POST https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token=ACCESS_TOKEN
//!
//! Notes:
//! - Only access_token acquired using WeCom Kf Secret can call this API.
//! - You can specify an optional msgid; if not provided, the server will generate one.
//! - Respect the delivery limits: within 48 hours after a user message, up to 5 messages can be sent.
//!
//! Usage:
//!   let client = KfClient::default();
//!   let req = SendMsgRequest {
//!       touser: external_userid.into(),
//!       open_kfid: open_kfid.into(),
//!       msgid: None,
//!       payload: SendMsgPayload::Text {
//!           text: TextContent { content: "hello".into() }
//!       },
//!   };
//!   let resp = client.send_msg(&access_token, &req).await?;
//!   println!("msgid={:?}", resp.msgid);

use crate::{Error, KfClient, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

/// Request body for kf/send_msg
#[derive(Debug, Clone, Serialize)]
pub struct SendMsgRequest {
    /// Customer's external_userid
    pub touser: String,
    /// Kf account ID
    pub open_kfid: String,
    /// Optional message ID (unique within the Kf account). If omitted, server generates one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msgid: Option<String>,
    /// Payload tagged by "msgtype"
    #[serde(flatten)]
    pub payload: SendMsgPayload,
}

/// Supported message payloads, tagged by "msgtype".
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "msgtype")]
pub enum SendMsgPayload {
    #[serde(rename = "text")]
    Text { text: TextContent },

    #[serde(rename = "image")]
    Image { image: MediaContent },

    #[serde(rename = "voice")]
    Voice { voice: MediaContent },

    #[serde(rename = "video")]
    Video { video: MediaContent },

    #[serde(rename = "file")]
    File { file: MediaContent },

    #[serde(rename = "link")]
    Link { link: LinkContent },

    #[serde(rename = "miniprogram")]
    MiniProgram { miniprogram: MiniProgramContent },

    #[serde(rename = "msgmenu")]
    MsgMenu { msgmenu: MsgMenuContent },

    #[serde(rename = "location")]
    Location { location: LocationContent },

    #[serde(rename = "business_card")]
    BusinessCard { business_card: BusinessCardContent },

    #[serde(rename = "ca_link")]
    CaLink { ca_link: CaLinkContent },
}

/// Text message content
#[derive(Debug, Clone, Serialize)]
pub struct TextContent {
    /// Text content, up to 2048 bytes
    pub content: String,
}

/// Unified media content (image/voice/video/file)
#[derive(Debug, Clone, Serialize)]
pub struct MediaContent {
    /// Media file ID (from temporary material upload API)
    pub media_id: String,
}

/// Link (rich) message content
#[derive(Debug, Clone, Serialize)]
pub struct LinkContent {
    /// Title, up to 128 bytes (truncated by server if longer)
    pub title: String,
    /// Description, up to 512 bytes (truncated by server if longer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// Target URL (must include protocol), up to 2048 bytes
    pub url: String,
    /// Thumbnail media_id (from material API)
    pub thumb_media_id: String,
}

/// Mini program message content
#[derive(Debug, Clone, Serialize)]
pub struct MiniProgramContent {
    /// Mini program appid
    pub appid: String,
    /// Optional title, up to 64 bytes (truncated by server if longer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Thumbnail media_id
    pub thumb_media_id: String,
    /// Page path. Note: per doc, path should end with ".html" for WeChat browser context.
    pub pagepath: String,
}

/// Menu message content
#[derive(Debug, Clone, Serialize)]
pub struct MsgMenuContent {
    /// Header text, up to 1024 bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_content: Option<String>,
    /// Menu items (max 10)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub list: Vec<MsgMenuItem>,
    /// Tail text, up to 1024 bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tail_content: Option<String>,
}

/// Menu item variants (tagged by "type")
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum MsgMenuItem {
    #[serde(rename = "click")]
    Click { click: MsgMenuClick },

    #[serde(rename = "view")]
    View { view: MsgMenuView },

    #[serde(rename = "miniprogram")]
    MiniProgram { miniprogram: MsgMenuMiniProgram },

    #[serde(rename = "text")]
    Text { text: MsgMenuText },
}

#[derive(Debug, Clone, Serialize)]
pub struct MsgMenuClick {
    /// Optional menu ID (1..=128 bytes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Display content (1..=128 bytes)
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MsgMenuView {
    /// Target URL (1..=2048 bytes)
    pub url: String,
    /// Display content (1..=1024 bytes)
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MsgMenuMiniProgram {
    /// Mini program appid (1..=32 bytes)
    pub appid: String,
    /// Target page path (1..=1024 bytes)
    pub pagepath: String,
    /// Display content (<=1024 bytes)
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MsgMenuText {
    /// Text content (supports literal "\n"), 1..=256 bytes
    pub content: String,
    /// 0-newline, 1-no newline; default 0
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_newline: Option<u8>,
}

/// Location message content
#[derive(Debug, Clone, Serialize)]
pub struct LocationContent {
    /// Optional name/title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional address info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Latitude in [-90, 90]
    pub latitude: f64,
    /// Longitude in [-180, 180]
    pub longitude: f64,
}

/// Business card message content
#[derive(Debug, Clone, Serialize)]
pub struct BusinessCardContent {
    /// Member userid (or open_userid for 3rd-party app)
    pub userid: String,
}

/// Customer acquisition link message content
#[derive(Debug, Clone, Serialize)]
pub struct CaLinkContent {
    /// Link URL created by the customer acquisition assistant
    pub link_url: String,
}

/// Success response for kf/send_msg
#[derive(Debug, Clone, Deserialize)]
pub struct SendMsgResponse {
    pub errcode: i32,
    pub errmsg: String,
    #[serde(default)]
    pub msgid: Option<String>,
}

impl KfClient {
    /// Call kf/send_msg to send a message to a customer.
    ///
    /// - access_token: WeCom Kf access_token
    /// - req: request body with touser, open_kfid and payload
    #[instrument(level = "debug", skip(self, req))]
    pub async fn send_msg(
        &self,
        access_token: &str,
        req: &SendMsgRequest,
    ) -> Result<SendMsgResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "send_msg request");

        // Use a short-lived client to avoid touching private fields of KfClient
        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;
        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        match serde_json::from_slice::<SendMsgResponse>(&bytes) {
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
                // Provide rich context for debugging
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
