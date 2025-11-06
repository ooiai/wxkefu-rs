#![allow(dead_code)]
//! WeCom Kf sync_msg API
//!
//! Implements the "Receive messages and events" flow for WeChat Customer Service (Kf):
//! - The WeCom Kf server pushes a lightweight event to your callback URL with a short-lived token.
//! - Your service then calls `kf/sync_msg` with the token (and optional cursor/open_kfid) to pull the
//!   actual messages/events in batches.
//!
//! API doc (CN): https://kf.weixin.qq.com/api/doc/path/94745
//! Endpoint: POST https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg?access_token=ACCESS_TOKEN
//!
//! Notes:
//! - access_token must be acquired using corpid + Kf Secret (WeCom) and cached.
//! - The short-lived "token" is provided by the callback event; it is optional but recommended
//!   to avoid strict rate limiting on the sync_msg API.
//! - Always check has_more and next_cursor to continue incremental pulling.

use crate::{Error, KfClient, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

/// Request body for kf/sync_msg
#[derive(Debug, Clone, Serialize, Default)]
pub struct SyncMsgRequest {
    /// The cursor from last response; omit on first request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Short-lived token from the callback event; optional but recommended
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Desired batch size (default and max 1000)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Voice format: 0-Amr, 1-Silk (default 0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voice_format: Option<u32>,
    /// Pull messages for a specific Kf account; otherwise, pull from all accounts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_kfid: Option<String>,
}

/// Success response for kf/sync_msg
#[derive(Debug, Clone, Deserialize)]
pub struct SyncMsgResponse {
    pub errcode: i32,
    pub errmsg: String,
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// 0-no more; 1-has more
    #[serde(default)]
    pub has_more: u32,
    #[serde(default)]
    pub msg_list: Vec<SyncMsgItem>,
}

/// Common fields of each message item
#[derive(Debug, Clone, Deserialize)]
pub struct SyncMsgItemCommon {
    pub msgid: String,
    pub open_kfid: String,
    #[serde(default)]
    pub external_userid: Option<String>,
    pub send_time: u64,
    #[serde(default)]
    pub origin: Option<u32>,
}

/// A single message item (common fields + typed payload via `msgtype`)
#[derive(Debug, Clone, Deserialize)]
pub struct SyncMsgItem {
    #[serde(flatten)]
    pub common: SyncMsgItemCommon,
    #[serde(flatten)]
    pub payload: MsgPayload,
}

/// Typed payload by msgtype
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "msgtype")]
pub enum MsgPayload {
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
    #[serde(rename = "location")]
    Location { location: LocationContent },
    #[serde(rename = "miniprogram")]
    MiniProgram { miniprogram: MiniProgramContent },
    #[serde(rename = "channels_shop_product")]
    ChannelsShopProduct {
        channels_shop_product: ChannelsShopProductContent,
    },
    #[serde(rename = "channels_shop_order")]
    ChannelsShopOrder {
        channels_shop_order: ChannelsShopOrderContent,
    },
    #[serde(rename = "merged_msg")]
    MergedMsg { merged_msg: MergedMsgContent },
    #[serde(rename = "channels")]
    Channels { channels: ChannelsContent },
    #[serde(rename = "note")]
    Note {},
    #[serde(rename = "event")]
    Event { event: EventContent },
}

/// Text payload
#[derive(Debug, Clone, Deserialize)]
pub struct TextContent {
    pub content: String,
    #[serde(default)]
    pub menu_id: Option<String>,
}

/// Media payload (image/voice/video/file)
#[derive(Debug, Clone, Deserialize)]
pub struct MediaContent {
    pub media_id: String,
}

/// Location payload
#[derive(Debug, Clone, Deserialize)]
pub struct LocationContent {
    pub latitude: f64,
    pub longitude: f64,
    pub name: String,
    pub address: String,
}

/// Mini program payload
#[derive(Debug, Clone, Deserialize)]
pub struct MiniProgramContent {
    pub title: String,
    pub appid: String,
    pub pagepath: String,
    pub thumb_media_id: String,
}

/// Channels product payload
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelsShopProductContent {
    pub product_id: String,
    pub head_image: String,
    pub title: String,
    pub sales_price: String,
    pub shop_nickname: String,
    pub shop_head_image: String,
}

/// Channels order payload
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelsShopOrderContent {
    pub order_id: String,
    pub product_titles: String,
    pub price_wording: String,
    pub state: String,
    pub image_url: String,
    pub shop_nickname: String,
}

/// Merged chat records payload
#[derive(Debug, Clone, Deserialize)]
pub struct MergedMsgContent {
    pub title: String,
    #[serde(default)]
    pub item: Vec<MergedMsgItem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MergedMsgItem {
    pub send_time: u64,
    pub msgtype: String,
    pub sender_name: String,
    /// JSON string; structure follows the same message types as above
    pub msg_content: String,
}

/// Channels (video account) payload
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelsContent {
    pub sub_type: u32,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
}

/// Event payload
#[derive(Debug, Clone, Deserialize)]
pub struct EventContent {
    pub event_type: String,
    #[serde(default)]
    pub open_kfid: Option<String>,
    #[serde(default)]
    pub external_userid: Option<String>,
    #[serde(default)]
    pub scene: Option<String>,
    #[serde(default)]
    pub scene_param: Option<String>,
    #[serde(default)]
    pub welcome_code: Option<String>,
    #[serde(default)]
    pub wechat_channels: Option<EventWechatChannels>,
    #[serde(default)]
    pub fail_msgid: Option<String>,
    #[serde(default)]
    pub fail_type: Option<u32>,
    #[serde(default)]
    pub recall_msgid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventWechatChannels {
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub shop_nickname: Option<String>,
    pub scene: u32,
}

impl KfClient {
    /// Call kf/sync_msg to pull messages/events
    ///
    /// - access_token: WeCom Kf access_token
    /// - req: request body, include token from callback event when available
    #[instrument(level = "debug", skip(self, req))]
    pub async fn sync_msg(
        &self,
        access_token: &str,
        req: &SyncMsgRequest,
    ) -> Result<SyncMsgResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/kf/sync_msg")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
        }
        debug!(%url, "sync_msg request");
        // Use a short-lived client for this call to avoid relying on private fields
        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;
        let resp = http.post(url).json(req).send().await.map_err(Error::from)?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(Error::from)?;

        // Decode JSON; on errcode != 0, map to Error::Wx
        match serde_json::from_slice::<SyncMsgResponse>(&bytes) {
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
                // Reuse UnexpectedTokenResponse for detailed diagnostics
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
