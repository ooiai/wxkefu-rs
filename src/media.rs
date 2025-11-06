#![allow(dead_code)]
//! WeCom (WeChat Customer Service) media (temporary material) API
//!
//! Provides upload and download helpers without extra dependencies:
//! - Upload (multipart/form-data built manually)
//! - Download with optional HTTP Range (RFC 7233) support
//!
//! Official API:
//! - Upload:  POST https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token=ACCESS_TOKEN&type=TYPE
//!            form-data field name: "media"; include filename=..., filelength=..., Content-Type
//! - Download: GET  https://qyapi.weixin.qq.com/cgi-bin/media/get?access_token=ACCESS_TOKEN&media_id=MEDIA_ID
//!            Supports HTTP Range (partial content, 206)
//!
//! Notes
//! - media_id is valid for 3 days
//! - File size/type limits (at time of writing):
//!   * image: 2MB JPG/PNG
//!   * voice: 2MB AMR (<=60s)
//!   * video: 10MB MP4
//!   * file:  20MB
//! - On error, server returns JSON { errcode, errmsg }. Binary responses carry media data.
//! - Range requests follow RFC 7233 (e.g., "Range: bytes=0-1023" or "Range: bytes=-1024").
//!
//! Example upload:
//! ```ignore
//! use wxkefu_rs::{Auth, KfClient};
//! use wxkefu_rs::media::{MediaType};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = KfClient::default();
//!     let at = client.get_access_token(&Auth::WeCom {
//!         corp_id: "ww...".into(), corp_secret: "secret...".into()
//!     }).await?;
//!
//!     let data = std::fs::read("demo.png")?;
//!     let resp = client.media_upload(
//!         &at.access_token,
//!         MediaType::Image,
//!         "demo.png",
//!         Some("image/png"),
//!         data,
//!     ).await?;
//!     println!("uploaded: type={:?}, media_id={}, created_at={}",
//!         resp.r#type, resp.media_id, resp.created_at);
//!     Ok(())
//! }
//! ```
//!
//! Example download with Range:
//! ```ignore
//! use wxkefu_rs::{Auth, KfClient};
//! use wxkefu_rs::media::{ByteRange, MediaGetOk};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let client = KfClient::default();
//!     let at = client.get_access_token(&Auth::WeCom {
//!         corp_id: "ww...".into(), corp_secret: "secret...".into()
//!     }).await?;
//!
//!     let part = client.media_get(
//!         &at.access_token,
//!         "MEDIA_ID",
//!         Some(ByteRange::from_to(0, Some(1023))),
//!     ).await?;
//!     println!("HTTP status: {}", part.status);
//!     println!("Content-Range: {:?}", part.content_range);
//!     println!("len={}", part.bytes.len());
//!     Ok(())
//! }
//! ```

use bytes::Bytes;
use reqwest::Url;
use reqwest::header::{
    CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderMap, HeaderValue, RANGE,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::{Error, KfClient, Result};

/// Media type for upload
#[derive(Debug, Clone, Copy)]
pub enum MediaType {
    Image,
    Voice,
    Video,
    File,
}

impl MediaType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MediaType::Image => "image",
            MediaType::Voice => "voice",
            MediaType::Video => "video",
            MediaType::File => "file",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MediaUploadResponse {
    pub errcode: i32,
    pub errmsg: String,
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    pub media_id: String,
    pub created_at: String,
}

/// A successful binary media response from `media/get`
#[derive(Debug, Clone)]
pub struct MediaGetOk {
    /// HTTP status, 200 or 206 (Partial Content) on success
    pub status: u16,
    /// Content-Type header (if any)
    pub content_type: Option<String>,
    /// Content-Disposition header (suggested filename, if any)
    pub content_disposition: Option<String>,
    /// Accept-Ranges header (e.g., "bytes"), if provided
    pub accept_ranges: Option<String>,
    /// Content-Range header for partial responses
    pub content_range: Option<String>,
    /// Content-Length header, if provided
    pub content_length: Option<u64>,
    /// Raw bytes of the media payload
    pub bytes: Bytes,
}

/// HTTP byte range request helper (RFC 7233)
#[derive(Debug, Clone, Copy)]
pub enum ByteRange {
    /// bytes=start-end (inclusive), end=None means start..end-of-file
    FromTo { start: u64, end: Option<u64> },
    /// bytes=-len (suffix last len bytes)
    Suffix { len: u64 },
}

impl ByteRange {
    pub fn from_to(start: u64, end: Option<u64>) -> Self {
        ByteRange::FromTo { start, end }
    }
    pub fn suffix(len: u64) -> Self {
        ByteRange::Suffix { len }
    }

    /// Build a valid Range header value (e.g., "bytes=0-1023", "bytes=9500-", "bytes=-500")
    pub fn to_header_value(&self) -> String {
        match *self {
            ByteRange::FromTo { start, end } => match end {
                Some(e) => format!("bytes={}-{}", start, e),
                None => format!("bytes={}-", start),
            },
            ByteRange::Suffix { len } => format!("bytes=-{}", len),
        }
    }
}

impl KfClient {
    /// Upload a temporary media (multipart/form-data) without depending on external multipart crates.
    ///
    /// - `media_type`: one of image/voice/video/file
    /// - `filename`: displayed filename on downstream usage
    /// - `content_type`: MIME, e.g., "image/png". If None, a naive guess is applied
    /// - `data`: raw media bytes
    #[instrument(level = "debug", skip(self, data))]
    pub async fn media_upload(
        &self,
        access_token: &str,
        media_type: MediaType,
        filename: &str,
        content_type: Option<&str>,
        data: impl Into<Bytes>,
    ) -> Result<MediaUploadResponse> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/media/upload")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
            qp.append_pair("type", media_type.as_str());
        }

        let data: Bytes = data.into();
        let filelength = data.len();

        let boundary = make_boundary();
        let mime = content_type
            .map(|s| s.to_string())
            .unwrap_or_else(|| guess_mime_from_filename(filename).to_string());

        let body = build_multipart_body(&boundary, filename, filelength, &mime, data);

        let content_type_header = format!("multipart/form-data; boundary={}", boundary);
        debug!(%url, boundary=%boundary, "media_upload request");

        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, content_type_header)
            .body(body)
            .send()
            .await?;

        let status = resp.status();
        let bytes = resp.bytes().await?;

        // Upload response is JSON with errcode
        match serde_json::from_slice::<MediaUploadResponse>(&bytes) {
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

    /// Download a temporary media; returns binary content on success (status 200/206),
    /// or maps JSON error to Error::Wx.
    ///
    /// - `range`: optional byte range ("Range: bytes=...") request per RFC 7233
    #[instrument(level = "debug", skip(self))]
    pub async fn media_get(
        &self,
        access_token: &str,
        media_id: &str,
        range: Option<ByteRange>,
    ) -> Result<MediaGetOk> {
        let mut url = Url::parse("https://qyapi.weixin.qq.com/cgi-bin/media/get")
            .map_err(|e| Error::InvalidUrl(e.to_string()))?;
        {
            let mut qp = url.query_pairs_mut();
            qp.append_pair("access_token", access_token);
            qp.append_pair("media_id", media_id);
        }
        debug!(%url, "media_get request");

        let http = reqwest::Client::builder()
            .gzip(true)
            .build()
            .map_err(|e| Error::Http(e.into()))?;

        let mut req = http.get(url);
        if let Some(r) = range {
            req = req.header(
                RANGE,
                HeaderValue::from_str(&r.to_header_value())
                    .unwrap_or_else(|_| HeaderValue::from_static("bytes=0-")),
            );
        }

        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let bytes = resp.bytes().await?;

        // Content may be JSON error. Try detect via header or leading char
        let is_json = headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.to_ascii_lowercase().starts_with("application/json"))
            .unwrap_or_else(|| starts_like_json(&bytes));

        if is_json {
            #[derive(Deserialize)]
            struct WxErr {
                errcode: i64,
                errmsg: String,
            }
            match serde_json::from_slice::<WxErr>(&bytes) {
                Ok(e) => {
                    return Err(Error::Wx {
                        code: e.errcode,
                        message: e.errmsg,
                    });
                }
                Err(de_err) => {
                    let body = String::from_utf8_lossy(&bytes).to_string();
                    return Err(Error::UnexpectedTokenResponse {
                        status,
                        error: de_err.to_string(),
                        body,
                    });
                }
            }
        }

        Ok(MediaGetOk {
            status,
            content_type: headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            content_disposition: headers
                .get(CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            accept_ranges: get_header_string(&headers, "accept-ranges"),
            content_range: headers
                .get(CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            content_length: headers
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok()),
            bytes,
        })
    }
}

/* -------------------- helpers -------------------- */

fn get_header_string(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .or_else(|| headers.get(name.to_ascii_lowercase()))
        .or_else(|| headers.get(name.to_ascii_uppercase()))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn starts_like_json(b: &Bytes) -> bool {
    let s = std::str::from_utf8(b).unwrap_or("");
    let t = s.trim_start();
    t.starts_with('{') || t.starts_with('[')
}

/// Very simple boundary generator; sufficient uniqueness for our purpose
fn make_boundary() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let addr = (&now as *const _ as usize) as u64;
    format!("----wxkefu-rs-{}-{:x}", now, addr.rotate_left(17))
}

/// Build a minimal multipart/form-data body:
/// --boundary\r\n
/// Content-Disposition: form-data; name="media"; filename="..."; filelength=LEN\r\n
/// Content-Type: MIME\r\n
/// \r\n
/// <bytes>\r\n
/// --boundary--\r\n
fn build_multipart_body(
    boundary: &str,
    filename: &str,
    filelength: usize,
    mime: &str,
    data: Bytes,
) -> Bytes {
    let mut buf =
        Vec::with_capacity(boundary.len() + filename.len() + mime.len() + data.len() + 256);

    // Preamble
    push_str(&mut buf, "--");
    push_str(&mut buf, boundary);
    push_str(&mut buf, "\r\n");

    // Content-Disposition (include non-standard "filelength" per doc/example)
    push_str(
        &mut buf,
        &format!(
            "Content-Disposition: form-data; name=\"media\";filename=\"{}\"; filelength={}\r\n",
            escape_filename(filename),
            filelength
        ),
    );

    // Content-Type
    push_str(&mut buf, &format!("Content-Type: {}\r\n", mime));
    push_str(&mut buf, "\r\n");

    // File bytes
    buf.extend_from_slice(&data);

    // CRLF and closing boundary
    push_str(&mut buf, "\r\n--");
    push_str(&mut buf, boundary);
    push_str(&mut buf, "--\r\n");

    Bytes::from(buf)
}

fn push_str(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(s.as_bytes());
}

fn escape_filename(name: &str) -> String {
    // Minimal escaping: replace double quotes with underscores
    name.replace('"', "_")
}

fn guess_mime_from_filename(name: &str) -> &'static str {
    let lower = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match lower.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "bmp" => "image/bmp",
        "mp4" => "video/mp4",
        "amr" => "audio/amr",
        "silk" | "sil" => "audio/silk",
        "ogg" => "audio/ogg",
        "mp3" => "audio/mpeg",
        "txt" => "text/plain",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}
