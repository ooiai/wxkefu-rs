/*!
Example: Upload a temporary media file to WeCom (Kf) and print media_id

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_FILE_PATH=/absolute/or/relative/path/to/file.ext \
  WXKF_MEDIA_TYPE=image|voice|video|file \
  [optional] WXKF_CONTENT_TYPE=image/png \
  cargo run --example media_upload

Notes:
- media_id is valid for 3 days.
- Size/type limits (subject to official docs):
  * image: 2MB (JPG, PNG)
  * voice: 2MB (AMR, <=60s)
  * video: 10MB (MP4)
  * file:  20MB
- The displayed filename is controlled by the filename provided here.
*/

use anyhow::{Context, Result, bail};
use dotenvy::dotenv;
use std::env;
use std::path::Path;
use wxkefu_rs::media::MediaType;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();

    // Required environment variables
    let corp_id =
        env::var("WXKF_CORP_ID").context("set WXKF_CORP_ID (WeCom corpid, starts with 'ww')")?;
    let corp_secret = env::var("WXKF_APP_SECRET")
        .context("set WXKF_APP_SECRET (WeChat Customer Service Secret)")?;
    let file_path = env::var("WXKF_FILE_PATH").context("set WXKF_FILE_PATH (path to the file)")?;
    let media_type_str =
        env::var("WXKF_MEDIA_TYPE").context("set WXKF_MEDIA_TYPE (image|voice|video|file)")?;

    // Optional content type
    let content_type = env::var("WXKF_CONTENT_TYPE").ok();

    // Parse media type
    let media_type = parse_media_type(&media_type_str)
        .with_context(|| format!("invalid WXKF_MEDIA_TYPE: {media_type_str}"))?;

    // Read file and derive filename
    let data =
        std::fs::read(&file_path).with_context(|| format!("failed to read file: {}", file_path))?;
    if data.len() < 5 {
        bail!("file too small (< 5 bytes), per API requirements");
    }
    let filename = file_name_from_path(&file_path)
        .ok_or_else(|| anyhow::anyhow!("cannot derive filename from WXKF_FILE_PATH"))?;

    // 1) Acquire WeCom Kf access_token
    let client = KfClient::default();
    let at = client
        .get_access_token(&Auth::WeCom {
            corp_id,
            corp_secret,
        })
        .await
        .context("failed to get WeCom (Kf) access_token")?;

    // 2) Upload media
    let resp = client
        .media_upload(
            &at.access_token,
            media_type,
            &filename,
            content_type.as_deref(),
            data,
        )
        .await
        .context("media_upload failed")?;

    println!(
        "upload ok: errcode={}, errmsg={}, type={:?}, media_id={}, created_at={}",
        resp.errcode, resp.errmsg, resp.r#type, resp.media_id, resp.created_at
    );

    Ok(())
}

fn parse_media_type(s: &str) -> Result<MediaType> {
    match s.trim().to_ascii_lowercase().as_str() {
        "image" => Ok(MediaType::Image),
        "voice" => Ok(MediaType::Voice),
        "video" => Ok(MediaType::Video),
        "file" => Ok(MediaType::File),
        _ => bail!("must be one of: image | voice | video | file"),
    }
}

fn file_name_from_path(p: &str) -> Option<String> {
    let path = Path::new(p);
    path.file_name()
        .and_then(|os| os.to_str())
        .map(|s| s.to_string())
}
