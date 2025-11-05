/*!
Example: Download a temporary media file from WeCom (Kf), with optional HTTP Range

Run:
  WXKF_CORP_ID=ww... \
  WXKF_APP_SECRET=your_kf_secret \
  WXKF_MEDIA_ID=MEDIA_ID \
  [optional] WXKF_RANGE="0-1023" | "9500-" | "-500" | "bytes=0-1023" \
  [optional] WXKF_OUTPUT_PATH=/path/to/save.bin \
  cargo run --example media_get

Notes:
- WXKF_RANGE supports formats:
    "start-end"   => bytes=start-end (inclusive)
    "start-"      => bytes=start- (till end)
    "-len"        => bytes=-len (last len bytes)
    "bytes=..."   => same as above, prefixed with "bytes="
- On success, the API may return:
    * 200 OK (full content)
    * 206 Partial Content (for range requests)
  Headers include Content-Type, Content-Disposition (filename), Content-Range, etc.
*/

use anyhow::{Context, Result, bail};
use dotenvy::dotenv;
use std::env;
use std::fs::File;
use std::io::Write;
use wxkefu_rs::media::ByteRange;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenv();

    // Required environment variables
    let corp_id =
        env::var("WXKF_CORP_ID").context("set WXKF_CORP_ID (WeCom corpid, starts with 'ww')")?;
    let corp_secret = env::var("WXKF_APP_SECRET")
        .context("set WXKF_APP_SECRET (WeChat Customer Service Secret)")?;
    let media_id = env::var("WXKF_MEDIA_ID").context("set WXKF_MEDIA_ID (temporary media id)")?;

    // Optional: Range and output path
    let range = env::var("WXKF_RANGE")
        .ok()
        .and_then(|s| parse_range(&s).transpose())
        .transpose()?;
    let output_path = env::var("WXKF_OUTPUT_PATH").ok();

    // 1) Acquire WeCom Kf access_token
    let client = KfClient::default();
    let at = client
        .get_access_token(&Auth::WeCom {
            corp_id,
            corp_secret,
        })
        .await
        .context("failed to get WeCom (Kf) access_token")?;

    // 2) Download media (with optional Range)
    let part = client
        .media_get(&at.access_token, &media_id, range)
        .await
        .context("media_get failed")?;

    println!("HTTP status: {}", part.status);
    println!("Content-Type: {:?}", part.content_type);
    println!("Content-Disposition: {:?}", part.content_disposition);
    println!("Accept-Ranges: {:?}", part.accept_ranges);
    println!("Content-Range: {:?}", part.content_range);
    println!("Content-Length (header): {:?}", part.content_length);
    println!("Downloaded bytes: {}", part.bytes.len());

    if let Some(path) = output_path {
        let mut f = File::create(&path)
            .with_context(|| format!("failed to create output file: {}", path))?;
        f.write_all(&part.bytes)
            .with_context(|| format!("failed to write output file: {}", path))?;
        println!("Saved to {}", path);
    }

    Ok(())
}

fn parse_range(s: &str) -> Result<Option<ByteRange>> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(None);
    }
    let t = t.strip_prefix("bytes=").unwrap_or(t);

    // suffix form: "-len"
    if let Some(rest) = t.strip_prefix('-') {
        let len: u64 = rest
            .trim()
            .parse()
            .context("invalid suffix length in WXKF_RANGE")?;
        if len == 0 {
            bail!("suffix length must be > 0");
        }
        return Ok(Some(ByteRange::suffix(len)));
    }

    // from-to form: "start-end" or "start-"
    if let Some((start_s, end_s)) = t.split_once('-') {
        let start: u64 = start_s
            .trim()
            .parse()
            .context("invalid start in WXKF_RANGE")?;
        let end = if end_s.trim().is_empty() {
            None
        } else {
            Some(
                end_s
                    .trim()
                    .parse::<u64>()
                    .context("invalid end in WXKF_RANGE")?,
            )
        };
        return Ok(Some(ByteRange::from_to(start, end)));
    }

    bail!(
        "invalid WXKF_RANGE format; expected \"start-end\", \"start-\", \"-len\", or prefixed with \"bytes=\""
    )
}
