use dotenvy::dotenv;

use wxkefu_rs::token_tool::get_token;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Run with:
    //   cargo run --example get_token_tool
    //
    // Environment:
    //   REDIS_URL (optional, defaults to redis://127.0.0.1/)
    //   WXKF_CORP_ID
    //   WXKF_APP_SECRET

    let _ = dotenv();

    // One-call utility: get cached or freshly fetched token with auto-refresh.
    let token = get_token().await?;
    println!("access_token received (redacted): len={}", token.len());

    Ok(())
}
