use dotenvy::dotenv;
use std::env;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Run with:
    //   cargo run --example get_token
    //
    // Env vars:
    // - Official Account / Mini Program: WX_APPID, WX_APPSECRET
    // - WeCom (WeChat Customer Service): WXKF_CORP_ID, WXKF_APP_SECRET
    //
    // If both are set, the example will request both tokens (for comparison)

    let _ = dotenv();

    let client = KfClient::default();
    let mut attempted = false;

    // Official Account / Mini Program token
    match (env::var("WX_APPID"), env::var("WX_APPSECRET")) {
        (Ok(appid), Ok(secret)) => {
            attempted = true;
            // OA/MP access_token request (note: not used for WeCom Kf APIs)
            let appid_hint = if appid.len() <= 4 {
                format!("{}***", appid)
            } else {
                format!(
                    "{}***{}",
                    &appid[..2],
                    &appid[appid.len().saturating_sub(2)..]
                )
            };
            if appid.starts_with("ww") {
                eprintln!(
                    "Hint: detected appid starts with 'ww' (likely a WeCom corpid). If you intend to call WeChat Customer Service APIs, use corpid + Kf Secret (WXKF_CORP_ID/WXKF_APP_SECRET)."
                );
            }
            println!("Requesting Official Account / Mini Program access_token...");
            println!("appid hint: {}", appid_hint);
            match client
                .get_access_token(&Auth::OfficialAccount { appid, secret })
                .await
            {
                Ok(token) => {
                    println!(
                        "[OK] Official Account / Mini Program access_token: {}\nexpires_in: {} seconds\n",
                        token.access_token, token.expires_in
                    );
                }
                Err(e) => {
                    eprintln!("[ERR] Official Account / Mini Program access_token failed: {e}");
                }
            }
        }
        _ => {
            println!(
                "Skip Official Account / Mini Program: set WX_APPID and WX_APPSECRET to test this mode."
            );
        }
    }

    // WeCom token
    match (env::var("WXKF_CORP_ID"), env::var("WXKF_APP_SECRET")) {
        (Ok(corp_id), Ok(corp_secret)) => {
            attempted = true;
            // WeCom (WeChat Customer Service) access_token request
            let corp_id_hint = if corp_id.len() <= 4 {
                format!("{}***", corp_id)
            } else {
                format!(
                    "{}***{}",
                    &corp_id[..2],
                    &corp_id[corp_id.len().saturating_sub(2)..]
                )
            };
            if corp_id.starts_with("wx") {
                eprintln!(
                    "Hint: detected corpid starts with 'wx' (likely an OA/MP appid). WeChat Customer Service should use corpid (starts with 'ww') with the Kf Secret."
                );
            }
            println!("Requesting WeCom (WeChat Customer Service) access_token...");
            println!("corpid hint: {}", corp_id_hint);
            match client
                .get_access_token(&Auth::WeCom {
                    corp_id,
                    corp_secret,
                })
                .await
            {
                Ok(token) => {
                    println!(
                        "[OK] WeCom (Kf) access_token: {}\nexpires_in: {} seconds\n",
                        token.access_token, token.expires_in
                    );
                }
                Err(e) => {
                    eprintln!("[ERR] WeCom (Kf) access_token failed: {e}");
                }
            }
        }
        _ => {
            println!("Skip WeCom (Kf): set WXKF_CORP_ID and WXKF_APP_SECRET to test this mode.");
        }
    }

    if !attempted {
        println!(
            "\nNo auth mode attempted. Please set environment variables for at least one mode:"
        );
        println!("  - Official Account / Mini Program: WX_APPID, WX_APPSECRET");
        println!("  - WeCom (Kf): WXKF_CORP_ID, WXKF_APP_SECRET");
    }

    Ok(())
}
