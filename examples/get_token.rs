use std::env;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Run with:
    //   cargo run --example get_token
    //
    // Env vars:
    // - Official Account / Mini Program: WX_APPID, WX_APPSECRET
    // - WeCom (企业微信): WXKF_CORP_ID, WXKF_APP_SECRET
    //
    // If both modes have their env vars set, both will be requested.

    let client = KfClient::default();
    let mut attempted = false;

    // Official Account / Mini Program token
    match (env::var("WX_APPID"), env::var("WX_APPSECRET")) {
        (Ok(appid), Ok(secret)) => {
            attempted = true;
            println!("Requesting OfficialAccount/MiniProgram access_token...");
            match client
                .get_access_token(&Auth::OfficialAccount { appid, secret })
                .await
            {
                Ok(token) => {
                    println!(
                        "[OK] OfficialAccount token: {}\nexpires_in: {} seconds\n",
                        token.access_token, token.expires_in
                    );
                }
                Err(e) => {
                    eprintln!("[ERR] OfficialAccount token failed: {e}");
                }
            }
        }
        _ => {
            println!(
                "Skip OfficialAccount/MiniProgram: set WX_APPID and WX_APPSECRET to test this mode."
            );
        }
    }

    // WeCom token
    match (env::var("WXKF_CORP_ID"), env::var("WXKF_APP_SECRET")) {
        (Ok(corp_id), Ok(corp_secret)) => {
            attempted = true;
            println!("Requesting WeCom (企业微信) access_token...");
            match client
                .get_access_token(&Auth::WeCom {
                    corp_id,
                    corp_secret,
                })
                .await
            {
                Ok(token) => {
                    println!(
                        "[OK] WeCom token: {}\nexpires_in: {} seconds\n",
                        token.access_token, token.expires_in
                    );
                }
                Err(e) => {
                    eprintln!("[ERR] WeCom token failed: {e}");
                }
            }
        }
        _ => {
            println!("Skip WeCom: set WXKF_CORP_ID and WXKF_APP_SECRET to test this mode.");
        }
    }

    if !attempted {
        println!(
            "\nNo auth mode attempted. Please set environment variables for at least one mode:"
        );
        println!("  - OfficialAccount/MiniProgram: WX_APPID, WX_APPSECRET");
        println!("  - WeCom: WXKF_CORP_ID, WXKF_APP_SECRET");
    }

    Ok(())
}
