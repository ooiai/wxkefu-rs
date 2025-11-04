use dotenvy::dotenv;
use std::env;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 运行方式：
    //   cargo run --example get_token
    //
    // 环境变量：
    // - 公众号 / 小程序：WX_APPID, WX_APPSECRET
    // - 微信客服（企业微信）：WXKF_CORP_ID, WXKF_APP_SECRET
    //
    // 如两类变量均已设置，将分别请求两种 access_token（便于对比调试）

    let _ = dotenv();

    let client = KfClient::default();
    let mut attempted = false;

    // Official Account / Mini Program token
    match (env::var("WX_APPID"), env::var("WX_APPSECRET")) {
        (Ok(appid), Ok(secret)) => {
            attempted = true;
            // 公众平台（公众号/小程序）access_token 请求（注意：与微信客服无直接关系）
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
                    "提示：检测到 appid 以 ww 开头，这通常是企业微信 corpid；若要调用『微信客服』接口，请使用 corpid + 微信客服 Secret（WXKF_CORP_ID/WXKF_APP_SECRET）"
                );
            }
            println!("请求公众号/小程序 access_token...");
            println!("appid 提示: {}", appid_hint);
            match client
                .get_access_token(&Auth::OfficialAccount { appid, secret })
                .await
            {
                Ok(token) => {
                    println!(
                        "[OK] 公众号/小程序 access_token 获取成功：{}\n有效期：{} 秒\n",
                        token.access_token, token.expires_in
                    );
                }
                Err(e) => {
                    eprintln!("[ERR] 公众号/小程序 access_token 获取失败: {e}");
                }
            }
        }
        _ => {
            println!("跳过 公众号/小程序：请设置环境变量 WX_APPID 与 WX_APPSECRET 以测试此模式。");
        }
    }

    // WeCom token
    match (env::var("WXKF_CORP_ID"), env::var("WXKF_APP_SECRET")) {
        (Ok(corp_id), Ok(corp_secret)) => {
            attempted = true;
            // 微信客服（企业微信）access_token 请求
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
                    "提示：检测到 corpid 以 wx 开头，这通常是公众平台 appid；『微信客服』应使用 corpid（以 ww 开头）与微信客服 Secret。"
                );
            }
            println!("请求微信客服（企业微信） access_token...");
            println!("corpid 提示: {}", corp_id_hint);
            match client
                .get_access_token(&Auth::WeCom {
                    corp_id,
                    corp_secret,
                })
                .await
            {
                Ok(token) => {
                    println!(
                        "[OK] 微信客服（企业微信）access_token 获取成功：{}\n有效期：{} 秒\n",
                        token.access_token, token.expires_in
                    );
                }
                Err(e) => {
                    eprintln!("[ERR] 微信客服（企业微信）access_token 获取失败: {e}");
                }
            }
        }
        _ => {
            println!(
                "跳过 微信客服（企业微信）：请设置环境变量 WXKF_CORP_ID 与 WXKF_APP_SECRET 以测试此模式。"
            );
        }
    }

    if !attempted {
        println!("\n未尝试任何鉴权模式。请至少为以下任一模式设置环境变量：");
        println!("  - 公众号/小程序：WX_APPID, WX_APPSECRET");
        println!("  - 微信客服（企业微信）：WXKF_CORP_ID, WXKF_APP_SECRET");
    }

    Ok(())
}
