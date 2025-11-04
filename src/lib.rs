#![doc = r#"
wxkefu-rs

面向「微信客服」的 Rust 基础库（可扩展）。当前提供获取调用凭证 access_token 的通用客户端与类型定义，
同时兼容两类凭证体系：
- 微信客服（企业微信侧）：使用企业ID（corpid，以 `ww...` 开头）与微信客服 Secret（corpsecret），
  通过企业微信接口 `https://qyapi.weixin.qq.com/cgi-bin/gettoken` 获取。
- 公众号 / 小程序：使用 appid（以 `wx...` 开头）与 appsecret，走公众平台接口
  `https://api.weixin.qq.com/cgi-bin/token` 获取。

若你的目标是对接「微信客服」能力（客服账号管理、客服消息收发、会话分配等），请使用企业微信侧
的 corpid + corpsecret 模式（即 `Auth::WeCom`）。公众平台的 appid/appsecret 不适用于
微信客服接口的调用与鉴权。

官方文档（建议先阅读）：
- 获取调用凭证 access_token（微信客服）：https://kf.weixin.qq.com/api/doc/path/93304

包含内容
- 统一鉴权枚举 `Auth`：区分「微信客服（企业微信）」与「公众号 / 小程序」两种模式
- 访问令牌类型 `AccessToken`
- 错误类型 `Error`（包含 HTTP、微信错误码、解析异常等）
- 客户端 `KfClient`：封装 HTTP 请求与返回解析，便于后续扩展更多接口

使用说明（微信客服/企业微信）
1. 在「微信客服管理后台-开发配置」获取企业ID（corpid）与 Secret（corpsecret）
2. 使用 corpid + corpsecret 调用本库的 `get_access_token` 获取 access_token
3. 按官方要求在业务侧缓存 access_token（有效期通常为 7200 秒），避免频繁获取导致限频
4. 当 access_token 失效或过期时，再次调用获取新的 access_token

注意事项（重要）
- 微信客服使用的是企业微信侧凭证：corpid 形如 `ww...`，与公众平台 `wx...` 的 appid 不同
- 频率限制：请缓存 access_token，避免频繁调用获取接口
- 有效期：正常为 7200 秒；有效期内重复获取返回相同结果；过期后返回新的 access_token
- 可能提前失效：需在业务中处理失效重取的逻辑
- 安全建议：不要在日志中输出密钥（secret / corpsecret / access_token）

快速上手示例（仅演示，代码注释均为中文）

示例一：微信客服（企业微信）获取 access_token
```ignore
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 业务侧建议将 corpid 与 corpsecret 放入安全的配置中心或环境变量中
    let corpid = std::env::var("WXKF_CORP_ID")?;
    let corpsecret = std::env::var("WXKF_APP_SECRET")?;

    let client = KfClient::default();
    let token = client
        .get_access_token(&Auth::WeCom {
            corp_id: corpid,
            corp_secret: corpsecret,
        })
        .await?;

    // 仅演示打印；生产中不要打印密钥与 token
    println!("access_token: {}, expires_in: {}", token.access_token, token.expires_in);

    // 在此处将 token 缓存到你的存储（内存/Redis/DB 等），并做好过期刷新
    Ok(())
}
```

示例二：公众号 / 小程序获取 access_token（注意：此模式不适用于「微信客服」接口）
```ignore
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 若你的业务是调用公众平台接口，可使用此模式；与微信客服无直接关联
    let appid = std::env::var("WX_APPID")?;
    let appsecret = std::env::var("WX_APPSECRET")?;

    let client = KfClient::default();
    let token = client
        .get_access_token(&Auth::OfficialAccount {
            appid,
            secret: appsecret,
        })
        .await?;

    println!("access_token: {}, expires_in: {}", token.access_token, token.expires_in);
    Ok(())
}
```

示例三：结合 .env 使用（便于本地调试）
```ignore
use dotenvy::dotenv;
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 加载 .env（例如放置 WXKF_CORP_ID 与 WXKF_APP_SECRET）
    let _ = dotenv();

    let client = KfClient::default();

    // 微信客服（企业微信）模式
    if let (Ok(corpid), Ok(corpsecret)) = (std::env::var("WXKF_CORP_ID"), std::env::var("WXKF_APP_SECRET")) {
        let token = client
            .get_access_token(&Auth::WeCom {
                corp_id: corpid,
                corp_secret: corpsecret,
            })
            .await?;
        println!("wecom access_token: {}, expires_in: {}", token.access_token, token.expires_in);
    }

    // 公众号 / 小程序模式（若仅使用微信客服，可忽略此段）
    if let (Ok(appid), Ok(appsecret)) = (std::env::var("WX_APPID"), std::env::var("WX_APPSECRET")) {
        let token = client
            .get_access_token(&Auth::OfficialAccount {
                appid,
                secret: appsecret,
            })
            .await?;
        println!("mp access_token: {}, expires_in: {}", token.access_token, token.expires_in);
    }

    Ok(())
}
```

错误处理
- 当微信返回非零错误码时，本库会将其映射为统一错误 `Error::Wx { code, message }`
- 当返回体格式异常时，会给出 `Error::UnexpectedTokenResponse` 以便排查
- 网络或解析相关错误归为 `Error::Http` 等

后续规划
- 在现有 `KfClient` 基础上扩展微信客服的客服账号管理、消息收发、会话管理等接口
- 提供访问令牌的内置缓存与自动刷新中间件（当前需由业务侧实现）

"#]

pub mod token;
pub use token::*;
