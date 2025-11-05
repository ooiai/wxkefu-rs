# wxkefu-rs · 微信客服 API 集成（Rust）

简体中文 | English

概览
wxkefu-rs 是一个面向微信客服（WeCom Kf）的 Rust 客户端库，覆盖从获取 token、回调验签解密、消息拉取与发送、欢迎语、素材上传下载、消息撤回，到客户信息与客服账号管理等常用能力，并提供可运行的 examples 方便你快速上手。

- 产品主页：https://kf.weixin.qq.com/
- API 文档：https://kf.weixin.qq.com/api/doc/path/93304

特性概览

- WeCom（企业微信）微信客服 API 封装（Kf 专用）
- 回调验签与 AES 解密工具（框架无关）
- 消息拉取（sync_msg）与发送（text/image/link/...）
- 欢迎消息（进入会话事件 welcome_code）
- 临时媒体上传/下载（支持 HTTP Range）
- 消息撤回（2 分钟时效）
- 客户基础信息（customer/batchget）
- 客服账号管理（新增/删除/修改/列表/获取客服链接）
- 全局错误码辅助与排查建议（含“Warning: wrong json format.” 检测）
- Token/AESKey 生成与验证工具
- 完整可运行的 examples

重要范围说明

- 微信客服（Kf）使用企业微信（WeCom）凭据：corpid（通常以 ww 开头）+ 微信客服 Secret（corpsecret）。
- 公众号/小程序的 appid/appsecret 所获取的 token 不能调用 Kf 接口。
- Token 端点差异：
  - WeCom（Kf）：https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=ID&corpsecret=SECRET
  - 公众号/小程序：https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=APPID&secret=APPSECRET
- access_token 需缓存并在过期或早失效（如 40014/40001）时刷新。

安装与环境

- 将本库加入你的 Cargo 项目（示例为本地路径依赖）：
  /dev/null/Cargo.toml#L1-10
  [dependencies]
  wxkefu-rs = { path = "./wxkefu-rs" }

- 常用环境变量（examples 会使用）：
  - 微信客服（Kf）：WXKF_CORP_ID、WXKF_APP_SECRET
  - 回调开发：WXKF_TOKEN、WXKF_AES_KEY
  - 其他示例：WXKF_OPEN_KFID、WXKF_TOUSER（或 WXKF_EXTERNAL_USERID）、WXKF_MEDIA_ID 等

快速开始：获取 WeCom（Kf） access_token

```/dev/null/examples/get_token.rs#L1-40
use wxkefu_rs::{Auth, KfClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = KfClient::default();
    let token = client
        .get_access_token(&Auth::WeCom {
            corp_id: std::env::var("WXKF_CORP_ID")?,
            corp_secret: std::env::var("WXKF_APP_SECRET")?,
        })
        .await?;
    println!("access_token={}, expires_in={}", token.access_token, token.expires_in);
    Ok(())
}
```

发送一条文本消息（更完整示例见 examples/send_text.rs）

```/dev/null/examples/send_text.rs#L1-40
use wxkefu_rs::{Auth, KfClient};
use wxkefu_rs::send_msg::{SendMsgRequest, SendMsgPayload, TextContent};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = KfClient::default();
    let at = client
        .get_access_token(&Auth::WeCom {
            corp_id: std::env::var("WXKF_CORP_ID")?,
            corp_secret: std::env::var("WXKF_APP_SECRET")?,
        })
        .await?;

    let req = SendMsgRequest {
        touser: std::env::var("WXKF_TOUSER")?,       // external_userid
        open_kfid: std::env::var("WXKF_OPEN_KFID")?, // 客服账号ID
        msgid: None,
        payload: SendMsgPayload::Text { text: TextContent { content: "hello from wxkefu-rs".into() } },
    };
    let resp = client.send_msg(&at.access_token, &req).await?;
    println!("send_msg: errcode={}, errmsg={}", resp.errcode, resp.errmsg);
    Ok(())
}
```

关键能力与模块

- token（在 crate 根导出）
  - Auth（WeCom | OfficialAccount）
  - KfClient::get_access_token(&Auth) -> AccessToken
  - 统一 Error/Result
- callback（框架无关）
  - verify_and_decrypt_echostr(...)（URL 校验）
  - verify_and_decrypt_post_body(...)（POST 回调处理）
  - decrypt_b64_message(...)（底层 AES）
- sync_msg（消息拉取）
  - KfClient::sync_msg(access_token, req) -> ...，使用 next_cursor/has_more 分页
- send_msg（发送消息）
  - KfClient::send_msg(access_token, &SendMsgRequest) -> ...
  - 支持 text/image/voice/video/file/link/miniprogram/msgmenu/location/business_card/ca_link
- send_msg_on_event（欢迎消息）
  - KfClient::send_msg_on_event(access_token, &SendMsgOnEventRequest) -> ...
  - 使用 enter_session 事件中的一次性 welcome_code
- recall_msg（撤回消息）
  - KfClient::recall_msg(access_token, &RecallMsgRequest) -> ...
  - 仅支持 2 分钟内通过 API 发送的消息
- media（临时素材）
  - KfClient::media_upload(access_token, media_type, filename, content_type, data) -> ...
  - KfClient::media_get(access_token, media_id, range) -> ...
  - 支持 HTTP Range（206 Partial Content）
- customer（客户基础信息）
  - KfClient::customer_batchget(access_token, &CustomerBatchGetRequest) -> ...
- account（客服账号管理）
  - account_add / account_del / account_update / account_list / add_contact_way
- keygen（密钥生成）
  - generate_token(len)、generate_encoding_aes_key()、verify_encoding_aes_key()
- errors（全局错误码辅助）
  - explain(errcode, errmsg) -> String（单行人类可读说明）
  - lookup/hint_for/category_for/should_retry/should_refresh_token
  - contains_wrong_json_format(errmsg) 检测

关键示例（可运行）

- 令牌与回调
  - examples/get_token.rs
  - examples/callback_server.rs
  - examples/keygen_example.rs
  - examples/error_help.rs
- 消息收发与会话
  - examples/pull_messages.rs（sync_msg）
  - examples/send_text.rs / send_image.rs / send_link.rs
  - examples/send_welcome_text.rs / send_welcome_menu.rs
  - examples/recall_msg.rs
- 媒体
  - examples/media_upload.rs
  - examples/media_get.rs
- 客户与账号管理
  - examples/customer_batchget.rs
  - examples/account_add.rs / account_del.rs
  - examples/account_more.rs（update/list/add_contact_way）
- 更多案例请查看 examples 目录

回调配置

配置回调服务需要三个配置项：URL、Token、EncodingAESKey。

- URL：你的公网回调地址（例如 https://your.domain/callback），必须可被微信客服服务器访问
- Token：仅字母或数字，长度不超过 32，用于 SHA1 签名校验；仅你与微信客服后台知晓，不在传输中出现
- EncodingAESKey：43 位字母数字字符串；在尾部追加一个“=”后 Base64 解码得到 32 字节密钥（IV 为密钥前 16 字节），用于回调消息的 AES-256-CBC 解密

生成 Token 和 EncodingAESKey

- 运行示例生成：cargo run --example keygen_example
  - TOKEN：默认 32 位字母数字
  - ENCODING_AES_KEY：43 位字母数字；可通过在末尾追加“=”并 Base64 解码校验应为 32 字节
- 将生成结果用于回调服务器与管理后台配置

为回调服务设置环境变量（examples/callback_server.rs）

- WXKF_TOKEN：使用上一步生成的 TOKEN
- WXKF_ENCODING_AES_KEY：使用上一步生成的 ENCODING_AES_KEY（43 位）
- WXKF_CORP_ID 或 WXKF_RECEIVER_ID：可选但推荐，一般为 corpid（ww...），用于校验解密明文尾部的 receiver id
- PORT：可选，默认 3000

URL 验证（GET /callback）

- WeCom/Kf 会携带 msg_signature、timestamp、nonce、echostr（加密回声，Base64）
- 服务端需使用 Token 校验签名，并用 EncodingAESKey 解密 echostr，返回解密后的明文回声
- 注意：
  - echostr 由微信下发，请勿自行构造（更不要把 EncodingAESKey 当作 echostr）
  - 若经过代理/CDN 导致 Base64 被改写（如 “+” 被替换为空格），需确保未被改写；本库在解密时对 URL-safe Base64 和缺失 padding 做了归一化处理，但空格等仍会破坏解码

消息/事件推送（POST /callback）

- 请求体为 XML 或 JSON 包裹的 Encrypt 字段；Query 中包含 msg_signature、timestamp、nonce
- 处理流程：
  1）提取 Encrypt
  2）用 Token、timestamp、nonce、Encrypt 计算签名并校验
  3）使用 EncodingAESKey 解密得到真实负载
  4）处理解密出的消息/事件（Kf 通常为 JSON）
- kf_msg_or_event 事件的解密 JSON 通常包含一个短期 token，用于调用 kf/sync_msg 拉取消息；拉取结果使用 next_cursor/has_more 分页直至拉取完毕

库内说明与辅助函数

- Base64 处理：解密时会对 URL-safe 字符（-/\_）与缺失 “=” padding 做归一化，提升兼容性
- 辅助函数：
  - verify_and_decrypt_echostr(...)：用于 GET 验证解密
  - handle_callback_raw(...) / verify_and_decrypt_post_body(...)：用于 POST 解密与校验
- 收到 kf_msg_or_event 后，请使用短期 token 调用 sync_msg，并根据 has_more/next_cursor 分页拉取

示例：新增客服账号（头像需先上传临时素材获得 media_id）

```/dev/null/examples/account_add.rs#L1-40
use wxkefu_rs::{Auth, KfClient};
use wxkefu_rs::account::AccountAddRequest;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = KfClient::default();
    let at = client.get_access_token(&Auth::WeCom {
        corp_id: std::env::var("WXKF_CORP_ID")?,
        corp_secret: std::env::var("WXKF_APP_SECRET")?,
    }).await?;

    let req = AccountAddRequest { name: "客服A".into(), media_id: std::env::var("WXKF_MEDIA_ID")? };
    let resp = client.account_add(&at.access_token, &req).await?;
    println!("open_kfid={}", resp.open_kfid);
    Ok(())
}
```

最佳实践

- 缓存 access_token（通常 7200s），并在 40014/40001 出现时优先刷新重试。
- 不要在日志中输出明文密钥与 token，注意脱敏。
- 回调验签：SHA1(token, timestamp, nonce, encrypt)；解密：AES-256-CBC（EncodingAESKey）。
- 遵循约束：
  - 48 小时+5 条消息规则（用户主动发消息后的 48 小时内最多 5 条）
  - 撤回仅限 2 分钟内
  - 临时素材 media_id 有效期 3 天
- unionid 获取需按官方绑定要求；第三方服务商通常无法直接通过 Kf 接口获得 unionid。
- 全局错误处理：
  - 统一使用 errcode 判断，不要依赖 errmsg 文本
  - 出现 “Warning: wrong json format.” 请检查并修正 JSON 请求体
  - 可结合 errors 模块进行分类（是否重试、是否刷新 token 等）

常见问题

- 必须使用企业微信扫码登录吗？
  - 推荐使用，便于统一企业成员权限与客服账号。是否开放微信扫码取决于你的业务与合规。
- 如何处理回调加解密？
  - 按官方算法（token、EncodingAESKey）先验签后解密；本库提供了独立工具函数，便于在任意 Web 框架中集成。
- 为什么我拿到的 OA/MP token 无法调用客服接口？
  - Kf 接口只接受企业微信 corpid + 微信客服 Secret 所获得的 token，OA/MP token 不适用。

贡献与许可

- 欢迎提交 Issue/PR，新增接口、补充示例或修复问题。较大的改动建议先讨论以统一方向。
- 请在仓库中添加合适的 LICENSE（如 MIT/Apache-2.0）。
