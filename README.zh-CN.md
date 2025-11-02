wxkefu-rs · 微信客服 API 集成 / WeChat Customer Service API Integration

简体中文 | English

---

## 简介（中文）

`wxkefu-rs` 旨在帮助你快速接入「微信客服」，提供一致的咨询体验，并通过 API 完成消息的收发与客服账号管理。支持使用「企业微信」扫码登录。

- 官方入口：https://kf.weixin.qq.com/
- 开发者文档: https://kf.weixin.qq.com/api/doc/path/93304

## 获取 token 示例与分类

根据项目语言（Rust）与 Cargo.toml 依赖，下面给出“获取 token”的最小示例，并对常见鉴权方式做分类，便于后续扩展更多 API。

分类说明：

- 公众号/小程序
  - 接口：GET https://api.weixin.qq.com/cgi-bin/token
  - 参数：grant_type=client_credential、appid、secret
- 企业微信（WeCom）
  - 接口：GET https://qyapi.weixin.qq.com/cgi-bin/gettoken
  - 参数：corpid、corpsecret

示例代码（基于本库 `kf` 模块，后续可在此基础上扩展更多 API 客户端）：

```/dev/null/examples/get_token.rs#L1-60
use wxkefu_rs::kf::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = KfClient::default();

    // 公众号/小程序
    if let (Ok(appid), Ok(secret)) = (std::env::var("WX_APPID"), std::env::var("WX_APPSECRET")) {
        let token = client
            .get_access_token(&Auth::OfficialAccount { appid, secret })
            .await?;
        println!(
            "OfficialAccount token: {}, expires_in: {}",
            token.access_token, token.expires_in
        );
    }

    // 企业微信
    if let (Ok(corp_id), Ok(corp_secret)) = (
        std::env::var("WXKF_CORP_ID"),
        std::env::var("WXKF_APP_SECRET"),
    ) {
        let token = client
            .get_access_token(&Auth::WeCom { corp_id, corp_secret })
            .await?;
        println!(
            "WeCom token: {}, expires_in: {}",
            token.access_token, token.expires_in
        );
    }

    Ok(())
}
```

使用说明：

- 在运行前设置环境变量：
  - 公众号/小程序：WX_APPID、WX_APPSECRET
  - 企业微信：WXKF_CORP_ID、WXKF_APP_SECRET
- 将上述代码集成到你的可执行程序中运行；本库只负责 HTTP 调用与基础错误处理，Token 缓存与续期建议在上层实现。

微信客服可在微信内的视频号、公众号、小程序、微信搜索、微信支付凭证，以及微信外的 App、网页等多个入口接入，为客户提供统一的咨询与服务体验。

### 功能特性

- 丰富的接入口：支持在微信内外多种场景接入。
- 一致的咨询体验：客户无需加好友即可与客服沟通，消息提醒与微信一致。
- API 收发消息：通过 API 收发客服消息、管理客服帐号，支持多坐席协作、自动回复等。
- 使用企业微信扫码登录：便捷、安全，适合企业环境统一账号接入。

### 使用场景

- 在网站/App 内嵌微信客服入口，统一客户咨询渠道
- 后台系统通过 API 自动回复或分配客服
- 结合工单系统，实现会话归档与追踪

---

## 快速开始（中文）

1. 开通与准备

- 确保企业已在企业微信后台开通「微信客服」能力
- 在微信客服与企业微信后台完成应用创建、域名与回调配置
- 准备必要的凭据（示例命名，实际以你的项目为准）：
  - `WXKF_CORP_ID`（企业 ID）
  - `WXKF_APP_SECRET`（应用密钥）
  - `WXKF_TOKEN`（回调校验用）
  - `WXKF_AES_KEY`（回调消息加解密）

2. 企业微信扫码登录

- 在你的页面或管理端展示「企业微信」登录二维码
- 用户使用企业微信扫码并授权
- 服务端校验登录态，建立会话与权限关系
- 绑定客服账号或路由规则（如有）

3. 接入 API

- 根据官方文档配置消息收发、客服账号管理、会话分配等能力
- 处理回调事件（消息、会话状态等），执行业务逻辑（如自动回复、转人工）

文档与 API 请参考：

- 官方首页：https://kf.weixin.qq.com/
- API 文档：https://kf.weixin.qq.com/api/doc/path/93304

### 安全与合规

- 妥善保管企业与应用密钥，不要提交到代码仓库
- 回调接口需验证签名并解密消息
- 遵循微信与企业微信平台的使用规范与合规要求

### 更新日志（摘自官方）

【10月9日更新】

- 丰富的接入口：支持视频号、公众号、小程序、微信搜索、微信支付凭证，及微信外 App、网页等
- 一致的咨询体验：无需加好友即可沟通，回复后在微信收到新消息提醒
- API 收发消息：支持通过 API 收发消息、管理客服帐号，实现多坐席协作与自动回复

---

## 常见问题（中文）

- Q：是否必须使用企业微信扫码登录？
  A：推荐使用，便于统一管理企业成员权限与客服账号。也可支持微信扫码（视你的业务与合规）

- Q：如何处理回调消息的加解密？
  A：使用官方提供的加解密流程，结合 `token`、`AES Key` 按文档完成签名校验与消息体解密

- Q：能否做自动回复或分配坐席？
  A：可以。在接收消息或事件回调后，根据业务策略调用 API 进行回复或转接

---

## 贡献（中文）

欢迎提交 Issue 与 PR 来完善文档、补充示例、修复问题或新增能力。建议先讨论再提交实现，便于对齐方向。

## 许可证（中文）

根据实际项目选择并在仓库中补充 `LICENSE` 文件（例如 MIT/Apache-2.0 等）。
