Overview (English)

`wxkefu-rs` helps you integrate WeChat Customer Service (WeChat Kefu) to deliver a consistent consulting experience across WeChat internal and external entry points. It supports WeCom (Enterprise WeChat) QR code login and provides API-based messaging and agent management.

- Official site: https://kf.weixin.qq.com/
- Developer docs: https://kf.weixin.qq.com/api/doc/path/93304

WeChat Kefu can be embedded in multiple entry points such as Channels, Official Accounts, Mini Programs, WeChat Search, WeChat Pay receipts, as well as external apps and web pages.

### Features

- Rich entry points across WeChat and external surfaces
- Consistent chat experience without requiring users to add contacts
- API for sending/receiving messages and managing customer service accounts
- WeCom QR login for enterprise-grade identity and access control

### Use Cases

- Embed WeChat Kefu into your website/app as a unified customer support channel
- Implement auto-reply and routing via backend APIs
- Integrate with ticketing systems for session archiving and tracking

---

## Quick Start (English)

1. Enable and prepare

- Ensure WeChat Kefu is enabled for your enterprise in WeCom admin
- Configure your app, domain, and callback endpoints
- Prepare credentials (example names; adapt to your project):
  - `WXKF_CORP_ID` (Corp ID)
  - `WXKF_APP_SECRET` (App Secret)
  - `WXKF_TOKEN` (Callback token)
  - `WXKF_AES_KEY` (Callback AES key)

2. WeCom QR code login

- Render a WeCom login QR on your page/admin portal
- User scans with WeCom and grants consent
- Server validates the login state and establishes session/permissions
- Bind agent accounts or routing rules if needed

3. API integration

- Follow official docs to implement message send/receive, agent management, and session routing
- Handle callbacks (messages, session events), then run your business logic (auto-reply, escalate to human agent, etc.)

Docs and APIs:

- Homepage: https://kf.weixin.qq.com/
- API Docs: https://kf.weixin.qq.com/api/doc/path/93304

### Security and Compliance

- Keep enterprise/app secrets safe; never commit to VCS
- Verify callback signatures and decrypt payloads per the official spec
- Follow WeChat/WeCom platform policies and compliance requirements

### Changelog (from official)

[Oct 9 Update]

- Rich entry points: Channels, Official Accounts, Mini Programs, Search, Pay receipts, and external apps/webpages
- Consistent chat experience: user doesn’t need to add contact; receives message notifications in WeChat
- API-based messaging: send/receive via API, manage agents; supports multi-agent collaboration and auto-replies

---

## FAQ (English)

- Q: Is WeCom QR login required?
  A: It’s recommended for centralized enterprise identity and agent permissions. WeChat QR login may also be supported depending on your compliance needs.

- Q: How to handle callback encryption/decryption?
  A: Use the official algorithm with `token` and `AES Key` to validate signatures and decrypt messages.

- Q: Can I implement auto-replies or agent routing?
  A: Yes. Process incoming messages/events and call APIs according to your routing policies.

---

## Contributing

Issues and PRs are welcome. Please discuss major changes first to align direction.

## License

Add a `LICENSE` file that matches your project’s preferred license (e.g., MIT/Apache-2.0).

## Rust Example: Fetch Access Token (获取 token)

Set credentials via environment variables:

- Official Account / Mini Program: WX_APPID, WX_APPSECRET
- WeCom (企业微信): WXKF_CORP_ID, WXKF_APP_SECRET

```/dev/null/examples/get_token.rs#L1-40
use wxkefu_rs::kf::{Auth, KfClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = KfClient::default();

    // Official Account / Mini Program
    if let (Ok(appid), Ok(secret)) = (
        std::env::var("WX_APPID"),
        std::env::var("WX_APPSECRET"),
    ) {
        let token = client
            .get_access_token(&Auth::OfficialAccount { appid, secret })
            .await?;
        println!(
            "OfficialAccount token: {}, expires_in: {}",
            token.access_token, token.expires_in
        );
    }

    // WeCom (企业微信)
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
