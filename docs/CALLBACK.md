# WeChat Kf Callback 回调处理指南

本文档详细说明如何使用 `wxkefu-rs` 的回调模块处理来自微信客服的回调事件。

## 概述

微信客服回调系统允许您在以下事件发生时接收通知：
- 客户发送新消息
- 消息发送失败
- 客户进入会话
- 客户撤回消息
- 其他事件

回调流程：
1. 您配置回调 URL、Token 和 EncodingAESKey
2. 微信客服服务器推送事件到您的回调 URL
3. 您验证签名以确保消息来自微信
4. 您解密并解析事件
5. 您使用事件中的 Token 调用 `sync_msg` API 获取实际消息

## 配置

### 基本步骤

1. **获取配置参数**
   - 登录微信客服管理后台
   - 进入"开发配置"页面
   - 配置回调 URL（必须是公开可访问的 HTTPS）
   - 设置 Token（英文/数字，最多 32 字符）
   - 设置 EncodingAESKey（英文/数字，43 字符）

2. **在代码中创建配置**

```rust
use wxkefu_rs::callback::CallbackConfig;

let config = CallbackConfig::new(
    "your_token".to_string(),
    "your_43_char_encoding_aes_key".to_string(),
)?;
```

### 验证配置

配置会自动验证：
- Token 长度：1-32 字符
- Token 字符：仅英文和数字
- AES Key 长度：恰好 43 字符（base64 格式）
- AES Key 字符：仅英文和数字

## 签名验证

### 工作原理

微信客服使用 Token 对回调请求签名。您必须验证签名以确保：
1. 消息确实来自微信
2. 消息内容未被篡改

### 签名算法

1. 收集查询参数：`msg_signature`, `timestamp`, `nonce`
2. 按字母顺序排序这三个值
3. 将排序后的值连接成一个字符串
4. 计算 SHA1 哈希
5. 与查询参数中的 `msg_signature` 比较

### 代码示例

```rust
use wxkefu_rs::callback::{CallbackConfig, CallbackValidator};

// 创建验证器
let config = CallbackConfig::new(token, encoding_aes_key)?;
let validator = CallbackValidator::new(&config)?;

// 验证签名
let is_valid = validator.verify_signature(
    msg_signature,  // 来自查询参数
    timestamp,       // 来自查询参数
    nonce,           // 来自查询参数
)?;

if !is_valid {
    return Err("Invalid signature");
}
```

## 消息解密

### 工作原理

WeChat 使用 AES-128-CBC (PKCS7 padding) 加密消息内容。

加密流程：
1. Base64 解码加密的消息
2. 前 16 字节是 IV（初始化向量）
3. 剩余字节是密文
4. 使用 AES-128-CBC 解密
5. 移除 PKCS7 填充
6. 得到 XML 格式的消息

### 代码示例

```rust
// 解密消息
let decrypted_xml = validator.decrypt_message(encrypted_message)?;
println!("Decrypted: {}", decrypted_xml);
```

## 事件解析

### 回调事件结构

```xml
<xml>
   <ToUserName><![CDATA[ww12345678910]]></ToUserName>
   <CreateTime>1348831860</CreateTime>
   <MsgType><![CDATA[event]]></MsgType>
   <Event><![CDATA[kf_msg_or_event]]></Event>
   <Token><![CDATA[ENCApHxnGDNAVNY4AaSJKj4Tb5mwsEMzxhFmHVGcra996NR]]></Token>
   <OpenKfId><![CDATA[wkxxxxxxx]]></OpenKfId>
</xml>
```

### 字段说明

| 字段 | 说明 |
|------|------|
| ToUserName | 微信客服企业 ID（通常以 `ww` 开头） |
| CreateTime | 消息创建时间（Unix 时间戳） |
| MsgType | 消息类型（通常为 `event`） |
| Event | 事件类型（例如 `kf_msg_or_event`） |
| Token | 短期有效的 Token，用于调用 sync_msg API |
| OpenKfId | 有新消息的客服账号 ID |

### 代码示例

```rust
use wxkefu_rs::callback::CallbackEvent;

let event = CallbackEvent::parse_xml(&decrypted_xml)?;
println!("Enterprise: {}", event.to_user_name);
println!("Kf Account: {}", event.open_kfid);
println!("Token: {}", event.token);
println!("Event Type: {}", event.event);
```

## 完整工作流

### 步骤 1：接收回调请求

从 HTTP 请求中提取：
- 查询参数：`msg_signature`, `timestamp`, `nonce`
- 请求体：JSON 格式，包含 `encrypt` 字段

### 步骤 2：验证签名

```rust
let is_valid = validator.verify_signature(
    msg_signature,
    timestamp,
    nonce,
)?;

if !is_valid {
    return Err("Signature verification failed");
}
```

### 步骤 3：解密消息

```rust
if let Some(encrypted) = body.encrypt {
    let decrypted = validator.decrypt_message(&encrypted)?;
    // 现在 decrypted 包含 XML 格式的事件
}
```

### 步骤 4：解析事件

```rust
let event = CallbackEvent::parse_xml(&decrypted)?;
```

### 步骤 5：获取消息

使用事件中的 Token 调用 `sync_msg` API：

```rust
use wxkefu_rs::sync_msg::SyncMsgRequest;

let req = SyncMsgRequest {
    token: Some(event.token),
    open_kfid: Some(event.open_kfid),
    cursor: None,  // 首次请求时为 None
    limit: Some(1000),
    voice_format: Some(0),
};

let resp = kf_client.sync_msg(&access_token, &req).await?;

// 处理消息
for msg in resp.msg_list {
    println!("Message ID: {}", msg.common.msgid);
    match msg.payload {
        MsgPayload::Text { text } => println!("Text: {}", text.content),
        MsgPayload::Image { image } => println!("Image: {}", image.media_id),
        // ... 处理其他消息类型
    }
}

// 保存 next_cursor 供下次使用
if let Some(next_cursor) = resp.next_cursor {
    store_cursor(event.open_kfid, next_cursor);
}
```

### 步骤 6：响应微信

立即响应 HTTP 200 和 "success"：

```rust
// 在处理完请求后
ctx.response.status = 200;
ctx.response.body = "success";
```

**重要**：不要让微信等待过长时间。如果处理需要时间，应该立即响应，然后异步处理。

## 集成示例：Axum Web 框架

```rust
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use wxkefu_rs::callback::{CallbackConfig, CallbackEvent, CallbackValidator};
use wxkefu_rs::{Auth, KfClient};

#[derive(Deserialize)]
struct CallbackQuery {
    msg_signature: String,
    timestamp: String,
    nonce: String,
}

#[derive(Deserialize)]
struct CallbackBody {
    #[serde(default)]
    encrypt: Option<String>,
}

#[derive(Clone)]
struct AppState {
    validator: Arc<CallbackValidator>,
    kf_client: Arc<KfClient>,
    access_token: String,
}

async fn handle_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
    body_str: String,
) -> Result<impl IntoResponse, StatusCode> {
    // 步骤 1：验证签名
    match state.validator.verify_signature(
        &query.msg_signature,
        &query.timestamp,
        &query.nonce,
    ) {
        Ok(true) => {},
        _ => return Err(StatusCode::UNAUTHORIZED),
    }

    // 步骤 2：解析请求体
    let body: CallbackBody = serde_json::from_str(&body_str)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if let Some(encrypted) = body.encrypt {
        // 步骤 3：解密
        let decrypted = state.validator.decrypt_message(&encrypted)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // 步骤 4：解析事件
        let event = CallbackEvent::parse_xml(&decrypted)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // 步骤 5：异步处理事件
        let access_token = state.access_token.clone();
        let kf_client = state.kf_client.clone();
        tokio::spawn(async move {
            // 调用 sync_msg 获取消息
            // 处理消息...
        });
    }

    // 步骤 6：立即响应微信
    Ok((StatusCode::OK, "success"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 加载配置
    let token = std::env::var("CALLBACK_TOKEN")?;
    let encoding_aes_key = std::env::var("CALLBACK_AES_KEY")?;
    let access_token = std::env::var("WXKF_ACCESS_TOKEN")?;

    // 创建验证器
    let config = CallbackConfig::new(token, encoding_aes_key)?;
    let validator = CallbackValidator::new(&config)?;

    let state = AppState {
        validator: Arc::new(validator),
        kf_client: Arc::new(KfClient::default()),
        access_token,
    };

    // 构建路由
    let app = Router::new()
        .route("/callback", post(handle_callback))
        .with_state(state);

    // 启动服务器
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

## 安全最佳实践

### 1. 始终验证签名

```rust
if !validator.verify_signature(msg_signature, timestamp, nonce)? {
    return Err("Invalid signature");
}
```

### 2. 保护敏感信息

```rust
// ✓ 好的做法
let token = std::env::var("CALLBACK_TOKEN")?;

// ✗ 不要这样做
const TOKEN: &str = "your_token"; // 不要硬编码在代码中
println!("{}", token);  // 不要在日志中打印 token
```

### 3. 快速响应

```rust
// 立即返回响应
Ok((StatusCode::OK, "success"))

// 然后异步处理
tokio::spawn(async move {
    process_event().await;
});
```

### 4. 幂等性处理

由于微信可能多次重试相同事件，使用 `msgid` 检测重复：

```rust
if let Some(msgid) = extract_msgid(&event) {
    if is_duplicate(msgid)? {
        return Ok((StatusCode::OK, "success"));
    }
    mark_processed(msgid)?;
}
```

### 5. 使用 HTTPS

回调 URL 必须使用 HTTPS，微信不接受 HTTP。

### 6. Token 轮换

定期轮换 Token 和 EncodingAESKey：
- 在微信管理后台生成新的
- 更新应用配置
- 通知团队成员

## 错误处理

### 常见错误

| 错误 | 原因 | 解决方案 |
|------|------|--------|
| 签名验证失败 | Token 不匹配 | 检查 Token 是否正确配置 |
| 解密失败 | AES Key 不正确 | 检查 AES Key 是否正确配置 |
| XML 解析失败 | 消息格式不正确 | 检查微信是否正确发送 |
| Token 过期 | Token 超过 10 分钟 | 立即调用 sync_msg，不要延迟处理 |

### 错误处理示例

```rust
match validator.decrypt_message(&encrypted) {
    Ok(decrypted) => {
        // 处理消息
    }
    Err(e) => {
        eprintln!("Decryption error: {}", e);
        // 不要在生产环境中暴露错误细节
    }
}
```

## 性能优化

### 1. 异步处理

```rust
// 立即响应
Ok((StatusCode::OK, "success"))

// 然后异步处理
tokio::spawn(async {
    let _ = process_messages().await;
});
```

### 2. 批量获取消息

```rust
let req = SyncMsgRequest {
    limit: Some(1000),  // 最大值
    token: Some(token),
    ..Default::default()
};
```

### 3. 游标管理

```rust
// 保存 next_cursor 以继续增量拉取
if resp.has_more == 1 && resp.next_cursor.is_some() {
    queue.push(SyncMsgRequest {
        cursor: resp.next_cursor,
        ..previous_request
    });
}
```

### 4. 数据库持久化

```rust
// 在处理前保存消息
for msg in resp.msg_list {
    db.insert_message(&msg).await?;
}
```

## 监控和告警

### 建议的监控项

1. 回调失败率
2. 签名验证失败次数
3. 解密失败次数
4. sync_msg 调用延迟
5. Token 过期情况

### 告警规则

```
- 10 分钟内签名验证失败 > 5 次 → 告警
- 响应时间 > 5 秒 → 告警
- 消息处理失败率 > 1% → 告警
```

## 运行示例

### 验证和解密示例

```bash
cargo run --example callback_verify
```

这个示例展示：
- 配置验证
- 签名验证
- 事件解析
- 安全最佳实践

### 完整流程示例

```bash
cargo run --example callback_with_sync_msg
```

这个示例展示：
- 完整的回调处理流程
- 如何调用 sync_msg API
- 如何处理不同消息类型

### Web 服务器示例

```bash
CALLBACK_TOKEN=mytoken \
CALLBACK_AES_KEY=your_43_char_key \
cargo run --example callback_server
```

这个示例提供一个完整的 HTTP 服务器。

## 常见问题

### Q: Token 是什么长度？
A: Token 必须是 1-32 个英文字母或数字。

### Q: EncodingAESKey 是什么长度？
A: EncodingAESKey 必须是 43 个英文字母或数字（这是 32 字节 base64 编码后的长度）。

### Q: 回调 URL 需要什么？
A: 必须是：
- 公开可访问（不在防火墙后）
- HTTPS 协议
- POST 方法
- 在 WeChat 管理后台配置

### Q: Token 多久过期？
A: 回调事件中的 Token 有效期为 10 分钟。必须在此期间调用 sync_msg。

### Q: 可以多次接收相同的消息吗？
A: 是的，WeChat 可能重试相同的回调。使用 msgid 检测并忽略重复。

### Q: 回调超时了怎么办？
A: WeChat 等待时间最多 5 秒。如果超时，它会重试。立即响应，然后异步处理。

## 相关资源

- [WeChat Kf 官方文档](https://kf.weixin.qq.com/api/doc/)
- [wxkefu-rs GitHub](https://github.com/your-org/wxkefu-rs)
- [AES 加密详解](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
