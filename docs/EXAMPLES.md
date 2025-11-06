# WeChat Kf Callback 示例和测试指南

本文档列出所有可用的回调示例，以及如何运行和理解它们。

## 快速开始

### 1. 基础验证示例

运行验证和解析示例：

```bash
cargo run --example callback_verify
```

**功能：**
- 配置验证（Token 和 AES Key 格式检查）
- 签名验证（SHA1 哈希计算）
- XML 事件解析
- 完整的回调流程演示
- 安全最佳实践

**输出示例：**
```
=== Example 1: Configuration Validation ===

✓ Valid config created: token='mytoken123', aes_key_len=43
✓ Expected error for token too long: Invalid configuration: Token must be 1-32 characters
✓ Expected error for invalid token: Invalid configuration: Token must contain only English and digits
✓ Expected error for AES key: Invalid configuration: EncodingAESKey must be exactly 43 bytes, got 8
```

### 2. 消息同步示例

运行完整的回调和消息同步示例：

```bash
cargo run --example callback_with_sync_msg
```

**功能：**
- 模拟回调接收
- 签名验证
- 事件解析
- 演示如何调用 sync_msg API
- 游标管理
- 消息类型处理
- 错误处理场景

**输出示例：**
```
Step 1: Load Configuration
✓ Callback config loaded

Step 2: Create Callback Validator
✓ Validator created

Step 3: Initialize API Client
✓ API client created

Step 4: Simulate Callback Reception
  Timestamp: 1348831860
  Nonce: nonce123
  Signature: dd99e450d5ab0b1b9952370803c0fbcadf6686aa

Step 5: Verify Callback Signature
✓ Signature verification passed
```

### 3. Web 服务器示例

运行完整的 HTTP 回调服务器：

```bash
CALLBACK_TOKEN=mytoken \
CALLBACK_AES_KEY=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE \
cargo run --example callback_server
```

**功能：**
- Axum Web 框架集成
- HTTP POST 回调处理
- 健康检查端点
- 完整的请求处理流程
- 错误处理

**使用方法：**

```bash
# 在另一个终端测试
curl http://localhost:3000/health

# 发送模拟回调
curl -X POST http://localhost:3000/callback \
  "?msg_signature=xxx&timestamp=123&nonce=abc" \
  -d '{"encrypt":"..."}'
```

## 单元测试

运行所有回调相关的测试：

```bash
cargo test callback
```

### 测试覆盖范围

#### 1. 配置验证测试

**测试用例：**
- ✓ 有效配置创建
- ✓ Token 过长被拒绝
- ✓ 无效 Token 字符被拒绝
- ✓ AES Key 长度检查

```rust
#[test]
fn test_config_validation() {
    // Valid config
    let result = CallbackConfig::new(
        "mytoken123".to_string(),
        "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
    );
    assert!(result.is_ok());

    // Token too long
    let result = CallbackConfig::new(
        "a".repeat(33),
        "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
    );
    assert!(result.is_err());
}
```

#### 2. 签名验证测试

**测试用例：**
- ✓ 正确签名验证通过
- ✓ 错误签名被拒绝
- ✓ 参数顺序排序正确

```rust
#[test]
fn test_signature_verification() {
    let config = CallbackConfig::new(
        "mytoken".to_string(),
        "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
    )?;
    let validator = CallbackValidator::new(&config)?;

    // Calculate expected signature
    let timestamp = "1348831860";
    let nonce = "nonce_value";

    let result = validator.verify_signature(&expected_sig, timestamp, nonce)?;
    assert!(result);

    // Incorrect signature should fail
    let result = validator.verify_signature("invalid_signature", timestamp, nonce)?;
    assert!(!result);
}
```

#### 3. 事件解析测试

**测试用例：**
- ✓ XML 解析成功
- ✓ 所有字段正确提取
- ✓ CDATA 部分正确处理

```rust
#[test]
fn test_event_parsing() {
    let xml = r#"<xml>
   <ToUserName><![CDATA[ww12345678910]]></ToUserName>
   <CreateTime>1348831860</CreateTime>
   <MsgType><![CDATA[event]]></MsgType>
   <Event><![CDATA[kf_msg_or_event]]></Event>
   <Token><![CDATA[ENCApHxnGDNAVNY4AaSJKj4Tb5mwsEMzxhFmHVGcra996NR]]></Token>
   <OpenKfId><![CDATA[wkxxxxxxx]]></OpenKfId>
</xml>"#;

    let event = CallbackEvent::parse_xml(xml).unwrap();
    assert_eq!(event.to_user_name, "ww12345678910");
    assert_eq!(event.create_time, 1348831860);
    assert_eq!(event.msg_type, "event");
    assert_eq!(event.event, "kf_msg_or_event");
    assert_eq!(event.token, "ENCApHxnGDNAVNY4AaSJKj4Tb5mwsEMzxhFmHVGcra996NR");
    assert_eq!(event.open_kfid, "wkxxxxxxx");
}
```

## 环境配置

### 必需环境变量

对于 Web 服务器示例：

```bash
# Token 用于签名计算（1-32 个英文或数字）
export CALLBACK_TOKEN="mytoken123"

# AES Key 用于消息加密（43 个英文或数字的 base64）
export CALLBACK_AES_KEY="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"

# 对于同步消息示例
export WXKF_CORP_ID="your_corp_id"
export WXKF_APP_SECRET="your_app_secret"
```

### 生成有效的 AES Key

```bash
# Python 生成
python3 -c "import base64; print(base64.b64encode(b'a' * 32).decode().rstrip('='))"

# 或使用任何随机的 32 字节数据
```

## 集成测试

### 模拟完整的回调流程

```rust
#[tokio::test]
async fn test_complete_callback_flow() {
    // 1. 创建配置和验证器
    let config = CallbackConfig::new(
        "test_token".to_string(),
        "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
    ).unwrap();
    let validator = CallbackValidator::new(&config).unwrap();

    // 2. 创建签名
    let timestamp = "1348831860";
    let nonce = "test_nonce";
    let mut params = vec!["test_token", timestamp, nonce];
    params.sort();
    let sorted = params.join("");
    let signature = format!("{:x}", sha1::Sha1::digest(sorted.as_bytes()));

    // 3. 验证签名
    assert!(validator.verify_signature(&signature, timestamp, nonce).unwrap());

    // 4. 解析事件
    let xml = r#"<xml>
        <ToUserName><![CDATA[ww123456789]]></ToUserName>
        <CreateTime>1348831860</CreateTime>
        <MsgType><![CDATA[event]]></MsgType>
        <Event><![CDATA[kf_msg_or_event]]></Event>
        <Token><![CDATA[test_token_123]]></Token>
        <OpenKfId><![CDATA[wktest123]]></OpenKfId>
    </xml>"#;
    let event = CallbackEvent::parse_xml(xml).unwrap();

    // 5. 验证事件字段
    assert_eq!(event.to_user_name, "ww123456789");
    assert_eq!(event.open_kfid, "wktest123");
}
```

## 性能测试

### 基准测试

运行性能基准测试：

```bash
cargo bench --example callback_verify
```

### 测试场景

1. **签名验证性能**
   - 平均时间：< 1ms
   - 10,000 请求：< 10s

2. **事件解析性能**
   - 平均时间：< 5ms
   - 10,000 事件：< 50s

3. **并发处理**
   - 1,000 并发请求：应该能正常处理
   - 无死锁或资源泄漏

## 调试技巧

### 1. 启用日志输出

```bash
RUST_LOG=debug cargo run --example callback_verify
```

### 2. 打印调试信息

```rust
println!("Signature: {}", msg_signature);
println!("Timestamp: {}", timestamp);
println!("Nonce: {}", nonce);
```

### 3. 验证配置

```bash
# 检查 Token 长度
echo -n "your_token" | wc -c

# 检查 AES Key 长度
echo -n "your_aes_key" | wc -c  # 应该是 43
```

### 4. 测试签名计算

```python
import sha1
import hashlib

token = "mytoken"
timestamp = "1348831860"
nonce = "nonce_value"

params = sorted([token, timestamp, nonce])
sorted_str = "".join(params)
signature = hashlib.sha1(sorted_str.encode()).hexdigest()
print(f"Expected signature: {signature}")
```

## 常见问题排查

### 问题 1：签名验证失败

**症状：** "Signature verification failed"

**排查步骤：**
1. 检查 Token 是否正确配置
2. 检查参数顺序是否正确
3. 验证 SHA1 计算
4. 检查是否有空格或其他字符

```rust
// 调试：打印参数
let mut params = vec![token, timestamp, nonce];
params.sort();
println!("Sorted params: {:?}", params);
println!("Joined: {}", params.join(""));
```

### 问题 2：解密失败

**症状：** "Invalid base64" 或 "Decryption failed"

**排查步骤：**
1. 检查 AES Key 长度（必须是 43）
2. 检查加密消息格式
3. 验证 base64 编码
4. 检查 IV 是否为前 16 字节

```rust
// 调试：检查加密消息
println!("Encrypted len: {}", encrypted_msg.len());
println!("First 20 chars: {}", &encrypted_msg[..20.min(encrypted_msg.len())]);
```

### 问题 3：XML 解析失败

**症状：** "XML parse error"

**排查步骤：**
1. 检查解密后的输出是否为有效 XML
2. 检查 CDATA 部分
3. 验证所有必需字段存在
4. 检查字符编码

```rust
// 调试：打印解密的 XML
println!("Decrypted XML:\n{}", decrypted);
```

## 完整的测试检查清单

在部署到生产环境前，确保：

- [ ] 所有单元测试通过
  ```bash
  cargo test
  ```

- [ ] 所有示例成功运行
  ```bash
  cargo run --example callback_verify
  cargo run --example callback_with_sync_msg
  ```

- [ ] 签名验证正确
  - [ ] 正确签名被接受
  - [ ] 错误签名被拒绝

- [ ] 消息解密正确
  - [ ] 加密消息被正确解密
  - [ ] 解密后是有效的 XML
  - [ ] 所有字段正确解析

- [ ] 错误处理
  - [ ] 无效 Token 被拒绝
  - [ ] 无效 AES Key 被拒绝
  - [ ] 解析错误被正确处理

- [ ] 性能
  - [ ] 单次请求 < 100ms
  - [ ] 无内存泄漏
  - [ ] 支持并发请求

- [ ] 安全性
  - [ ] Token 不在日志中显示
  - [ ] AES Key 不在代码中硬编码
  - [ ] HTTPS 已启用
  - [ ] 签名验证总是执行

## 进阶话题

### 自定义验证逻辑

```rust
impl CallbackValidator {
    pub fn verify_with_custom_logic(
        &self,
        msg_signature: &str,
        timestamp: &str,
        nonce: &str,
        extra_validation: impl Fn(&str, &str, &str) -> bool,
    ) -> Result<bool, CallbackError> {
        // 首先验证签名
        if !self.verify_signature(msg_signature, timestamp, nonce)? {
            return Ok(false);
        }

        // 然后执行自定义验证
        Ok(extra_validation(msg_signature, timestamp, nonce))
    }
}
```

### 批量处理回调

```rust
// 使用消息队列处理
let (tx, mut rx) = tokio::sync::mpsc::channel(1000);

// 接收回调
tokio::spawn(async move {
    while let Some(event) = rx.recv().await {
        process_event(event).await;
    }
});

// 发送到队列
tx.send(callback_event).await?;
```

### 持久化 Token

```rust
// 存储 token 以便重用
let token_store = Arc::new(Mutex::new(HashMap::new()));

// 保存 token
token_store.lock().await.insert(
    event.open_kfid.clone(),
    (event.token.clone(), Instant::now()),
);

// 检查是否过期（10 分钟）
if let Some((token, instant)) = token_store.lock().await.get(&kfid) {
    if instant.elapsed() < Duration::from_secs(600) {
        // Token 仍然有效
    }
}
```

## 相关文件

- `src/callback.rs` - 回调模块实现
- `examples/callback_verify.rs` - 验证和解析示例
- `examples/callback_with_sync_msg.rs` - 完整流程示例
- `examples/callback_server.rs` - Web 服务器示例
- `docs/CALLBACK.md` - 详细文档
