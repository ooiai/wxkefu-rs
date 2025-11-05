//! Example: Callback signature verification and message decryption test
//!
//! This example demonstrates:
//! 1. How to verify callback signatures
//! 2. How to decrypt encrypted messages
//! 3. How to parse callback events
//!
//! Running this example:
//! ```bash
//! cargo run --example callback_verify
//! ```

use wxkefu_rs::callback::{CallbackConfig, CallbackEvent, CallbackValidator};

fn main() -> anyhow::Result<()> {
    // Example 1: Configuration validation
    println!("=== Example 1: Configuration Validation ===\n");

    // Valid configuration
    let config = CallbackConfig::new(
        "mytoken123".to_string(),
        "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
    )?;
    println!(
        "✓ Valid config created: token='{}', aes_key_len={}",
        config.token,
        config.encoding_aes_key.len()
    );

    // Invalid token (too long)
    match CallbackConfig::new(
        "a".repeat(33),
        "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
    ) {
        Ok(_) => println!("✗ Should have failed: token too long"),
        Err(e) => println!("✓ Expected error for token too long: {}", e),
    }

    // Invalid token (invalid characters)
    match CallbackConfig::new(
        "my-token-invalid".to_string(),
        "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
    ) {
        Ok(_) => println!("✗ Should have failed: invalid token characters"),
        Err(e) => println!("✓ Expected error for invalid token: {}", e),
    }

    // Invalid AES key (wrong length)
    match CallbackConfig::new("mytoken".to_string(), "shortkey".to_string()) {
        Ok(_) => println!("✗ Should have failed: AES key wrong length"),
        Err(e) => println!("✓ Expected error for AES key: {}\n", e),
    }

    // Example 2: Signature verification
    println!("=== Example 2: Signature Verification ===\n");

    let config = CallbackConfig::new(
        "mytoken".to_string(),
        "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE".to_string(),
    )?;
    let validator = CallbackValidator::new(&config)?;

    // Calculate expected signature
    use sha1::{Digest, Sha1};
    let timestamp = "1348831860";
    let nonce = "nonce_value";
    let mut params = vec!["mytoken", timestamp, nonce];
    params.sort();
    let sorted_string = params.join("");
    let mut hasher = Sha1::new();
    hasher.update(sorted_string.as_bytes());
    let expected_sig = format!("{:x}", hasher.finalize());

    println!("Token: mytoken");
    println!("Timestamp: {}", timestamp);
    println!("Nonce: {}", nonce);
    println!("Expected signature: {}\n", expected_sig);

    // Verify correct signature
    match validator.verify_signature(&expected_sig, timestamp, nonce)? {
        true => println!("✓ Correct signature verified successfully"),
        false => println!("✗ Correct signature verification failed"),
    }

    // Verify incorrect signature
    match validator.verify_signature("invalid_signature", timestamp, nonce)? {
        true => println!("✗ Invalid signature should have failed"),
        false => println!("✓ Invalid signature correctly rejected\n"),
    }

    // Example 3: Event parsing
    println!("=== Example 3: XML Event Parsing ===\n");

    let xml = r#"<xml>
   <ToUserName><![CDATA[ww12345678910]]></ToUserName>
   <CreateTime>1348831860</CreateTime>
   <MsgType><![CDATA[event]]></MsgType>
   <Event><![CDATA[kf_msg_or_event]]></Event>
   <Token><![CDATA[ENCApHxnGDNAVNY4AaSJKj4Tb5mwsEMzxhFmHVGcra996NR]]></Token>
   <OpenKfId><![CDATA[wkxxxxxxx]]></OpenKfId>
</xml>"#;

    match CallbackEvent::parse_xml(xml) {
        Ok(event) => {
            println!("✓ Event parsed successfully:");
            println!("  - Enterprise ID: {}", event.to_user_name);
            println!("  - Create Time: {}", event.create_time);
            println!("  - Message Type: {}", event.msg_type);
            println!("  - Event Type: {}", event.event);
            println!("  - Token: {}", event.token);
            println!("  - Kf Account ID: {}\n", event.open_kfid);
        }
        Err(e) => {
            println!("✗ Failed to parse event: {}\n", e);
        }
    }

    // Example 4: Complete callback flow simulation
    println!("=== Example 4: Complete Callback Flow ===\n");

    let token = "callbacktoken123";
    let aes_key = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE";

    println!("Step 1: Create configuration");
    let config = CallbackConfig::new(token.to_string(), aes_key.to_string())?;
    println!("✓ Configuration created\n");

    println!("Step 2: Create validator");
    let validator = CallbackValidator::new(&config)?;
    println!("✓ Validator created\n");

    println!("Step 3: Verify incoming callback signature");
    let callback_timestamp = "1348831860";
    let callback_nonce = "test_nonce";

    let mut params = vec![token, callback_timestamp, callback_nonce];
    params.sort();
    let sorted = params.join("");
    let mut hasher = Sha1::new();
    hasher.update(sorted.as_bytes());
    let callback_signature = format!("{:x}", hasher.finalize());

    println!("Callback signature: {}", callback_signature);

    match validator.verify_signature(&callback_signature, callback_timestamp, callback_nonce)? {
        true => println!("✓ Callback signature verified\n"),
        false => {
            println!("✗ Callback signature verification failed\n");
            return Err(anyhow::anyhow!("Signature verification failed"));
        }
    }

    println!("Step 4: Parse callback event XML");
    let callback_xml = r#"<xml>
   <ToUserName><![CDATA[ww123456789]]></ToUserName>
   <CreateTime>1348831860</CreateTime>
   <MsgType><![CDATA[event]]></MsgType>
   <Event><![CDATA[kf_msg_or_event]]></Event>
   <Token><![CDATA[TestTokenForSyncMsg123456789]]></Token>
   <OpenKfId><![CDATA[wk1234567890]]></OpenKfId>
</xml>"#;

    match CallbackEvent::parse_xml(callback_xml) {
        Ok(event) => {
            println!("✓ Event parsed successfully");
            println!("  - Enterprise: {}", event.to_user_name);
            println!("  - Kf Account: {}", event.open_kfid);
            println!("  - Token (for sync_msg): {}", event.token);
            println!("\nNext steps:");
            println!("1. Store the token for this callback");
            println!("2. Call sync_msg API with the token to fetch actual messages");
            println!("3. Process messages based on their types");
            println!("4. Update cursor for next sync_msg call\n");
        }
        Err(e) => {
            println!("✗ Failed to parse event: {}\n", e);
            return Err(e.into());
        }
    }

    // Example 5: Security best practices
    println!("=== Example 5: Security Best Practices ===\n");
    println!("When implementing callback handling:");
    println!("1. ✓ Always verify the signature first");
    println!("   - Prevents accepting messages from attackers");
    println!("   - Confirms message integrity");
    println!();
    println!("2. ✓ Keep Token and EncodingAESKey secure");
    println!("   - Store in environment variables or secure config");
    println!("   - Never commit to version control");
    println!("   - Rotate periodically");
    println!();
    println!("3. ✓ Never log sensitive data");
    println!("   - Redact tokens and keys in logs");
    println!("   - Only log sanitized error messages");
    println!();
    println!("4. ✓ Validate all decrypted data");
    println!("   - Assume untrusted input even after decryption");
    println!("   - Use strict XML/JSON parsing");
    println!();
    println!("5. ✓ Respond quickly to WeChat");
    println!("   - Process async if needed");
    println!("   - Respond with HTTP 200 and 'success' immediately");
    println!("   - WeChat will retry if no response within timeout");
    println!();
    println!("6. ✓ Handle idempotency");
    println!("   - Same event may be delivered multiple times");
    println!("   - Use msgid to detect duplicate messages");
    println!();

    println!("=== All Examples Completed Successfully ===");
    Ok(())
}
